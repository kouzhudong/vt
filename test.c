#include "h.h"

// 全局 per-CPU 上下文
VMX_CPU_CONTEXT g_CpuContext[MAX_CPU_COUNT] = {0};


static ULONG32  VmxAdjustControls(ULONG32 Ctl, ULONG32 Msr)
{
    LARGE_INTEGER MsrValue;

    MsrValue.QuadPart = __readmsr(Msr);
    Ctl &= MsrValue.HighPart;
    Ctl |= MsrValue.LowPart;
    return Ctl;
}


SSIZE_T get_segment_selector(IN SSIZE_T segment_registers)
{
    SSIZE_T segment_selector = segment_registers;

    _bittestandreset64(&segment_selector, 0);
    _bittestandreset64(&segment_selector, 1);
    _bittestandreset64(&segment_selector, 2);

    return segment_selector;
}


SIZE_T Get_Segment_Base(IN SSIZE_T Segment_Registers)
{
    if (_bittest64(&Segment_Registers, 2) == 1) {
        return 0;
    }

    if (Segment_Registers > GetGdtLimit()) {
        return 0;
    }

    SSIZE_T Segment_Selector = get_segment_selector(Segment_Registers);

    PKGDTENTRY64 p = (PKGDTENTRY64)((Segment_Selector)+(SIZE_T)(KeGetPcr()->GdtBase));

    SIZE_T Base = (p->Bytes.BaseHigh << 24) | (p->Bytes.BaseMiddle << 16) | (p->BaseLow);

    if (!(p->Bytes.Flags1 & 0x10)) {
        Base |= (*(PULONG64)((PUCHAR)p + 8)) << 32;
    }

    return Base;
}


SIZE_T get_segments_access_right(SIZE_T segment_registers)
{
    if (0 == segment_registers) {
        return 0x10000i64;
    }

    SIZE_T access_right = (get_access_rights(segment_registers) >> 8) & 0xF0FF;

    return access_right;
}


PHYSICAL_ADDRESS NTAPI MmAllocateContiguousPagesEx(PVOID *ppVA)
{
    PHYSICAL_ADDRESS l1, l2, l3;

    l1.QuadPart = 0;
    l2.QuadPart = -1;
    l3.QuadPart = 0x200000;

    PVOID PageVA = MmAllocateContiguousNodeMemory(PAGE_SIZE, l1, l2, l3, PAGE_READWRITE, MM_ANY_NODE_OK);

    if (PageVA) {
        RtlZeroMemory(PageVA, PAGE_SIZE);
        if (ppVA) *ppVA = PageVA;
        return MmGetPhysicalAddress(PageVA);
    } else {
        if (ppVA) *ppVA = NULL;
        PHYSICAL_ADDRESS invalid = {0};
        return invalid;
    }
}


PHYSICAL_ADDRESS NTAPI MmAllocateContiguousPages()
{
    return MmAllocateContiguousPagesEx(NULL);
}


VOID SetVMCS(SIZE_T HostRsp, SIZE_T GuestRsp)
{
    SIZE_T           GdtBase = (SIZE_T)(KeGetPcr()->GdtBase);
    AMD64_DESCRIPTOR idtr = {0};
    ULONG            cpuIndex = KeGetCurrentProcessorNumberEx(NULL);

    PHYSICAL_ADDRESS IOBitmapAPA = MmAllocateContiguousPagesEx(&g_CpuContext[cpuIndex].IOBitmapA);
    PHYSICAL_ADDRESS IOBitmapBPA = MmAllocateContiguousPagesEx(&g_CpuContext[cpuIndex].IOBitmapB);
    PHYSICAL_ADDRESS MSRBitmapPA = MmAllocateContiguousPagesEx(&g_CpuContext[cpuIndex].MSRBitmap);

    __sidt(&idtr.Limit);

    __vmx_vmwrite(VMCS_LINK_POINTER, 0xffffffffffffffffULL);

    __vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, VmxAdjustControls(0, MSR_IA32_VMX_PINBASED_CTLS));

    VMX_CPU_BASED_CONTROLS vmCpuCtlRequested = {0};
    vmCpuCtlRequested.Fields.UseMSRBitmaps = 1;
    vmCpuCtlRequested.Fields.ActivateSecondaryControl = TRUE;
    vmCpuCtlRequested.Fields.UseTSCOffseting = 0;
    vmCpuCtlRequested.Fields.RDTSCExiting = FALSE;
    vmCpuCtlRequested.Fields.CR3LoadExiting = 0;
    size_t x = VmxAdjustControls(vmCpuCtlRequested.All, 0x48E);
    __vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, x);

    VmxSecondaryProcessorBasedControls vm_procctl2_requested = {0};
    vm_procctl2_requested.fields.enable_ept = 0;
    vm_procctl2_requested.fields.descriptor_table_exiting = 0;
    vm_procctl2_requested.fields.enable_rdtscp = 1;
    vm_procctl2_requested.fields.enable_vpid = 0;
    vm_procctl2_requested.fields.enable_xsaves_xstors = 1;
    vm_procctl2_requested.fields.enable_invpcid = 1;

    VmxSecondaryProcessorBasedControls vm_procctl2;
    vm_procctl2.all = VmxAdjustControls(vm_procctl2_requested.all, 0x48B);
    __vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, vm_procctl2.all);

    __vmx_vmwrite(VM_EXIT_CONTROLS, VmxAdjustControls(VM_EXIT_IA32E_MODE | VM_EXIT_ACK_INTR_ON_EXIT, MSR_IA32_VMX_EXIT_CTLS));
    __vmx_vmwrite(VM_ENTRY_CONTROLS, VmxAdjustControls(VM_ENTRY_IA32E_MODE, MSR_IA32_VMX_ENTRY_CTLS));

    __vmx_vmwrite(CR4_GUEST_HOST_MASK, X86_CR4_VMXE);
    __vmx_vmwrite(CR4_READ_SHADOW, __readcr4() & ~X86_CR4_VMXE);
    __vmx_vmwrite(CR0_GUEST_HOST_MASK, X86_CR0_PG);
    __vmx_vmwrite(CR0_READ_SHADOW, (__readcr0() & X86_CR0_PG) | X86_CR0_PG);

    __vmx_vmwrite(IO_BITMAP_A, IOBitmapAPA.QuadPart);
    __vmx_vmwrite(IO_BITMAP_B, IOBitmapBPA.QuadPart);
    __vmx_vmwrite(MSR_BITMAP, MSRBitmapPA.QuadPart);

    __vmx_vmwrite(EXCEPTION_BITMAP, 0);

    __vmx_vmwrite(GUEST_ES_SELECTOR, RegGetEs());
    __vmx_vmwrite(GUEST_CS_SELECTOR, RegGetCs());
    __vmx_vmwrite(GUEST_SS_SELECTOR, RegGetSs());
    __vmx_vmwrite(GUEST_DS_SELECTOR, RegGetDs());
    __vmx_vmwrite(GUEST_FS_SELECTOR, RegGetFs());
    __vmx_vmwrite(GUEST_GS_SELECTOR, RegGetGs());
    __vmx_vmwrite(GUEST_LDTR_SELECTOR, GetLdtr());
    __vmx_vmwrite(GUEST_TR_SELECTOR, GetTrSelector());

    __vmx_vmwrite(GUEST_ES_LIMIT, __segmentlimit(RegGetEs()));
    __vmx_vmwrite(GUEST_CS_LIMIT, __segmentlimit(RegGetCs()));
    __vmx_vmwrite(GUEST_SS_LIMIT, __segmentlimit(RegGetSs()));
    __vmx_vmwrite(GUEST_DS_LIMIT, __segmentlimit(RegGetDs()));
    __vmx_vmwrite(GUEST_FS_LIMIT, __segmentlimit(RegGetFs()));
    __vmx_vmwrite(GUEST_GS_LIMIT, __segmentlimit(RegGetGs()));
    __vmx_vmwrite(GUEST_TR_LIMIT, __segmentlimit(GetTrSelector()));
    __vmx_vmwrite(GUEST_IDTR_LIMIT, idtr.Limit);
    __vmx_vmwrite(GUEST_LDTR_LIMIT, __segmentlimit(GetLdtr()));
    __vmx_vmwrite(GUEST_GDTR_LIMIT, GetGdtLimit());

    __vmx_vmwrite(GUEST_ES_AR_BYTES, get_segments_access_right(RegGetEs()));
    __vmx_vmwrite(GUEST_CS_AR_BYTES, get_segments_access_right(RegGetCs()));
    __vmx_vmwrite(GUEST_SS_AR_BYTES, get_segments_access_right(RegGetSs()));
    __vmx_vmwrite(GUEST_DS_AR_BYTES, get_segments_access_right(RegGetDs()));
    __vmx_vmwrite(GUEST_FS_AR_BYTES, get_segments_access_right(RegGetFs()));
    __vmx_vmwrite(GUEST_GS_AR_BYTES, get_segments_access_right(RegGetGs()));
    __vmx_vmwrite(GUEST_LDTR_AR_BYTES, get_segments_access_right(GetLdtr()));
    __vmx_vmwrite(GUEST_TR_AR_BYTES, get_segments_access_right(GetTrSelector()));

    __vmx_vmwrite(GUEST_FS_BASE, __readmsr(MSR_FS_BASE));
    __vmx_vmwrite(GUEST_GS_BASE, __readmsr(MSR_GS_BASE));
    __vmx_vmwrite(GUEST_TR_BASE, (SIZE_T)KeGetPcr()->TssBase);
    __vmx_vmwrite(GUEST_IDTR_BASE, idtr.Base);
    __vmx_vmwrite(GUEST_LDTR_BASE, Get_Segment_Base(GetLdtr()));
    __vmx_vmwrite(GUEST_GDTR_BASE, GdtBase);

    __vmx_vmwrite(GUEST_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
    __vmx_vmwrite(GUEST_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
    __vmx_vmwrite(GUEST_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));

    __vmx_vmwrite(GUEST_CR0, __readcr0());
    __vmx_vmwrite(GUEST_CR3, __readcr3());
    __vmx_vmwrite(GUEST_CR4, __readcr4());

    __vmx_vmwrite(GUEST_DR7, 0x400);

    __vmx_vmwrite(GUEST_RSP, GuestRsp);
    __vmx_vmwrite(GUEST_RIP, (SIZE_T)CmGuestEip);
    __vmx_vmwrite(GUEST_RFLAGS, __getcallerseflags());

    __vmx_vmwrite(GUEST_IA32_DEBUGCTL, __readmsr(MSR_IA32_DEBUGCTL));

    __vmx_vmwrite(HOST_CS_SELECTOR, get_segment_selector(RegGetCs()));
    __vmx_vmwrite(HOST_DS_SELECTOR, get_segment_selector(RegGetDs()));
    __vmx_vmwrite(HOST_ES_SELECTOR, get_segment_selector(RegGetEs()));
    __vmx_vmwrite(HOST_SS_SELECTOR, get_segment_selector(RegGetSs()));
    __vmx_vmwrite(HOST_FS_SELECTOR, get_segment_selector(RegGetFs()));
    __vmx_vmwrite(HOST_GS_SELECTOR, get_segment_selector(RegGetGs()));
    __vmx_vmwrite(HOST_TR_SELECTOR, get_segment_selector(GetTrSelector()));

    __vmx_vmwrite(HOST_FS_BASE, __readmsr(MSR_FS_BASE));
    __vmx_vmwrite(HOST_GS_BASE, __readmsr(MSR_GS_BASE));
    __vmx_vmwrite(HOST_TR_BASE, (SIZE_T)KeGetPcr()->TssBase);
    __vmx_vmwrite(HOST_GDTR_BASE, GdtBase);
    __vmx_vmwrite(HOST_IDTR_BASE, idtr.Base);

    __vmx_vmwrite(HOST_IA32_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
    __vmx_vmwrite(HOST_IA32_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
    __vmx_vmwrite(HOST_IA32_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));

    __vmx_vmwrite(HOST_CR0, __readcr0());
    __vmx_vmwrite(HOST_CR3, __readcr3());
    __vmx_vmwrite(HOST_CR4, __readcr4());

    __vmx_vmwrite(HOST_RSP, HostRsp);
    __vmx_vmwrite(HOST_RIP, (SIZE_T)VmxVmexitHandler);
}


VOID set_cr4()
{
    unsigned __int64 cr4 = __readcr4();
    cr4 = cr4 | 0x2000;
    __writecr4(cr4);
}


NTSTATUS HvmSubvertCpu()
{
    PHYSICAL_ADDRESS PhyAddr;
    SIZE_T GuestRsp = (size_t)_AddressOfReturnAddress() + sizeof(void *);
    PHYSICAL_ADDRESS lowest_acceptable_address = {0};
    PHYSICAL_ADDRESS boundary_address_multiple = {0};
    ULONG cpuIndex = KeGetCurrentProcessorNumberEx(NULL);

    if (cpuIndex >= MAX_CPU_COUNT) {
        return STATUS_NOT_SUPPORTED;
    }

    int CPUInfo[4];
    __cpuid(CPUInfo, 1);
    if ((CPUInfo[2] & 0x80000000) != 0) {
        KdPrint(("Warning: Hypervisor present bit is set. VMXON might fail.\n"));
    }

    PhyAddr.QuadPart = -1;
    PVOID VmxonR = MmAllocateContiguousNodeMemory(PAGE_SIZE, lowest_acceptable_address, PhyAddr, boundary_address_multiple, PAGE_READWRITE, MM_ANY_NODE_OK);
    if (VmxonR == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(VmxonR, PAGE_SIZE);

    PVOID Vmcs = MmAllocateContiguousNodeMemory(PAGE_SIZE, lowest_acceptable_address, PhyAddr, boundary_address_multiple, PAGE_READWRITE, MM_ANY_NODE_OK);
    if (Vmcs == NULL) {
        MmFreeContiguousMemory(VmxonR);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(Vmcs, PAGE_SIZE);

    PVOID Stack = ExAllocatePoolWithTag(NonPagedPoolNx, 2 * PAGE_SIZE, TAG);
    if (Stack == NULL) {
        MmFreeContiguousMemory(Vmcs);
        MmFreeContiguousMemory(VmxonR);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(Stack, 2 * PAGE_SIZE);

    // 分配 Trampoline 页 — 必须可执行 (NonPagedPool, not NX)
    PVOID TrampolinePage = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, TAG);
    if (TrampolinePage == NULL) {
        ExFreePool(Stack);
        MmFreeContiguousMemory(Vmcs);
        MmFreeContiguousMemory(VmxonR);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(TrampolinePage, PAGE_SIZE);

    g_CpuContext[cpuIndex].VmxonRegion = VmxonR;
    g_CpuContext[cpuIndex].VmcsRegion = Vmcs;
    g_CpuContext[cpuIndex].HostStack = Stack;
    g_CpuContext[cpuIndex].TrampolinePage = TrampolinePage;
    g_CpuContext[cpuIndex].IOBitmapA = NULL;
    g_CpuContext[cpuIndex].IOBitmapB = NULL;
    g_CpuContext[cpuIndex].MSRBitmap = NULL;
    g_CpuContext[cpuIndex].Launched = FALSE;

    set_cr4();

    *(SIZE_T *)VmxonR = (__readmsr(MSR_IA32_VMX_BASIC) & 0xffffffff);
    *(SIZE_T *)Vmcs = (__readmsr(MSR_IA32_VMX_BASIC) & 0xffffffff);

    PhyAddr = MmGetPhysicalAddress(VmxonR);

    unsigned char rc = __vmx_on((unsigned __int64 *)&PhyAddr);
    if (rc != 0) {
        KdPrint(("__vmx_on failed with rc=%d. Maybe Hyper-V/VBS is active?\n", rc));
        ExFreePool(TrampolinePage);
        MmFreeContiguousMemory(Vmcs);
        MmFreeContiguousMemory(VmxonR);
        ExFreePool(Stack);
        RtlZeroMemory(&g_CpuContext[cpuIndex], sizeof(VMX_CPU_CONTEXT));
        return STATUS_HV_OPERATION_FAILED;
    }

    PhyAddr = MmGetPhysicalAddress(Vmcs);
    rc = __vmx_vmclear((unsigned __int64 *)&PhyAddr); ASSERT(!rc);
    rc = __vmx_vmptrld((unsigned __int64 *)&PhyAddr); ASSERT(!rc);

    SIZE_T HostRsp = (SIZE_T)Stack + 2 * PAGE_SIZE - sizeof(void *);
    SetVMCS(HostRsp, GuestRsp);

    rc = __vmx_vmlaunch();
    // vmlaunch 成功时不返回
    KdPrint(("VMLAUNCH failed!\n"));

    size_t FieldValue = 0;
#define VM_instruction_error  0x00004400

    rc = __vmx_vmread(VM_instruction_error, &FieldValue);
    if (0 == rc) {
        KdPrint(("VMLAUNCH error: 0x%llx\n", FieldValue));
    }

    __vmx_off();

    ExFreePool(TrampolinePage);
    MmFreeContiguousMemory(Vmcs);
    MmFreeContiguousMemory(VmxonR);
    ExFreePool(Stack);
    RtlZeroMemory(&g_CpuContext[cpuIndex], sizeof(VMX_CPU_CONTEXT));

    return STATUS_HV_OPERATION_FAILED;
}


BOOL is_support_blos()
{
    SSIZE_T FeatureControlMsr = __readmsr(IA32_FEATURE_CONTROL);

    unsigned char b = _bittest64(&FeatureControlMsr, 0);
    if (0 == b) {
        return FALSE;
    }

    b = _bittest64(&FeatureControlMsr, 1);
    if (0 == b) {
        KdPrint(("SMX not supported, OK.\r\n"));
    }

    b = _bittest64(&FeatureControlMsr, 2);
    if (0 == b) {
        return FALSE;
    }

    return TRUE;
}


BOOL is_support_vmx()
{
    int CPUInfo[4] = {-1};

    __cpuid(CPUInfo, 1);

    int ecx = CPUInfo[2];

    BOOL B = _bittest((LONG const *)&ecx, 5);

    return B;
}


BOOL is_support_intel()
{
    BOOL B = FALSE;
    char CPUString[0x20];
    int CPUInfo[4] = {-1};

    __cpuid(CPUInfo, 0);
    memset(CPUString, 0, sizeof(CPUString));
    *((int *)CPUString) = CPUInfo[1];
    *((int *)(CPUString + 4)) = CPUInfo[3];
    *((int *)(CPUString + 8)) = CPUInfo[2];

    if (_stricmp(CPUString, "GenuineIntel") == 0) {
        B = TRUE;
    }

    return B;
}


BOOL is_support_cpuid()
{
    SIZE_T original = __readeflags();

    SIZE_T flipped = original ^ 0x200000;

    __writeeflags(flipped);
    SIZE_T readback = __readeflags();
    __writeeflags(original);

    if ((readback ^ original) & 0x200000) {
        return TRUE;
    }

    return FALSE;
}


#pragma warning(push)
#pragma warning(disable : 6387)
static VOID UnloadDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);

    ULONG cpuIndex = KeGetCurrentProcessorNumberEx(NULL);

    if (cpuIndex < MAX_CPU_COUNT && g_CpuContext[cpuIndex].Launched) {
        // 阶段 1: VMCALL 通知 hypervisor 准备卸载
        // VmxShutdown 会设置 Launched=FALSE 并清除大部分 VM-Exit 拦截
        // vmresume 将 Guest 送回这里
        VmxVmCall(NBP_HYPERCALL_UNLOAD);

        // 阶段 2: 执行 CPUID 触发最后的 VM-Exit
        // 此时 VmExitHandler 检测到 Launched==FALSE，执行 vmxoff
        // vmxoff 后恢复 Guest 状态并跳到 CPUID 之后继续执行
        int cpuInfo[4];
        __cpuid(cpuInfo, 0);
    }

    KeSignalCallDpcSynchronize(SystemArgument2);
    KeSignalCallDpcDone(SystemArgument1);
}
#pragma warning(pop)


#pragma warning(push)
#pragma warning(disable : 6001)
VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    KeGenericCallDpc(UnloadDpcRoutine, NULL);

    ULONG numProcs = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    for (ULONG i = 0; i < numProcs && i < MAX_CPU_COUNT; i++) {
        if (!g_CpuContext[i].VmxonRegion) {
            continue;
        }

        if (g_CpuContext[i].TrampolinePage) {
            ExFreePool(g_CpuContext[i].TrampolinePage);
        }
        if (g_CpuContext[i].VmxonRegion) {
            MmFreeContiguousMemory(g_CpuContext[i].VmxonRegion);
        }
        if (g_CpuContext[i].VmcsRegion) {
            MmFreeContiguousMemory(g_CpuContext[i].VmcsRegion);
        }
        if (g_CpuContext[i].HostStack) {
            ExFreePool(g_CpuContext[i].HostStack);
        }
        if (g_CpuContext[i].IOBitmapA) {
            MmFreeContiguousMemory(g_CpuContext[i].IOBitmapA);
        }
        if (g_CpuContext[i].IOBitmapB) {
            MmFreeContiguousMemory(g_CpuContext[i].IOBitmapB);
        }
        if (g_CpuContext[i].MSRBitmap) {
            MmFreeContiguousMemory(g_CpuContext[i].MSRBitmap);
        }

        RtlZeroMemory(&g_CpuContext[i], sizeof(VMX_CPU_CONTEXT));
    }
}
#pragma warning(pop)


DRIVER_INITIALIZE DriverEntry;


_Use_decl_annotations_
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    KdBreakPoint();

    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    if (!is_support_cpuid()) {
        return STATUS_NOT_SUPPORTED;
    }

    if (!is_support_intel()) {
        return STATUS_NOT_SUPPORTED;
    }

    if (!is_support_vmx()) {
        return STATUS_NOT_SUPPORTED;
    }

    if (!is_support_blos()) {
        return STATUS_NOT_SUPPORTED;
    }

    RtlZeroMemory(g_CpuContext, sizeof(g_CpuContext));

    ULONG numProcs = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    for (ULONG i = 0; i < numProcs; i++) {
        PROCESSOR_NUMBER procNumber;
        KeGetProcessorNumberFromIndex(i, &procNumber);

        GROUP_AFFINITY affinity = {0};
        affinity.Group = procNumber.Group;
        affinity.Mask = (KAFFINITY)1 << procNumber.Number;

        GROUP_AFFINITY oldAffinity;
        KeSetSystemGroupAffinityThread(&affinity, &oldAffinity);

        KIRQL OldIrql = KeRaiseIrqlToDpcLevel();
        NTSTATUS Status = CmSubvert();
        KeLowerIrql(OldIrql);
        KeRevertToUserGroupAffinityThread(&oldAffinity);

        if (!NT_SUCCESS(Status)) {
            KdPrint(("CmSubvert failed on processor %d with status 0x%x\n", i, Status));
            return Status;
        }
    }

    DriverObject->DriverUnload = DriverUnload;
    return STATUS_SUCCESS;
}