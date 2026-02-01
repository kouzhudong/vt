#include "h.h"


static ULONG32  VmxAdjustControls(ULONG32 Ctl, ULONG32 Msr)
{
    LARGE_INTEGER MsrValue;

    MsrValue.QuadPart = __readmsr(Msr);
    // 高位部分为 0 的位，CTL 中必须为 0 (不允许设为1)
    Ctl &= MsrValue.HighPart;
    // 低位部分为 1 的位，CTL 中必须为 1 (强制设为1)
    Ctl |= MsrValue.LowPart;
    return Ctl;
}


SSIZE_T get_segment_selector(IN SSIZE_T segment_registers)
{
    SSIZE_T segment_selector = segment_registers;

    //屏蔽低3位。即在GDT的地址，每一项8字节对齐。
    _bittestandreset64(&segment_selector, 0);
    _bittestandreset64(&segment_selector, 1);
    _bittestandreset64(&segment_selector, 2);

    return segment_selector;
}


SIZE_T Get_Segment_Base(IN SSIZE_T Segment_Registers)
{
    //SIZE_T BaseLow = 0;
    //SIZE_T BaseMiddle = 0;
    //SIZE_T BaseHigh = 0;

    if (_bittest64(&Segment_Registers, 2) == 1) {
        //在LDT中。
        return 0;
    }

    if (Segment_Registers > GetGdtLimit()) {
        return 0;
    }

    //清楚低三位的标志，也就是获取Segment Selector。
    SSIZE_T Segment_Selector = get_segment_selector(Segment_Registers);

    PKGDTENTRY64 p = (PKGDTENTRY64)((Segment_Selector)+(SIZE_T)(KeGetPcr()->GdtBase));

    SIZE_T Base = (p->Bytes.BaseHigh << 24) | (p->Bytes.BaseMiddle << 16) | (p->BaseLow);

    //if (p->Bits.DefaultBig && Base)
    //{
    //    //扩充高位为1.即F.
    //    Base += 0xffffffff00000000;
    //}

    //TSS的有点特殊。请看在WINDBG中用命令查看GDT。其实这个值可以在每个CPU的PCR中获取。
    if (!(p->Bytes.Flags1 & 0x10)) {// this is a TSS or callgate etc, save the base high part    
        Base |= (*(PULONG64)((PUCHAR)p + 8)) << 32;
    }

    return Base;
}


SIZE_T get_segments_access_right(SIZE_T segment_registers)
{
    if (0 == segment_registers) {
        return 0x10000i64;//Ldtr会走这里。为何返回这个数，有待思考。
    }

    SIZE_T access_right = get_access_rights(segment_registers);
    /*
    估计这个返回的是：Segment Descriptor的高DWORD，但是也排除这个 DWORD的高八位（Base 31:24）和低八位（Base 23:16）。
    */

    /*
    此时剩余的有效位是十六位，即一个WORD，但是低八位要移除。
    但是这16位中还有几位（4位）位：Seg.Limit19:16，所以要清除。
    所以有此算法。
    由此可见：segments_access_right就是segments中除去limit和Base的剩余部分，其格式以WORD存在。
    */
    access_right = (get_access_rights(segment_registers) >> 8) & 0xF0FF;

    return access_right;
}


PHYSICAL_ADDRESS NTAPI MmAllocateContiguousPages()
{
    PHYSICAL_ADDRESS l1, l2, l3;

    l1.QuadPart = 0;
    l2.QuadPart = -1;
    l3.QuadPart = 0x200000; // 边界对齐

    // 修复：使用 MmAllocateContiguousNodeMemory 替代废弃API，提高兼容性
    PVOID PageVA = MmAllocateContiguousNodeMemory(PAGE_SIZE, l1, l2, l3, PAGE_READWRITE, MM_ANY_NODE_OK);

    // ASSERT(PageVA); // 如果内存耗尽，ASSERT会导致蓝屏，建议在Release中移除
    if (PageVA) {
        RtlZeroMemory(PageVA, PAGE_SIZE);
        return MmGetPhysicalAddress(PageVA);
    } else {
        PHYSICAL_ADDRESS invalid = {0};
        return invalid;
    }
}


VOID SetVMCS(SIZE_T HostRsp, SIZE_T GuestRsp)
{
    SIZE_T           GdtBase = (SIZE_T)(KeGetPcr()->GdtBase);//r gdtr
    AMD64_DESCRIPTOR idtr = {0};
    //PKPCR            pcr = KeGetPcr();

    // 关键修正：确保 MSR Bitmap 内存被正确分配。
    // 如果分配失败（Phys=0），系统会访问物理地址0，导致异常。但在这里我们已经在分配函数里做了处理。
    PHYSICAL_ADDRESS IOBitmapAPA = MmAllocateContiguousPages();
    PHYSICAL_ADDRESS IOBitmapBPA = MmAllocateContiguousPages();
    PHYSICAL_ADDRESS MSRBitmapPA = MmAllocateContiguousPages();

    //unsigned char r = 0;     

    __sidt(&idtr.Limit);

    // 在 64 位模式下，该字段是 64 位的。设置为全 1 (-1) 表示不使用 VMCS 链接指针。
    __vmx_vmwrite(VMCS_LINK_POINTER, 0xffffffffffffffffULL);
    // __vmx_vmwrite (VMCS_LINK_POINTER_HIGH, 0xffffffff); // 不需要，64位环境不支持 High 字段操作

    // PIN-BASED CONTROLS
    __vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, VmxAdjustControls(0, MSR_IA32_VMX_PINBASED_CTLS));

    // PRIMARY PROCESSOR-BASED CONTROLS
    VMX_CPU_BASED_CONTROLS vmCpuCtlRequested = {0};

    // [FIX 1] 启用 MSR Bitmaps
    // Win11 访问大量特定 MSR，如果不启用 Bitmap（让所有MSR访问都产生 VMExit），会导致极高的性能开销，看起来像卡死。
    // 我们传入全 0 的 Bitmap，意味着不拦截任何 MSR，直通硬件，性能最好。
    vmCpuCtlRequested.Fields.UseMSRBitmaps = 1;

    vmCpuCtlRequested.Fields.ActivateSecondaryControl = TRUE;
    vmCpuCtlRequested.Fields.UseTSCOffseting = 0;

    // [FIX 2] 禁用 RDTSC 退出 !!!
    // 此处原代码为 TRUE。在 Win11 上，RDTSC 被高频使用。
    // 除非你有极其优化的汇编处理程序并正确处理 RDTSCP 的 RCX 寄存器，否则开启此项会导致系统卡顿甚至 "Freeze"。
    // 这里改为 FALSE，允许 Guest 直接执行 RDTSC。
    vmCpuCtlRequested.Fields.RDTSCExiting = FALSE;

    vmCpuCtlRequested.Fields.CR3LoadExiting = 0;// VPID caches must be invalidated on CR3 change
    size_t x = VmxAdjustControls(vmCpuCtlRequested.All, 0x48E);
    __vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, x);


    // SECONDARY PROCESSOR-BASED CONTROLS
    VmxSecondaryProcessorBasedControls vm_procctl2_requested = {0};
    vm_procctl2_requested.fields.enable_ept = 0;
    vm_procctl2_requested.fields.descriptor_table_exiting = 0;

    // [FIX 3] Enable RDTSCP
    // 即使 RDTSCExiting = 0，如果 enable_rdtscp = 0，Guest 执行 RDTSCP 指令会触发 #UD 异常。
    // Win10/11 必须置 1。
    vm_procctl2_requested.fields.enable_rdtscp = 1;

    vm_procctl2_requested.fields.enable_vpid = 0;

    // [FIX 4] Win11 必需特性支持
    // Windows 11 默认使用 XSAVES/XRSTORS 和 INVPCID。
    // 如果不在 VMCS 中声明支持，Guest 尝试执行时会触发 #UD。
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
    __vmx_vmwrite(CR0_READ_SHADOW, (__readcr4() & X86_CR0_PG) | X86_CR0_PG);

    // 写入地址字段
    __vmx_vmwrite(IO_BITMAP_A, IOBitmapAPA.QuadPart);
    __vmx_vmwrite(IO_BITMAP_B, IOBitmapBPA.QuadPart);
    __vmx_vmwrite(MSR_BITMAP, MSRBitmapPA.QuadPart);

    __vmx_vmwrite(EXCEPTION_BITMAP, 0);

    //////////////////////////////////////////////////////////////////////////////////////////////
    // Guest State Area
    __vmx_vmwrite(GUEST_ES_SELECTOR, RegGetEs());
    __vmx_vmwrite(GUEST_CS_SELECTOR, RegGetCs());
    __vmx_vmwrite(GUEST_SS_SELECTOR, RegGetSs());
    __vmx_vmwrite(GUEST_DS_SELECTOR, RegGetDs());
    __vmx_vmwrite(GUEST_FS_SELECTOR, RegGetFs());
    __vmx_vmwrite(GUEST_GS_SELECTOR, RegGetGs());
    __vmx_vmwrite(GUEST_LDTR_SELECTOR, GetLdtr());
    __vmx_vmwrite(GUEST_TR_SELECTOR, GetTrSelector());//应该和r tr这个命令的结果一样。

    __vmx_vmwrite(GUEST_ES_LIMIT, __segmentlimit(RegGetEs()));//__segmentlimit
    __vmx_vmwrite(GUEST_CS_LIMIT, __segmentlimit(RegGetCs()));
    __vmx_vmwrite(GUEST_SS_LIMIT, __segmentlimit(RegGetSs()));
    __vmx_vmwrite(GUEST_DS_LIMIT, __segmentlimit(RegGetDs()));
    __vmx_vmwrite(GUEST_FS_LIMIT, __segmentlimit(RegGetFs()));
    __vmx_vmwrite(GUEST_GS_LIMIT, __segmentlimit(RegGetGs()));
    __vmx_vmwrite(GUEST_TR_LIMIT, __segmentlimit(GetTrSelector()));
    __vmx_vmwrite(GUEST_IDTR_LIMIT, idtr.Limit);//r idtl
    __vmx_vmwrite(GUEST_LDTR_LIMIT, __segmentlimit(GetLdtr()));
    __vmx_vmwrite(GUEST_GDTR_LIMIT, GetGdtLimit()); //r gdtl

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
    __vmx_vmwrite(GUEST_TR_BASE, (SIZE_T)KeGetPcr()->TssBase);//Get_Segment_Base(GetTrSelector())
    __vmx_vmwrite(GUEST_IDTR_BASE, idtr.Base);//r idtr
    __vmx_vmwrite(GUEST_LDTR_BASE, Get_Segment_Base(GetLdtr()));
    __vmx_vmwrite(GUEST_GDTR_BASE, GdtBase);

    __vmx_vmwrite(GUEST_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
    __vmx_vmwrite(GUEST_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
    __vmx_vmwrite(GUEST_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));

    __vmx_vmwrite(GUEST_CR0, __readcr0());
    __vmx_vmwrite(GUEST_CR3, __readcr3());
    __vmx_vmwrite(GUEST_CR4, __readcr4());

    __vmx_vmwrite(GUEST_DR7, 0x400);

    __vmx_vmwrite(GUEST_RSP, GuestRsp);//GuestRsp (SIZE_T)CmSubvert
    __vmx_vmwrite(GUEST_RIP, (SIZE_T)CmGuestEip);
    __vmx_vmwrite(GUEST_RFLAGS, __getcallerseflags());

    __vmx_vmwrite(GUEST_IA32_DEBUGCTL, __readmsr(MSR_IA32_DEBUGCTL));
    // __vmx_vmwrite (GUEST_IA32_DEBUGCTL_HIGH, __readmsr (MSR_IA32_DEBUGCTL) >> 32); // 64位环境不需要

    //////////////////////////////////////////////////////////////////////////////////////////////

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
//设置CR4的一个位。
{
    unsigned __int64 cr4 = __readcr4();

    //VMX-Enable Bit (bit 13 of CR4) — Enables VMX operation when set
    cr4 = cr4 | 0x2000;//1>>13

    //另一个思路是：_bittestandset, _bittestandset64

    __writecr4((unsigned int)cr4);
}


NTSTATUS HvmSubvertCpu()
{
    PHYSICAL_ADDRESS PhyAddr;
    SIZE_T GuestRsp = (size_t)_AddressOfReturnAddress() + sizeof(void *);//即父函数中的RSP的值。_ReturnAddress().
    PHYSICAL_ADDRESS lowest_acceptable_address = {0};
    PHYSICAL_ADDRESS boundary_address_multiple = {0};

    // 检查是否已经在 Hypervisor 之下（例如 VBS/Hyper-V 开启）
    int CPUInfo[4];
    __cpuid(CPUInfo, 1);
    if ((CPUInfo[2] & 0x80000000) != 0) {
        KdPrint(("Warning: Hypervisor present bit is set. VMXON might fail or cause nested VM exit loop.\n"));
    }

    PhyAddr.QuadPart = -1;//MmAllocateNonCachedMemory 
    //VmxonR = MmAllocateContiguousMemory(PAGE_SIZE, PhyAddr);
    PVOID VmxonR = MmAllocateContiguousNodeMemory(PAGE_SIZE, lowest_acceptable_address, PhyAddr, boundary_address_multiple, PAGE_READWRITE, MM_ANY_NODE_OK);
    if (VmxonR == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(VmxonR, PAGE_SIZE);

    //Vmcs  = MmAllocateContiguousMemory(PAGE_SIZE, PhyAddr);
    PVOID Vmcs = MmAllocateContiguousNodeMemory(PAGE_SIZE, lowest_acceptable_address, PhyAddr, boundary_address_multiple, PAGE_READWRITE, MM_ANY_NODE_OK);
    if (Vmcs == NULL) {
        MmFreeContiguousMemory(VmxonR);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(Vmcs, PAGE_SIZE);

    PVOID Stack = ExAllocatePoolWithTag(NonPagedPoolNx, 2 * PAGE_SIZE, TAG); // ExAllocatePool2容易失败。
    if (Stack == NULL) {
        if (Vmcs) {
            MmFreeContiguousMemory(Vmcs);
        }
        if (VmxonR) {
            MmFreeContiguousMemory(VmxonR);
        }
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(Stack, 2 * PAGE_SIZE);

    set_cr4();

    *(SIZE_T *)VmxonR = (__readmsr(MSR_IA32_VMX_BASIC) & 0xffffffff);
    *(SIZE_T *)Vmcs = (__readmsr(MSR_IA32_VMX_BASIC) & 0xffffffff);

    PhyAddr = MmGetPhysicalAddress(VmxonR);

    // [SAFETY] 检查 __vmx_on 返回值。如果失败(例如 VBS 开启且未启用嵌套)，继续执行会导致 0x7E 蓝屏
    unsigned char rc = __vmx_on((unsigned __int64 *)&PhyAddr);

    if (rc != 0) {
        KdPrint(("__vmx_on failed with rc=%d. Maybe Hyper-V/VBS is active?\n", rc));

        MmFreeContiguousMemory(Vmcs);
        MmFreeContiguousMemory(VmxonR);
        ExFreePool(Stack);
        return STATUS_HV_OPERATION_FAILED; // 宏需要在头文件定义，或使用 STATUS_UNSUCCESSFUL
    }

    PhyAddr = MmGetPhysicalAddress(Vmcs);
    rc = __vmx_vmclear((unsigned __int64 *)&PhyAddr); ASSERT(!rc);
    rc = __vmx_vmptrld((unsigned __int64 *)&PhyAddr); ASSERT(!rc);

    SIZE_T HostRsp = (SIZE_T)Stack + 2 * PAGE_SIZE - sizeof(void *);
    SetVMCS(HostRsp, GuestRsp);

    rc = __vmx_vmlaunch();
    ASSERT(0 == rc);
    if (0 != rc) {
        size_t FieldValue = 0;
#define VM_instruction_error  0x00004400

        rc = __vmx_vmread(VM_instruction_error, &FieldValue);
        if (0 == rc) {
            //根据错误码：FieldValue参见：30.4 VM INSTRUCTION ERROR NUMBERS
            //KdPrint(("__vmx_vmread VM_instruction_error FieldValue:0x%x. in line: %d at file:%s.\r\n", FieldValue, __LINE__, __FILE__));
        }

        __vmx_off();

        //释放内存 - 防止泄漏
        MmFreeContiguousMemory(Vmcs);
        MmFreeContiguousMemory(VmxonR);
        ExFreePool(Stack);
    }

    return STATUS_SUCCESS;
}


BOOL is_support_blos()
/*
功能：判断主板中是否开启vmx。
可以用位结构：
https://msdn.microsoft.com/zh-cn/library/ewwyfdbe.aspx
https://msdn.microsoft.com/zh-cn/library/yszfawxh.aspx
也可以用指令完成：
https://msdn.microsoft.com/en-us/library/h65k4tze.aspx

权威资料：
23.7 ENABLING AND ENTERING VMX OPERATION
*/
{
    SSIZE_T FeatureControlMsr = __readmsr(IA32_FEATURE_CONTROL);

    unsigned char b = _bittest64(&FeatureControlMsr, 0);
    if (0 == b) {
        return FALSE;//If this bit is clear, VMXON causes a general-protection exception.
    }

    b = _bittest64(&FeatureControlMsr, 1);
    if (0 == b) {
        KdPrint(("SMX 下不支持 VMX，不过这也没关系.\r\n"));
        //return FALSE;
    }

    b = _bittest64(&FeatureControlMsr, 2);
    if (0 == b) {
        return FALSE;
    }

    return TRUE;
}


BOOL is_support_vmx()
/*
功能：判断CPU是否支持VMX指令。
权威资料：23.6 DISCOVERING SUPPORT FOR VMX

System software can determine whether a processor supports VMX operation using CPUID.
If CPUID.1:ECX.VMX[bit 5] = 1, then VMX operation is supported.
*/
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

    // __cpuid with an InfoType argument of 0 returns the number of valid Ids in CPUInfo[0] and the CPU identification string in the other three array elements.
    // The CPU identification string is not in linear order. 
    // The code below arranges the information in a human readable form.
    __cpuid(CPUInfo, 0);
    //unsigned nIds = CPUInfo[0];
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
/*
判断CPU是否支持CPUID指令。

The ID flag (bit 21) in the EFLAGS register indicates support for the CPUID instruction.
If a software procedure can set and clear this flag, the processor executing the procedure supports the CPUID instruction.
This instruction operates the same in non-64-bit modes and 64-bit mode.
*/
{
    SIZE_T original = __readeflags(); //读取

    // 尝试翻转第 21 位
    SIZE_T flipped = original ^ 0x200000;

    __writeeflags(flipped);
    SIZE_T readback = __readeflags();
    __writeeflags(original); // 恢复

    // 检查第 21 位是否已改变
    if ((readback ^ original) & 0x200000) {
        return TRUE;
    }

    return FALSE;
}


VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    for (CHAR i = 0; i < KeNumberProcessors; i++) {
        KeSetSystemAffinityThread((KAFFINITY)((ULONG_PTR)1 << i));
        KIRQL OldIrql = KeRaiseIrqlToDpcLevel();
        VmxVmCall(NBP_HYPERCALL_UNLOAD);
        KeLowerIrql(OldIrql);
        KeRevertToUserAffinityThread();
    }
}


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

    if (!is_support_intel()) //AMD虚拟化的功能还有待加入。
    {
        return STATUS_NOT_SUPPORTED;
    }

    if (!is_support_vmx()) {
        return STATUS_NOT_SUPPORTED;
    }

    //读取0x480的MSR的信息。

    if (!is_support_blos()) {
        return STATUS_NOT_SUPPORTED;
    }

    //读取0x48C的MSR的信息，判断是否支持EPT。

    for (CHAR i = 0; i < KeNumberProcessors; i++) {
        KeSetSystemAffinityThread((KAFFINITY)((ULONG_PTR)1 << i));
        KIRQL OldIrql = KeRaiseIrqlToDpcLevel();

        // 增加对返回状态的检查，不要用 ASSERT，因为 Release 版本通过后可能会让系统处于不一致状态
        NTSTATUS Status = CmSubvert();//一个汇编函数：流程是保存所有寄存器(除了段寄存器)的内容到栈里后，调用HvmSubvertCpu
        KeLowerIrql(OldIrql);
        KeRevertToUserAffinityThread();

        if (!NT_SUCCESS(Status)) {
            KdPrint(("CmSubvert failed on processor %d with status 0x%x\n", i, Status));
            // 在实际产品中，这里可能需要执行回滚操作（卸载已成功的CPU上的 Hypervisor）
            return Status;
        }
    }

    DriverObject->DriverUnload = DriverUnload;
    return STATUS_SUCCESS;
}