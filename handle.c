#include "h.h"


NTSTATUS  CmGenerateMovReg(PUCHAR pCode, PULONG pGeneratedCodeLength, ULONG Register, ULONG64 Value)
{
    ULONG uCodeLength = 0;

    if (!pCode || !pGeneratedCodeLength)
        return STATUS_INVALID_PARAMETER;

    switch (Register & ~REG_MASK) {
    case REG_GP:
        pCode[0] = 0x48;
        pCode[1] = 0xb8 | (UCHAR)(Register & REG_MASK);
        memcpy(&pCode[2], &Value, 8);
        uCodeLength = 10;
        break;
    case REG_GP_ADDITIONAL:
        pCode[0] = 0x49;
        pCode[1] = 0xb8 | (UCHAR)(Register & REG_MASK);
        memcpy(&pCode[2], &Value, 8);
        uCodeLength = 10;
        break;
    case REG_CONTROL:
        uCodeLength = *pGeneratedCodeLength;
        CmGenerateMovReg(pCode, pGeneratedCodeLength, REG_RAX, Value);
        uCodeLength = *pGeneratedCodeLength - uCodeLength;
        pCode += uCodeLength;
        uCodeLength = 0;

        if (Register == (REG_CR8)) {
            pCode[0] = 0x44;
            uCodeLength = 1;
            pCode++;
            Register = 0;
        }

        pCode[0] = 0x0f;
        pCode[1] = 0x22;
        pCode[2] = 0xc0 | (UCHAR)((Register & REG_MASK) << 3);
        uCodeLength += 3;
        break;
    default:
        return STATUS_NOT_SUPPORTED;
    }

    if (pGeneratedCodeLength)
        *pGeneratedCodeLength += uCodeLength;

    return STATUS_SUCCESS;
}


NTSTATUS  CmGeneratePushReg(PUCHAR pCode, PULONG pGeneratedCodeLength, ULONG Register)
{
    if (!pCode || !pGeneratedCodeLength)
        return STATUS_INVALID_PARAMETER;

    if ((Register & ~REG_MASK) != REG_GP)
        return STATUS_NOT_SUPPORTED;

    pCode[0] = 0x50 | (UCHAR)(Register & REG_MASK);
    *pGeneratedCodeLength += 1;

    return STATUS_SUCCESS;
}


NTSTATUS  CmGenerateIretq(PUCHAR pCode, PULONG pGeneratedCodeLength)
{
    if (!pCode || !pGeneratedCodeLength)
        return STATUS_INVALID_PARAMETER;

    pCode[0] = 0x48;
    pCode[1] = 0xcf;
    *pGeneratedCodeLength += 2;
    return STATUS_SUCCESS;
}


VOID CmGenerateDescTableLoad(PUCHAR Trampoline, PULONG pOffset, UCHAR SubOpcode, ULONG DataOffsetRelative)
{
    PUCHAR pCode = &Trampoline[*pOffset];

    pCode[0] = 0x0F;
    pCode[1] = 0x01;
    pCode[2] = (SubOpcode == 2) ? 0x15 : 0x1D;

    ULONG32 displacement = DataOffsetRelative - (*pOffset + 7);
    memcpy(&pCode[3], &displacement, 4);

    *pOffset += 7;
}


VOID CmGenerateWrmsr(PUCHAR Trampoline, PULONG pOffset)
{
    PUCHAR pCode = &Trampoline[*pOffset];
    pCode[0] = 0x0F;
    pCode[1] = 0x30;
    *pOffset += 2;
}


VOID CmGenerateLtrAx(PUCHAR Trampoline, PULONG pOffset)
{
    PUCHAR pCode = &Trampoline[*pOffset];
    pCode[0] = 0x0F;
    pCode[1] = 0x00;
    pCode[2] = 0xD8;
    *pOffset += 3;
}


VOID CmGenerateClearTssBusy(PUCHAR Trampoline, PULONG pOffset, ULONG64 GdtBase, ULONG64 TrSelector)
{
    ULONG64 TssTypeByteAddr = GdtBase + (TrSelector & ~7ULL) + 5;

    CmGenerateMovReg(&Trampoline[*pOffset], pOffset, REG_RAX, TssTypeByteAddr);

    PUCHAR pCode = &Trampoline[*pOffset];
    pCode[0] = 0x80;
    pCode[1] = 0x20;
    pCode[2] = 0xFD;
    *pOffset += 3;
}


// =====================================================================
// VmxShutdown — 直接在 VMCALL 的 VM-Exit 中执行 vmxoff
//
// 不再分两阶段，避免 vmresume 因 GUEST_CR4 约束失败而卡死
// =====================================================================
VOID VmxShutdown(PGUEST_REGS GuestRegs)
{
    ULONG cpuIndex = KeGetCurrentProcessorNumberEx(NULL);

    // 读取 VMCALL 指令长度，计算返回地址（vmcall 之后的 ret）
    ULONG64 GuestRip = VmxRead(GUEST_RIP);
    ULONG64 InstLen = VmxRead(VM_EXIT_INSTRUCTION_LEN);
    ULONG64 nextRip = GuestRip + InstLen;

    // 设置 VMCALL 返回值
    GuestRegs->rcx = NBP_MAGIC;
    GuestRegs->rdx = 0;

    // 在 vmxoff 之前从 VMCS 中读取所有 Guest 状态
    ULONG64 guestCr3 = VmxRead(GUEST_CR3);
    ULONG64 guestCr0 = VmxRead(GUEST_CR0);
    ULONG64 guestCr4 = VmxRead(GUEST_CR4) & ~X86_CR4_VMXE;
    ULONG64 guestRsp = VmxRead(GUEST_RSP);
    ULONG64 guestRflags = VmxRead(GUEST_RFLAGS);

    ULONG64 guestFsBase = VmxRead(GUEST_FS_BASE);
    ULONG64 guestGsBase = VmxRead(GUEST_GS_BASE);

    USHORT guestGdtLimit = (USHORT)VmxRead(GUEST_GDTR_LIMIT);
    ULONG64 guestGdtBase = VmxRead(GUEST_GDTR_BASE);
    USHORT guestIdtLimit = (USHORT)VmxRead(GUEST_IDTR_LIMIT);
    ULONG64 guestIdtBase = VmxRead(GUEST_IDTR_BASE);

    ULONG64 guestTrSel = VmxRead(GUEST_TR_SELECTOR);

    ULONG64 guestSysenterCs = VmxRead(GUEST_SYSENTER_CS);
    ULONG64 guestSysenterEsp = VmxRead(GUEST_SYSENTER_ESP);
    ULONG64 guestSysenterEip = VmxRead(GUEST_SYSENTER_EIP);

    USHORT guestSsSel = (USHORT)VmxRead(GUEST_SS_SELECTOR);
    USHORT guestCsSel = (USHORT)VmxRead(GUEST_CS_SELECTOR);

    // vmxoff
    __vmx_off();

    // 恢复系统寄存器
    __writecr4(guestCr4);
    __writecr0(guestCr0);

    AMD64_DESCRIPTOR gdtDesc = {0};
    gdtDesc.Limit = guestGdtLimit;
    gdtDesc.Base = guestGdtBase;
    AsmLoadGdt(&gdtDesc.Limit);

    AMD64_DESCRIPTOR idtDesc = {0};
    idtDesc.Limit = guestIdtLimit;
    idtDesc.Base = guestIdtBase;
    AsmLoadIdt(&idtDesc.Limit);

    {
        PUCHAR gdtBytes = (PUCHAR)guestGdtBase;
        ULONG64 tssDescOffset = guestTrSel & ~7ULL;
        gdtBytes[tssDescOffset + 5] &= ~0x02;
        AsmLoadTr((USHORT)guestTrSel);
    }

    __writemsr(MSR_FS_BASE, guestFsBase);
    __writemsr(MSR_GS_BASE, guestGsBase);

    __writemsr(MSR_IA32_SYSENTER_CS, guestSysenterCs);
    __writemsr(MSR_IA32_SYSENTER_ESP, guestSysenterEsp);
    __writemsr(MSR_IA32_SYSENTER_EIP, guestSysenterEip);

    __writecr3(guestCr3);

    // 标记已关闭
    g_CpuContext[cpuIndex].Launched = FALSE;

    // 生成 Trampoline 并跳转
    PUCHAR Trampoline = (PUCHAR)g_CpuContext[cpuIndex].TrampolinePage;
    if (!Trampoline) {
        KeBugCheckEx(MANUALLY_INITIATED_CRASH, 0xDEAD0001, 0, 0, 0);
    }

    ULONG uSize = 0;
    RtlZeroMemory(Trampoline, PAGE_SIZE);

    // 关键修复：每次调用都传 Trampoline + uSize 作为写入位置
    CmGenerateMovReg(&Trampoline[uSize], &uSize, REG_RCX, GuestRegs->rcx);
    CmGenerateMovReg(&Trampoline[uSize], &uSize, REG_RDX, GuestRegs->rdx);
    CmGenerateMovReg(&Trampoline[uSize], &uSize, REG_RBX, GuestRegs->rbx);
    CmGenerateMovReg(&Trampoline[uSize], &uSize, REG_RBP, GuestRegs->rbp);
    CmGenerateMovReg(&Trampoline[uSize], &uSize, REG_RSI, GuestRegs->rsi);
    CmGenerateMovReg(&Trampoline[uSize], &uSize, REG_RDI, GuestRegs->rdi);
    CmGenerateMovReg(&Trampoline[uSize], &uSize, REG_R8, GuestRegs->r8);
    CmGenerateMovReg(&Trampoline[uSize], &uSize, REG_R9, GuestRegs->r9);
    CmGenerateMovReg(&Trampoline[uSize], &uSize, REG_R10, GuestRegs->r10);
    CmGenerateMovReg(&Trampoline[uSize], &uSize, REG_R11, GuestRegs->r11);
    CmGenerateMovReg(&Trampoline[uSize], &uSize, REG_R12, GuestRegs->r12);
    CmGenerateMovReg(&Trampoline[uSize], &uSize, REG_R13, GuestRegs->r13);
    CmGenerateMovReg(&Trampoline[uSize], &uSize, REG_R14, GuestRegs->r14);
    CmGenerateMovReg(&Trampoline[uSize], &uSize, REG_R15, GuestRegs->r15);

    // 设置新的 RSP（为 IRETQ 帧预留 40 字节 = 5 * 8）
    ULONG64 NewRsp = guestRsp - 40;
    CmGenerateMovReg(&Trampoline[uSize], &uSize, REG_RSP, NewRsp);

    // IRETQ 帧 (push 顺序: SS, RSP, RFLAGS, CS, RIP)
    CmGenerateMovReg(&Trampoline[uSize], &uSize, REG_RAX, (ULONG64)guestSsSel);
    CmGeneratePushReg(&Trampoline[uSize], &uSize, REG_RAX);

    CmGenerateMovReg(&Trampoline[uSize], &uSize, REG_RAX, guestRsp);
    CmGeneratePushReg(&Trampoline[uSize], &uSize, REG_RAX);

    CmGenerateMovReg(&Trampoline[uSize], &uSize, REG_RAX, guestRflags);
    CmGeneratePushReg(&Trampoline[uSize], &uSize, REG_RAX);

    CmGenerateMovReg(&Trampoline[uSize], &uSize, REG_RAX, (ULONG64)guestCsSel);
    CmGeneratePushReg(&Trampoline[uSize], &uSize, REG_RAX);

    CmGenerateMovReg(&Trampoline[uSize], &uSize, REG_RAX, nextRip);
    CmGeneratePushReg(&Trampoline[uSize], &uSize, REG_RAX);

    // 恢复 RAX
    CmGenerateMovReg(&Trampoline[uSize], &uSize, REG_RAX, GuestRegs->rax);

    // IRETQ
    CmGenerateIretq(&Trampoline[uSize], &uSize);

    // jmp 到 Trampoline，永不返回
    AsmJmpToTrampoline((ULONG64)Trampoline);
}


NTSTATUS NTAPI HvmResumeGuest()
{
    ULONG cpuIndex = KeGetCurrentProcessorNumberEx(NULL);
    if (cpuIndex < MAX_CPU_COUNT) {
        g_CpuContext[cpuIndex].Launched = TRUE;
    }

    return STATUS_SUCCESS;
}


VOID VmExitHandler(PGUEST_REGS GuestRegs)
{
    ULONG64 ExitReason;
    ULONG_PTR GuestEIP;
    ULONG_PTR inst_len;

    if (!GuestRegs) {
        return;
    }

    __vmx_vmread(VM_EXIT_REASON, &ExitReason);
    __vmx_vmread(GUEST_RIP, &GuestEIP);
    __vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &inst_len);

    switch (ExitReason) {
    case EXIT_REASON_CPUID:
    {
        int CPUInfo[4] = {-1};
        __cpuidex(CPUInfo, (int)GuestRegs->rax, (int)GuestRegs->rcx);
        if (GuestRegs->rax == 0) {
            GuestRegs->rax = CPUInfo[0];
            GuestRegs->rbx = 'edaM';
            GuestRegs->rcx = 'yerr';
            GuestRegs->rdx = 'oCyB';
        } else {
            GuestRegs->rax = CPUInfo[0];
            GuestRegs->rbx = CPUInfo[1];
            GuestRegs->rcx = CPUInfo[2];
            GuestRegs->rdx = CPUInfo[3];
        }
    }
    break;
    case EXIT_REASON_VMCALL:
    {
        ULONG32 HypercallNumber = (ULONG32)(GuestRegs->rcx & 0xffff);
        switch (HypercallNumber) {
        case NBP_HYPERCALL_UNLOAD:
            VmxShutdown(GuestRegs);
            return;  // 不会到达
        default:
            break;
        }

        GuestRegs->rcx = NBP_MAGIC;
        GuestRegs->rdx = 0;
    }
    break;
    case EXIT_REASON_CR_ACCESS:
    {
        ULONG32 exit_qualification = (ULONG32)VmxRead(EXIT_QUALIFICATION);
        ULONG32 gp = (exit_qualification & CONTROL_REG_ACCESS_REG) >> 8;
        ULONG32 cr = exit_qualification & CONTROL_REG_ACCESS_NUM;

        switch (exit_qualification & CONTROL_REG_ACCESS_TYPE) {
        case TYPE_MOV_TO_CR:
            if (cr == 3) {
                __vmx_vmwrite(GUEST_CR3, *((PULONG64)GuestRegs + gp));
            }
            break;
        case TYPE_MOV_FROM_CR:
            if (cr == 3) {
                __vmx_vmread(GUEST_CR3, (PULONG64)GuestRegs + gp);
            }
            break;
        }
    }
    break;
    case EXIT_REASON_MSR_READ:
    {
        LARGE_INTEGER MsrValue;
        ULONG32 rcx = (ULONG32)GuestRegs->rcx;
        switch (rcx) {
        case MSR_IA32_SYSENTER_CS:
            MsrValue.QuadPart = VmxRead(GUEST_SYSENTER_CS);
            break;
        case MSR_IA32_SYSENTER_ESP:
            MsrValue.QuadPart = VmxRead(GUEST_SYSENTER_ESP);
            break;
        case MSR_IA32_SYSENTER_EIP:
            MsrValue.QuadPart = VmxRead(GUEST_SYSENTER_EIP);
            break;
        case MSR_GS_BASE:
            MsrValue.QuadPart = VmxRead(GUEST_GS_BASE);
            break;
        case MSR_FS_BASE:
            MsrValue.QuadPart = VmxRead(GUEST_FS_BASE);
            break;
        default:
            MsrValue.QuadPart = __readmsr(rcx);
        }

        GuestRegs->rax = MsrValue.LowPart;
        GuestRegs->rdx = MsrValue.HighPart;
    }
    break;
    case EXIT_REASON_MSR_WRITE:
    {
        LARGE_INTEGER MsrValue;
        ULONG32 rcx = (ULONG32)GuestRegs->rcx;

        MsrValue.LowPart = (ULONG32)GuestRegs->rax;
        MsrValue.HighPart = (ULONG32)GuestRegs->rdx;

        switch (rcx) {
        case MSR_IA32_SYSENTER_CS:
            __vmx_vmwrite(GUEST_SYSENTER_CS, MsrValue.QuadPart);
            break;
        case MSR_IA32_SYSENTER_ESP:
            __vmx_vmwrite(GUEST_SYSENTER_ESP, MsrValue.QuadPart);
            break;
        case MSR_IA32_SYSENTER_EIP:
            __vmx_vmwrite(GUEST_SYSENTER_EIP, MsrValue.QuadPart);
            break;
        case MSR_GS_BASE:
            __vmx_vmwrite(GUEST_GS_BASE, MsrValue.QuadPart);
            break;
        case MSR_FS_BASE:
            __vmx_vmwrite(GUEST_FS_BASE, MsrValue.QuadPart);
            break;
        default:
            __writemsr(rcx, MsrValue.QuadPart);
        }
    }
    break;
    case EXIT_REASON_RDTSC:
    {
        unsigned __int64 tick = __rdtsc();

        GuestRegs->rax = tick & 0xffffffff;
        GuestRegs->rdx = (tick & 0xffffffff00000000) / 0x100000000;
    }
    break;
    case 51://EXIT_REASON_RDTSCP
    {
        unsigned int Aux;
        unsigned __int64 tick = __rdtscp(&Aux);

        GuestRegs->rax = tick & 0xffffffff;
        GuestRegs->rdx = (tick & 0xffffffff00000000) / 0x100000000;
        GuestRegs->rcx = Aux;
    }
    break;
    default:
    {
        ULONG64 x = ExitReason;
        x = 0;
    }
    break;
    }

    __vmx_vmwrite(GUEST_RIP, GuestEIP + inst_len);
}
