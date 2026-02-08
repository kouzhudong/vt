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
// 在 Trampoline 中生成 vmxoff 指令
// 这样 vmxoff 在 Trampoline 页的地址空间中执行，
// 而不是在即将被卸载的 test.sys 地址空间中。
// =====================================================================
VOID CmGenerateVmxOff(PUCHAR Trampoline, PULONG pOffset)
{
    PUCHAR pCode = &Trampoline[*pOffset];
    pCode[0] = 0x0F;  // vmxoff = 0F 01 C4
    pCode[1] = 0x01;
    pCode[2] = 0xC4;
    *pOffset += 3;
}


VOID VmxGenerateTrampolineToGuest(PGUEST_REGS GuestRegs, PUCHAR Trampoline)
{
    ULONG uSize = 0;
    ULONG uDataOffset = 0x800;

    USHORT gdtLimit = (USHORT)VmxRead(GUEST_GDTR_LIMIT);
    ULONG64 gdtBase = VmxRead(GUEST_GDTR_BASE);
    memcpy(&Trampoline[uDataOffset], &gdtLimit, 2);
    memcpy(&Trampoline[uDataOffset + 2], &gdtBase, 8);

    USHORT idtLimit = (USHORT)VmxRead(GUEST_IDTR_LIMIT);
    ULONG64 idtBase = VmxRead(GUEST_IDTR_BASE);
    memcpy(&Trampoline[uDataOffset + 10], &idtLimit, 2);
    memcpy(&Trampoline[uDataOffset + 12], &idtBase, 8);

    __vmx_vmwrite(GUEST_RFLAGS, VmxRead(GUEST_RFLAGS) & ~0x100);

    // 0. VMXOFF — 必须在 VMX root operation 中执行，放在 Trampoline 最前面
    //    这确保 vmxoff 后续的 CR 修改不再触发嵌套 VT-x 层的 VM-Exit
    CmGenerateVmxOff(Trampoline, &uSize);

    // 1. 恢复 CR4 — 清除 VMXE (bit 13)，必须在 vmxoff 之后立即执行
    ULONG64 GuestCr4 = VmxRead(GUEST_CR4);
    CmGenerateMovReg(Trampoline, &uSize, REG_CR4, GuestCr4 & ~X86_CR4_VMXE);

    // 2. 恢复 CR0
    CmGenerateMovReg(Trampoline, &uSize, REG_CR0, VmxRead(GUEST_CR0));

    // 3. 恢复 CR3
    CmGenerateMovReg(Trampoline, &uSize, REG_CR3, VmxRead(GUEST_CR3));

    // 4. 恢复 GDT 和 IDT
    CmGenerateDescTableLoad(Trampoline, &uSize, 2, uDataOffset);
    CmGenerateDescTableLoad(Trampoline, &uSize, 3, uDataOffset + 10);

    // 5. 清除 TSS Busy 位，然后 LTR
    ULONG64 TrSelector = VmxRead(GUEST_TR_SELECTOR);
    CmGenerateClearTssBusy(Trampoline, &uSize, gdtBase, TrSelector);
    CmGenerateMovReg(Trampoline, &uSize, REG_RAX, TrSelector);
    CmGenerateLtrAx(Trampoline, &uSize);

    // 6. 恢复 FS/GS MSR
    CmGenerateMovReg(Trampoline, &uSize, REG_RCX, 0xC0000100);
    CmGenerateMovReg(Trampoline, &uSize, REG_RAX, (VmxRead(GUEST_FS_BASE) & 0xFFFFFFFF));
    CmGenerateMovReg(Trampoline, &uSize, REG_RDX, (VmxRead(GUEST_FS_BASE) >> 32));
    CmGenerateWrmsr(Trampoline, &uSize);

    CmGenerateMovReg(Trampoline, &uSize, REG_RCX, 0xC0000101);
    CmGenerateMovReg(Trampoline, &uSize, REG_RAX, (VmxRead(GUEST_GS_BASE) & 0xFFFFFFFF));
    CmGenerateMovReg(Trampoline, &uSize, REG_RDX, (VmxRead(GUEST_GS_BASE) >> 32));
    CmGenerateWrmsr(Trampoline, &uSize);

    // 7. 恢复通用寄存器 (RAX 最后恢复)
    CmGenerateMovReg(Trampoline, &uSize, REG_RCX, GuestRegs->rcx);
    CmGenerateMovReg(Trampoline, &uSize, REG_RDX, GuestRegs->rdx);
    CmGenerateMovReg(Trampoline, &uSize, REG_RBX, GuestRegs->rbx);
    CmGenerateMovReg(Trampoline, &uSize, REG_RBP, GuestRegs->rbp);
    CmGenerateMovReg(Trampoline, &uSize, REG_RSI, GuestRegs->rsi);
    CmGenerateMovReg(Trampoline, &uSize, REG_RDI, GuestRegs->rdi);

    CmGenerateMovReg(Trampoline, &uSize, REG_R8, GuestRegs->r8);
    CmGenerateMovReg(Trampoline, &uSize, REG_R9, GuestRegs->r9);
    CmGenerateMovReg(Trampoline, &uSize, REG_R10, GuestRegs->r10);
    CmGenerateMovReg(Trampoline, &uSize, REG_R11, GuestRegs->r11);
    CmGenerateMovReg(Trampoline, &uSize, REG_R12, GuestRegs->r12);
    CmGenerateMovReg(Trampoline, &uSize, REG_R13, GuestRegs->r13);
    CmGenerateMovReg(Trampoline, &uSize, REG_R14, GuestRegs->r14);
    CmGenerateMovReg(Trampoline, &uSize, REG_R15, GuestRegs->r15);

    // 8. 调整 Guest RSP 预留 IRETQ 帧空间 (5 * 8 = 40 字节)
    ULONG64 GuestRsp = VmxRead(GUEST_RSP);
    ULONG64 NewRsp = GuestRsp - 40;
    CmGenerateMovReg(Trampoline, &uSize, REG_RSP, NewRsp);

    // 9. 构建 IRETQ 栈帧: SS, RSP, RFLAGS, CS, RIP (从高地址到低地址 push)
    CmGenerateMovReg(Trampoline, &uSize, REG_RAX, VmxRead(GUEST_SS_SELECTOR));
    CmGeneratePushReg(Trampoline, &uSize, REG_RAX);

    CmGenerateMovReg(Trampoline, &uSize, REG_RAX, GuestRsp);
    CmGeneratePushReg(Trampoline, &uSize, REG_RAX);

    CmGenerateMovReg(Trampoline, &uSize, REG_RAX, VmxRead(GUEST_RFLAGS));
    CmGeneratePushReg(Trampoline, &uSize, REG_RAX);

    CmGenerateMovReg(Trampoline, &uSize, REG_RAX, VmxRead(GUEST_CS_SELECTOR));
    CmGeneratePushReg(Trampoline, &uSize, REG_RAX);

    CmGenerateMovReg(Trampoline, &uSize, REG_RAX, VmxRead(GUEST_RIP) + VmxRead(VM_EXIT_INSTRUCTION_LEN));
    CmGeneratePushReg(Trampoline, &uSize, REG_RAX);

    // 10. 恢复 RAX
    CmGenerateMovReg(Trampoline, &uSize, REG_RAX, GuestRegs->rax);

    // 11. IRETQ
    CmGenerateIretq(Trampoline, &uSize);
}


VOID reset_cr4()
{
    unsigned __int64 cr4 = __readcr4();
    cr4 = cr4 & ~0x2000ULL;
    __writecr4(cr4);
}


VOID VmxShutdown(PGUEST_REGS GuestRegs)
{
    ULONG cpuIndex = KeGetCurrentProcessorNumberEx(NULL);
    PUCHAR Trampoline = (PUCHAR)g_CpuContext[cpuIndex].TrampolinePage;

    if (!Trampoline) {
        __vmx_off();
        reset_cr4();
        return;
    }

    RtlZeroMemory(Trampoline, PAGE_SIZE);

    // 生成 Trampoline 代码 — 内含 vmxoff 指令
    VmxGenerateTrampolineToGuest(GuestRegs, Trampoline);

    // 不在这里执行 __vmx_off() — vmxoff 已经被编码到 Trampoline 中
    // 也不在这里执行 reset_cr4() — CR4 恢复已在 Trampoline 中

    // 使用 vmresume 切换到 Guest 模式执行 Trampoline
    // 将 GUEST_RIP 指向 Trampoline 页，让 VM 以 Guest 身份执行它
    // Trampoline 的第一条指令就是 vmxoff
    __vmx_vmwrite(GUEST_RIP, (SIZE_T)Trampoline);
    __vmx_vmwrite(GUEST_RSP, VmxRead(GUEST_RSP));

    // 清除 CR0/CR4 guest-host mask，这样 Trampoline 中对 CR 的写入
    // 不会再触发 VM-Exit（直接在 Guest 模式下生效）
    __vmx_vmwrite(CR0_GUEST_HOST_MASK, 0);
    __vmx_vmwrite(CR4_GUEST_HOST_MASK, 0);
    __vmx_vmwrite(CR0_READ_SHADOW, 0);
    __vmx_vmwrite(CR4_READ_SHADOW, 0);

    // 清除异常 bitmap，避免 Trampoline 中的指令触发意外 VM-Exit
    __vmx_vmwrite(EXCEPTION_BITMAP, 0);

    // vmresume 将切换到 Guest，Guest RIP = Trampoline
    // Trampoline 执行 vmxoff → 恢复 CR → 恢复寄存器 → iretq
    // 不返回
}


NTSTATUS NTAPI HvmResumeGuest()
{
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
            // VmxShutdown 修改了 GUEST_RIP 指向 Trampoline
            // 返回到 VmxVmexitHandler 的 vmresume 即可
            return;  // 不要再修改 GUEST_RIP
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
