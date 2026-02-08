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


// =====================================================================
// 关键修复：在 Trampoline 中生成清除 TSS Busy 位的代码
// 
// LTR 指令要求 TSS 描述符的 Type 为 0x9 (Available 64-bit TSS)。
// 但当前 CPU 的 TSS 已经是 0xB (Busy 64-bit TSS)。
// 如果直接 LTR，会触发 #GP。
// 
// 解决方案：在 LGDT 之后、LTR 之前，用代码修改 GDT 中 TSS 描述符的
// Type 字段，将 Busy 位 (bit 1) 清除。
//
// GDT 中 TSS 描述符偏移 = TR_Selector & ~0x7
// Type 字段位于描述符偏移 +5 字节的低 4 位
// Busy 位 = byte[5] 的 bit 1
//
// 生成的代码序列 (使用 RAX 作为 scratch):
//   mov rax, <GDTR_BASE + TR_SELECTOR_INDEX + 5>
//   and byte [rax], 0xFD   ; 清除 bit 1 (Busy)
// =====================================================================
VOID CmGenerateClearTssBusy(PUCHAR Trampoline, PULONG pOffset, ULONG64 GdtBase, ULONG64 TrSelector)
{
    // 计算 TSS 描述符中 Type 字节的地址
    ULONG64 TssTypeByteAddr = GdtBase + (TrSelector & ~7ULL) + 5;

    // mov rax, imm64
    CmGenerateMovReg(&Trampoline[*pOffset], pOffset, REG_RAX, TssTypeByteAddr);

    // and byte [rax], 0xFD  =>  80 20 FD  =>  实际是 80 /4 ib => and [rax], 0xFD
    // 编码: 80 20 FD
    PUCHAR pCode = &Trampoline[*pOffset];
    pCode[0] = 0x80;   // AND r/m8, imm8
    pCode[1] = 0x20;   // ModRM: mod=00, reg=4(/4=AND), rm=0(RAX)
    pCode[2] = 0xFD;   // ~0x02, 清除 bit 1
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

    // 1. 恢复 CR0
    CmGenerateMovReg(Trampoline, &uSize, REG_CR0, VmxRead(GUEST_CR0));

    // 2. 恢复 CR4 — 仅清除 VMXE (bit 13)，保留 SMAP 等其他位
    ULONG64 GuestCr4 = VmxRead(GUEST_CR4);
    CmGenerateMovReg(Trampoline, &uSize, REG_CR4, GuestCr4 & ~X86_CR4_VMXE);

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
    // 这样 push 操作不会覆盖 Guest 原有栈数据
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
    // 仅清除 VMXE (bit 13)，不要动 SMAP (bit 21) 等其他位
    cr4 = cr4 & ~0x2000ULL;
    __writecr4(cr4);
}


VOID VmxShutdown(PGUEST_REGS GuestRegs)
{
    // 获取当前 CPU 编号，使用预分配的 Trampoline 页
    ULONG cpuIndex = KeGetCurrentProcessorNumberEx(NULL);
    PUCHAR Trampoline = (PUCHAR)g_CpuContext[cpuIndex].TrampolinePage;

    if (!Trampoline) {
        // 没有预分配的页面，无法安全卸载 — 直接 VMXOFF 后返回
        // Guest 会在 VMCALL 下一条指令处继续，但状态可能不完整
        __vmx_off();
        reset_cr4();
        return;
    }

    RtlZeroMemory(Trampoline, PAGE_SIZE);

    VmxGenerateTrampolineToGuest(GuestRegs, Trampoline);

    __vmx_off();
    reset_cr4();

    ((VOID(*)()) Trampoline) ();
    // 永远不会返回
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
            // VmxShutdown 不再分配内存，直接使用预分配页
            // 如果成功，它会跳转到 Trampoline 永远不返回
            VmxShutdown(GuestRegs);
            // 如果到达这里，说明 Trampoline 为 NULL（回退路径）
            // 设置返回值让调用方知道卸载已完成
            GuestRegs->rcx = NBP_MAGIC;
            GuestRegs->rdx = 0;
            break;
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
