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
        uCodeLength = *pGeneratedCodeLength - uCodeLength;// calc the size of the "mov rax, value"
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
        uCodeLength += 3;// *pGeneratedCodeLength has already been adjusted to the length of the "mov rax"
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


VOID VmxGenerateTrampolineToGuest(PGUEST_REGS GuestRegs, PUCHAR Trampoline)
{
    ULONG uTrampolineSize = 0;

    // assume Trampoline buffer is big enough
    __vmx_vmwrite(GUEST_RFLAGS, VmxRead(GUEST_RFLAGS) & ~0x100);     // disable TF

    CmGenerateMovReg(&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RCX, GuestRegs->rcx);
    CmGenerateMovReg(&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RDX, GuestRegs->rdx);
    CmGenerateMovReg(&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RBX, GuestRegs->rbx);
    CmGenerateMovReg(&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RBP, GuestRegs->rbp);
    CmGenerateMovReg(&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RSI, GuestRegs->rsi);
    CmGenerateMovReg(&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RDI, GuestRegs->rdi);

    CmGenerateMovReg(&Trampoline[uTrampolineSize], &uTrampolineSize, REG_R8, GuestRegs->r8);
    CmGenerateMovReg(&Trampoline[uTrampolineSize], &uTrampolineSize, REG_R9, GuestRegs->r9);
    CmGenerateMovReg(&Trampoline[uTrampolineSize], &uTrampolineSize, REG_R10, GuestRegs->r10);
    CmGenerateMovReg(&Trampoline[uTrampolineSize], &uTrampolineSize, REG_R11, GuestRegs->r11);
    CmGenerateMovReg(&Trampoline[uTrampolineSize], &uTrampolineSize, REG_R12, GuestRegs->r12);
    CmGenerateMovReg(&Trampoline[uTrampolineSize], &uTrampolineSize, REG_R13, GuestRegs->r13);
    CmGenerateMovReg(&Trampoline[uTrampolineSize], &uTrampolineSize, REG_R14, GuestRegs->r14);
    CmGenerateMovReg(&Trampoline[uTrampolineSize], &uTrampolineSize, REG_R15, GuestRegs->r15);

    CmGenerateMovReg(&Trampoline[uTrampolineSize], &uTrampolineSize, REG_CR0, VmxRead(GUEST_CR0));
    CmGenerateMovReg(&Trampoline[uTrampolineSize], &uTrampolineSize, REG_CR3, VmxRead(GUEST_CR3));
    CmGenerateMovReg(&Trampoline[uTrampolineSize], &uTrampolineSize, REG_CR4, VmxRead(GUEST_CR4));

    ULONG64 NewRsp = VmxRead(GUEST_RSP);
    CmGenerateMovReg(&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RSP, NewRsp);

    CmGenerateMovReg(&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX, VmxRead(GUEST_SS_SELECTOR));
    CmGeneratePushReg(&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX);
    CmGenerateMovReg(&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX, NewRsp);
    CmGeneratePushReg(&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX);
    CmGenerateMovReg(&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX, VmxRead(GUEST_RFLAGS));
    CmGeneratePushReg(&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX);
    CmGenerateMovReg(&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX, VmxRead(GUEST_CS_SELECTOR));
    CmGeneratePushReg(&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX);
    CmGenerateMovReg(&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX, VmxRead(GUEST_RIP) + VmxRead(VM_EXIT_INSTRUCTION_LEN));
    CmGeneratePushReg(&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX);
    CmGenerateMovReg(&Trampoline[uTrampolineSize], &uTrampolineSize, REG_RAX, GuestRegs->rax);

    CmGenerateIretq(&Trampoline[uTrampolineSize], &uTrampolineSize);
}


VOID reset_cr4()
//设置CR4的一个位。
{    
    unsigned __int64 cr4 = __readcr4();

    //VMX-Enable Bit (bit 13 of CR4) — Enables VMX operation when set
    cr4 = cr4 & (~0x2000);//1>>13

    //_bittestandreset, _bittestandreset64
    _bittestandreset64((__int64 *)&cr4, 13);

    __writecr4(cr4);
}


NTSTATUS VmxShutdown(PGUEST_REGS GuestRegs)
{
    UCHAR Trampoline[0x600];
    VmxGenerateTrampolineToGuest(GuestRegs, Trampoline);// The code should be updated to build an approproate trampoline to exit to any guest mode.

    __vmx_off();
    reset_cr4();

    ((VOID(*)()) & Trampoline) ();
    return STATUS_SUCCESS; // never returns
}


NTSTATUS NTAPI HvmResumeGuest() //汇编函数CmGuestEip调用。
{
    return STATUS_SUCCESS;
}


VOID VmExitHandler(PGUEST_REGS GuestRegs)//在函数 VmxVmexitHandler 中被引用
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
    case EXIT_REASON_CPUID://CPU-Z总是有些信息显示不出来。不过兼容自己写的几个程序。
    {
        int CPUInfo[4] = {-1};

        __cpuidex(CPUInfo, (int)GuestRegs->rax, (int)GuestRegs->rcx);
        //__cpuid(CPUInfo, (int)GuestRegs->rax);
        if (GuestRegs->rax == 0) {//返回MadeByCorrey
            GuestRegs->rax = CPUInfo[0];
            GuestRegs->rbx = 'edaM';
            GuestRegs->rcx = 'yerr';
            GuestRegs->rdx = 'oCyB';
            //GuestRegs->rbx = CPUInfo[1];
            //GuestRegs->rcx = CPUInfo[3];
            //GuestRegs->rdx = CPUInfo[2];
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
            GuestRegs->rcx = NBP_MAGIC;
            GuestRegs->rdx = 0;
            VmxShutdown(GuestRegs);// disable virtualization, resume guest, don't setup time bomb
            break;// never returns
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
        //size_t FieldValue = 0;
        LARGE_INTEGER MsrValue;
        ULONG32 rcx = (ULONG32)GuestRegs->rcx;
        switch (rcx) {
        case MSR_IA32_SYSENTER_CS:
            MsrValue.QuadPart = VmxRead(GUEST_SYSENTER_CS);//这几个改为__vmx_vmread有问题。
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
    //(ExitReason >= EXIT_REASON_VMCLEAR && ExitReason <= EXIT_REASON_VMXON)
    //{
    //    __vmx_vmwrite(GUEST_RFLAGS, VmxRead(GUEST_RFLAGS) & (~0x8d5) | 0x1);
    //}
    default:
    {
        //KdPrint (("VmExitHandler(): failed for exitcode 0x%llX\n", ExitReason));
        ULONG64 x = ExitReason;
        x = 0;
    }
    break;
    }

    __vmx_vmwrite(GUEST_RIP, GuestEIP + inst_len);
}
