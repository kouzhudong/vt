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

// Helper to write descriptor table instructions (LGDT/LIDT)
// Opcode: 2 for LGDT (0F 01 /2), 3 for LIDT (0F 01 /3)
VOID CmGenerateDescTableLoad(PUCHAR Trampoline, PULONG pOffset, UCHAR SubOpcode, ULONG DataOffsetRelative)
{
    PUCHAR pCode = &Trampoline[*pOffset];
    // 0F 01 /n [RIP + offset]
    // ModRM: mod=00, reg=SubOpcode, rm=101 (RIP-relative) -> no, 64-bit uses mod 00 rm 101 as RIP-rel
    
    pCode[0] = 0x0F;
    pCode[1] = 0x01;
    // ModRM byte encoded:
    // Mod=00 (00b), Reg=SubOpcode (010b or 011b), RM=101 (101b for RIP rel 32 DISP)
    // For LGDT (2): 00 010 101 = 0x15
    // For LIDT (3): 00 011 101 = 0x1D
    pCode[2] = (SubOpcode == 2) ? 0x15 : 0x1D; 
    
    // Offset calculation: Target - (CurrentIP + InstructionLength)
    // InstructionLength = 3 (opcode+modrm) + 4 (disp) = 7
    ULONG32 displacement = DataOffsetRelative - (*pOffset + 7);
    memcpy(&pCode[3], &displacement, 4);
    
    *pOffset += 7;
}

// Helper for WRMSR (0F 30). Expects ECX, EDX:EAX to be set.
VOID CmGenerateWrmsr(PUCHAR Trampoline, PULONG pOffset)
{
    PUCHAR pCode = &Trampoline[*pOffset];
    pCode[0] = 0x0F;
    pCode[1] = 0x30;
    *pOffset += 2;
}

// Helper for LTR r16 (0F 00 /3). Uses AX (register 0).
VOID CmGenerateLtrAx(PUCHAR Trampoline, PULONG pOffset)
{
    PUCHAR pCode = &Trampoline[*pOffset];
    pCode[0] = 0x0F;
    pCode[1] = 0x00;
    pCode[2] = 0xD8; // ModRM: 11 011 000 (Register mode, LTR, AX)
    *pOffset += 3;
}


VOID VmxGenerateTrampolineToGuest(PGUEST_REGS GuestRegs, PUCHAR Trampoline)
{
    ULONG uSize = 0;
    ULONG uDataOffset = 0x800; // Place data (GDT/IDT descriptors) further down in the page
    
    // Store GDT/IDT pseudo-descriptors in the data area
    // struct { USHORT Limit; ULONG64 Base; }
    // GDT at uDataOffset, IDT at uDataOffset + 10
    
    USHORT gdtLimit = (USHORT)VmxRead(GUEST_GDTR_LIMIT);
    ULONG64 gdtBase = VmxRead(GUEST_GDTR_BASE);
    memcpy(&Trampoline[uDataOffset], &gdtLimit, 2);
    memcpy(&Trampoline[uDataOffset + 2], &gdtBase, 8);

    USHORT idtLimit = (USHORT)VmxRead(GUEST_IDTR_LIMIT);
    ULONG64 idtBase = VmxRead(GUEST_IDTR_BASE);
    memcpy(&Trampoline[uDataOffset + 10], &idtLimit, 2);
    memcpy(&Trampoline[uDataOffset + 12], &idtBase, 8);

    // Disable TF in Guest RFLAGS before exit
    __vmx_vmwrite(GUEST_RFLAGS, VmxRead(GUEST_RFLAGS) & ~0x100);

    // 1. Restore CR0 and CR4 first (sets machine state for subsequent loads)
    CmGenerateMovReg(Trampoline, &uSize, REG_CR0, VmxRead(GUEST_CR0));
    
    // CR4: Ensure Safe (clear SMAP to allow stack switching if guest stack is user, clear VMXE implicitly irrelevant after off)
    ULONG64 GuestCr4 = VmxRead(GUEST_CR4);
    CmGenerateMovReg(Trampoline, &uSize, REG_CR4, GuestCr4 & ~0x200000ULL);

    // 2. Restore CR3 (Context Switch)
    // Code sequence MUST be mapped in the target CR3 (Kernel pool is usually shared)
    CmGenerateMovReg(Trampoline, &uSize, REG_CR3, VmxRead(GUEST_CR3));

    // 3. Restore GDT and IDT (Crucial for IRETQ and Segment loads)
    CmGenerateDescTableLoad(Trampoline, &uSize, 2, uDataOffset);      // LGDT
    CmGenerateDescTableLoad(Trampoline, &uSize, 3, uDataOffset + 10); // LIDT

    // 4. Restore TR (Task Register) - Requires valid GDT
    // Load Selector into RAX, then LTR AX
    CmGenerateMovReg(Trampoline, &uSize, REG_RAX, VmxRead(GUEST_TR_SELECTOR));
    CmGenerateLtrAx(Trampoline, &uSize);

    // 5. Restore MSRs (FS/GS/KernelGS) - Uses RCX, RAX, RDX. Clobbers them.
    // Must occur BEFORE GPR restoration.
    
    // MSR_FS_BASE
    CmGenerateMovReg(Trampoline, &uSize, REG_RCX, 0xC0000100);
    CmGenerateMovReg(Trampoline, &uSize, REG_RAX, (VmxRead(GUEST_FS_BASE) & 0xFFFFFFFF));
    CmGenerateMovReg(Trampoline, &uSize, REG_RDX, (VmxRead(GUEST_FS_BASE) >> 32));
    CmGenerateWrmsr(Trampoline, &uSize);

    // MSR_GS_BASE
    CmGenerateMovReg(Trampoline, &uSize, REG_RCX, 0xC0000101);
    CmGenerateMovReg(Trampoline, &uSize, REG_RAX, (VmxRead(GUEST_GS_BASE) & 0xFFFFFFFF));
    CmGenerateMovReg(Trampoline, &uSize, REG_RDX, (VmxRead(GUEST_GS_BASE) >> 32));
    CmGenerateWrmsr(Trampoline, &uSize);

    // MSR_KERNEL_GS_BASE (0xC0000102) - Assuming we can assume it's valid or zero.
    // If we don't restore this, SwapGS in guest kernel entry will load garbage.
    // However, finding the field requires reading the MSR while in VMX root or MSR bitmaps?
    // Generally, GUEST stores it. If not available in VMCS, we might skip or read via Rdmsr if needed.
    // Proceeding without KernelGSBase for now to avoid invalid VMCS reads if index unknown in h.h context.

    // 6. Restore GPRs (Restores GuestRegs values into CPU registers)
    // NOTE: RAX is NOT restored here because we still need it for stack setup.
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

    // 7. Switch Stack to Guest RSP
    ULONG64 NewRsp = VmxRead(GUEST_RSP);
    CmGenerateMovReg(Trampoline, &uSize, REG_RSP, NewRsp);

    // 8. Build IRETQ Stack Frame on the GUEST Stack
    // Frame: SS, RSP, RFLAGS, CS, RIP
    // We use RAX as scratch to push these values.
    
    // SS
    CmGenerateMovReg(Trampoline, &uSize, REG_RAX, VmxRead(GUEST_SS_SELECTOR));
    CmGeneratePushReg(Trampoline, &uSize, REG_RAX);
    
    // RSP (The value we just loaded into RSP register is the *current* stack pointer.
    // IRETQ expects the RSP to restore *after* return. 
    // Usually same as current if no privilege change, but we must match the frame logic.
    // Since we are already on NewRsp, pushing NewRsp is redundant if same priv, but required by IRETQ format.)
    CmGenerateMovReg(Trampoline, &uSize, REG_RAX, NewRsp);
    CmGeneratePushReg(Trampoline, &uSize, REG_RAX);
    
    // RFLAGS
    CmGenerateMovReg(Trampoline, &uSize, REG_RAX, VmxRead(GUEST_RFLAGS));
    CmGeneratePushReg(Trampoline, &uSize, REG_RAX);
    
    // CS
    CmGenerateMovReg(Trampoline, &uSize, REG_RAX, VmxRead(GUEST_CS_SELECTOR));
    CmGeneratePushReg(Trampoline, &uSize, REG_RAX);
    
    // RIP
    CmGenerateMovReg(Trampoline, &uSize, REG_RAX, VmxRead(GUEST_RIP) + VmxRead(VM_EXIT_INSTRUCTION_LEN));
    CmGeneratePushReg(Trampoline, &uSize, REG_RAX);

    // 9. Restore Guest RAX (Last register)
    CmGenerateMovReg(Trampoline, &uSize, REG_RAX, GuestRegs->rax);

    // 10. Execute IRETQ
    // This will pop RIP, CS, RFLAGS, RSP, SS and transfer control to guest code.
    // Since we restored GDTR/IDTR/CR3, the environment is valid.
    CmGenerateIretq(Trampoline, &uSize);
}


VOID reset_cr4()
//设置CR4的一个位。
{    
    unsigned __int64 cr4 = __readcr4();

    // VMX-Enable Bit (bit 13 of CR4) — Enables VMX operation when set
    // Also clear SMAP (bit 21) if present to safely write to guest stack if it is user-mode.
    // 0x2000 = 1 << 13
    // 0x200000 = 1 << 21
    cr4 = cr4 & (~(0x2000ULL | 0x200000ULL));

    __writecr4(cr4);
}


NTSTATUS VmxShutdown(PGUEST_REGS GuestRegs)
{
    // 使用 ExAllocatePool2 替代已弃用的 ExAllocatePoolWithTag
    // POOL_FLAG_NON_PAGED: 非分页内存 (可执行)
    // 注意: ExAllocatePool2 分配的 NonPaged 内存默认是 NX 的，
    // 但 POOL_FLAG_NON_PAGED 在某些版本上仍映射为可执行。
    // 为确保可执行，使用 NonPagedPool (旧API) 或 MmAllocateContiguousMemory。
    PUCHAR Trampoline = (PUCHAR)MmAllocateContiguousMemory(0x1000, (PHYSICAL_ADDRESS){.QuadPart = -1});

    if (!Trampoline) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Trampoline, 0x1000);

    VmxGenerateTrampolineToGuest(GuestRegs, Trampoline);

    __vmx_off();
    reset_cr4();

    ((VOID(*)()) Trampoline) ();
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
            // VmxShutdown now returns status if allocation fails
            if (!NT_SUCCESS(VmxShutdown(GuestRegs))) {
                // If shutdown failed, we fall through and just return from hypercall normally
                break;
            }
            // If shutdown succeeds, it jumps to trampoline and never returns here.
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
