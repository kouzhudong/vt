EXTERN HvmSubvertCpu:PROC
EXTERN VmExitHandler:PROC
EXTERN HvmResumeGuest:PROC


HVM_SAVE_ALL_NOSEGREGS MACRO
        push r15
        push r14
        push r13
        push r12
        push r11
        push r10
        push r9
        push r8        
        push rdi
        push rsi
        push rbp
        push rbp	; rsp
        push rbx
        push rdx
        push rcx
        push rax
ENDM


HVM_RESTORE_ALL_NOSEGREGS MACRO
        pop rax
        pop rcx
        pop rdx
        pop rbx
        pop rbp		; rsp
        pop rbp
        pop rsi
        pop rdi 
        pop r8
        pop r9
        pop r10
        pop r11
        pop r12
        pop r13
        pop r14
        pop r15
ENDM



.CODE


VmxRead PROC
	vmread rax, rcx
	ret
VmxRead ENDP


VmxVmCall PROC
	vmcall
	ret
VmxVmCall ENDP


VmxVmexitHandler PROC
	HVM_SAVE_ALL_NOSEGREGS

	mov   rcx, rsp		 ;GuestRegs	

	sub	  rsp, 28h
	call  VmExitHandler
	add	  rsp,28h	

	HVM_RESTORE_ALL_NOSEGREGS
	vmresume
	ret
VmxVmexitHandler ENDP



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;



CmSubvert PROC
	push	rax
	push	rcx
	push	rdx
	push	rbx
	push	rbp
	push	rsi
	push	rdi
	push	r8
	push	r9
	push	r10
	push	r11
	push	r12
	push	r13
	push	r14
	push	r15

	sub	rsp, 20h
	call	HvmSubvertCpu
CmSubvert ENDP


CmGuestEip PROC
   call	HvmResumeGuest
add	rsp, 20h

pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	r11
	pop	r10
	pop	r9
	pop	r8
	pop	rdi
	pop	rsi
	pop	rbp
	pop	rbx
	pop	rdx
	pop	rcx
	pop	rax
	ret
CmGuestEip ENDP



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;



RegGetCs PROC
	mov		rax, cs
	ret
RegGetCs ENDP


RegGetDs PROC
	mov		rax, ds
	ret
RegGetDs ENDP


RegGetEs PROC
	mov		rax, es
	ret
RegGetEs ENDP


RegGetSs PROC
	mov		rax, ss
	ret
RegGetSs ENDP


RegGetFs PROC
	mov		rax, fs
	ret
RegGetFs ENDP


RegGetGs PROC
	mov		rax, gs
	ret
RegGetGs ENDP


GetGdtLimit PROC
	LOCAL	gdtr[10]:BYTE
	sgdt	gdtr
	mov		ax, WORD PTR gdtr[0]
	ret
GetGdtLimit ENDP


GetLdtr PROC
	sldt	rax
	ret
GetLdtr ENDP


GetTrSelector PROC
	str	rax
	ret
GetTrSelector ENDP


get_access_rights proc
	lar rax,rcx
    ret
get_access_rights endp




;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;



END