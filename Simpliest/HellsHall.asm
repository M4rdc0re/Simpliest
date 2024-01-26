.data
	wSystemCall         DWORD	0h
	qSyscallInsAdress   QWORD	0h


.code

	SetSSn proc
		xor eax, eax
		nop
		mov wSystemCall, eax
		nop
		mov qSyscallInsAdress, rax
		nop
		mov eax, ecx
		nop
		mov wSystemCall, eax
		nop
		mov r8, rdx
		nop
		mov qSyscallInsAdress, r8
		ret
	SetSSn endp


	RunSyscall proc
		xor r10, r10
		nop
		mov rax, rcx
		nop
		mov r10, rax
		nop
		mov eax, wSystemCall
		nop
		jmp Run
		xor eax, eax
		nop
		xor rcx, rcx
		nop
		shl r10, 2
		Run:
			jmp qword ptr [qSyscallInsAdress]
			nop
			xor r10, r10
			nop
			mov qSyscallInsAdress, r10
			ret
	RunSyscall endp

end