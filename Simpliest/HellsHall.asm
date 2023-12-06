.data
	wSystemCall         DWORD	0h
	qSyscallInsAdress   QWORD	0h


.code

	SetSSn proc
		xor eax, eax
		mov wSystemCall, eax
		mov qSyscallInsAdress, rax
		mov eax, ecx
		mov wSystemCall, eax
		mov r8, rdx
		mov qSyscallInsAdress, r8
		ret
	SetSSn endp


	RunSyscall proc
		xor r10, r10
		mov rax, rcx
		mov r10, rax
		mov eax, wSystemCall
		jmp Run
		xor eax, eax
		xor rcx, rcx
		shl r10, 2
		Run:
			jmp qword ptr [qSyscallInsAdress]
			xor r10, r10
			mov qSyscallInsAdress, r10
			ret
	RunSyscall endp

end