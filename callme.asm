.data

extern dwSSN:dword
extern qwJMP:qword

.code

CallMe proc
	mov r10, rcx
	mov eax, dwSSN
	jmp qwJMP
CallMe endp

end