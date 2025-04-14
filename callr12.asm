.code

CallR12 proc
    ; Allocate stack space
    sub rsp, 100h

    ; Store non-volatile registers
    mov qword ptr [rsp + 08h], rsi
    mov qword ptr [rsp + 10h], rdi
    mov qword ptr [rsp + 18h], r12

    ; Set up registers for function and fixup handler
    mov r10, rcx                        ; R10 now holds the function to call
    lea r12, Fixup                      ; R12 points to Fixup label for return address

    ; More stack space for arguments and spoofed return address
    sub rsp, 200h

    ; Place the gadget address as the return address
    mov qword ptr [rsp], r8             ; Spoofed return address is now set to r12_gadget

    ; Check if there are any arguments
    cmp rdx, 0
    je CallFunction                     ; If no arguments, jump to call the function directly

    ; Backup the number of arguments in R11
    mov r11, rdx                        ; R11 = nArgs

    ; Shift arguments if necessary (move arguments into appropriate registers for calling convention)
    cmp rdx, 4
    mov rcx, r9                         ; First argument to RCX (from R9 if provided)
    mov rdx, qword ptr [rsp + 300h + 28h]
    mov r8, qword ptr [rsp + 300h + 30h]
    mov r9, qword ptr [rsp + 300h + 38h]
    jle CallFunction                    ; Jump if there are 4 or fewer arguments

    ; Move additional arguments from stack to align with calling convention
    mov rax, rcx
    mov rcx, r11
    sub rcx, 4                          ; RCX = number of extra arguments to move
    lea rsi, [rsp + 28h + 18h + 300h]   ; Source (additional arguments in original stack frame)
    lea rdi, [rsp + 28h]                ; Destination in stack frame
    rep movsq                           ; Move the arguments from RSI to RDI

    ; Restore RCX for function call
    mov rcx, rax

CallFunction:
    ; Call the target function
    jmp r10                             ; Jump to function (R10), with r12_gadget as return address

Fixup:
    ; Restore non-volatile registers and stack frame
    mov rsi, qword ptr [rsp + 200h + 08h]
    mov rdi, qword ptr [rsp + 200h + 10h]
    mov r12, qword ptr [rsp + 200h + 18h]
    add rsp, 300h                       ; Clean up the stack frame

    ret                                 ; Return to caller

CallR12 endp

end
