.code

;   A function can be called like so
;   
;   Spoof(arg1, arg2, arg3, arg4, &param, function, (PVOID)0);
;   
;   Param is a struct containing some necessary information for the call to have fake frames added.
;   The 6th argument is a pointer to the function to execute
;   The 7th argument specifies the number of args to pass to the stack. It has to be at an 8 byte size.

Spoof PROC
    pop    rax                         ; Real return address in rax

    mov    r10, rdi                    ; Store OG rdi in r10
    mov    r11, rsi                    ; Store OG rsi in r11

    mov    rdi, qword ptr [rsp + 32]   ; Storing struct in rdi
    mov    rsi, qword ptr [rsp + 40]   ; Storing function to call

    ; ---------------------------------------------------------------------
    ; Storing our original registers
    ; ---------------------------------------------------------------------

    mov qword ptr [rdi + 24], r10       ; Storing OG rdi into param
    mov qword ptr [rdi + 88], r11       ; Storing OG rsi into param
    mov qword ptr [rdi + 96], r12       ; Storing OG r12 into param
    mov qword ptr [rdi + 104], r13      ; Storing OG r13 into param
    mov qword ptr [rdi + 112], r14      ; Storing OG r14 into param
    mov qword ptr [rdi + 120], r15      ; Storing OG r15 into param

    mov r12, rax                        ; OG code used r12 for ret addr

    ; ---------------------------------------------------------------------
    ; Prepping to move stack args
    ; ---------------------------------------------------------------------

    xor r11, r11                        ; r11 = # of args pushed
    mov r13, qword ptr [rsp + 30h]      ; r13 = total args to push

    mov r14, 200h                       ; Initial offset
    add r14, 8
    add r14, qword ptr [rdi + 56]       ; Add RUTS stack size
    add r14, qword ptr [rdi + 48]       ; Add BTIT stack size
    add r14, qword ptr [rdi + 32]       ; Add gadget frame size
    sub r14, 20h                        ; Adjust for first stack arg

    mov r10, rsp            
    add r10, 30h                        ; Stack args base address

looping_label:
    xor r15, r15            
    cmp r11, r13            
    je finish_label
    
    ; ---------------------------------------------------------------------
    ; Calculate target stack position
    ; ---------------------------------------------------------------------
    sub r14, 8          
    mov r15, rsp        
    sub r15, r14        
    
    ; ---------------------------------------------------------------------
    ; Move stack argument
    ; ---------------------------------------------------------------------
    add r10, 8
    push qword ptr [r10]
    pop qword ptr [r15]     

    ; ---------------------------------------------------------------------
    ; Increment counter and loop
    ; ---------------------------------------------------------------------
    add r11, 1
    jmp looping_label
    
finish_label:

    ; ----------------------------------------------------------------------
    ; Create working space and setup fake frames
    ; ----------------------------------------------------------------------
    sub    rsp, 200h
    push   0

    ; RtlUserThreadStart frame
    sub    rsp, qword ptr [rdi + 56]
    mov    r11, qword ptr [rdi + 64]
    mov    qword ptr [rsp], r11

    ; BaseThreadInitThunk frame
    sub    rsp, qword ptr [rdi + 32]
    mov    r11, qword ptr [rdi + 40]
    mov    qword ptr [rsp], r11

    ; Gadget frame -- `jmp QWORD PTR [rbx]`
    sub    rsp, qword ptr [rdi + 48]
    mov    r11, qword ptr [rdi + 80]
    mov    qword ptr [rsp], r11

    ; ----------------------------------------------------------------------
    ; Prepare for function call and fixup
    ; ----------------------------------------------------------------------
    mov    r11, rsi                     ; Function to call
    mov    qword ptr [rdi + 8], r12     ; Store real return address
    mov    qword ptr [rdi + 16], rbx    ; Store original RBX
    lea    rbx, fixup_label             ; Get fixup address
    mov    qword ptr [rdi], rbx         ; Store fixup in struct
    mov    rbx, rdi                     ; Param struct pointer

    ; Prepare syscall (if needed)
    mov    r10, rcx
    mov    rax, qword ptr [rdi + 72]
    
    jmp    r11                          ; Jump to target function

fixup_label: 
    mov    rcx, rbx                     ; Restore param struct

    ; Cleanup stack frames
    add    rsp, 200h
    add    rsp, qword ptr [rbx + 48]
    add    rsp, qword ptr [rbx + 32]
    add    rsp, qword ptr [rbx + 56]

    ; Restore original registers
    mov    rbx, qword ptr [rcx + 16]
    mov    rdi, qword ptr [rcx + 24]
    mov    rsi, qword ptr [rcx + 88]
    mov    r12, qword ptr [rcx + 96]
    mov    r13, qword ptr [rcx + 104]
    mov    r14, qword ptr [rcx + 112]
    mov    r15, qword ptr [rcx + 120]

    jmp    qword ptr [rcx + 8]          ; Jump to original return address

Spoof ENDP

END
