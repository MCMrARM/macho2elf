BITS 64

; 0x13374200 __libc_start_main
; 0x13374201 main
; 0x13374202 __cxa_finalize
; 0x13374203 (elf header)

main:
    endbr64
    xor     ebp, ebp
    mov     r9, rdx         ; rtld_fini
    pop     rsi             ; argc
    mov     rdx, rsp        ; ubp_av
    and     rsp, 0FFFFFFFFFFFFFFF0h
    push    rax
    push    rsp             ; stack_end
    xor     r8d, r8d        ; fini
    xor     ecx, ecx        ; init
    mov     rdi, [rel $+7+0x13374201]  ; main
    call    qword [rel $+6+0x13374200] ; __libc_start_main
    hlt

finalize:
    mov     rdi, [rel $+7+0x13374203]  ; (elf header)
    jmp     qword [rel $+6+0x13374202] ; __cxa_finalize


pointers:
dq main
dq finalize
