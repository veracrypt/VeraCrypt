; opt_avx2.asm - Optimized Argon2 implementation using AVX2 instructions
;
; Generated from opt_avx2.c using GCC ""gcc -S -O2 -DARGON2_NO_THREADS -masm=intel -mavx2"
; Then converted manually to YASM syntax, after omitting SEH and GCC-specific directives
; Target: Win64 (x64), No SEH prologue/epilogue, No PTR, YASM section syntax
;
; This was needed because Windows driver doesn't allow using AVX2 C intrinsic in kernel mode
;
; For use in VeraCrypt. 
; Copyright (c) 2025 Mounir IDRASSI <mounir.idrassi@amcrypto.jp>

section .text align=16

fill_block:
    sub     rsp, 1160
    vmovups [rsp+1040], xmm6
    vmovups [rsp+1056], xmm7
    vmovups [rsp+1072], xmm8
    vmovups [rsp+1088], xmm9
    vmovups [rsp+1104], xmm10
    vmovups [rsp+1120], xmm11
    vmovups [rsp+1136], xmm12
    xor     eax, eax
    mov     r11, rdx
    lea     rdx, [rsp+31]
    mov     r10, rcx
    mov     rcx, rdx
    and     rcx, -32
    test    r9d, r9d
    je      .L5
    align   64
    align   16
    align   8
.L3:
    vmovdqu ymm0, [r11+rax]
    vpxor   ymm0, ymm0, [r10+rax]
    add     rcx, 32
    vmovdqu [r10+rax], ymm0
    vpxor   ymm0, ymm0, [r8+rax]
    add     rax, 32
    vmovdqu [rcx-32], ymm0
    cmp     rax, 1024
    jne     .L3
.L4:
    vmovdqu ymm2, [rel LC0]
    mov     rax, r10
    mov     rcx, r10
    vmovdqu ymm3, [rel LC1]
    lea     r9, [r10+1024]
.L6:
    vmovdqu ymm0, [rcx+32]
    vmovdqu ymm1, [rcx]
    add     rcx, 256
    vmovdqu ymm7, [rcx-128]
    vpmuludq ymm4, ymm1, ymm0
    vpaddq  ymm1, ymm1, ymm0
    vpaddq  ymm4, ymm4, ymm4
    vpaddq  ymm4, ymm4, ymm1
    vpxor   ymm5, ymm4, [rcx-160]
    vmovdqu ymm1, [rcx-192]
    vpshufd ymm5, ymm5, 177
    vpmuludq ymm8, ymm1, ymm5
    vpaddq  ymm1, ymm1, ymm5
    vpaddq  ymm8, ymm8, ymm8
    vpaddq  ymm8, ymm8, ymm1
    vmovdqu ymm1, [rcx-96]
    vpxor   ymm0, ymm8, ymm0
    vpmuludq ymm6, ymm7, ymm1
    vpshufb ymm0, ymm0, ymm2
    vpaddq  ymm7, ymm7, ymm1
    vpmuludq ymm9, ymm4, ymm0
    vpaddq  ymm4, ymm4, ymm0
    vpaddq  ymm6, ymm6, ymm6
    vpaddq  ymm6, ymm6, ymm7
    vpxor   ymm12, ymm6, [rcx-32]
    vmovdqu ymm7, [rcx-64]
    vpaddq  ymm9, ymm9, ymm9
    vpaddq  ymm9, ymm9, ymm4
    vpshufd ymm12, ymm12, 177
    vpxor   ymm5, ymm9, ymm5
    vpmuludq ymm10, ymm7, ymm12
    vpshufb ymm5, ymm5, ymm3
    vpaddq  ymm7, ymm7, ymm12
    vpaddq  ymm10, ymm10, ymm10
    vpaddq  ymm10, ymm10, ymm7
    vpmuludq ymm7, ymm8, ymm5
    vpaddq  ymm8, ymm8, ymm5
    vpxor   ymm1, ymm10, ymm1
    vpermq  ymm5, ymm5, 147
    vpshufb ymm1, ymm1, ymm2
    vpaddq  ymm7, ymm7, ymm7
    vpaddq  ymm7, ymm7, ymm8
    vpmuludq ymm8, ymm6, ymm1
    vpaddq  ymm6, ymm6, ymm1
    vpxor   ymm0, ymm7, ymm0
    vpermq  ymm7, ymm7, 78
    vpsrlq  ymm11, ymm0, 63
    vpaddq  ymm0, ymm0, ymm0
    vpxor   ymm0, ymm0, ymm11
    vpermq  ymm0, ymm0, 57
    vpaddq  ymm8, ymm8, ymm8
    vpaddq  ymm8, ymm8, ymm6
    vpxor   ymm4, ymm8, ymm12
    vpmuludq ymm12, ymm9, ymm0
    vpaddq  ymm9, ymm0, ymm9
    vpshufb ymm4, ymm4, ymm3
    vpmuludq ymm6, ymm10, ymm4
    vpaddq  ymm10, ymm10, ymm4
    vpermq  ymm4, ymm4, 147
    vpaddq  ymm12, ymm12, ymm12
    vpaddq  ymm12, ymm12, ymm9
    vpaddq  ymm6, ymm6, ymm6
    vpxor   ymm5, ymm5, ymm12
    vpaddq  ymm6, ymm6, ymm10
    vpshufd ymm5, ymm5, 177
    vpxor   ymm1, ymm6, ymm1
    vpmuludq ymm11, ymm7, ymm5
    vpaddq  ymm7, ymm7, ymm5
    vpsrlq  ymm10, ymm1, 63
    vpaddq  ymm1, ymm1, ymm1
    vpermq  ymm6, ymm6, 78
    vpxor   ymm1, ymm1, ymm10
    vpermq  ymm1, ymm1, 57
    vpmuludq ymm10, ymm8, ymm1
    vpaddq  ymm8, ymm1, ymm8
    vpaddq  ymm11, ymm11, ymm11
    vpaddq  ymm11, ymm11, ymm7
    vpxor   ymm0, ymm0, ymm11
    vpshufb ymm0, ymm0, ymm2
    vpaddq  ymm10, ymm10, ymm10
    vpaddq  ymm10, ymm10, ymm8
    vpxor   ymm4, ymm4, ymm10
    vpshufd ymm9, ymm4, 177
    vpmuludq ymm4, ymm12, ymm0
    vpaddq  ymm12, ymm12, ymm0
    vpmuludq ymm7, ymm6, ymm9
    vpaddq  ymm6, ymm6, ymm9
    vpaddq  ymm4, ymm4, ymm4
    vpaddq  ymm7, ymm7, ymm7
    vpaddq  ymm4, ymm4, ymm12
    vpaddq  ymm7, ymm7, ymm6
    vmovdqu [rcx-256], ymm4
    vpxor   ymm4, ymm4, ymm5
    vpxor   ymm1, ymm1, ymm7
    vpshufb ymm6, ymm4, ymm3
    vpshufb ymm1, ymm1, ymm2
    vpmuludq ymm8, ymm11, ymm6
    vpaddq  ymm11, ymm11, ymm6
    vpmuludq ymm4, ymm10, ymm1
    vpaddq  ymm10, ymm10, ymm1
    vpaddq  ymm8, ymm8, ymm8
    vpaddq  ymm4, ymm4, ymm4
    vpaddq  ymm8, ymm8, ymm11
    vpaddq  ymm4, ymm4, ymm10
    vpxor   ymm0, ymm8, ymm0
    vpermq  ymm8, ymm8, 78
    vmovdqu [rcx-128], ymm4
    vpxor   ymm4, ymm4, ymm9
    vpsrlq  ymm11, ymm0, 63
    vpaddq  ymm0, ymm0, ymm0
    vpshufb ymm5, ymm4, ymm3
    vpxor   ymm0, ymm0, ymm11
    vmovdqu [rcx-192], ymm8
    vpmuludq ymm4, ymm7, ymm5
    vpermq  ymm0, ymm0, 147
    vmovdqu [rcx-224], ymm0
    vpaddq  ymm9, ymm4, ymm4
    vpaddq  ymm4, ymm7, ymm5
    vpaddq  ymm7, ymm9, ymm4
    vpermq  ymm4, ymm6, 57
    vpxor   ymm1, ymm7, ymm1
    vmovdqu [rcx-160], ymm4
    vpermq  ymm7, ymm7, 78
    vpermq  ymm4, ymm5, 57
    vpsrlq  ymm9, ymm1, 63
    vpaddq  ymm1, ymm1, ymm1
    vmovdqu [rcx-64], ymm7
    vpxor   ymm1, ymm1, ymm9
    vmovdqu [rcx-32], ymm4
    vpermq  ymm1, ymm1, 147
    vmovdqu [rcx-96], ymm1
    cmp     r9, rcx
    jne     .L6
    lea     rcx, [r10+128]
.L7:
    vmovdqu ymm1, [rax+256]
    vmovdqu ymm0, [rax]
    add     rax, 32
    vmovdqu ymm6, [rax+96]
    vpmuludq ymm5, ymm0, ymm1
    vpaddq  ymm0, ymm0, ymm1
    vpaddq  ymm5, ymm5, ymm5
    vpaddq  ymm5, ymm5, ymm0
    vpxor   ymm9, ymm5, [rax+736]
    vmovdqu ymm0, [rax+480]
    vpshufd ymm9, ymm9, 177
    vpmuludq ymm4, ymm0, ymm9
    vpaddq  ymm0, ymm0, ymm9
    vpaddq  ymm4, ymm4, ymm4
    vpaddq  ymm4, ymm4, ymm0
    vmovdqu ymm0, [rax+352]
    vpxor   ymm1, ymm4, ymm1
    vpmuludq ymm8, ymm6, ymm0
    vpaddq  ymm6, ymm6, ymm0
    vpshufb ymm1, ymm1, ymm2
    vpaddq  ymm7, ymm5, ymm1
    vpaddq  ymm8, ymm8, ymm8
    vpaddq  ymm8, ymm8, ymm6
    vpxor   ymm12, ymm8, [rax+864]
    vmovdqu ymm6, [rax+608]
    vpshufd ymm12, ymm12, 177
    vpmuludq ymm10, ymm6, ymm12
    vpaddq  ymm6, ymm6, ymm12
    vpaddq  ymm10, ymm10, ymm10
    vpaddq  ymm10, ymm10, ymm6
    vpmuludq ymm6, ymm5, ymm1
    vpxor   ymm0, ymm10, ymm0
    vpshufb ymm0, ymm0, ymm2
    vpaddq  ymm6, ymm6, ymm6
    vpaddq  ymm6, ymm6, ymm7
    vpmuludq ymm7, ymm8, ymm0
    vpxor   ymm5, ymm6, ymm9
    vpshufb ymm5, ymm5, ymm3
    vpmuludq ymm9, ymm4, ymm5
    vpaddq  ymm4, ymm4, ymm5
    vpaddq  ymm7, ymm7, ymm7
    vpaddq  ymm9, ymm9, ymm9
    vpaddq  ymm9, ymm9, ymm4
    vpaddq  ymm4, ymm8, ymm0
    vpaddq  ymm7, ymm7, ymm4
    vpxor   ymm1, ymm9, ymm1
    vpxor   ymm8, ymm7, ymm12
    vpsrlq  ymm11, ymm1, 63
    vpaddq  ymm1, ymm1, ymm1
    vpshufb ymm8, ymm8, ymm3
    vpxor   ymm1, ymm1, ymm11
    vpmuludq ymm4, ymm10, ymm8
    vpaddq  ymm10, ymm10, ymm8
    vpaddq  ymm4, ymm4, ymm4
    vpaddq  ymm4, ymm4, ymm10
    vpxor   ymm0, ymm4, ymm0
    vpsrlq  ymm10, ymm0, 63
    vpaddq  ymm0, ymm0, ymm0
    vpxor   ymm0, ymm0, ymm10
    vpblendd ymm10, ymm5, ymm8, 204
    vpblendd ymm5, ymm5, ymm8, 51
    vpblendd ymm11, ymm1, ymm0, 204
    vpblendd ymm1, ymm1, ymm0, 51
    vpermq  ymm10, ymm10, 177
    vpermq  ymm1, ymm1, 177
    vpermq  ymm11, ymm11, 177
    vpermq  ymm5, ymm5, 177
    vpmuludq ymm0, ymm6, ymm1
    vpaddq  ymm6, ymm1, ymm6
    vpaddq  ymm0, ymm0, ymm0
    vpaddq  ymm6, ymm6, ymm0
    vpxor   ymm10, ymm10, ymm6
    vpshufd ymm10, ymm10, 177
    vpmuludq ymm8, ymm4, ymm10
    vpaddq  ymm4, ymm4, ymm10
    vpaddq  ymm8, ymm8, ymm8
    vpaddq  ymm8, ymm8, ymm4
    vpmuludq ymm4, ymm7, ymm11
    vpaddq  ymm7, ymm11, ymm7
    vpxor   ymm1, ymm8, ymm1
    vpshufb ymm0, ymm1, ymm2
    vpaddq  ymm4, ymm4, ymm4
    vpaddq  ymm4, ymm4, ymm7
    vpxor   ymm5, ymm5, ymm4
    vpshufd ymm7, ymm5, 177
    vpmuludq ymm1, ymm9, ymm7
    vpaddq  ymm5, ymm1, ymm1
    vpaddq  ymm1, ymm9, ymm7
    vpaddq  ymm9, ymm5, ymm1
    vpmuludq ymm5, ymm6, ymm0
    vpaddq  ymm6, ymm6, ymm0
    vpxor   ymm1, ymm9, ymm11
    vpshufb ymm1, ymm1, ymm2
    vpaddq  ymm5, ymm5, ymm5
    vpaddq  ymm5, ymm5, ymm6
    vmovdqu [rax-32], ymm5
    vpxor   ymm5, ymm5, ymm10
    vpmuludq ymm10, ymm4, ymm1
    vpaddq  ymm4, ymm4, ymm1
    vpshufb ymm5, ymm5, ymm3
    vpmuludq ymm6, ymm8, ymm5
    vpaddq  ymm8, ymm8, ymm5
    vpaddq  ymm10, ymm10, ymm10
    vpaddq  ymm4, ymm4, ymm10
    vmovdqu [rax+96], ymm4
    vpxor   ymm4, ymm4, ymm7
    vpaddq  ymm6, ymm6, ymm6
    vpshufb ymm7, ymm4, ymm3
    vpaddq  ymm6, ymm6, ymm8
    vpmuludq ymm4, ymm9, ymm7
    vpaddq  ymm9, ymm9, ymm7
    vpxor   ymm0, ymm6, ymm0
    vmovdqu [rax+608], ymm6
    vpsrlq  ymm8, ymm0, 63
    vpaddq  ymm0, ymm0, ymm0
    vpxor   ymm0, ymm0, ymm8
    vpaddq  ymm4, ymm4, ymm4
    vpaddq  ymm4, ymm4, ymm9
    vpxor   ymm1, ymm4, ymm1
    vmovdqu [rax+480], ymm4
    vpsrlq  ymm9, ymm1, 63
    vpaddq  ymm1, ymm1, ymm1
    vpxor   ymm1, ymm1, ymm9
    vpblendd ymm8, ymm0, ymm1, 204
    vpblendd ymm0, ymm0, ymm1, 51
    vpermq  ymm0, ymm0, 177
    vpermq  ymm1, ymm8, 177
    vmovdqu [rax+352], ymm0
    vpblendd ymm0, ymm5, ymm7, 51
    vpblendd ymm5, ymm5, ymm7, 204
    vpermq  ymm0, ymm0, 177
    vpermq  ymm5, ymm5, 177
    vmovdqu [rax+224], ymm1
    vmovdqu [rax+736], ymm0
    vmovdqu [rax+864], ymm5
    cmp     rax, rcx
    jne     .L7
    and     rdx, -32
    xor     eax, eax
    align   64
    align   16
    align   8
.L8:
    vmovdqu ymm0, [r10+rax]
    vpxor   ymm0, ymm0, [rdx]
    add     rdx, 32
    vmovdqu [r10+rax], ymm0
    vmovdqu [r8+rax], ymm0
    add     rax, 32
    cmp     rax, 1024
    jne     .L8
    vzeroupper
    vmovups xmm6, [rsp+1040]
    vmovups xmm7, [rsp+1056]
    vmovups xmm8, [rsp+1072]
    vmovups xmm9, [rsp+1088]
    vmovups xmm10, [rsp+1104]
    vmovups xmm11, [rsp+1120]
    vmovups xmm12, [rsp+1136]
    add     rsp, 1160
    ret
    align   64
    align   16
    align   8
.L5:
    vmovdqu ymm0, [r11+rax]
    vpxor   ymm0, ymm0, [r10+rax]
    add     rcx, 32
    vmovdqu [r10+rax], ymm0
    add     rax, 32
    vmovdqu [rcx-32], ymm0
    cmp     rax, 1024
    jne     .L5
    jmp     .L4


align 16
next_addresses:
    push    rdi
    push    rbx
    sub     rsp, 2104
    xor     eax, eax
    xor     r9d, r9d
    add     qword [rdx+48], 1
    lea     rbx, [rsp+63]
    mov     r8, rcx
    mov     ecx, 128
    and     rbx, -32
    lea     rdi, [rbx+1024]
    rep stosq
    mov     rdi, rbx
    mov     ecx, 128
    rep stosq
    lea     rcx, [rbx+1024]
    call    fill_block
    xor     r9d, r9d
    mov     rdx, r8
    mov     rcx, rbx
    call    fill_block
    nop
    add     rsp, 2104
    pop     rbx
    pop     rdi
    ret


align 16
global fill_segment_avx2
fill_segment_avx2:
    push    r15
    push    r14
    push    r13
    push    r12
    push    rbp
    push    rdi
    push    rsi
    push    rbx
    sub     rsp, 3160
    vmovdqu xmm1, [rdx]
    lea     r14, [rsp+2143]
    mov     rbx, rcx
    vmovdqu [rsp+48], xmm1
    and     r14, -32
    test    rcx, rcx
    je      .L37
    mov     edx, dword [rcx+36]
    cmp     edx, 1
    je      .L18
    mov     r12d, dword [rsp+48]
    movzx   eax, byte [rsp+56]
    cmp     edx, 2
    je      .L19
    mov     ebp, dword [rsp+52]
    test    r12d, r12d
    je      .L51
    xor     r15d, r15d
    xor     r12d, r12d
.L20:
    mov     ecx, dword [rbx+24]
    mov     r8d, dword [rbx+20]
    xor     edx, edx
    mov     rdi, r14
    imul    ebp, ecx
    imul    eax, r8d
    add     ebp, r12d
    add     ebp, eax
    mov     eax, ebp
    lea     r13d, [rbp-1]
    div     ecx
    lea     eax, [rbp+rcx-1]
    mov     ecx, 128
    test    edx, edx
    cmove   r13d, eax
    lea     rax, [rsp+64]
    mov     qword [rsp+40], rax
    mov     esi, r13d
    sal     rsi, 10
    add     rsi, qword [rbx]
    rep movsq
    cmp     r12d, r8d
    jb      .L24
    jmp     .L36

align 16
align 8
.L53:
    mov     esi, r12d
    and     esi, 127
    je      .L52
.L29:
    mov     edx, dword [rsp+48]
    mov     eax, esi
    mov     ecx, dword [rsp+52]
    mov     r8, qword [rsp+64+rax*8]
    test    edx, edx
    jne     .L31
.L54:
    cmp     byte [rsp+56], 0
    jne     .L31
    mov     rsi, rcx
    mov     r9d, 1
.L32:
    lea     rdx, [rsp+48]
    mov     rcx, rbx
    mov     dword [rsp+60], r12d
    call    index_alpha
    mov     edx, dword [rbx+24]
    mov     r8, qword [rbx]
    mov     eax, eax
    imul    rdx, rsi
    add     rdx, rax
    mov     eax, ebp
    sal     rdx, 10
    sal     rax, 10
    add     rdx, r8
    add     r8, rax
    cmp     dword [rbx+8], 16
    je      .L33
    mov     eax, dword [rsp+48]
    test    eax, eax
    je      .L33
    mov     r9d, 1
    mov     rcx, r14
    add     r12d, 1
    add     ebp, 1
    call    fill_block
    cmp     r12d, dword [rbx+20]
    jnb     .L36
.L24:
    test    r12b, 63
    jne     .L25
    mov     rax, qword [rbx+48]
    mov     rax, qword [rax+96]
    test    rax, rax
    je      .L25
    mov     eax, dword [rax]
    test    eax, eax
    jne     .L41
.L25:
    mov     eax, ebp
    xor     edx, edx
    div     dword [rbx+24]
    cmp     edx, 1
    je      .L26
    mov     eax, r13d
    add     r13d, 1
.L27:
    test    r15d, r15d
    jne     .L53
    mov     edx, dword [rsp+48]
    sal     rax, 10
    add     rax, qword [rbx]
    mov     r8, qword [rax]
    mov     ecx, dword [rsp+52]
    test    edx, edx
    je      .L54
.L31:
    mov     esi, dword [rbx+28]
    mov     rax, r8
    xor     edx, edx
    xor     r9d, r9d
    shr     rax, 32
    div     rsi
    cmp     rdx, rcx
    mov     rsi, rdx
    sete    r9b
    jmp     .L32

align 16
align 8
.L51:
    xor     r12d, r12d
    test    al, al
    sete    r12b
    xor     r15d, r15d
    add     r12d, r12d
    jmp     .L20

align 16
align 8
.L33:
    xor     r9d, r9d
    mov     rcx, r14
    add     r12d, 1
    add     ebp, 1
    call    fill_block
    cmp     r12d, dword [rbx+20]
    jb      .L24
.L36:
    xor     eax, eax
.L16:
    add     rsp, 3160
    pop     rbx
    pop     rsi
    pop     rdi
    pop     rbp
    pop     r12
    pop     r13
    pop     r14
    pop     r15
    ret

align 16
align 8
.L26:
    lea     eax, [rbp-1]
    mov     r13d, ebp
    jmp     .L27

align 16
align 8
.L52:
    mov     rcx, qword [rsp+40]
    lea     rdx, [rsp+1088]
    call    next_addresses
    jmp     .L29

align 16
align 8
.L19:
    test    r12d, r12d
    jne     .L55
    cmp     al, 1
    jbe     .L18
    mov     ebp, dword [rsp+52]
    xor     r15d, r15d
    jmp     .L20

align 16
align 8
.L18:
    xor     edx, edx
    lea     rcx, [rsp+1088]
    mov     r15d, 1
    call    init_block_value
    mov     eax, dword [rsp+48]
    vmovd   xmm2, dword [rbx+12]
    vpinsrd xmm0, xmm2, dword [rbx+36], 1
    movzx   edx, byte [rsp+56]
    mov     qword [rsp+1088], rax
    mov     edi, dword [rbx+16]
    mov     r12, rax
    mov     eax, dword [rsp+52]
    vpmovzxdq xmm0, xmm0
    mov     qword [rsp+1104], rdx
    mov     qword [rsp+1112], rdi
    mov     qword [rsp+1096], rax
    mov     rbp, rax
    mov     rax, rdx
    vmovdqu [rsp+1120], xmm0
    test    r12d, r12d
    jne     .L39
    test    dl, dl
    jne     .L20
    lea     rcx, [rsp+64]
    lea     rdx, [rsp+1088]
    mov     r12d, 2
    call    next_addresses
    mov     ebp, dword [rsp+52]
    movzx   eax, byte [rsp+56]
    jmp     .L20

align 16
align 8
.L41:
    mov     eax, -36
    jmp     .L16

.L55:
    mov     ebp, dword [rsp+52]
    xor     r15d, r15d
    xor     r12d, r12d
    jmp     .L20

.L39:
    xor     r12d, r12d
    jmp     .L20

.L37:
    mov     eax, -25
    jmp     .L16


section .rdata align=32
LC0:
    db 3,4,5,6,7,0,1,2,11,12,13,14,15,8,9,10
    db 3,4,5,6,7,0,1,2,11,12,13,14,15,8,9,10
align 32
LC1:
    db 2,3,4,5,6,7,0,1,10,11,12,13,14,15,8,9
    db 2,3,4,5,6,7,0,1,10,11,12,13,14,15,8,9

; External symbols
extern index_alpha
extern init_block_value

; End of file
