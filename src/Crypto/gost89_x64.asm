;
; GOST89 implementation x64
; 
; Copyright (c) 2016. Disk Cryptography Services for EFI (DCS), Alex Kolotnikov
;
; This program and the accompanying materials
; are licensed and made available under the terms and conditions
; of the Apache License, Version 2.0.  
;
; The full text of the license may be found at
; https://opensource.org/licenses/Apache-2.0
;
; Some ideas from article https://xakep.ru/2013/10/19/shifrovanie-gost-28147-89/
;

[section .bss align=16]

;///////////////////////////////////////////////////////////////////
;// Win64 registers to save
;///////////////////////////////////////////////////////////////////
%macro SaveRegs 0
   sub rsp,8*8+10*16
   mov [rsp], rbx
   mov [rsp+8], rbp
   mov [rsp+8*2], rdi
   mov [rsp+8*3], rsi
   mov [rsp+8*4], r12
   mov [rsp+8*5], r13
   mov [rsp+8*6], r14
   mov [rsp+8*7], r15
%endmacro

%macro RestoreRegs 0
   mov rbx, [rsp]
   mov rbp, [rsp+8]
   mov rdi, [rsp+8*2]
   mov rsi, [rsp+8*3]
   mov r12, [rsp+8*4]
   mov r13, [rsp+8*5]
   mov r14, [rsp+8*6]
   mov r15, [rsp+8*7]
   add rsp,8*8+10*16
%endmacro

[section .text align=16]
;///////////////////////////////////////////////////////////////////
;// Crypting 2 blocks
;///////////////////////////////////////////////////////////////////
%macro gost_round2 2                               ; 1 - pos1, 2 - pos2
   ; 1st
   ; 1-2 byte
   add   ecx, r13d                                 ; add key
   movzx edi, cl
   movzx esi, ch
   xor   r14d, dword [r8 + 32 + 256*3*4 + rdi*4]
   xor   r14d, dword [r8 + 32 + 256*2*4 + rsi*4]
   shr   ecx, 16
   ; 3-4 байт
   movzx edi, cl
   xor   r14d, dword [r8 + 32 + 256*4 + rdi*4]
   movzx esi, ch
   xor   r14d, dword [r8 + 32 + rsi*4]
   mov   edx, [r8 + %1*4]                          ; read key for second step
   
   ; 2nd
   ; 1-2 byte
   add   eax, r10d                                 ; read key
   movzx r15d, al
   movzx ebp, ah
   xor   r11d, dword [r8 + 32 + 256*3*4 + r15*4]
   xor   r11d, dword [r8 + 32 + 256*2*4 + rbp*4]
   shr   eax, 16
   ; 3-4 байт
   movzx r15d, al
   xor   r11d, dword [r8 + 32 + 256*4 + r15*4]
   movzx ebp, ah
   xor   r11d, dword [r8 + 32 + rbp*4]
   mov   ebx, [r8 + %1*4]                          ; read key for second step
   
   ; second step
   ; 1st
   ; 1-2 byte
   add   edx, r14d                                 ; add key
   movzx edi, dl
   movzx esi, dh
   xor   r13d, dword [r8 + 32 + 256*3*4 + rdi*4]
   xor   r13d, dword [r8 + 32 + 256*2*4 + rsi*4]
   shr   edx, 16
   ; 3-4 байт
   movzx edi, dl
   xor   r13d, dword [r8 + 32 + 256*4 + rdi*4]
   movzx esi, dh
   xor   r13d, dword [r8 + 32 + rsi*4]
   mov   ecx, [r8 + %2*4]                          ; read key
   
   ; 2nd
   ; 1-2 byte
   add   ebx, r11d;                                ; add key
   movzx r15d, bl;
   movzx ebp, bh;
   xor   r10d, dword [r8 + 32 + 256*3*4 + r15*4]
   xor   r10d, dword [r8 + 32 + 256*2*4 + rbp*4]
   shr   ebx, 16
   ; 3-4 байт
   movzx r15d, bl
   xor   r10d, dword [r8 + 32 + 256*4 + r15*4]
   movzx ebp, bh
   xor   r10d, dword [r8 + 32 + rbp*4]
   mov   eax, [r8 + %2*4]                          ; read key
%endmacro

; input: r8 - &key, rcx - &IN
; returns: (r13) & (r10)
GostEncrypt2x64:
   ; 1st
   mov   r13d, [rcx]
   mov   r14,  [rcx]
   shr   r14, 32

   ; 2nd
   mov   r10d, [rcx + 16]
   mov   r11,  [rcx + 16]
   shr   r11, 32

   mov   ecx, [r8]
   mov   eax, ecx

   gost_round2 1, 2
   gost_round2 3, 4
   gost_round2 5, 6
   gost_round2 7, 0

   gost_round2 1, 2
   gost_round2 3, 4
   gost_round2 5, 6
   gost_round2 7, 0

   gost_round2 1, 2
   gost_round2 3, 4
   gost_round2 5, 6
   gost_round2 7, 7

   gost_round2 6, 5
   gost_round2 4, 3
   gost_round2 2, 1
   gost_round2 0, 0

   shl r13, 32                             ; combine
   or  r13, r14

   shl r10, 32                             ; combine
   or  r10, r11
   ret

; input: r8 - &key, rcx - &IN
; returns: (r13) & (r10)
GostDecrypt2x64:
   ; 1st
   mov   r13d, [rcx]
   mov   r14,  [rcx]
   shr   r14, 32

   ; 2nd
   mov   r10d, [rcx + 16]
   mov   r11,  [rcx + 16]
   shr   r11, 32

   mov   ecx, [r8]
   mov   eax, ecx

   gost_round2 1, 2
   gost_round2 3, 4
   gost_round2 5, 6
   gost_round2 7, 7

   gost_round2 6, 5
   gost_round2 4, 3
   gost_round2 2, 1
   gost_round2 0, 7

   gost_round2 6, 5
   gost_round2 4, 3
   gost_round2 2, 1
   gost_round2 0, 7

   gost_round2 6, 5
   gost_round2 4, 3
   gost_round2 2, 1
   gost_round2 0, 0

   shl r13, 32                             ; combine
   or  r13, r14

   shl r10, 32                             ; combine
   or  r10, r11
ret

;///////////////////////////////////////////////////////////////////
;// Crypting 1 block
;///////////////////////////////////////////////////////////////////
%macro gost_round1 2                                     ; 1 - pos1, 2 - pos2
   ; 1-2 byte
   add   ecx, r13d                                 ; add key
   movzx edi, cl
   movzx esi, ch
   xor   r14d, dword [r8 + 32 + 256*3*4 + rdi*4]
   xor   r14d, dword [r8 + 32 + 256*2*4 + rsi*4]
   shr   ecx, 16
   ; 3-4 байт
   movzx edi, cl
   xor   r14d, dword [r8 + 32 + 256*4 + rdi*4]
   movzx esi, ch
   xor   r14d, dword [r8 + 32 + rsi*4]
   mov   edx, [r8 + %1*4]                          ; read key for second step
   
   ; second step
   ; 1-2 byte
   add   edx, r14d                                 ; add key
   movzx edi, dl
   movzx esi, dh
   xor   r13d, dword [r8 + 32 + 256*3*4 + rdi*4]
   xor   r13d, dword [r8 + 32 + 256*2*4 + rsi*4]
   shr   edx, 16
   ; 3-4 байт
   movzx edi, dl
   xor   r13d, dword [r8 + 32 + 256*4 + rdi*4]
   movzx esi, dh
   xor   r13d, dword [r8 + 32 + rsi*4]
   mov   ecx, [r8 + %2*4]                          ; read key
%endmacro

; input: r8 - &gost_kds rcx - &IN
; returns: r13
GostEncrypt1x64:
   mov   r13d, [rcx]
   mov   r14,  [rcx]
   shr   r14, 32
   mov   ecx, [r8]

   gost_round1 1, 2
   gost_round1 3, 4
   gost_round1 5, 6
   gost_round1 7, 0
   
   gost_round1 1, 2
   gost_round1 3, 4
   gost_round1 5, 6
   gost_round1 7, 0
   
   gost_round1 1, 2
   gost_round1 3, 4
   gost_round1 5, 6
   gost_round1 7, 7
   
   gost_round1 6, 5
   gost_round1 4, 3
   gost_round1 2, 1
   gost_round1 0, 0

   shl r13, 32                             ; combine
   or  r13, r14
ret

; input: r8 - &gost_kds rcx - IN
; returns: r13
GostDecrypt1x64:
   mov   r13d, [rcx]
   mov   r14, [rcx]
   shr   r14, 32
   mov   ecx, [r8]
   
   gost_round1 1, 2
   gost_round1 3, 4
   gost_round1 5, 6
   gost_round1 7, 7
   
   gost_round1 6, 5
   gost_round1 4, 3
   gost_round1 2, 1
   gost_round1 0, 7
   
   gost_round1 6, 5
   gost_round1 4, 3
   gost_round1 2, 1
   gost_round1 0, 7
   
   gost_round1 6, 5
   gost_round1 4, 3
   gost_round1 2, 1
   gost_round1 0, 0

   shl r13, 32                             ; combine
   or  r13, r14
ret

global gost_encrypt_128_CBC_asm                     ; gost_encrypt_128_CBC_asm(uint64* in, uint64* out, gost_kds* kds, uint64 count);
; rcx - &in
; rdx - &out
; r8  - &gost_kds
; r9  - count
gost_encrypt_128_CBC_asm:
   SaveRegs                                 ; Saving
   
   sub rsp, 32
   mov [rsp], rdx                             ; Save out addr
   mov [rsp + 8], rcx                         ; Save in addr
   mov [rsp + 16], r8                         ; key addr

.do:
   mov [rsp + 24], r9                      ; Save count
   cmp r9, 2
   jge .blk2
   cmp r9, 1
   jge .blk1
   jmp .end

; One 128 block encryption
.blk1:
   mov  rcx, [rsp + 8]                         ; set in addr
   call GostEncrypt1x64

   mov rdx, [rsp]                              ; Restore out
   mov rcx, [rsp + 8]                          ; restore in

   mov [rdx], r13
   mov rax, [rcx + 8]
   xor rax, r13                              ; CBC

   add rdx, 8                                ;next 8 bytes
   mov [rdx], rax

   mov rcx, rdx
   call GostEncrypt1x64

   mov rdx, [rsp]                             ; Restore out addr
   mov rcx, [rsp+8]                           ; Restore in addr

   mov [rdx + 8], r13

   add rdx,16
   mov [rsp], rdx

   add rcx, 16
   mov [rsp+8], rcx

   mov r9, [rsp + 24]
   dec r9

   jmp .do

.blk2:
   mov  rcx, [rsp + 8]                         ; set in addr
   call GostEncrypt2x64

   mov rdx, [rsp]                              ; Restore out
   mov rcx, [rsp + 8]                          ; restore in

   mov [rdx], r13

   mov rax, [rcx + 8]
   xor rax, r13                              ; CBC

   mov [rdx + 16], r10

   mov rbx, [rcx + 24]
   xor rbx, r10                              ; CBC

   mov [rdx + 8], rax
   mov [rdx + 24], rbx

   add rdx, 8                                ;next 8 bytes

   mov rcx, rdx
   call GostEncrypt2x64

   mov rdx, [rsp]                             ; Restore out addr
   mov rcx, [rsp+8]                           ; Restore in addr

   mov [rdx + 8], r13
   mov [rdx + 24], r10

   add rdx,32
   mov [rsp], rdx

   add rcx, 32
   mov [rsp+8], rcx

   mov r9, [rsp + 24]
   sub r9, 2

   jmp .do

.end:
   add rsp, 32                              ; Load out addr
   RestoreRegs                              ; Load
ret

global gost_decrypt_128_CBC_asm                     ; gost_decrypt_128_CBC_asm(uint64* in, uint64* out, const gost_kds* kds, uint64 count);
; rcx - &in
; rdx - &out
; r8  - &gost_kds
; r9  - count
gost_decrypt_128_CBC_asm:
   SaveRegs                                 ; Saving
   
   sub rsp, 32
   mov [rsp], rdx                           ; Save out addr
   mov [rsp+8], rcx                         ; Save in addr
   mov [rsp+16], r8                         ; key addr

.do:
   mov [rsp + 24], r9                      ; Save count
   cmp r9, 2
   jge .blk2
   cmp r9, 1
   jge .blk1
   jmp .end

; One 128 block decryption
.blk1:
   add  rcx, 8
   call GostDecrypt1x64
   mov rdx, [rsp]                              ; Restore out
   mov rcx, [rsp + 8]                          ; Restore in
   mov rax, [rcx]
   xor rax, r13                                ; CBC
   mov [rdx + 8], rax

   call GostDecrypt1x64

   mov rdx, [rsp]                             ; Restore out addr
   mov rcx, [rsp+8]                           ; Restore in addr

   mov [rdx], r13

   add rdx,16
   mov [rsp], rdx

   add rcx, 16
   mov [rsp+8], rcx

   mov r9, [rsp + 24]
   dec r9

   jmp .do

.blk2:
   add  rcx, 8
   call GostDecrypt2x64
   mov rdx, [rsp]                              ; Restore out
   mov rcx, [rsp + 8]                          ; Restore in

   mov rax, [rcx]
   xor rax, r13                                ; CBC
   mov [rdx + 8], rax

   mov rbx, [rcx+16]
   xor rbx, r10                                ; CBC
   mov [rdx + 24], rbx

   call GostDecrypt2x64

   mov rdx, [rsp]                             ; Restore out addr
   mov rcx, [rsp+8]                           ; Restore in addr

   mov [rdx], r13
   mov [rdx+16], r10

   add rdx,32
   mov [rsp], rdx

   add rcx,32
   mov [rsp+8], rcx

   mov r9, [rsp + 24]
   sub r9, 2

   jmp .do

.end:
   add rsp, 32                              ; Load out addr
   RestoreRegs                              ; Load
ret
