
; ---------------------------------------------------------------------------
; Copyright (c) 1998-2007, Brian Gladman, Worcester, UK. All rights reserved.
; 
; LICENSE TERMS
; 
; The free distribution and use of this software is allowed (with or without
; changes) provided that:
; 
;  1. source code distributions include the above copyright notice, this
;     list of conditions and the following disclaimer;
; 
;  2. binary distributions include the above copyright notice, this list
;     of conditions and the following disclaimer in their documentation;
; 
;  3. the name of the copyright holder is not used to endorse products
;     built using this software without specific written permission.
; 
; DISCLAIMER
; 
; This software is provided 'as is' with no explicit or implied warranties
; in respect of its properties, including, but not limited to, correctness
; and/or fitness for purpose.
; ---------------------------------------------------------------------------
; Issue 20/12/2007
;
; This code requires ASM_X86_V1C to be set in aesopt.h. It requires the C files
; aeskey.c and aestab.c for support.

;
; Adapted for TrueCrypt:
; - Compatibility with NASM and GCC
;

; An AES implementation for x86 processors using the YASM (or NASM) assembler.
; This is an assembler implementation that covers encryption and decryption
; only and is intended as a replacement of the C file aescrypt.c. It hence
; requires the file aeskey.c for keying and aestab.c for the AES tables. It
; employs full tables rather than compressed tables.

; This code provides the standard AES block size (128 bits, 16 bytes) and the
; three standard AES key sizes (128, 192 and 256 bits). It has the same call
; interface as my C implementation. The ebx, esi, edi and ebp registers are
; preserved across calls but eax, ecx and edx and the artihmetic status flags
; are not.  It is also important that the defines below match those used in the
; C code.  This code uses the VC++ register saving conentions; if it is used
; with another compiler, conventions for using and saving registers may need to
; be checked (and calling conventions).  The YASM command line for the VC++
; custom build step is:
;
;    yasm -Xvc -f win32 -o "$(TargetDir)\$(InputName).obj" "$(InputPath)"
;
;  The calling intefaces are:
;
;     AES_RETURN aes_encrypt(const unsigned char in_blk[],
;                   unsigned char out_blk[], const aes_encrypt_ctx cx[1]);
;
;     AES_RETURN aes_decrypt(const unsigned char in_blk[],
;                   unsigned char out_blk[], const aes_decrypt_ctx cx[1]);
;
;     AES_RETURN aes_encrypt_key<NNN>(const unsigned char key[],
;                                            const aes_encrypt_ctx cx[1]);
;
;     AES_RETURN aes_decrypt_key<NNN>(const unsigned char key[],
;                                            const aes_decrypt_ctx cx[1]);
;
;     AES_RETURN aes_encrypt_key(const unsigned char key[],
;                           unsigned int len, const aes_decrypt_ctx cx[1]);
;
;     AES_RETURN aes_decrypt_key(const unsigned char key[],
;                           unsigned int len, const aes_decrypt_ctx cx[1]);
;
; where <NNN> is 128, 102 or 256.  In the last two calls the length can be in
; either bits or bytes.
;
; Comment in/out the following lines to obtain the desired subroutines. These
; selections MUST match those in the C header file aes.h

; %define AES_128                 ; define if AES with 128 bit keys is needed
; %define AES_192                 ; define if AES with 192 bit keys is needed
%define AES_256                 ; define if AES with 256 bit keys is needed
; %define AES_VAR                 ; define if a variable key size is needed
%define ENCRYPTION              ; define if encryption is needed
%define DECRYPTION              ; define if decryption is needed
%define AES_REV_DKS             ; define if key decryption schedule is reversed
%define LAST_ROUND_TABLES       ; define if tables are to be used for last round

; offsets to parameters

in_blk  equ     4   ; input byte array address parameter
out_blk equ     8   ; output byte array address parameter
ctx     equ    12   ; AES context structure
stk_spc equ    20   ; stack space
%define parms  12   ; parameter space on stack

; The encryption key schedule has the following in memory layout where N is the
; number of rounds (10, 12 or 14):
;
; lo: | input key (round 0)  |  ; each round is four 32-bit words
;     | encryption round 1   |
;     | encryption round 2   |
;     ....
;     | encryption round N-1 |
; hi: | encryption round N   |
;
; The decryption key schedule is normally set up so that it has the same
; layout as above by actually reversing the order of the encryption key
; schedule in memory (this happens when AES_REV_DKS is set):
;
; lo: | decryption round 0   | =              | encryption round N   |
;     | decryption round 1   | = INV_MIX_COL[ | encryption round N-1 | ]
;     | decryption round 2   | = INV_MIX_COL[ | encryption round N-2 | ]
;     ....                       ....
;     | decryption round N-1 | = INV_MIX_COL[ | encryption round 1   | ]
; hi: | decryption round N   | =              | input key (round 0)  |
;
; with rounds except the first and last modified using inv_mix_column()
; But if AES_REV_DKS is NOT set the order of keys is left as it is for
; encryption so that it has to be accessed in reverse when used for
; decryption (although the inverse mix column modifications are done)
;
; lo: | decryption round 0   | =              | input key (round 0)  |
;     | decryption round 1   | = INV_MIX_COL[ | encryption round 1   | ]
;     | decryption round 2   | = INV_MIX_COL[ | encryption round 2   | ]
;     ....                       ....
;     | decryption round N-1 | = INV_MIX_COL[ | encryption round N-1 | ]
; hi: | decryption round N   | =              | encryption round N   |
;
; This layout is faster when the assembler key scheduling provided here
; is used.
;
; The DLL interface must use the _stdcall convention in which the number
; of bytes of parameter space is added after an @ to the sutine's name.
; We must also remove our parameters from the stack before return (see
; the do_exit macro). Define DLL_EXPORT for the Dynamic Link Library version.

;%define DLL_EXPORT

; End of user defines

%ifdef AES_VAR
%ifndef AES_128
%define AES_128
%endif
%ifndef AES_192
%define AES_192
%endif
%ifndef AES_256
%define AES_256
%endif
%endif

%ifdef AES_VAR
%define KS_LENGTH       60
%elifdef AES_256
%define KS_LENGTH       60
%elifdef AES_192
%define KS_LENGTH       52
%else
%define KS_LENGTH       44
%endif

; These macros implement stack based local variables

%macro  save 2
    mov     [esp+4*%1],%2
%endmacro

%macro  restore 2
    mov     %1,[esp+4*%2]
%endmacro

; the DLL has to implement the _stdcall calling interface on return
; In this case we have to take our parameters (3 4-byte pointers)
; off the stack

%macro  do_name 1-2 parms
%ifndef DLL_EXPORT
    align 32
    global  %1
%1:
%else
    align 32
    global  %1@%2
    export  _%1@%2
%1@%2:
%endif
%endmacro

%macro  do_call 1-2 parms
%ifndef DLL_EXPORT
    call    %1
    add     esp,%2
%else
    call    %1@%2
%endif
%endmacro

%macro  do_exit  0-1 parms
%ifdef DLL_EXPORT
    ret %1
%else
    ret
%endif
%endmacro

%ifdef  ENCRYPTION

    extern  t_fn

%define etab_0(x)   [t_fn+4*x]
%define etab_1(x)   [t_fn+1024+4*x]
%define etab_2(x)   [t_fn+2048+4*x]
%define etab_3(x)   [t_fn+3072+4*x]

%ifdef LAST_ROUND_TABLES

    extern  t_fl

%define eltab_0(x)  [t_fl+4*x]
%define eltab_1(x)  [t_fl+1024+4*x]
%define eltab_2(x)  [t_fl+2048+4*x]
%define eltab_3(x)  [t_fl+3072+4*x]

%else

%define etab_b(x)   byte [t_fn+3072+4*x]

%endif

; ROUND FUNCTION.  Build column[2] on ESI and column[3] on EDI that have the
; round keys pre-loaded. Build column[0] in EBP and column[1] in EBX.
;
; Input:
;
;   EAX     column[0]
;   EBX     column[1]
;   ECX     column[2]
;   EDX     column[3]
;   ESI     column key[round][2]
;   EDI     column key[round][3]
;   EBP     scratch
;
; Output:
;
;   EBP     column[0]   unkeyed
;   EBX     column[1]   unkeyed
;   ESI     column[2]   keyed
;   EDI     column[3]   keyed
;   EAX     scratch
;   ECX     scratch
;   EDX     scratch

%macro rnd_fun 2

    rol     ebx,16
    %1      esi, cl, 0, ebp
    %1      esi, dh, 1, ebp
    %1      esi, bh, 3, ebp
    %1      edi, dl, 0, ebp
    %1      edi, ah, 1, ebp
    %1      edi, bl, 2, ebp
    %2      ebp, al, 0, ebp
    shr     ebx,16
    and     eax,0xffff0000
    or      eax,ebx
    shr     edx,16
    %1      ebp, ah, 1, ebx
    %1      ebp, dh, 3, ebx
    %2      ebx, dl, 2, ebx
    %1      ebx, ch, 1, edx
    %1      ebx, al, 0, edx
    shr     eax,16
    shr     ecx,16
    %1      ebp, cl, 2, edx
    %1      edi, ch, 3, edx
    %1      esi, al, 2, edx
    %1      ebx, ah, 3, edx

%endmacro

; Basic MOV and XOR Operations for normal rounds

%macro  nr_xor  4
    movzx   %4,%2
    xor     %1,etab_%3(%4)
%endmacro

%macro  nr_mov  4
    movzx   %4,%2
    mov     %1,etab_%3(%4)
%endmacro

; Basic MOV and XOR Operations for last round

%ifdef LAST_ROUND_TABLES

    %macro  lr_xor  4
        movzx   %4,%2
        xor     %1,eltab_%3(%4)
    %endmacro

    %macro  lr_mov  4
        movzx   %4,%2
        mov     %1,eltab_%3(%4)
    %endmacro

%else

    %macro  lr_xor  4
        movzx   %4,%2
        movzx   %4,etab_b(%4)
    %if %3 != 0
        shl     %4,8*%3
    %endif
        xor     %1,%4
    %endmacro

    %macro  lr_mov  4
        movzx   %4,%2
        movzx   %1,etab_b(%4)
    %if %3 != 0
        shl     %1,8*%3
    %endif
    %endmacro

%endif

%macro enc_round 0

    add     ebp,16
    save    0,ebp
    mov     esi,[ebp+8]
    mov     edi,[ebp+12]

    rnd_fun nr_xor, nr_mov

    mov     eax,ebp
    mov     ecx,esi
    mov     edx,edi
    restore ebp,0
    xor     eax,[ebp]
    xor     ebx,[ebp+4]

%endmacro

%macro enc_last_round 0

    add     ebp,16
    save    0,ebp
    mov     esi,[ebp+8]
    mov     edi,[ebp+12]

    rnd_fun lr_xor, lr_mov

    mov     eax,ebp
    restore ebp,0
    xor     eax,[ebp]
    xor     ebx,[ebp+4]

%endmacro

    section .text align=32

; AES Encryption Subroutine

    do_name aes_encrypt

    sub     esp,stk_spc
    mov     [esp+16],ebp
    mov     [esp+12],ebx
    mov     [esp+ 8],esi
    mov     [esp+ 4],edi

    mov     esi,[esp+in_blk+stk_spc] ; input pointer
    mov     eax,[esi   ]
    mov     ebx,[esi+ 4]
    mov     ecx,[esi+ 8]
    mov     edx,[esi+12]

    mov     ebp,[esp+ctx+stk_spc]    ; key pointer
    movzx   edi,byte [ebp+4*KS_LENGTH]
    xor     eax,[ebp   ]
    xor     ebx,[ebp+ 4]
    xor     ecx,[ebp+ 8]
    xor     edx,[ebp+12]

; determine the number of rounds

    cmp     edi,10*16
    je      .3
    cmp     edi,12*16
    je      .2
    cmp     edi,14*16
    je      .1
    mov     eax,-1
    jmp     .5

.1: enc_round
    enc_round
.2: enc_round
    enc_round
.3: enc_round
    enc_round
    enc_round
    enc_round
    enc_round
    enc_round
    enc_round
    enc_round
    enc_round
    enc_last_round

    mov     edx,[esp+out_blk+stk_spc]
    mov     [edx],eax
    mov     [edx+4],ebx
    mov     [edx+8],esi
    mov     [edx+12],edi
    xor     eax,eax

.5: mov     ebp,[esp+16]
    mov     ebx,[esp+12]
    mov     esi,[esp+ 8]
    mov     edi,[esp+ 4]
    add     esp,stk_spc
    do_exit

%endif

%ifdef  DECRYPTION

    extern  t_in

%define dtab_0(x)   [t_in+4*x]
%define dtab_1(x)   [t_in+1024+4*x]
%define dtab_2(x)   [t_in+2048+4*x]
%define dtab_3(x)   [t_in+3072+4*x]

%ifdef LAST_ROUND_TABLES

    extern  t_il

%define dltab_0(x)  [t_il+4*x]
%define dltab_1(x)  [t_il+1024+4*x]
%define dltab_2(x)  [t_il+2048+4*x]
%define dltab_3(x)  [t_il+3072+4*x]

%else

    extern  _t_ibox

%define dtab_x(x)   byte [_t_ibox+x]

%endif

%macro irn_fun 2

    rol eax,16
    %1      esi, cl, 0, ebp
    %1      esi, bh, 1, ebp
    %1      esi, al, 2, ebp
    %1      edi, dl, 0, ebp
    %1      edi, ch, 1, ebp
    %1      edi, ah, 3, ebp
    %2      ebp, bl, 0, ebp
    shr     eax,16
    and     ebx,0xffff0000
    or      ebx,eax
    shr     ecx,16
    %1      ebp, bh, 1, eax
    %1      ebp, ch, 3, eax
    %2      eax, cl, 2, ecx
    %1      eax, bl, 0, ecx
    %1      eax, dh, 1, ecx
    shr     ebx,16
    shr     edx,16
    %1      esi, dh, 3, ecx
    %1      ebp, dl, 2, ecx
    %1      eax, bh, 3, ecx
    %1      edi, bl, 2, ecx

%endmacro

; Basic MOV and XOR Operations for normal rounds

%macro  ni_xor  4
    movzx   %4,%2
    xor     %1,dtab_%3(%4)
%endmacro

%macro  ni_mov  4
    movzx   %4,%2
    mov     %1,dtab_%3(%4)
%endmacro

; Basic MOV and XOR Operations for last round

%ifdef LAST_ROUND_TABLES

%macro  li_xor  4
    movzx   %4,%2
    xor     %1,dltab_%3(%4)
%endmacro

%macro  li_mov  4
    movzx   %4,%2
    mov     %1,dltab_%3(%4)
%endmacro

%else

    %macro  li_xor  4
        movzx   %4,%2
        movzx   %4,dtab_x(%4)
    %if %3 != 0
        shl     %4,8*%3
    %endif
        xor     %1,%4
    %endmacro

    %macro  li_mov  4
        movzx   %4,%2
        movzx   %1,dtab_x(%4)
    %if %3 != 0
        shl     %1,8*%3
    %endif
    %endmacro

%endif

%macro dec_round 0

%ifdef AES_REV_DKS
    add     ebp,16
%else
    sub     ebp,16
%endif
    save    0,ebp
    mov     esi,[ebp+8]
    mov     edi,[ebp+12]

    irn_fun ni_xor, ni_mov

    mov     ebx,ebp
    mov     ecx,esi
    mov     edx,edi
    restore ebp,0
    xor     eax,[ebp]
    xor     ebx,[ebp+4]

%endmacro

%macro dec_last_round 0

%ifdef AES_REV_DKS
    add     ebp,16
%else
    sub     ebp,16
%endif
    save    0,ebp
    mov     esi,[ebp+8]
    mov     edi,[ebp+12]

    irn_fun li_xor, li_mov

    mov     ebx,ebp
    restore ebp,0
    xor     eax,[ebp]
    xor     ebx,[ebp+4]

%endmacro

    section .text

; AES Decryption Subroutine

    do_name aes_decrypt

    sub     esp,stk_spc
    mov     [esp+16],ebp
    mov     [esp+12],ebx
    mov     [esp+ 8],esi
    mov     [esp+ 4],edi

; input four columns and xor in first round key

    mov     esi,[esp+in_blk+stk_spc] ; input pointer
    mov     eax,[esi   ]
    mov     ebx,[esi+ 4]
    mov     ecx,[esi+ 8]
    mov     edx,[esi+12]
    lea     esi,[esi+16]

    mov     ebp,[esp+ctx+stk_spc]    ; key pointer
    movzx   edi,byte[ebp+4*KS_LENGTH]
%ifndef  AES_REV_DKS        ; if decryption key schedule is not reversed
    lea     ebp,[ebp+edi]   ; we have to access it from the top down
%endif
    xor     eax,[ebp   ]    ; key schedule
    xor     ebx,[ebp+ 4]
    xor     ecx,[ebp+ 8]
    xor     edx,[ebp+12]

; determine the number of rounds

    cmp     edi,10*16
    je      .3
    cmp     edi,12*16
    je      .2
    cmp     edi,14*16
    je      .1
    mov     eax,-1
    jmp     .5

.1: dec_round
    dec_round
.2: dec_round
    dec_round
.3: dec_round
    dec_round
    dec_round
    dec_round
    dec_round
    dec_round
    dec_round
    dec_round
    dec_round
    dec_last_round

; move final values to the output array.

    mov     ebp,[esp+out_blk+stk_spc]
    mov     [ebp],eax
    mov     [ebp+4],ebx
    mov     [ebp+8],esi
    mov     [ebp+12],edi
    xor     eax,eax

.5: mov     ebp,[esp+16]
    mov     ebx,[esp+12]
    mov     esi,[esp+ 8]
    mov     edi,[esp+ 4]
    add     esp,stk_spc
    do_exit

%endif
