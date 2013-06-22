
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
; This code requires either ASM_X86_V2 or ASM_X86_V2C to be set in aesopt.h
; and the same define to be set here as well. If AES_V2C is set this file
; requires the C files aeskey.c and aestab.c for support.

; An AES implementation for x86 processors using the YASM (or NASM) assembler.
; This is a full assembler implementation covering encryption, decryption and
; key scheduling. It uses 2k bytes of tables but its encryption and decryption
; performance is very close to that obtained using large tables.  Key schedule
; expansion is slower for both encryption and decryption but this is likely to
; be offset by the much smaller load that this version places on the processor
; cache. I acknowledge the contribution made by Daniel Bernstein to aspects of
; the design of the AES round function used here.
;
; This code provides the standard AES block size (128 bits, 16 bytes) and the
; three standard AES key sizes (128, 192 and 256 bits). It has the same call
; interface as my C implementation. The ebx, esi, edi and ebp registers are
; preserved across calls but eax, ecx and edx and the artihmetic status flags
; are not.  Although this is a full assembler implementation, it can be used
; in conjunction with my C code which provides faster key scheduling using
; large tables. In this case aeskey.c should be compiled with ASM_X86_V2C
; defined.  It is also important that the defines below match those used in the
; C code.  This code uses the VC++ register saving conentions; if it is used
; with another compiler, conventions for using and saving registers may need
; to be checked (and calling conventions).  The YASM command line for the VC++
; custom build step is:
;
;    yasm -Xvc -f win32 -D <Z> -o "$(TargetDir)\$(InputName).obj" "$(InputPath)"
;
; For the cryptlib build this is (pcg):
;
;	yasm -Xvc -f win32 -D ASM_X86_V2C -o aescrypt2.obj aes_x86_v2.asm
;
; where <Z> is ASM_X86_V2 or ASM_X86_V2C.  The calling intefaces are:
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

; The DLL interface must use the _stdcall convention in which the number
; of bytes of parameter space is added after an @ to the sutine's name.
; We must also remove our parameters from the stack before return (see
; the do_exit macro). Define DLL_EXPORT for the Dynamic Link Library version.

;
; Adapted for TrueCrypt:
; - All tables generated at run-time
; - Adapted for 16-bit environment
;

CPU 386
USE16
SEGMENT _TEXT PUBLIC CLASS=CODE USE16
SEGMENT _DATA PUBLIC CLASS=DATA USE16

GROUP DGROUP _TEXT _DATA

extern _aes_dec_tab		; Aestab.c
extern _aes_enc_tab

; %define DLL_EXPORT

; The size of the code can be reduced by using functions for the encryption
; and decryption rounds in place of macro expansion

%define REDUCE_CODE_SIZE

; Comment in/out the following lines to obtain the desired subroutines. These
; selections MUST match those in the C header file aes.h

; %define AES_128                 ; define if AES with 128 bit keys is needed
; %define AES_192                 ; define if AES with 192 bit keys is needed
%define AES_256                 ; define if AES with 256 bit keys is needed
; %define AES_VAR                 ; define if a variable key size is needed
%define ENCRYPTION              ; define if encryption is needed
%define DECRYPTION              ; define if decryption is needed
; %define AES_REV_DKS             ; define if key decryption schedule is reversed

%ifndef ASM_X86_V2C
%define ENCRYPTION_KEY_SCHEDULE ; define if encryption key expansion is needed
%define DECRYPTION_KEY_SCHEDULE ; define if decryption key expansion is needed
%endif

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

%ifdef  REDUCE_CODE_SIZE
    %macro mf_call 1
        call %1
    %endmacro
%else
    %macro mf_call 1
        %1
    %endmacro
%endif

; the DLL has to implement the _stdcall calling interface on return
; In this case we have to take our parameters (3 4-byte pointers)
; off the stack

%define parms 12

%macro  do_name 1-2 parms
%ifndef DLL_EXPORT
    global  %1
%1:
%else
    global  %1@%2
    export  %1@%2
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

; finite field multiplies by {02}, {04} and {08}

%define f2(x)   ((x<<1)^(((x>>7)&1)*0x11b))
%define f4(x)   ((x<<2)^(((x>>6)&1)*0x11b)^(((x>>6)&2)*0x11b))
%define f8(x)   ((x<<3)^(((x>>5)&1)*0x11b)^(((x>>5)&2)*0x11b)^(((x>>5)&4)*0x11b))

; finite field multiplies required in table generation

%define f3(x)   (f2(x) ^ x)
%define f9(x)   (f8(x) ^ x)
%define fb(x)   (f8(x) ^ f2(x) ^ x)
%define fd(x)   (f8(x) ^ f4(x) ^ x)
%define fe(x)   (f8(x) ^ f4(x) ^ f2(x))

%define etab_0(x)   [_aes_enc_tab+4+8*x]
%define etab_1(x)   [_aes_enc_tab+3+8*x]
%define etab_2(x)   [_aes_enc_tab+2+8*x]
%define etab_3(x)   [_aes_enc_tab+1+8*x]
%define etab_b(x)   byte [_aes_enc_tab+1+8*x] ; used with movzx for 0x000000xx
%define etab_w(x)   word [_aes_enc_tab+8*x]   ; used with movzx for 0x0000xx00

%define btab_0(x)   [_aes_enc_tab+6+8*x]
%define btab_1(x)   [_aes_enc_tab+5+8*x]
%define btab_2(x)   [_aes_enc_tab+4+8*x]
%define btab_3(x)   [_aes_enc_tab+3+8*x]

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

%if 1

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

%else       ; less effective but worth leaving as an option

    %macro  lr_xor  4
        movzx   %4,%2
        mov     %4,btab_%3(%4)
        and     %4,0x000000ff << 8 * %3
        xor     %1,%4
    %endmacro

    %macro  lr_mov  4
        movzx   %4,%2
        mov     %1,btab_%3(%4)
        and     %1,0x000000ff << 8 * %3
    %endmacro

%endif

; Apply S-Box to the 4 bytes in a 32-bit word and rotate byte positions

%ifdef REDUCE_CODE_SIZE
    
l3s_col:
    movzx   ecx,al              ; in      eax
    movzx   ecx, etab_b(ecx)    ; out     eax
    xor     edx,ecx             ; scratch ecx,edx
    movzx   ecx,ah
    movzx   ecx, etab_b(ecx)
    shl     ecx,8
    xor     edx,ecx
    shr     eax,16
    movzx   ecx,al
    movzx   ecx, etab_b(ecx)
    shl     ecx,16
    xor     edx,ecx
    movzx   ecx,ah
    movzx   ecx, etab_b(ecx)
    shl     ecx,24
    xor     edx,ecx
    mov     eax,edx
    ret

%else

%macro l3s_col 0

    movzx   ecx,al              ; in      eax
    movzx   ecx, etab_b(ecx)    ; out     eax
    xor     edx,ecx             ; scratch ecx,edx
    movzx   ecx,ah
    movzx   ecx, etab_b(ecx)
    shl     ecx,8
    xor     edx,ecx
    shr     eax,16
    movzx   ecx,al
    movzx   ecx, etab_b(ecx)
    shl     ecx,16
    xor     edx,ecx
    movzx   ecx,ah
    movzx   ecx, etab_b(ecx)
    shl     ecx,24
    xor     edx,ecx
    mov     eax,edx

%endmacro

%endif
    
; offsets to parameters

in_blk  equ     2   ; input byte array address parameter
out_blk equ     4   ; output byte array address parameter
ctx     equ     6   ; AES context structure
stk_spc equ    20   ; stack space

%ifdef  ENCRYPTION

; %define ENCRYPTION_TABLE

%ifdef REDUCE_CODE_SIZE

enc_round:
	sub		sp, 2
    add     ebp,16
    save    1,ebp
    mov     esi,[ebp+8]
    mov     edi,[ebp+12]

    rnd_fun nr_xor, nr_mov

    mov     eax,ebp
    mov     ecx,esi
    mov     edx,edi
    restore ebp,1
    xor     eax,[ebp]
    xor     ebx,[ebp+4]
	add		sp, 2
    ret
    
%else

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

%endif

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

    section _TEXT

; AES Encryption Subroutine

    do_name _aes_encrypt,12

	mov		ax, sp
	movzx	esp, ax

    sub     esp,stk_spc
    mov     [esp+16],ebp
    mov     [esp+12],ebx
    mov     [esp+ 8],esi
    mov     [esp+ 4],edi

    movzx   esi,word [esp+in_blk+stk_spc] ; input pointer
    mov     eax,[esi   ]
    mov     ebx,[esi+ 4]
    mov     ecx,[esi+ 8]
    mov     edx,[esi+12]

    movzx   ebp,word [esp+ctx+stk_spc]    ; key pointer
    movzx   edi,byte [ebp+4*KS_LENGTH]
    xor     eax,[ebp   ]
    xor     ebx,[ebp+ 4]
    xor     ecx,[ebp+ 8]
    xor     edx,[ebp+12]

; determine the number of rounds

%ifndef AES_256
    cmp     edi,10*16
    je      .3
    cmp     edi,12*16
    je      .2
    cmp     edi,14*16
    je      .1
    mov     eax,-1
    jmp     .5
%endif

.1: mf_call enc_round
    mf_call enc_round
.2: mf_call enc_round
    mf_call enc_round
.3: mf_call enc_round
    mf_call enc_round
    mf_call enc_round
    mf_call enc_round
    mf_call enc_round
    mf_call enc_round
    mf_call enc_round
    mf_call enc_round
    mf_call enc_round
    enc_last_round

    movzx   edx,word [esp+out_blk+stk_spc]
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
    do_exit 12

%endif

%macro f_key 2

    push    ecx
    push    edx
    mov     edx,esi
    ror     eax,8
    mf_call l3s_col
    mov     esi,eax
    pop     edx
    pop     ecx
    xor     esi,rc_val

    mov     [ebp+%1*%2],esi
    xor     edi,esi
    mov     [ebp+%1*%2+4],edi
    xor     ecx,edi
    mov     [ebp+%1*%2+8],ecx
    xor     edx,ecx
    mov     [ebp+%1*%2+12],edx
    mov     eax,edx

%if %2 == 24

%if %1 < 7
    xor     eax,[ebp+%1*%2+16-%2]
    mov     [ebp+%1*%2+16],eax
    xor     eax,[ebp+%1*%2+20-%2]
    mov     [ebp+%1*%2+20],eax
%endif

%elif %2 == 32

%if %1 < 6
    push    ecx
    push    edx
    mov     edx,[ebp+%1*%2+16-%2]
    mf_call l3s_col
    pop     edx
    pop     ecx
    mov     [ebp+%1*%2+16],eax
    xor     eax,[ebp+%1*%2+20-%2]
    mov     [ebp+%1*%2+20],eax
    xor     eax,[ebp+%1*%2+24-%2]
    mov     [ebp+%1*%2+24],eax
    xor     eax,[ebp+%1*%2+28-%2]
    mov     [ebp+%1*%2+28],eax
%endif

%endif

%assign rc_val f2(rc_val)

%endmacro

%ifdef ENCRYPTION_KEY_SCHEDULE

%ifdef  AES_128

%ifndef ENCRYPTION_TABLE
; %define ENCRYPTION_TABLE
%endif

%assign rc_val  1

    do_name _aes_encrypt_key128,8

    push    ebp
    push    ebx
    push    esi
    push    edi

    mov     ebp,[esp+24]
    mov     [ebp+4*KS_LENGTH],dword 10*16
    mov     ebx,[esp+20]

    mov     esi,[ebx]
    mov     [ebp],esi
    mov     edi,[ebx+4]
    mov     [ebp+4],edi
    mov     ecx,[ebx+8]
    mov     [ebp+8],ecx
    mov     edx,[ebx+12]
    mov     [ebp+12],edx
    add     ebp,16
    mov     eax,edx

    f_key   0,16        ; 11 * 4 = 44 unsigned longs
    f_key   1,16        ; 4 + 4 * 10 generated = 44
    f_key   2,16
    f_key   3,16
    f_key   4,16
    f_key   5,16
    f_key   6,16
    f_key   7,16
    f_key   8,16
    f_key   9,16

    pop     edi
    pop     esi
    pop     ebx
    pop     ebp
    xor     eax,eax
    do_exit  8

%endif

%ifdef  AES_192

%ifndef ENCRYPTION_TABLE
; %define ENCRYPTION_TABLE
%endif

%assign rc_val  1

    do_name _aes_encrypt_key192,8

    push    ebp
    push    ebx
    push    esi
    push    edi

    mov     ebp,[esp+24]
    mov     [ebp+4*KS_LENGTH],dword 12 * 16
    mov     ebx,[esp+20]

    mov     esi,[ebx]
    mov     [ebp],esi
    mov     edi,[ebx+4]
    mov     [ebp+4],edi
    mov     ecx,[ebx+8]
    mov     [ebp+8],ecx
    mov     edx,[ebx+12]
    mov     [ebp+12],edx
    mov     eax,[ebx+16]
    mov     [ebp+16],eax
    mov     eax,[ebx+20]
    mov     [ebp+20],eax
    add     ebp,24

    f_key   0,24        ; 13 * 4 = 52 unsigned longs
    f_key   1,24        ; 6 + 6 * 8 generated = 54
    f_key   2,24
    f_key   3,24
    f_key   4,24
    f_key   5,24
    f_key   6,24
    f_key   7,24

    pop     edi
    pop     esi
    pop     ebx
    pop     ebp
    xor     eax,eax
    do_exit  8

%endif

%ifdef  AES_256

%ifndef ENCRYPTION_TABLE
; %define ENCRYPTION_TABLE
%endif

%assign rc_val  1

    do_name _aes_encrypt_key256,8

	mov		ax, sp
	movzx	esp, ax
	
    push    ebp
    push    ebx
    push    esi
    push    edi

    movzx   ebp, word [esp+20] ; ks
    mov     [ebp+4*KS_LENGTH],dword 14 * 16
    movzx   ebx, word [esp+18] ; key

    mov     esi,[ebx]
    mov     [ebp],esi
    mov     edi,[ebx+4]
    mov     [ebp+4],edi
    mov     ecx,[ebx+8]
    mov     [ebp+8],ecx
    mov     edx,[ebx+12]
    mov     [ebp+12],edx
    mov     eax,[ebx+16]
    mov     [ebp+16],eax
    mov     eax,[ebx+20]
    mov     [ebp+20],eax
    mov     eax,[ebx+24]
    mov     [ebp+24],eax
    mov     eax,[ebx+28]
    mov     [ebp+28],eax
    add     ebp,32

    f_key   0,32        ; 15 * 4 = 60 unsigned longs
    f_key   1,32        ; 8 + 8 * 7 generated = 64
    f_key   2,32
    f_key   3,32
    f_key   4,32
    f_key   5,32
    f_key   6,32

    pop     edi
    pop     esi
    pop     ebx
    pop     ebp
    xor     eax,eax
    do_exit  8

%endif

%ifdef  AES_VAR

%ifndef ENCRYPTION_TABLE
; %define ENCRYPTION_TABLE
%endif

    do_name _aes_encrypt_key,12

    mov     ecx,[esp+4]
    mov     eax,[esp+8]
    mov     edx,[esp+12]
    push    edx
    push    ecx

    cmp     eax,16
    je      .1
    cmp     eax,128
    je      .1

    cmp     eax,24
    je      .2
    cmp     eax,192
    je      .2

    cmp     eax,32
    je      .3
    cmp     eax,256
    je      .3
    mov     eax,-1
    add     esp,8
    do_exit 12

.1: do_call _aes_encrypt_key128,8
    do_exit 12
.2: do_call _aes_encrypt_key192,8
    do_exit 12
.3: do_call _aes_encrypt_key256,8
    do_exit 12

%endif

%endif

%ifdef ENCRYPTION_TABLE

; S-box data - 256 entries

    section _DATA

%define u8(x)   0, x, x, f3(x), f2(x), x, x, f3(x)

_aes_enc_tab:
    db  u8(0x63),u8(0x7c),u8(0x77),u8(0x7b),u8(0xf2),u8(0x6b),u8(0x6f),u8(0xc5)
    db  u8(0x30),u8(0x01),u8(0x67),u8(0x2b),u8(0xfe),u8(0xd7),u8(0xab),u8(0x76)
    db  u8(0xca),u8(0x82),u8(0xc9),u8(0x7d),u8(0xfa),u8(0x59),u8(0x47),u8(0xf0)
    db  u8(0xad),u8(0xd4),u8(0xa2),u8(0xaf),u8(0x9c),u8(0xa4),u8(0x72),u8(0xc0)
    db  u8(0xb7),u8(0xfd),u8(0x93),u8(0x26),u8(0x36),u8(0x3f),u8(0xf7),u8(0xcc)
    db  u8(0x34),u8(0xa5),u8(0xe5),u8(0xf1),u8(0x71),u8(0xd8),u8(0x31),u8(0x15)
    db  u8(0x04),u8(0xc7),u8(0x23),u8(0xc3),u8(0x18),u8(0x96),u8(0x05),u8(0x9a)
    db  u8(0x07),u8(0x12),u8(0x80),u8(0xe2),u8(0xeb),u8(0x27),u8(0xb2),u8(0x75)
    db  u8(0x09),u8(0x83),u8(0x2c),u8(0x1a),u8(0x1b),u8(0x6e),u8(0x5a),u8(0xa0)
    db  u8(0x52),u8(0x3b),u8(0xd6),u8(0xb3),u8(0x29),u8(0xe3),u8(0x2f),u8(0x84)
    db  u8(0x53),u8(0xd1),u8(0x00),u8(0xed),u8(0x20),u8(0xfc),u8(0xb1),u8(0x5b)
    db  u8(0x6a),u8(0xcb),u8(0xbe),u8(0x39),u8(0x4a),u8(0x4c),u8(0x58),u8(0xcf)
    db  u8(0xd0),u8(0xef),u8(0xaa),u8(0xfb),u8(0x43),u8(0x4d),u8(0x33),u8(0x85)
    db  u8(0x45),u8(0xf9),u8(0x02),u8(0x7f),u8(0x50),u8(0x3c),u8(0x9f),u8(0xa8)
    db  u8(0x51),u8(0xa3),u8(0x40),u8(0x8f),u8(0x92),u8(0x9d),u8(0x38),u8(0xf5)
    db  u8(0xbc),u8(0xb6),u8(0xda),u8(0x21),u8(0x10),u8(0xff),u8(0xf3),u8(0xd2)
    db  u8(0xcd),u8(0x0c),u8(0x13),u8(0xec),u8(0x5f),u8(0x97),u8(0x44),u8(0x17)
    db  u8(0xc4),u8(0xa7),u8(0x7e),u8(0x3d),u8(0x64),u8(0x5d),u8(0x19),u8(0x73)
    db  u8(0x60),u8(0x81),u8(0x4f),u8(0xdc),u8(0x22),u8(0x2a),u8(0x90),u8(0x88)
    db  u8(0x46),u8(0xee),u8(0xb8),u8(0x14),u8(0xde),u8(0x5e),u8(0x0b),u8(0xdb)
    db  u8(0xe0),u8(0x32),u8(0x3a),u8(0x0a),u8(0x49),u8(0x06),u8(0x24),u8(0x5c)
    db  u8(0xc2),u8(0xd3),u8(0xac),u8(0x62),u8(0x91),u8(0x95),u8(0xe4),u8(0x79)
    db  u8(0xe7),u8(0xc8),u8(0x37),u8(0x6d),u8(0x8d),u8(0xd5),u8(0x4e),u8(0xa9)
    db  u8(0x6c),u8(0x56),u8(0xf4),u8(0xea),u8(0x65),u8(0x7a),u8(0xae),u8(0x08)
    db  u8(0xba),u8(0x78),u8(0x25),u8(0x2e),u8(0x1c),u8(0xa6),u8(0xb4),u8(0xc6)
    db  u8(0xe8),u8(0xdd),u8(0x74),u8(0x1f),u8(0x4b),u8(0xbd),u8(0x8b),u8(0x8a)
    db  u8(0x70),u8(0x3e),u8(0xb5),u8(0x66),u8(0x48),u8(0x03),u8(0xf6),u8(0x0e)
    db  u8(0x61),u8(0x35),u8(0x57),u8(0xb9),u8(0x86),u8(0xc1),u8(0x1d),u8(0x9e)
    db  u8(0xe1),u8(0xf8),u8(0x98),u8(0x11),u8(0x69),u8(0xd9),u8(0x8e),u8(0x94)
    db  u8(0x9b),u8(0x1e),u8(0x87),u8(0xe9),u8(0xce),u8(0x55),u8(0x28),u8(0xdf)
    db  u8(0x8c),u8(0xa1),u8(0x89),u8(0x0d),u8(0xbf),u8(0xe6),u8(0x42),u8(0x68)
    db  u8(0x41),u8(0x99),u8(0x2d),u8(0x0f),u8(0xb0),u8(0x54),u8(0xbb),u8(0x16)

%endif

%ifdef  DECRYPTION

; %define DECRYPTION_TABLE

%define dtab_0(x)   [_aes_dec_tab+  8*x]
%define dtab_1(x)   [_aes_dec_tab+3+8*x]
%define dtab_2(x)   [_aes_dec_tab+2+8*x]
%define dtab_3(x)   [_aes_dec_tab+1+8*x]
%define dtab_x(x)   byte [_aes_dec_tab+7+8*x]

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

%ifdef REDUCE_CODE_SIZE

dec_round:
	sub		sp, 2
%ifdef AES_REV_DKS
    add     ebp,16
%else
    sub     ebp,16
%endif
    save    1,ebp
    mov     esi,[ebp+8]
    mov     edi,[ebp+12]

    irn_fun ni_xor, ni_mov

    mov     ebx,ebp
    mov     ecx,esi
    mov     edx,edi
    restore ebp,1
    xor     eax,[ebp]
    xor     ebx,[ebp+4]
   	add		sp, 2
    ret

%else

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

%endif

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

    section _TEXT

; AES Decryption Subroutine

    do_name _aes_decrypt,12
    
	mov		ax, sp
	movzx	esp, ax

    sub     esp,stk_spc
    mov     [esp+16],ebp
    mov     [esp+12],ebx
    mov     [esp+ 8],esi
    mov     [esp+ 4],edi

; input four columns and xor in first round key

    movzx   esi,word [esp+in_blk+stk_spc] ; input pointer
    mov     eax,[esi   ]
    mov     ebx,[esi+ 4]
    mov     ecx,[esi+ 8]
    mov     edx,[esi+12]
    lea     esi,[esi+16]

    movzx   ebp, word [esp+ctx+stk_spc]    ; key pointer
    movzx   edi,byte[ebp+4*KS_LENGTH]
%ifndef  AES_REV_DKS        ; if decryption key schedule is not reversed
    lea     ebp,[ebp+edi] ; we have to access it from the top down
%endif
    xor     eax,[ebp   ]  ; key schedule
    xor     ebx,[ebp+ 4]
    xor     ecx,[ebp+ 8]
    xor     edx,[ebp+12]

; determine the number of rounds

%ifndef AES_256
    cmp     edi,10*16
    je      .3
    cmp     edi,12*16
    je      .2
    cmp     edi,14*16
    je      .1
    mov     eax,-1
    jmp     .5
%endif

.1: mf_call dec_round
    mf_call dec_round
.2: mf_call dec_round
    mf_call dec_round
.3: mf_call dec_round
    mf_call dec_round
    mf_call dec_round
    mf_call dec_round
    mf_call dec_round
    mf_call dec_round
    mf_call dec_round
    mf_call dec_round
    mf_call dec_round
    dec_last_round

; move final values to the output array.

    movzx   ebp,word [esp+out_blk+stk_spc]
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
    do_exit 12

%endif

%ifdef REDUCE_CODE_SIZE

inv_mix_col:
    movzx   ecx,dl          ; input  eax, edx
    movzx   ecx,etab_b(ecx) ; output eax
    mov     eax,dtab_0(ecx) ; used   ecx
    movzx   ecx,dh
    shr     edx,16
    movzx   ecx,etab_b(ecx)
    xor     eax,dtab_1(ecx)
    movzx   ecx,dl
    movzx   ecx,etab_b(ecx)
    xor     eax,dtab_2(ecx)
    movzx   ecx,dh
    movzx   ecx,etab_b(ecx)
    xor     eax,dtab_3(ecx)
    ret

%else

%macro  inv_mix_col 0   

    movzx   ecx,dl          ; input  eax, edx
    movzx   ecx,etab_b(ecx) ; output eax
    mov     eax,dtab_0(ecx) ; used   ecx
    movzx   ecx,dh
    shr     edx,16
    movzx   ecx,etab_b(ecx)
    xor     eax,dtab_1(ecx)
    movzx   ecx,dl
    movzx   ecx,etab_b(ecx)
    xor     eax,dtab_2(ecx)
    movzx   ecx,dh
    movzx   ecx,etab_b(ecx)
    xor     eax,dtab_3(ecx)

%endmacro

%endif

%ifdef DECRYPTION_KEY_SCHEDULE

%ifdef AES_128

%ifndef DECRYPTION_TABLE
; %define DECRYPTION_TABLE
%endif

    do_name _aes_decrypt_key128,8

    push    ebp
    push    ebx
    push    esi
    push    edi
    mov     eax,[esp+24]    ; context
    mov     edx,[esp+20]    ; key
    push    eax
    push    edx
    do_call _aes_encrypt_key128,8   ; generate expanded encryption key
    mov     eax,10*16
    mov     esi,[esp+24]    ; pointer to first round key
    lea     edi,[esi+eax]   ; pointer to last round key
    add     esi,32
                            ; the inverse mix column transformation
    mov     edx,[esi-16]    ; needs to be applied to all round keys
    mf_call inv_mix_col     ; except first and last. Hence start by
    mov     [esi-16],eax    ; transforming the four sub-keys in the
    mov     edx,[esi-12]    ; second round key
    mf_call inv_mix_col
    mov     [esi-12],eax    ; transformations for subsequent rounds
    mov     edx,[esi-8]     ; can then be made more efficient by
    mf_call inv_mix_col     ; noting that for three of the four sub-keys
    mov     [esi-8],eax     ; in the encryption round key ek[r]:
    mov     edx,[esi-4]     ;
    mf_call inv_mix_col     ;   ek[r][n] = ek[r][n-1] ^ ek[r-1][n]
    mov     [esi-4],eax     ;
                            ; where n is 1..3. Hence the corresponding
.0: mov     edx,[esi]       ; subkeys in the decryption round key dk[r]
    mf_call inv_mix_col     ; also obey since inv_mix_col is linear in
    mov     [esi],eax       ; GF(256):
    xor     eax,[esi-12]    ;
    mov     [esi+4],eax     ;   dk[r][n] = dk[r][n-1] ^ dk[r-1][n]
    xor     eax,[esi-8]     ;
    mov     [esi+8],eax     ; So we only need one inverse mix column
    xor     eax,[esi-4]     ; operation (n = 0) for each four word cycle
    mov     [esi+12],eax    ; in the expanded key.
    add     esi,16
    cmp     edi,esi
    jg      .0
    jmp     dec_end

%endif

%ifdef AES_192

%ifndef DECRYPTION_TABLE
; %define DECRYPTION_TABLE
%endif

    do_name _aes_decrypt_key192,8

    push    ebp
    push    ebx
    push    esi
    push    edi
    mov     eax,[esp+24]    ; context
    mov     edx,[esp+20]    ; key
    push    eax
    push    edx
    do_call _aes_encrypt_key192,8   ; generate expanded encryption key
    mov     eax,12*16
    mov     esi,[esp+24]    ; first round key
    lea     edi,[esi+eax]   ; last round key
    add     esi,48          ; the first 6 words are the key, of
                            ; which the top 2 words are part of
    mov     edx,[esi-32]    ; the second round key and hence
    mf_call inv_mix_col     ; need to be modified. After this we
    mov     [esi-32],eax    ; need to do a further six values prior
    mov     edx,[esi-28]    ; to using a more efficient technique
    mf_call inv_mix_col     ; based on:
    mov     [esi-28],eax    ;
                            ; dk[r][n] = dk[r][n-1] ^ dk[r-1][n]
    mov     edx,[esi-24]    ;
    mf_call inv_mix_col     ; for n = 1 .. 5 where the key expansion
    mov     [esi-24],eax    ; cycle is now 6 words long
    mov     edx,[esi-20]
    mf_call inv_mix_col
    mov     [esi-20],eax
    mov     edx,[esi-16]
    mf_call inv_mix_col
    mov     [esi-16],eax
    mov     edx,[esi-12]
    mf_call inv_mix_col
    mov     [esi-12],eax
    mov     edx,[esi-8]
    mf_call inv_mix_col
    mov     [esi-8],eax
    mov     edx,[esi-4]
    mf_call inv_mix_col
    mov     [esi-4],eax

.0: mov     edx,[esi]       ; the expanded key is 13 * 4 = 44 32-bit words
    mf_call inv_mix_col     ; of which 11 * 4 = 44 have to be modified
    mov     [esi],eax       ; using inv_mix_col.  We have already done 8
    xor     eax,[esi-20]    ; of these so 36 are left - hence we need
    mov     [esi+4],eax     ; exactly 6 loops of six here
    xor     eax,[esi-16]
    mov     [esi+8],eax
    xor     eax,[esi-12]
    mov     [esi+12],eax
    xor     eax,[esi-8]
    mov     [esi+16],eax
    xor     eax,[esi-4]
    mov     [esi+20],eax
    add     esi,24
    cmp     edi,esi
    jg      .0
    jmp     dec_end

%endif

%ifdef AES_256

%ifndef DECRYPTION_TABLE
; %define DECRYPTION_TABLE
%endif

    do_name _aes_decrypt_key256,8
    
    mov		ax, sp
	movzx	esp, ax
    push    ebp
    push    ebx
    push    esi
    push    edi
    
    movzx   eax, word [esp+20] ; ks
    movzx   edx, word [esp+18] ; key
    push    ax
    push    dx
    do_call _aes_encrypt_key256,4   ; generate expanded encryption key
    mov     eax,14*16
    movzx   esi, word [esp+20] ; ks
    lea     edi,[esi+eax]
    add     esi,64

    mov     edx,[esi-48]    ; the primary key is 8 words, of which
    mf_call inv_mix_col     ; the top four require modification
    mov     [esi-48],eax
    mov     edx,[esi-44]
    mf_call inv_mix_col
    mov     [esi-44],eax
    mov     edx,[esi-40]
    mf_call inv_mix_col
    mov     [esi-40],eax
    mov     edx,[esi-36]
    mf_call inv_mix_col
    mov     [esi-36],eax

    mov     edx,[esi-32]    ; the encryption key expansion cycle is
    mf_call inv_mix_col     ; now eight words long so we need to
    mov     [esi-32],eax    ; start by doing one complete block
    mov     edx,[esi-28]
    mf_call inv_mix_col
    mov     [esi-28],eax
    mov     edx,[esi-24]
    mf_call inv_mix_col
    mov     [esi-24],eax
    mov     edx,[esi-20]
    mf_call inv_mix_col
    mov     [esi-20],eax
    mov     edx,[esi-16]
    mf_call inv_mix_col
    mov     [esi-16],eax
    mov     edx,[esi-12]
    mf_call inv_mix_col
    mov     [esi-12],eax
    mov     edx,[esi-8]
    mf_call inv_mix_col
    mov     [esi-8],eax
    mov     edx,[esi-4]
    mf_call inv_mix_col
    mov     [esi-4],eax

.0: mov     edx,[esi]       ; we can now speed up the remaining
    mf_call inv_mix_col     ; rounds by using the technique
    mov     [esi],eax       ; outlined earlier.  But note that
    xor     eax,[esi-28]    ; there is one extra inverse mix
    mov     [esi+4],eax     ; column operation as the 256 bit
    xor     eax,[esi-24]    ; key has an extra non-linear step
    mov     [esi+8],eax     ; for the midway element.
    xor     eax,[esi-20]
    mov     [esi+12],eax    ; the expanded key is 15 * 4 = 60
    mov     edx,[esi+16]    ; 32-bit words of which 52 need to
    mf_call inv_mix_col     ; be modified.  We have already done
    mov     [esi+16],eax    ; 12 so 40 are left - which means
    xor     eax,[esi-12]    ; that we need exactly 5 loops of 8
    mov     [esi+20],eax
    xor     eax,[esi-8]
    mov     [esi+24],eax
    xor     eax,[esi-4]
    mov     [esi+28],eax
    add     esi,32
    cmp     edi,esi
    jg      .0

%endif

dec_end:

%ifdef AES_REV_DKS

    movzx   esi,word [esp+20]	; this reverses the order of the
.1: mov     eax,[esi]			; round keys if required
    mov     ebx,[esi+4]
    mov     ebp,[edi]
    mov     edx,[edi+4]
    mov     [esi],ebp
    mov     [esi+4],edx
    mov     [edi],eax
    mov     [edi+4],ebx

    mov     eax,[esi+8]
    mov     ebx,[esi+12]
    mov     ebp,[edi+8]
    mov     edx,[edi+12]
    mov     [esi+8],ebp
    mov     [esi+12],edx
    mov     [edi+8],eax
    mov     [edi+12],ebx

    add     esi,16
    sub     edi,16
    cmp     edi,esi
    jg      .1

%endif

    pop     edi
    pop     esi
    pop     ebx
    pop     ebp
    xor     eax,eax
    do_exit  8

%ifdef AES_VAR

    do_name _aes_decrypt_key,12

    mov     ecx,[esp+4]
    mov     eax,[esp+8]
    mov     edx,[esp+12]
    push    edx
    push    ecx

    cmp     eax,16
    je      .1
    cmp     eax,128
    je      .1

    cmp     eax,24
    je      .2
    cmp     eax,192
    je      .2

    cmp     eax,32
    je      .3
    cmp     eax,256
    je      .3
    mov     eax,-1
    add     esp,8
    do_exit 12

.1: do_call _aes_decrypt_key128,8
    do_exit 12
.2: do_call _aes_decrypt_key192,8
    do_exit 12
.3: do_call _aes_decrypt_key256,8
    do_exit 12

%endif

%endif

%ifdef DECRYPTION_TABLE

; Inverse S-box data - 256 entries

    section _DATA

%define v8(x)   fe(x), f9(x), fd(x), fb(x), fe(x), f9(x), fd(x), x

_aes_dec_tab:
    db  v8(0x52),v8(0x09),v8(0x6a),v8(0xd5),v8(0x30),v8(0x36),v8(0xa5),v8(0x38)
    db  v8(0xbf),v8(0x40),v8(0xa3),v8(0x9e),v8(0x81),v8(0xf3),v8(0xd7),v8(0xfb)
    db  v8(0x7c),v8(0xe3),v8(0x39),v8(0x82),v8(0x9b),v8(0x2f),v8(0xff),v8(0x87)
    db  v8(0x34),v8(0x8e),v8(0x43),v8(0x44),v8(0xc4),v8(0xde),v8(0xe9),v8(0xcb)
    db  v8(0x54),v8(0x7b),v8(0x94),v8(0x32),v8(0xa6),v8(0xc2),v8(0x23),v8(0x3d)
    db  v8(0xee),v8(0x4c),v8(0x95),v8(0x0b),v8(0x42),v8(0xfa),v8(0xc3),v8(0x4e)
    db  v8(0x08),v8(0x2e),v8(0xa1),v8(0x66),v8(0x28),v8(0xd9),v8(0x24),v8(0xb2)
    db  v8(0x76),v8(0x5b),v8(0xa2),v8(0x49),v8(0x6d),v8(0x8b),v8(0xd1),v8(0x25)
    db  v8(0x72),v8(0xf8),v8(0xf6),v8(0x64),v8(0x86),v8(0x68),v8(0x98),v8(0x16)
    db  v8(0xd4),v8(0xa4),v8(0x5c),v8(0xcc),v8(0x5d),v8(0x65),v8(0xb6),v8(0x92)
    db  v8(0x6c),v8(0x70),v8(0x48),v8(0x50),v8(0xfd),v8(0xed),v8(0xb9),v8(0xda)
    db  v8(0x5e),v8(0x15),v8(0x46),v8(0x57),v8(0xa7),v8(0x8d),v8(0x9d),v8(0x84)
    db  v8(0x90),v8(0xd8),v8(0xab),v8(0x00),v8(0x8c),v8(0xbc),v8(0xd3),v8(0x0a)
    db  v8(0xf7),v8(0xe4),v8(0x58),v8(0x05),v8(0xb8),v8(0xb3),v8(0x45),v8(0x06)
    db  v8(0xd0),v8(0x2c),v8(0x1e),v8(0x8f),v8(0xca),v8(0x3f),v8(0x0f),v8(0x02)
    db  v8(0xc1),v8(0xaf),v8(0xbd),v8(0x03),v8(0x01),v8(0x13),v8(0x8a),v8(0x6b)
    db  v8(0x3a),v8(0x91),v8(0x11),v8(0x41),v8(0x4f),v8(0x67),v8(0xdc),v8(0xea)
    db  v8(0x97),v8(0xf2),v8(0xcf),v8(0xce),v8(0xf0),v8(0xb4),v8(0xe6),v8(0x73)
    db  v8(0x96),v8(0xac),v8(0x74),v8(0x22),v8(0xe7),v8(0xad),v8(0x35),v8(0x85)
    db  v8(0xe2),v8(0xf9),v8(0x37),v8(0xe8),v8(0x1c),v8(0x75),v8(0xdf),v8(0x6e)
    db  v8(0x47),v8(0xf1),v8(0x1a),v8(0x71),v8(0x1d),v8(0x29),v8(0xc5),v8(0x89)
    db  v8(0x6f),v8(0xb7),v8(0x62),v8(0x0e),v8(0xaa),v8(0x18),v8(0xbe),v8(0x1b)
    db  v8(0xfc),v8(0x56),v8(0x3e),v8(0x4b),v8(0xc6),v8(0xd2),v8(0x79),v8(0x20)
    db  v8(0x9a),v8(0xdb),v8(0xc0),v8(0xfe),v8(0x78),v8(0xcd),v8(0x5a),v8(0xf4)
    db  v8(0x1f),v8(0xdd),v8(0xa8),v8(0x33),v8(0x88),v8(0x07),v8(0xc7),v8(0x31)
    db  v8(0xb1),v8(0x12),v8(0x10),v8(0x59),v8(0x27),v8(0x80),v8(0xec),v8(0x5f)
    db  v8(0x60),v8(0x51),v8(0x7f),v8(0xa9),v8(0x19),v8(0xb5),v8(0x4a),v8(0x0d)
    db  v8(0x2d),v8(0xe5),v8(0x7a),v8(0x9f),v8(0x93),v8(0xc9),v8(0x9c),v8(0xef)
    db  v8(0xa0),v8(0xe0),v8(0x3b),v8(0x4d),v8(0xae),v8(0x2a),v8(0xf5),v8(0xb0)
    db  v8(0xc8),v8(0xeb),v8(0xbb),v8(0x3c),v8(0x83),v8(0x53),v8(0x99),v8(0x61)
    db  v8(0x17),v8(0x2b),v8(0x04),v8(0x7e),v8(0xba),v8(0x77),v8(0xd6),v8(0x26)
    db  v8(0xe1),v8(0x69),v8(0x14),v8(0x63),v8(0x55),v8(0x21),v8(0x0c),v8(0x7d)

%endif
