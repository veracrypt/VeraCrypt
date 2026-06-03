;
; Copyright (c) 2010 TrueCrypt Developers Association. All rights reserved.
;
; Governed by the TrueCrypt License 3.0 the full text of which is contained in
; the file License.txt included in TrueCrypt binary and source code distribution
; packages.
;


%ifidn __BITS__, 16
	%define R(x) e %+ x
%elifidn __BITS__, 32
	%define R(x) e %+ x
%elifidn __BITS__, 64
	%define R(x) r %+ x
%endif


%macro export_function 1-2 0

	%ifdef MS_STDCALL
		global %1@%2
		export _%1@%2
	%1@%2:
	%elifidn __BITS__, 16
		global _%1
	_%1:
	%else
		global %1
	%1:
	%endif

%endmacro


%macro aes_function_entry 1

	; void (const byte *ks, byte *data);

	export_function %1, 8

	%ifidn __BITS__, 32
		mov ecx, [esp + 4 + 4 * 0]
		mov edx, [esp + 4 + 4 * 1]
	%elifidn __BITS__, 64
		%ifnidn __OUTPUT_FORMAT__, win64
			mov rcx, rdi
			mov rdx, rsi
		%endif
	%endif

	; ecx/rcx = ks
	; edx/rdx = data

%endmacro


%macro aes_function_exit 0

	; void (const byte *, byte *);

	%ifdef MS_STDCALL
		ret 8
	%else
		ret
	%endif

%endmacro


%macro aes_hw_cpu 2
	%define OPERATION %1
	%define BLOCK_COUNT %2

	; Load data blocks
	%assign block 1
	%rep BLOCK_COUNT
		movdqu xmm %+ block, [R(dx) + 16 * (block - 1)]
		%assign block block+1
	%endrep

	; Encrypt/decrypt data blocks
	%assign round 0
	%rep 15
		movdqu xmm0, [R(cx) + 16 * round]

		%assign block 1
		%rep BLOCK_COUNT

			%if round = 0
				pxor xmm %+ block, xmm0
			%else
				%if round < 14
					aes %+ OPERATION xmm %+ block, xmm0
				%else
					aes %+ OPERATION %+ last xmm %+ block, xmm0
				%endif
			%endif

			%assign block block+1
		%endrep

		%assign round round+1
	%endrep

	; Store data blocks
	%assign block 1
	%rep BLOCK_COUNT
		movdqu [R(dx) + 16 * (block - 1)], xmm %+ block
		%assign block block+1
	%endrep

	%undef OPERATION
	%undef BLOCK_COUNT
%endmacro


%macro aes_hw_cpu_32_blocks 2
	%define AES_HW_CPU_32_BLOCKS_NAME %1
	%define OPERATION_32_BLOCKS %2

	%ifidn __BITS__, 64
		%define MAX_REG_BLOCK_COUNT 15
	%else
		%define MAX_REG_BLOCK_COUNT 7
	%endif

	%ifidn __OUTPUT_FORMAT__, win64
		%if MAX_REG_BLOCK_COUNT > 5
			sub rsp, 16 * (MAX_REG_BLOCK_COUNT - 6 + 1) + 8
AES_HW_CPU_32_BLOCKS_NAME %+ _alloc_end:
			movdqu [rsp + 16 * 0], xmm6
AES_HW_CPU_32_BLOCKS_NAME %+ _save_xmm6_end:
			movdqu [rsp + 16 * 1], xmm7
AES_HW_CPU_32_BLOCKS_NAME %+ _save_xmm7_end:
			movdqu [rsp + 16 * 2], xmm8
AES_HW_CPU_32_BLOCKS_NAME %+ _save_xmm8_end:
			movdqu [rsp + 16 * 3], xmm9
AES_HW_CPU_32_BLOCKS_NAME %+ _save_xmm9_end:
			movdqu [rsp + 16 * 4], xmm10
AES_HW_CPU_32_BLOCKS_NAME %+ _save_xmm10_end:
			movdqu [rsp + 16 * 5], xmm11
AES_HW_CPU_32_BLOCKS_NAME %+ _save_xmm11_end:
			movdqu [rsp + 16 * 6], xmm12
AES_HW_CPU_32_BLOCKS_NAME %+ _save_xmm12_end:
			movdqu [rsp + 16 * 7], xmm13
AES_HW_CPU_32_BLOCKS_NAME %+ _save_xmm13_end:
			movdqu [rsp + 16 * 8], xmm14
AES_HW_CPU_32_BLOCKS_NAME %+ _save_xmm14_end:
			movdqu [rsp + 16 * 9], xmm15
AES_HW_CPU_32_BLOCKS_NAME %+ _save_xmm15_end:
AES_HW_CPU_32_BLOCKS_NAME %+ _prolog_end:
		%endif
	%endif

		mov eax, 32 / MAX_REG_BLOCK_COUNT
	.1:
		aes_hw_cpu OPERATION_32_BLOCKS, MAX_REG_BLOCK_COUNT

		add R(dx), 16 * MAX_REG_BLOCK_COUNT
		dec eax
		jnz .1

	%if (32 % MAX_REG_BLOCK_COUNT) != 0
		aes_hw_cpu OPERATION_32_BLOCKS, (32 % MAX_REG_BLOCK_COUNT)
	%endif

	%ifidn __OUTPUT_FORMAT__, win64
		%if MAX_REG_BLOCK_COUNT > 5
			movdqu xmm6, [rsp + 16 * 0]
			movdqu xmm7, [rsp + 16 * 1]
			movdqu xmm8, [rsp + 16 * 2]
			movdqu xmm9, [rsp + 16 * 3]
			movdqu xmm10, [rsp + 16 * 4]
			movdqu xmm11, [rsp + 16 * 5]
			movdqu xmm12, [rsp + 16 * 6]
			movdqu xmm13, [rsp + 16 * 7]
			movdqu xmm14, [rsp + 16 * 8]
			movdqu xmm15, [rsp + 16 * 9]
			add rsp, 16 * (MAX_REG_BLOCK_COUNT - 6 + 1) + 8
		%endif
	%endif

	%undef OPERATION_32_BLOCKS
	%undef AES_HW_CPU_32_BLOCKS_NAME
	%undef MAX_REG_BLOCK_COUNT
%endmacro


; Win64 unwind metadata for the 32-block AES-NI routines.
;
; The records below are hand-encoded and must stay in exact lockstep with the
; prologue emitted by aes_hw_cpu_32_blocks: the unwind codes describe the "sub
; rsp" allocation followed by the xmm6..xmm15 saves, listed in descending prolog
; offset order. The slot count (22 = 10 SAVE_XMM128 pairs + 1 ALLOC_LARGE pair)
; and the recorded allocation size are therefore fixed for the win64 /
; MAX_REG_BLOCK_COUNT == 15 layout. If that saved-register range or the
; allocation ever changes, update the prologue and this table together; a
; mismatch makes the OS unwinder mis-restore the caller's context.

%macro win64_aesni_32_unwind_info 2
%ifidn __OUTPUT_FORMAT__, win64
	section .pdata rdata align=4
	align 4
	dd %1 wrt ..imagebase
	dd %2 wrt ..imagebase
	dd %1 %+ _unwind_info wrt ..imagebase

	section .xdata rdata align=8
	align 4
%1 %+ _unwind_info:
	db 1
	db %1 %+ _prolog_end - %1
	db 22
	db 0
	db %1 %+ _save_xmm15_end - %1, (15 << 4) | 8
	dw 9
	db %1 %+ _save_xmm14_end - %1, (14 << 4) | 8
	dw 8
	db %1 %+ _save_xmm13_end - %1, (13 << 4) | 8
	dw 7
	db %1 %+ _save_xmm12_end - %1, (12 << 4) | 8
	dw 6
	db %1 %+ _save_xmm11_end - %1, (11 << 4) | 8
	dw 5
	db %1 %+ _save_xmm10_end - %1, (10 << 4) | 8
	dw 4
	db %1 %+ _save_xmm9_end - %1, (9 << 4) | 8
	dw 3
	db %1 %+ _save_xmm8_end - %1, (8 << 4) | 8
	dw 2
	db %1 %+ _save_xmm7_end - %1, (7 << 4) | 8
	dw 1
	db %1 %+ _save_xmm6_end - %1, (6 << 4) | 8
	dw 0
	db %1 %+ _alloc_end - %1, 1
	dw (16 * (15 - 6 + 1) + 8) / 8

	section .text
%endif
%endmacro


%ifidn __BITS__, 16

	USE16
	SEGMENT _TEXT PUBLIC CLASS=CODE USE16
	SEGMENT _DATA PUBLIC CLASS=DATA USE16
	GROUP DGROUP _TEXT _DATA
	SECTION _TEXT

%else

	SECTION .text

%endif


; void aes_hw_cpu_enable_sse ();

	export_function aes_hw_cpu_enable_sse
		mov R(ax), cr4
		or ax, 1 << 9
		mov cr4, R(ax)
	ret


%ifidn __BITS__, 16


; byte is_aes_hw_cpu_supported ();

	export_function is_aes_hw_cpu_supported
		mov eax, 1
		cpuid
		mov eax, ecx
		shr eax, 25
		and al, 1
	ret


; void aes_hw_cpu_decrypt (const byte *ks, byte *data);

	export_function aes_hw_cpu_decrypt
		mov ax, -16
		jmp aes_hw_cpu_encrypt_decrypt

; void aes_hw_cpu_encrypt (const byte *ks, byte *data);

	export_function aes_hw_cpu_encrypt
		mov ax, 16

	aes_hw_cpu_encrypt_decrypt:
		push bp
		mov bp, sp
		push di
		push si

		mov si, [bp + 4]			; ks
		mov di, [bp + 4 + 2]		; data

		movdqu xmm0, [si]
		movdqu xmm1, [di]

		pxor xmm1, xmm0

		mov cx, 13

	.round1_13:
		add si, ax
		movdqu xmm0, [si]

		cmp ax, 0
		jl .decrypt

		aesenc xmm1, xmm0
		jmp .2
	.decrypt:
		aesdec xmm1, xmm0
	.2:
		loop .round1_13

		add si, ax
		movdqu xmm0, [si]

		cmp ax, 0
		jl .decrypt_last

		aesenclast xmm1, xmm0
		jmp .3
	.decrypt_last:
		aesdeclast xmm1, xmm0
	.3:
		movdqu [di], xmm1

		pop si
		pop di
		pop bp
	ret


%else	; __BITS__ != 16


; byte is_aes_hw_cpu_supported ();

; We comment this since we have an alternative C implementation
; that supports Hyper-V detection workaround
;
;	export_function is_aes_hw_cpu_supported
;		push R(bx)
;
;		mov eax, 1
;		cpuid
;		mov eax, ecx
;		shr eax, 25
;		and eax, 1
;
;		pop R(bx)
;	ret


; void aes_hw_cpu_decrypt (const byte *ks, byte *data);

	aes_function_entry aes_hw_cpu_decrypt
		aes_hw_cpu dec, 1
	aes_function_exit


; void aes_hw_cpu_decrypt_32_blocks (const byte *ks, byte *data);

	aes_function_entry aes_hw_cpu_decrypt_32_blocks
		aes_hw_cpu_32_blocks aes_hw_cpu_decrypt_32_blocks, dec
	aes_function_exit
aes_hw_cpu_decrypt_32_blocks_end:
	win64_aesni_32_unwind_info aes_hw_cpu_decrypt_32_blocks, aes_hw_cpu_decrypt_32_blocks_end


; void aes_hw_cpu_encrypt (const byte *ks, byte *data);

	aes_function_entry aes_hw_cpu_encrypt
		aes_hw_cpu enc, 1
	aes_function_exit


; void aes_hw_cpu_encrypt_32_blocks (const byte *ks, byte *data);

	aes_function_entry aes_hw_cpu_encrypt_32_blocks
		aes_hw_cpu_32_blocks aes_hw_cpu_encrypt_32_blocks, enc
	aes_function_exit
aes_hw_cpu_encrypt_32_blocks_end:
	win64_aesni_32_unwind_info aes_hw_cpu_encrypt_32_blocks, aes_hw_cpu_encrypt_32_blocks_end


%endif	; __BITS__ != 16

%ifidn __OUTPUT_FORMAT__,elf
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
%ifidn __OUTPUT_FORMAT__,elf32
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
%ifidn __OUTPUT_FORMAT__,elf64
section .note.GNU-stack noalloc noexec nowrite progbits
%endif

