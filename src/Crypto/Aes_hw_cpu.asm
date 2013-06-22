;
; Copyright (c) 2010 TrueCrypt Developers Association. All rights reserved.
;
; Governed by the TrueCrypt License 3.0 the full text of which is contained in
; the file License.txt included in TrueCrypt binary and source code distribution
; packages.
;


%ifidn __BITS__, 16
	%define R e
%elifidn __BITS__, 32
	%define R e
%elifidn __BITS__, 64
	%define R r
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


%macro push_xmm 2
	sub rsp, 16 * (%2 - %1 + 1)

	%assign stackoffset 0
	%assign regnumber %1

	%rep (%2 - %1 + 1)
		movdqu [rsp + 16 * stackoffset], xmm%[regnumber]

		%assign stackoffset stackoffset+1
		%assign regnumber regnumber+1
	%endrep
%endmacro


%macro pop_xmm 2
	%assign stackoffset 0
	%assign regnumber %1

	%rep (%2 - %1 + 1)
		movdqu xmm%[regnumber], [rsp + 16 * stackoffset]

		%assign stackoffset stackoffset+1
		%assign regnumber regnumber+1
	%endrep

	add rsp, 16 * (%2 - %1 + 1)
%endmacro


%macro aes_hw_cpu 2
	%define OPERATION %1
	%define BLOCK_COUNT %2

	; Load data blocks
	%assign block 1
	%rep BLOCK_COUNT
		movdqu xmm%[block], [%[R]dx + 16 * (block - 1)]
		%assign block block+1
	%endrep

	; Encrypt/decrypt data blocks
	%assign round 0
	%rep 15
		movdqu xmm0, [%[R]cx + 16 * round]

		%assign block 1
		%rep BLOCK_COUNT

			%if round = 0
				pxor xmm%[block], xmm0
			%else
				%if round < 14
					aes%[OPERATION] xmm%[block], xmm0
				%else
					aes%[OPERATION]last xmm%[block], xmm0
				%endif
			%endif

			%assign block block+1
		%endrep

		%assign round round+1
	%endrep

	; Store data blocks
	%assign block 1
	%rep BLOCK_COUNT
		movdqu [%[R]dx + 16 * (block - 1)], xmm%[block]
		%assign block block+1
	%endrep

	%undef OPERATION
	%undef BLOCK_COUNT
%endmacro


%macro aes_hw_cpu_32_blocks 1
	%define OPERATION_32_BLOCKS %1

	%ifidn __BITS__, 64
		%define MAX_REG_BLOCK_COUNT 15
	%else
		%define MAX_REG_BLOCK_COUNT 7
	%endif

	%ifidn __OUTPUT_FORMAT__, win64
		%if MAX_REG_BLOCK_COUNT > 5
			push_xmm 6, MAX_REG_BLOCK_COUNT
		%endif
	%endif

		mov eax, 32 / MAX_REG_BLOCK_COUNT
	.1:
		aes_hw_cpu %[OPERATION_32_BLOCKS], MAX_REG_BLOCK_COUNT

		add %[R]dx, 16 * MAX_REG_BLOCK_COUNT
		dec eax
		jnz .1

	%if (32 % MAX_REG_BLOCK_COUNT) != 0
		aes_hw_cpu %[OPERATION_32_BLOCKS], (32 % MAX_REG_BLOCK_COUNT)
	%endif

	%ifidn __OUTPUT_FORMAT__, win64
		%if MAX_REG_BLOCK_COUNT > 5
			pop_xmm 6, MAX_REG_BLOCK_COUNT
		%endif
	%endif

	%undef OPERATION_32_BLOCKS
	%undef MAX_REG_BLOCK_COUNT
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
		mov %[R]ax, cr4
		or ax, 1 << 9
		mov cr4, %[R]ax
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

	export_function is_aes_hw_cpu_supported
		push %[R]bx

		mov eax, 1
		cpuid
		mov eax, ecx
		shr eax, 25
		and eax, 1

		pop %[R]bx
	ret


; void aes_hw_cpu_decrypt (const byte *ks, byte *data);

	aes_function_entry aes_hw_cpu_decrypt
		aes_hw_cpu dec, 1
	aes_function_exit


; void aes_hw_cpu_decrypt_32_blocks (const byte *ks, byte *data);

	aes_function_entry aes_hw_cpu_decrypt_32_blocks
		aes_hw_cpu_32_blocks dec
	aes_function_exit


; void aes_hw_cpu_encrypt (const byte *ks, byte *data);

	aes_function_entry aes_hw_cpu_encrypt
		aes_hw_cpu enc, 1
	aes_function_exit


; void aes_hw_cpu_encrypt_32_blocks (const byte *ks, byte *data);

	aes_function_entry aes_hw_cpu_encrypt_32_blocks
		aes_hw_cpu_32_blocks enc
	aes_function_exit


%endif	; __BITS__ != 16
