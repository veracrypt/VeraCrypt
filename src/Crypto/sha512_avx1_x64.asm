;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Copyright (c) 2012, Intel Corporation 
; 
; All rights reserved. 
; 
; Redistribution and use in source and binary forms, with or without
; modification, are permitted provided that the following conditions are
; met: 
; 
; * Redistributions of source code must retain the above copyright
;   notice, this list of conditions and the following disclaimer.  
; 
; * Redistributions in binary form must reproduce the above copyright
;   notice, this list of conditions and the following disclaimer in the
;   documentation and/or other materials provided with the
;   distribution. 
; 
; * Neither the name of the Intel Corporation nor the names of its
;   contributors may be used to endorse or promote products derived from
;   this software without specific prior written permission. 
; 
; 
; THIS SOFTWARE IS PROVIDED BY INTEL CORPORATION "AS IS" AND ANY
; EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
; IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
; PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL INTEL CORPORATION OR
; CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
; EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
; PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
; PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
; LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
; NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
; SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; Example YASM command lines:
; Windows:  yasm -f x64 -D WINABI sha512_avx.asm
; Linux:    yasm -f elf64 sha512_avx.asm
;

BITS 64
section .text

; Virtual Registers
%ifdef WINABI
	%define msg	rcx ; ARG1
	%define digest	rdx ; ARG2
	%define msglen	r8  ; ARG3
	%define T1	rsi
	%define T2	rdi
%else
	%define msg	rdi ; ARG1
	%define digest	rsi ; ARG2
	%define msglen	rdx ; ARG3
	%define T1	rcx
	%define T2	r8
%endif
%define a_64	r9
%define b_64	r10
%define c_64	r11
%define d_64	r12
%define e_64	r13
%define f_64	r14
%define g_64	r15
%define h_64	rbx
%define tmp0	rax

; Local variables (stack frame)
; Note: frame_size must be an odd multiple of 8 bytes to XMM align RSP
struc frame
	.W:       resq 80 ; Message Schedule
	.WK:      resq  2 ; W[t] + K[t] | W[t+1] + K[t+1]

%ifdef WINABI
	.XMMSAVE: resdq 4
	.GPRSAVE: resq  7
%else
	.GPRSAVE: resq  5
%endif
endstruc

; Useful QWORD "arrays" for simpler memory references
%define MSG(i)    msg    + 8*(i) ; Input message (arg1)
%define DIGEST(i) digest + 8*(i) ; Output Digest (arg2)
%define K_t(i)    K512   + 8*(i) wrt rip ; SHA Constants (static mem)
%define W_t(i)    rsp + frame.W  + 8*(i) ; Message Schedule (stack frame)
%define WK_2(i)   rsp + frame.WK + 8*((i) % 2) ; W[t]+K[t] (stack frame)
; MSG, DIGEST, K_t, W_t are arrays
; WK_2(t) points to 1 of 2 qwords at frame.WK depdending on t being odd/even

%macro RotateState 0
	; Rotate symbles a..h right
	%xdefine	%%TMP h_64
	%xdefine	h_64 g_64
	%xdefine	g_64 f_64
	%xdefine	f_64 e_64
	%xdefine	e_64 d_64
	%xdefine	d_64 c_64
	%xdefine	c_64 b_64
	%xdefine	b_64 a_64
	%xdefine	a_64 %%TMP
%endmacro

%macro RORQ 2
	; shld is faster than ror on Sandybridge
	shld	%1, %1, (64 - %2)
%endmacro

%macro SHA512_Round 1
%assign %%t   (%1)

	; Compute Round %%t
	mov	T1,   f_64        ; T1 = f
	mov	tmp0, e_64        ; tmp = e
	xor	T1,   g_64        ; T1 = f ^ g
	RORQ	tmp0, 23 ; 41     ; tmp = e ror 23
	and	T1,   e_64        ; T1 = (f ^ g) & e
	xor	tmp0, e_64        ; tmp = (e ror 23) ^ e
	xor	T1,   g_64        ; T1 = ((f ^ g) & e) ^ g = CH(e,f,g)
	add	T1,   [WK_2(%%t)] ; W[t] + K[t] from message scheduler
	RORQ	tmp0, 4 ; 18      ; tmp = ((e ror 23) ^ e) ror 4
	xor	tmp0, e_64        ; tmp = (((e ror 23) ^ e) ror 4) ^ e
	mov	T2,   a_64        ; T2 = a
	add	T1,   h_64        ; T1 = CH(e,f,g) + W[t] + K[t] + h
	RORQ	tmp0, 14 ; 14     ; tmp = ((((e ror23)^e)ror4)^e)ror14 = S1(e)
	add	T1,   tmp0        ; T1 = CH(e,f,g) + W[t] + K[t] + S1(e)
	mov	tmp0, a_64        ; tmp = a
	xor	T2,   c_64        ; T2 = a ^ c
	and	tmp0, c_64        ; tmp = a & c
	and	T2,   b_64        ; T2 = (a ^ c) & b
	xor	T2,   tmp0        ; T2 = ((a ^ c) & b) ^ (a & c) = Maj(a,b,c)
	mov	tmp0, a_64        ; tmp = a
	RORQ	tmp0, 5 ; 39      ; tmp = a ror 5
	xor	tmp0, a_64        ; tmp = (a ror 5) ^ a
	add	d_64, T1          ; e(next_state) = d + T1 
	RORQ	tmp0, 6 ; 34      ; tmp = ((a ror 5) ^ a) ror 6
	xor	tmp0, a_64        ; tmp = (((a ror 5) ^ a) ror 6) ^ a
	lea	h_64, [T1 + T2]   ; a(next_state) = T1 + Maj(a,b,c)
	RORQ	tmp0, 28 ; 28     ; tmp = ((((a ror5)^a)ror6)^a)ror28 = S0(a)
	add	h_64, tmp0        ; a(next_state) = T1 + Maj(a,b,c) S0(a)
	RotateState
%endmacro

%macro SHA512_2Sched_2Round_avx 1
%assign %%t %1
	; Compute rounds %%t-2 and %%t-1
	; Compute message schedule QWORDS %%t and %%t+1

	;   Two rounds are computed based on the values for K[t-2]+W[t-2] and 
	; K[t-1]+W[t-1] which were previously stored at WK_2 by the message
	; scheduler.
	;   The two new schedule QWORDS are stored at [W_t(%%t)] and [W_t(%%t+1)].
	; They are then added to their respective SHA512 constants at
	; [K_t(%%t)] and [K_t(%%t+1)] and stored at dqword [WK_2(%%t)]
	;   For brievity, the comments following vectored instructions only refer to
	; the first of a pair of QWORDS.
	; Eg. XMM4=W[t-2] really means XMM4={W[t-2]|W[t-1]}
	;   The computation of the message schedule and the rounds are tightly
	; stitched to take advantage of instruction-level parallelism.
	; For clarity, integer instructions (for the rounds calculation) are indented
	; by one tab. Vectored instructions (for the message scheduler) are indented
	; by two tabs.

		vmovdqa	xmm4, [W_t(%%t-2)]   ; XMM4 = W[t-2]
		vmovdqu	xmm5, [W_t(%%t-15)]  ; XMM5 = W[t-15]
	mov	T1,   f_64
		vpsrlq	xmm0, xmm4, 61       ; XMM0 = W[t-2]>>61
	mov	tmp0, e_64
		vpsrlq	xmm6, xmm5, 1        ; XMM6 = W[t-15]>>1
	xor	T1,   g_64
	RORQ	tmp0, 23 ; 41
		vpsrlq	xmm1, xmm4, 19       ; XMM1 = W[t-2]>>19
	and	T1,   e_64
	xor	tmp0, e_64
		vpxor	xmm0, xmm1           ; XMM0 = W[t-2]>>61 ^ W[t-2]>>19
	xor	T1,   g_64
	add	T1,   [WK_2(%%t)];
		vpsrlq	xmm7, xmm5, 8        ; XMM7 = W[t-15]>>8
	RORQ	tmp0, 4 ; 18
		vpsrlq	xmm2, xmm4, 6        ; XMM2 = W[t-2]>>6
	xor	tmp0, e_64
	mov	T2,   a_64
	add	T1,   h_64
		vpxor	xmm6, xmm7           ; XMM6 = W[t-15]>>1 ^ W[t-15]>>8
	RORQ	tmp0, 14 ; 14
	add	T1,   tmp0
		vpsrlq	xmm8, xmm5, 7        ; XMM8 = W[t-15]>>7
	mov 	tmp0, a_64
	xor	T2,   c_64
		vpsllq	xmm3, xmm4, (64-61)  ; XMM3 = W[t-2]<<3
	and	tmp0, c_64
	and	T2,   b_64
		vpxor	xmm2, xmm3           ; XMM2 = W[t-2]>>6 ^ W[t-2]<<3
	xor	T2,   tmp0
	mov	tmp0, a_64
		vpsllq	xmm9, xmm5, (64-1)   ; XMM9 = W[t-15]<<63
	RORQ	tmp0, 5 ; 39
		vpxor	xmm8, xmm9           ; XMM8 = W[t-15]>>7 ^ W[t-15]<<63
	xor	tmp0, a_64
	add	d_64, T1
	RORQ	tmp0, 6 ; 34
	xor	tmp0, a_64
		vpxor	xmm6, xmm8           ; XMM6 = W[t-15]>>1 ^ W[t-15]>>8 ^ W[t-15]>>7 ^ W[t-15]<<63
	lea	h_64, [T1 + T2]
	RORQ 	tmp0, 28 ; 28
		vpsllq	xmm4, (64-19)        ; XMM4 = W[t-2]<<25
	add	h_64, tmp0
	RotateState
		vpxor	xmm0, xmm4           ; XMM0 = W[t-2]>>61 ^ W[t-2]>>19 ^ W[t-2]<<25
	mov	T1, f_64
		vpxor	xmm0, xmm2           ; XMM0 = s1(W[t-2])
	mov	tmp0, e_64
	xor	T1,   g_64
		vpaddq	xmm0, [W_t(%%t-16)]  ; XMM0 = s1(W[t-2]) + W[t-16]
		vmovdqu	xmm1, [W_t(%%t- 7)]  ; XMM1 = W[t-7]
	RORQ	tmp0, 23 ; 41
	and	T1,   e_64
	xor	tmp0, e_64
	xor	T1,   g_64
		vpsllq	xmm5, (64-8)         ; XMM5 = W[t-15]<<56
	add	T1,   [WK_2(%%t+1)]
		vpxor	xmm6, xmm5           ; XMM6 = s0(W[t-15])
	RORQ	tmp0, 4 ; 18
		vpaddq	xmm0, xmm6           ; XMM0 = s1(W[t-2]) + W[t-16] + s0(W[t-15])
	xor	tmp0, e_64
		vpaddq	xmm0, xmm1           ; XMM0 = W[t] = s1(W[t-2]) + W[t-7] + s0(W[t-15]) + W[t-16]
	mov	T2,   a_64
	add	T1,   h_64
	RORQ	tmp0, 14 ; 14
	add	T1,   tmp0
		vmovdqa	[W_t(%%t)], xmm0      ; Store W[t]
		vpaddq	xmm0, [K_t(t)]        ; Compute W[t]+K[t]
		vmovdqa	[WK_2(t)], xmm0       ; Store W[t]+K[t] for next rounds
	mov	tmp0, a_64
	xor	T2,   c_64
	and	tmp0, c_64
	and	T2,   b_64
	xor	T2,   tmp0
	mov	tmp0, a_64
	RORQ	tmp0, 5 ; 39
	xor	tmp0, a_64
	add	d_64, T1
	RORQ	tmp0, 6 ; 34
	xor	tmp0, a_64
	lea	h_64, [T1 + T2]
	RORQ	tmp0, 28 ; 28
	add	h_64, tmp0
	RotateState
%endmacro

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; void sha512_avx(const void* M, void* D, uint64_t L);
; Purpose: Updates the SHA512 digest stored at D with the message stored in M.
; The size of the message pointed to by M must be an integer multiple of SHA512
;   message blocks.
; L is the message length in SHA512 blocks
global sha512_avx:function
sha512_avx:
	cmp	msglen, 0
	je	.nowork
	
	; Allocate Stack Space
	sub	rsp, frame_size

	; Save GPRs
	mov	[rsp + frame.GPRSAVE + 8 * 0], rbx
	mov	[rsp + frame.GPRSAVE + 8 * 1], r12
	mov	[rsp + frame.GPRSAVE + 8 * 2], r13
	mov	[rsp + frame.GPRSAVE + 8 * 3], r14
	mov	[rsp + frame.GPRSAVE + 8 * 4], r15
%ifdef WINABI
	mov	[rsp + frame.GPRSAVE + 8 * 5], rsi
	mov	[rsp + frame.GPRSAVE + 8 * 6], rdi
%endif
	; Save XMMs
%ifdef WINABI
	vmovdqa	[rsp + frame.XMMSAVE + 16 * 0], xmm6
	vmovdqa	[rsp + frame.XMMSAVE + 16 * 1], xmm7
	vmovdqa	[rsp + frame.XMMSAVE + 16 * 2], xmm8
	vmovdqa	[rsp + frame.XMMSAVE + 16 * 3], xmm9
%endif	

.updateblock:

	; Load state variables
	mov	a_64, [DIGEST(0)]
	mov	b_64, [DIGEST(1)]
	mov	c_64, [DIGEST(2)]
	mov	d_64, [DIGEST(3)]
	mov	e_64, [DIGEST(4)]
	mov	f_64, [DIGEST(5)]
	mov	g_64, [DIGEST(6)]
	mov	h_64, [DIGEST(7)]

	%assign t 0
	%rep 80/2 + 1
	; (80 rounds) / (2 rounds/iteration) + (1 iteration)
	; +1 iteration because the scheduler leads hashing by 1 iteration
		%if t < 2
			; BSWAP 2 QWORDS
			vmovdqa	xmm1, [XMM_QWORD_BSWAP wrt rip]
			vmovdqu	xmm0, [MSG(t)]
			vpshufb	xmm0, xmm0, xmm1     ; BSWAP
			vmovdqa	[W_t(t)], xmm0       ; Store Scheduled Pair
			vpaddq	xmm0, xmm0, [K_t(t)] ; Compute W[t]+K[t]
			vmovdqa	[WK_2(t)], xmm0      ; Store into WK for rounds
		%elif t < 16
			; BSWAP 2 QWORDS, Compute 2 Rounds
			vmovdqu	xmm0, [MSG(t)]
			vpshufb	xmm0, xmm0, xmm1     ; BSWAP
			SHA512_Round t - 2           ; Round t-2
			vmovdqa	[W_t(t)], xmm0       ; Store Scheduled Pair
			vpaddq	xmm0, xmm0, [K_t(t)] ; Compute W[t]+K[t]
			SHA512_Round t - 1           ; Round t-1
			vmovdqa	[WK_2(t)], xmm0      ; W[t]+K[t] into WK
		%elif t < 79
			; Schedule 2 QWORDS; Compute 2 Rounds
			SHA512_2Sched_2Round_avx t
		%else
			; Compute 2 Rounds
			SHA512_Round t - 2
			SHA512_Round t - 1
		%endif
	%assign t t+2
	%endrep

	; Update digest
	add	[DIGEST(0)], a_64
	add	[DIGEST(1)], b_64
	add	[DIGEST(2)], c_64
	add	[DIGEST(3)], d_64
	add	[DIGEST(4)], e_64
	add	[DIGEST(5)], f_64
	add	[DIGEST(6)], g_64
	add	[DIGEST(7)], h_64

	; Advance to next message block
	add	msg, 16*8
	dec	msglen
	jnz	.updateblock

	; Restore XMMs
%ifdef WINABI
	vmovdqa	xmm6, [rsp + frame.XMMSAVE + 16 * 0]
	vmovdqa	xmm7, [rsp + frame.XMMSAVE + 16 * 1]
	vmovdqa	xmm8, [rsp + frame.XMMSAVE + 16 * 2]
	vmovdqa	xmm9, [rsp + frame.XMMSAVE + 16 * 3]
%endif
	; Restore GPRs
	mov	rbx, [rsp + frame.GPRSAVE + 8 * 0]
	mov	r12, [rsp + frame.GPRSAVE + 8 * 1]
	mov	r13, [rsp + frame.GPRSAVE + 8 * 2]
	mov	r14, [rsp + frame.GPRSAVE + 8 * 3]
	mov	r15, [rsp + frame.GPRSAVE + 8 * 4]
%ifdef WINABI
	mov	rsi, [rsp + frame.GPRSAVE + 8 * 5]
	mov	rdi, [rsp + frame.GPRSAVE + 8 * 6]
%endif
	; Restore Stack Pointer
	add	rsp, frame_size

.nowork:
	ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Binary Data

section .data

ALIGN 16

; Mask for byte-swapping a couple of qwords in an XMM register using (v)pshufb.
XMM_QWORD_BSWAP: 
	ddq 0x08090a0b0c0d0e0f0001020304050607

; K[t] used in SHA512 hashing
K512:
	dq 0x428a2f98d728ae22,0x7137449123ef65cd 
	dq 0xb5c0fbcfec4d3b2f,0xe9b5dba58189dbbc
	dq 0x3956c25bf348b538,0x59f111f1b605d019 
	dq 0x923f82a4af194f9b,0xab1c5ed5da6d8118
	dq 0xd807aa98a3030242,0x12835b0145706fbe 
	dq 0x243185be4ee4b28c,0x550c7dc3d5ffb4e2
	dq 0x72be5d74f27b896f,0x80deb1fe3b1696b1 
	dq 0x9bdc06a725c71235,0xc19bf174cf692694
	dq 0xe49b69c19ef14ad2,0xefbe4786384f25e3 
	dq 0x0fc19dc68b8cd5b5,0x240ca1cc77ac9c65
	dq 0x2de92c6f592b0275,0x4a7484aa6ea6e483 
	dq 0x5cb0a9dcbd41fbd4,0x76f988da831153b5
	dq 0x983e5152ee66dfab,0xa831c66d2db43210 
	dq 0xb00327c898fb213f,0xbf597fc7beef0ee4
	dq 0xc6e00bf33da88fc2,0xd5a79147930aa725 
	dq 0x06ca6351e003826f,0x142929670a0e6e70
	dq 0x27b70a8546d22ffc,0x2e1b21385c26c926 
	dq 0x4d2c6dfc5ac42aed,0x53380d139d95b3df
	dq 0x650a73548baf63de,0x766a0abb3c77b2a8 
	dq 0x81c2c92e47edaee6,0x92722c851482353b
	dq 0xa2bfe8a14cf10364,0xa81a664bbc423001 
	dq 0xc24b8b70d0f89791,0xc76c51a30654be30
	dq 0xd192e819d6ef5218,0xd69906245565a910 
	dq 0xf40e35855771202a,0x106aa07032bbd1b8
	dq 0x19a4c116b8d2d0c8,0x1e376c085141ab53 
	dq 0x2748774cdf8eeb99,0x34b0bcb5e19b48a8
	dq 0x391c0cb3c5c95a63,0x4ed8aa4ae3418acb 
	dq 0x5b9cca4f7763e373,0x682e6ff3d6b2b8a3
	dq 0x748f82ee5defb2fc,0x78a5636f43172f60 
	dq 0x84c87814a1f0ab72,0x8cc702081a6439ec
	dq 0x90befffa23631e28,0xa4506cebde82bde9 
	dq 0xbef9a3f7b2c67915,0xc67178f2e372532b
	dq 0xca273eceea26619c,0xd186b8c721c0c207 
	dq 0xeada7dd6cde0eb1e,0xf57d4f7fee6ed178
	dq 0x06f067aa72176fba,0x0a637dc5a2c898a6 
	dq 0x113f9804bef90dae,0x1b710b35131c471b
	dq 0x28db77f523047d84,0x32caab7b40c72493 
	dq 0x3c9ebe0a15c9bebc,0x431d67c49c100d4c
	dq 0x4cc5d4becb3e42b6,0x597f299cfc657e2a 
	dq 0x5fcb6fab3ad6faec,0x6c44198c4a475817

%ifidn __OUTPUT_FORMAT__,elf
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
%ifidn __OUTPUT_FORMAT__,elf32
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
%ifidn __OUTPUT_FORMAT__,elf64
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
