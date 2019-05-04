TC_ASFLAGS = -Xvc -Ox
VC_YASMFLAGS = -Xvc -D WINABI -D __YASM__
VC_MLFLAGS = /nologo /W3 /Cx /Zi
VC_MLEXE = ml.exe

!if "$(TC_ARCH)" == "x86"
TC_ASFLAGS = $(TC_ASFLAGS) -f win32 --prefix _ -D MS_STDCALL -D DLL_EXPORT
VC_YASMFLAGS = $(VC_YASMFLAGS) -f win32 -D MS_STDCALL
VC_MLFLAGS = $(VC_MLFLAGS) /D_M_X86 /safeseh
!else
TC_ASFLAGS = $(TC_ASFLAGS) -f win64
VC_YASMFLAGS = $(VC_YASMFLAGS) -f win64
VC_MLFLAGS = $(VC_MLFLAGS) /D_M_X64
VC_MLEXE = ml64.exe
!endif

TC_ASM_ERR_LOG = ..\Driver\build_errors_asm.log

"$(OBJ_PATH)\$(O)\gost89_$(TC_ARCH).obj": gost89_$(TC_ARCH).asm
	nasm.exe $(TC_ASFLAGS) -o "$@" -l "$(OBJ_PATH)\$(O)\gost89_$(TC_ARCH).lst" gost89_$(TC_ARCH).asm 2>$(TC_ASM_ERR_LOG)

"$(OBJ_PATH)\$(O)\Aes_$(TC_ARCH).obj": Aes_$(TC_ARCH).asm
	nasm.exe $(TC_ASFLAGS) -o "$@" -l "$(OBJ_PATH)\$(O)\Aes_$(TC_ARCH).lst" Aes_$(TC_ARCH).asm 2>$(TC_ASM_ERR_LOG)

"$(OBJ_PATH)\$(O)\Aes_hw_cpu.obj": Aes_hw_cpu.asm
	nasm.exe $(TC_ASFLAGS) -o "$@" -l "$(OBJ_PATH)\$(O)\Aes_hw_cpu.lst" Aes_hw_cpu.asm 2>$(TC_ASM_ERR_LOG)

"$(OBJ_PATH)\$(O)\Twofish_$(TC_ARCH).obj": Twofish_$(TC_ARCH).S
	yasm.exe $(VC_YASMFLAGS) -p gas -o "$@" -l "$(OBJ_PATH)\$(O)\Twofish_$(TC_ARCH).lst" Twofish_$(TC_ARCH).S 2>$(TC_ASM_ERR_LOG)
	
"$(OBJ_PATH)\$(O)\Camellia_$(TC_ARCH).obj": Camellia_$(TC_ARCH).S
	yasm.exe $(VC_YASMFLAGS) -p gas -o "$@" -l "$(OBJ_PATH)\$(O)\Camellia_$(TC_ARCH).lst" Camellia_$(TC_ARCH).S 2>$(TC_ASM_ERR_LOG)
	
"$(OBJ_PATH)\$(O)\Camellia_aesni_$(TC_ARCH).obj": Camellia_aesni_$(TC_ARCH).S
	yasm.exe $(VC_YASMFLAGS) -p gas -o "$@" -l "$(OBJ_PATH)\$(O)\Camellia_aesni_$(TC_ARCH).lst" Camellia_aesni_$(TC_ARCH).S 2>$(TC_ASM_ERR_LOG)

"$(OBJ_PATH)\$(O)\sha256-$(TC_ARCH)-nayuki.obj": sha256-$(TC_ARCH)-nayuki.S
	yasm.exe $(VC_YASMFLAGS) -p gas -o "$@" -l "$(OBJ_PATH)\$(O)\sha256-$(TC_ARCH)-nayuki.lst" sha256-$(TC_ARCH)-nayuki.S 2>$(TC_ASM_ERR_LOG)

"$(OBJ_PATH)\$(O)\sha512-$(TC_ARCH)-nayuki.obj": sha512-$(TC_ARCH)-nayuki.S
	yasm.exe $(VC_YASMFLAGS) -p gas -o "$@" -l "$(OBJ_PATH)\$(O)\sha512-$(TC_ARCH)-nayuki.lst" sha512-$(TC_ARCH)-nayuki.S 2>$(TC_ASM_ERR_LOG)

"$(OBJ_PATH)\$(O)\sha512_avx1_$(TC_ARCH).obj": sha512_avx1_$(TC_ARCH).asm
	yasm.exe $(VC_YASMFLAGS) -o "$@" -l "$(OBJ_PATH)\$(O)\sha512_avx1_$(TC_ARCH).lst" sha512_avx1_$(TC_ARCH).asm 2>$(TC_ASM_ERR_LOG)

"$(OBJ_PATH)\$(O)\sha512_avx2_$(TC_ARCH).obj": sha512_avx2_$(TC_ARCH).asm
	yasm.exe $(VC_YASMFLAGS) -o "$@" -l "$(OBJ_PATH)\$(O)\sha512_avx2_$(TC_ARCH).lst" sha512_avx2_$(TC_ARCH).asm 2>$(TC_ASM_ERR_LOG)

"$(OBJ_PATH)\$(O)\sha512_sse4_$(TC_ARCH).obj": sha512_sse4_$(TC_ARCH).asm
	yasm.exe $(VC_YASMFLAGS) -o "$@" -l "$(OBJ_PATH)\$(O)\sha512_sse4_$(TC_ARCH).lst" sha512_sse4_$(TC_ARCH).asm 2>$(TC_ASM_ERR_LOG)

"$(OBJ_PATH)\$(O)\sha256_avx1_$(TC_ARCH).obj": sha256_avx1_$(TC_ARCH).asm
	yasm.exe $(VC_YASMFLAGS) -o "$@" -l "$(OBJ_PATH)\$(O)\sha256_avx1_$(TC_ARCH).lst" sha256_avx1_$(TC_ARCH).asm 2>$(TC_ASM_ERR_LOG)

"$(OBJ_PATH)\$(O)\sha256_avx2_$(TC_ARCH).obj": sha256_avx2_$(TC_ARCH).asm
	yasm.exe $(VC_YASMFLAGS) -o "$@" -l "$(OBJ_PATH)\$(O)\sha256_avx2_$(TC_ARCH).lst" sha256_avx2_$(TC_ARCH).asm 2>$(TC_ASM_ERR_LOG)

"$(OBJ_PATH)\$(O)\sha256_sse4_$(TC_ARCH).obj": sha256_sse4_$(TC_ARCH).asm
	yasm.exe $(VC_YASMFLAGS) -o "$@" -l "$(OBJ_PATH)\$(O)\sha256_sse4_$(TC_ARCH).lst" sha256_sse4_$(TC_ARCH).asm 2>$(TC_ASM_ERR_LOG)
	
"$(OBJ_PATH)\$(O)\rdrand_ml.obj": rdrand_ml.asm
	$(VC_MLEXE) $(VC_MLFLAGS) /Fo "$@" /c rdrand_ml.asm 2>$(TC_ASM_ERR_LOG)

