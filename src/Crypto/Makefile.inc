TC_ASFLAGS = -Xvc -Ox
VC_YASMFLAGS = -Xvc -p gas -D WINABI

!if "$(TC_ARCH)" == "x86"
TC_ASFLAGS = $(TC_ASFLAGS) -f win32 --prefix _ -D MS_STDCALL -D DLL_EXPORT
VC_YASMFLAGS = $(VC_YASMFLAGS) -f win32
!else
TC_ASFLAGS = $(TC_ASFLAGS) -f win64
VC_YASMFLAGS = $(VC_YASMFLAGS) -f win64
!endif

TC_ASM_ERR_LOG = ..\Driver\build_errors_asm.log

"$(OBJ_PATH)\$(O)\gost89_$(TC_ARCH).obj": gost89_$(TC_ARCH).asm
	nasm.exe $(TC_ASFLAGS) -o "$@" -l "$(OBJ_PATH)\$(O)\gost89_$(TC_ARCH).lst" gost89_$(TC_ARCH).asm 2>$(TC_ASM_ERR_LOG)

"$(OBJ_PATH)\$(O)\Aes_$(TC_ARCH).obj": Aes_$(TC_ARCH).asm
	nasm.exe $(TC_ASFLAGS) -o "$@" -l "$(OBJ_PATH)\$(O)\Aes_$(TC_ARCH).lst" Aes_$(TC_ARCH).asm 2>$(TC_ASM_ERR_LOG)

"$(OBJ_PATH)\$(O)\Aes_hw_cpu.obj": Aes_hw_cpu.asm
	nasm.exe $(TC_ASFLAGS) -o "$@" -l "$(OBJ_PATH)\$(O)\Aes_hw_cpu.lst" Aes_hw_cpu.asm 2>$(TC_ASM_ERR_LOG)

"$(OBJ_PATH)\$(O)\Twofish_$(TC_ARCH).obj": Twofish_$(TC_ARCH).S
	yasm.exe $(VC_YASMFLAGS) -o "$@" -l "$(OBJ_PATH)\$(O)\Twofish_$(TC_ARCH).lst" Twofish_$(TC_ARCH).S 2>$(TC_ASM_ERR_LOG)
