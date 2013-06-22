TC_ASFLAGS = -Xvc -Ox

!if "$(TC_ARCH)" == "x86"
TC_ASFLAGS = $(TC_ASFLAGS) -f win32 --prefix _ -D MS_STDCALL -D DLL_EXPORT
!else
TC_ASFLAGS = $(TC_ASFLAGS) -f win64
!endif

TC_ASM_ERR_LOG = ..\Driver\build_errors_asm.log

"$(OBJ_PATH)\$(O)\Aes_$(TC_ARCH).obj": Aes_$(TC_ARCH).asm
	nasm.exe $(TC_ASFLAGS) -o "$@" -l "$(OBJ_PATH)\$(O)\Aes_$(TC_ARCH).lst" Aes_$(TC_ARCH).asm 2>$(TC_ASM_ERR_LOG)

"$(OBJ_PATH)\$(O)\Aes_hw_cpu.obj": Aes_hw_cpu.asm
	nasm.exe $(TC_ASFLAGS) -o "$@" -l "$(OBJ_PATH)\$(O)\Aes_hw_cpu.lst" Aes_hw_cpu.asm 2>$(TC_ASM_ERR_LOG)
