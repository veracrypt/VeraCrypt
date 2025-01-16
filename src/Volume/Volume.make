#
# Derived from source code of TrueCrypt 7.1a, which is
# Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
# by the TrueCrypt License 3.0.
#
# Modifications and additions to the original source code (contained in this file)
# and all other portions of this file are Copyright (c) 2013-2017 IDRIX
# and are governed by the Apache License 2.0 the full text of which is
# contained in the file License.txt included in VeraCrypt binary and source
# code distribution packages.
#

OBJS :=
OBJSEX :=
OBJSNOOPT :=
OBJSSSE41 :=
OBJSSSSE3 :=
OBJSHANI :=
OBJS += Cipher.o
OBJS += EncryptionAlgorithm.o
OBJS += EncryptionMode.o
OBJS += EncryptionTest.o
OBJS += EncryptionThreadPool.o
OBJS += Hash.o
OBJS += Keyfile.o
OBJS += Pkcs5Kdf.o
OBJS += Volume.o
OBJS += VolumeException.o
OBJS += VolumeHeader.o
OBJS += VolumeInfo.o
OBJS += VolumeLayout.o
OBJS += VolumePassword.o
OBJS += VolumePasswordCache.o

ifeq "$(ENABLE_WOLFCRYPT)" "0"
OBJS += EncryptionModeXTS.o
else
OBJS += EncryptionModeWolfCryptXTS.o
endif

ifeq "$(ENABLE_WOLFCRYPT)" "0"
ifeq "$(PLATFORM)" "MacOSX"
ifneq "$(COMPILE_ASM)" "false"
	OBJSEX += ../Crypto/Aes_asm.oo
	OBJS += ../Crypto/Aes_hw_cpu.o
	OBJSEX += ../Crypto/Aes_hw_armv8.oo
	OBJS += ../Crypto/Aescrypt.o
	OBJSEX += ../Crypto/Twofish_asm.oo
	OBJSEX += ../Crypto/Camellia_asm.oo
	OBJSEX += ../Crypto/Camellia_aesni_asm.oo
	OBJSEX += ../Crypto/sha256-nayuki.oo
	OBJSEX += ../Crypto/sha512-nayuki.oo
	OBJSEX += ../Crypto/sha256_avx1.oo
	OBJSEX += ../Crypto/sha256_avx2.oo
	OBJSEX += ../Crypto/sha256_sse4.oo
	OBJSEX += ../Crypto/sha512_avx1.oo
	OBJSEX += ../Crypto/sha512_avx2.oo
	OBJSEX += ../Crypto/sha512_sse4.oo
endif
else ifeq "$(CPU_ARCH)" "x86"
	OBJS += ../Crypto/Aes_x86.o
	ifeq "$(DISABLE_AESNI)" "0"
		OBJS += ../Crypto/Aes_hw_cpu.o
	endif
	OBJS += ../Crypto/sha256-x86-nayuki.o
	OBJS += ../Crypto/sha512-x86-nayuki.o
else ifeq "$(CPU_ARCH)" "x64"
	OBJS += ../Crypto/Aes_x64.o
	ifeq "$(DISABLE_AESNI)" "0"
		OBJS += ../Crypto/Aes_hw_cpu.o
	endif
	OBJS += ../Crypto/Twofish_x64.o
	OBJS += ../Crypto/Camellia_x64.o
	OBJS += ../Crypto/Camellia_aesni_x64.o
	OBJS += ../Crypto/sha512-x64-nayuki.o
	OBJS += ../Crypto/sha256_avx1_x64.o
	OBJS += ../Crypto/sha256_avx2_x64.o
	OBJS += ../Crypto/sha256_sse4_x64.o
	OBJS += ../Crypto/sha512_avx1_x64.o
	OBJS += ../Crypto/sha512_avx2_x64.o
	OBJS += ../Crypto/sha512_sse4_x64.o
else ifeq "$(CPU_ARCH)" "arm64"
	OBJARMV8CRYPTO += ../Crypto/Aes_hw_armv8.oarmv8crypto
	OBJS += ../Crypto/Aescrypt.o
else
	OBJS += ../Crypto/Aescrypt.o
endif

ifeq "$(GCC_GTEQ_430)" "1"
	OBJSSSE41 += ../Crypto/blake2s_SSE41.osse41
	OBJSSSSE3 += ../Crypto/blake2s_SSSE3.ossse3
else
	OBJS += ../Crypto/blake2s_SSE41.o
	OBJS += ../Crypto/blake2s_SSSE3.o
endif
ifeq "$(GCC_GTEQ_500)" "1"
	OBJSHANI += ../Crypto/Sha2Intel.oshani
else
	OBJS += ../Crypto/Sha2Intel.o
endif
else
OBJS += ../Crypto/wolfCrypt.o
endif

ifeq "$(ENABLE_WOLFCRYPT)" "0"
OBJS += ../Crypto/Aeskey.o
OBJS += ../Crypto/Aestab.o
OBJS += ../Crypto/blake2s.o
OBJS += ../Crypto/blake2s_SSE2.o
OBJS += ../Crypto/SerpentFast.o
OBJS += ../Crypto/SerpentFast_simd.o
OBJS += ../Crypto/Sha2.o
OBJS += ../Crypto/Twofish.o
OBJS += ../Crypto/Whirlpool.o
OBJS += ../Crypto/Camellia.o
OBJS += ../Crypto/Streebog.o
OBJS += ../Crypto/kuznyechik.o
OBJS += ../Crypto/kuznyechik_simd.o
OBJS += ../Common/Pkcs5.o
endif

OBJS += ../Crypto/cpu.o

OBJSNOOPT += ../Crypto/jitterentropy-base.o0

OBJS += ../Common/CommandAPDU.o
OBJS += ../Common/PCSCException.o
OBJS += ../Common/ResponseAPDU.o
OBJS += ../Common/SCard.o
OBJS += ../Common/SCardLoader.o
OBJS += ../Common/SCardManager.o
OBJS += ../Common/SCardReader.o
OBJS += ../Common/Token.o
OBJS += ../Common/Crc.o
OBJS += ../Common/TLVParser.o
OBJS += ../Common/EMVCard.o
OBJS += ../Common/EMVToken.o
OBJS += ../Common/Endian.o
OBJS += ../Common/GfMul.o
OBJS += ../Common/SecurityToken.o

VolumeLibrary: Volume.a

ifeq "$(ENABLE_WOLFCRYPT)" "0"
ifeq "$(PLATFORM)" "MacOSX"
ifneq "$(COMPILE_ASM)" "false"
../Crypto/Aes_hw_armv8.oo: ../Crypto/Aes_hw_armv8.c
	@echo Compiling $(<F)
	$(CC) $(CFLAGS_ARM64) -c ../Crypto/Aes_hw_armv8.c -o ../Crypto/Aes_hw_armv8_arm64.o
	$(CC) $(CFLAGS_X64) -c ../Crypto/Aes_hw_armv8.c -o ../Crypto/Aes_hw_armv8_x64.o
	lipo -create ../Crypto/Aes_hw_armv8_arm64.o ../Crypto/Aes_hw_armv8_x64.o -output ../Crypto/Aes_hw_armv8.oo
	rm -fr ../Crypto/Aes_hw_armv8_arm64.o ../Crypto/Aes_hw_armv8_x64.o
../Crypto/Aes_asm.oo: ../Crypto/Aes_x86.asm ../Crypto/Aes_x64.asm
	@echo Assembling $(<F)
	$(AS) $(ASFLAGS32) -o ../Crypto/Aes_x86.o ../Crypto/Aes_x86.asm
	$(AS) $(ASFLAGS64) -o ../Crypto/Aes_x64.o ../Crypto/Aes_x64.asm
	lipo -create ../Crypto/Aes_x86.o ../Crypto/Aes_x64.o -output ../Crypto/Aes_asm.oo
	rm -fr ../Crypto/Aes_x86.o ../Crypto/Aes_x64.o
../Crypto/Twofish_asm.oo: ../Crypto/Twofish_x64.S
	@echo Assembling $(<F)
	$(AS) $(ASFLAGS64) -p gas -o ../Crypto/Twofish_asm.oo ../Crypto/Twofish_x64.S
../Crypto/Camellia_asm.oo: ../Crypto/Camellia_x64.S
	@echo Assembling $(<F)
	$(AS) $(ASFLAGS64) -p gas -o ../Crypto/Camellia_asm.oo ../Crypto/Camellia_x64.S
../Crypto/Camellia_aesni_asm.oo: ../Crypto/Camellia_aesni_x64.S
	@echo Assembling $(<F)
	$(AS) $(ASFLAGS64) -p gas -o ../Crypto/Camellia_aesni_asm.oo ../Crypto/Camellia_aesni_x64.S
../Crypto/sha256-nayuki.oo: ../Crypto/sha256-x86-nayuki.S
	@echo Assembling $(<F)
	$(AS) $(ASFLAGS32) -p gas -o ../Crypto/sha256-x86-nayuki.o ../Crypto/sha256-x86-nayuki.S
	$(AS) $(ASFLAGS64) -p gas -o ../Crypto/sha256-x64-nayuki.o ../Crypto/sha256-x64-nayuki.S
	lipo -create ../Crypto/sha256-x86-nayuki.o ../Crypto/sha256-x64-nayuki.o -output ../Crypto/sha256-nayuki.oo
	rm -fr ../Crypto/sha256-x86-nayuki.o ../Crypto/sha256-x64-nayuki.o
../Crypto/sha256_avx1.oo: ../Crypto/sha256_avx1_x64.asm
	@echo Assembling $(<F)
	$(AS) $(ASFLAGS64) -o ../Crypto/sha256_avx1.oo ../Crypto/sha256_avx1_x64.asm
../Crypto/sha256_avx2.oo: ../Crypto/sha256_avx2_x64.asm
	@echo Assembling $(<F)
	$(AS) $(ASFLAGS64) -o ../Crypto/sha256_avx2.oo ../Crypto/sha256_avx2_x64.asm
../Crypto/sha256_sse4.oo: ../Crypto/sha256_sse4_x64.asm
	@echo Assembling $(<F)
	$(AS) $(ASFLAGS64) -o ../Crypto/sha256_sse4.oo ../Crypto/sha256_sse4_x64.asm
../Crypto/sha512-nayuki.oo: ../Crypto/sha512-x64-nayuki.S
	@echo Assembling $(<F)
	$(AS) -p gas $(ASFLAGS64) -o ../Crypto/sha512-nayuki.oo ../Crypto/sha512-x64-nayuki.S
../Crypto/sha512_avx1.oo: ../Crypto/sha512_avx1_x64.asm
	@echo Assembling $(<F)
	$(AS) $(ASFLAGS64) -o ../Crypto/sha512_avx1.oo ../Crypto/sha512_avx1_x64.asm
../Crypto/sha512_avx2.oo: ../Crypto/sha512_avx2_x64.asm
	@echo Assembling $(<F)
	$(AS) $(ASFLAGS64) -o ../Crypto/sha512_avx2.oo ../Crypto/sha512_avx2_x64.asm
../Crypto/sha512_sse4.oo: ../Crypto/sha512_sse4_x64.asm
	@echo Assembling $(<F)
	$(AS) $(ASFLAGS64) -o ../Crypto/sha512_sse4.oo ../Crypto/sha512_sse4_x64.asm
endif
endif
endif

include $(BUILD_INC)/Makefile.inc
