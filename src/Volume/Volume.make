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
OBJS += Cipher.o
OBJS += EncryptionAlgorithm.o
OBJS += EncryptionMode.o
OBJS += EncryptionModeXTS.o
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

ifeq "$(PLATFORM)" "MacOSX"
    OBJSEX += ../Crypto/Aes_asm.oo
    OBJS += ../Crypto/Aes_hw_cpu.o
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
else ifeq "$(CPU_ARCH)" "x86"
	OBJS += ../Crypto/Aes_x86.o
	OBJS += ../Crypto/Aes_hw_cpu.o
	OBJS += ../Crypto/sha256-x86-nayuki.o
	OBJS += ../Crypto/sha512-x86-nayuki.o
else ifeq "$(CPU_ARCH)" "x64"
	OBJS += ../Crypto/Aes_x64.o
	OBJS += ../Crypto/Aes_hw_cpu.o
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
else
	OBJS += ../Crypto/Aescrypt.o
endif

OBJS += ../Crypto/Aeskey.o
OBJS += ../Crypto/Aestab.o
OBJS += ../Crypto/cpu.o
OBJS += ../Crypto/Rmd160.o
OBJS += ../Crypto/SerpentFast.o
OBJS += ../Crypto/SerpentFast_simd.o
OBJS += ../Crypto/Sha2.o
OBJS += ../Crypto/Twofish.o
OBJS += ../Crypto/Whirlpool.o
OBJS += ../Crypto/Camellia.o
OBJS += ../Crypto/GostCipher.o
OBJS += ../Crypto/Streebog.o
OBJS += ../Crypto/kuznyechik.o
OBJS += ../Crypto/kuznyechik_simd.o

OBJS += ../Common/Crc.o
OBJS += ../Common/Endian.o
OBJS += ../Common/GfMul.o
OBJS += ../Common/Pkcs5.o
OBJS += ../Common/SecurityToken.o

VolumeLibrary: Volume.a

ifeq "$(PLATFORM)" "MacOSX"
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

include $(BUILD_INC)/Makefile.inc
