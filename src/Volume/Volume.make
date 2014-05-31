#
# Copyright (c) 2008-2010 TrueCrypt Developers Association. All rights reserved.
#
# Governed by the TrueCrypt License 3.0 the full text of which is contained in
# the file License.txt included in TrueCrypt binary and source code distribution
# packages.
#

OBJS :=
OBJS += Cipher.o
OBJS += EncryptionAlgorithm.o
OBJS += EncryptionMode.o
OBJS += EncryptionModeCBC.o
OBJS += EncryptionModeLRW.o
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

ifeq "$(CPU_ARCH)" "x86"
	OBJS += ../Crypto/Aes_x86.o
	OBJS += ../Crypto/Aes_hw_cpu.o
	ifeq "$(PLATFORM)" "MacOSX"
		OBJS += ../Crypto/Aescrypt.o
	endif
else ifeq "$(CPU_ARCH)" "x64"
	OBJS += ../Crypto/Aes_x64.o
	OBJS += ../Crypto/Aes_hw_cpu.o
else
	OBJS += ../Crypto/Aescrypt.o
endif

OBJS += ../Crypto/Aeskey.o
OBJS += ../Crypto/Aestab.o
OBJS += ../Crypto/Blowfish.o
OBJS += ../Crypto/Cast.o
OBJS += ../Crypto/Des.o
OBJS += ../Crypto/Rmd160.o
OBJS += ../Crypto/Serpent.o
OBJS += ../Crypto/Sha1.o
OBJS += ../Crypto/Sha2.o
OBJS += ../Crypto/Twofish.o
OBJS += ../Crypto/Whirlpool.o

OBJS += ../Common/Crc.o
OBJS += ../Common/Endian.o
OBJS += ../Common/GfMul.o
OBJS += ../Common/Pkcs5.o
OBJS += ../Common/SecurityToken.o

VolumeLibrary: Volume.a

include $(BUILD_INC)/Makefile.inc
