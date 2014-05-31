#
# Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.
#
# Governed by the TrueCrypt License 3.0 the full text of which is contained in
# the file License.txt included in TrueCrypt binary and source code distribution
# packages.
#

OBJS :=
OBJS += CoreBase.o
OBJS += CoreException.o
OBJS += FatFormatter.o
OBJS += HostDevice.o
OBJS += MountOptions.o
OBJS += RandomNumberGenerator.o
OBJS += VolumeCreator.o
OBJS += Unix/CoreService.o
OBJS += Unix/CoreServiceRequest.o
OBJS += Unix/CoreServiceResponse.o
OBJS += Unix/CoreUnix.o
OBJS += Unix/$(PLATFORM)/Core$(PLATFORM).o
OBJS += Unix/$(PLATFORM)/Core$(PLATFORM).o
ifeq "$(PLATFORM)" "MacOSX"
OBJS += Unix/FreeBSD/CoreFreeBSD.o
endif

include $(BUILD_INC)/Makefile.inc
