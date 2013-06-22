#
# Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.
#
# Governed by the TrueCrypt License 3.0 the full text of which is contained in
# the file License.txt included in TrueCrypt binary and source code distribution
# packages.
#

OBJS := Buffer.o
OBJS += Exception.o
OBJS += Event.o
OBJS += FileCommon.o
OBJS += MemoryStream.o
OBJS += Memory.o
OBJS += PlatformTest.o
OBJS += Serializable.o
OBJS += Serializer.o
OBJS += SerializerFactory.o
OBJS += StringConverter.o
OBJS += TextReader.o
OBJS += Unix/Directory.o
OBJS += Unix/File.o
OBJS += Unix/FilesystemPath.o
OBJS += Unix/Mutex.o
OBJS += Unix/Pipe.o
OBJS += Unix/Poller.o
OBJS += Unix/Process.o
OBJS += Unix/SyncEvent.o
OBJS += Unix/SystemException.o
OBJS += Unix/SystemInfo.o
OBJS += Unix/SystemLog.o
OBJS += Unix/Thread.o
OBJS += Unix/Time.o

include $(BUILD_INC)/Makefile.inc
