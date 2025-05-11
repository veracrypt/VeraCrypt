#
# Derived from source code of TrueCrypt 7.1a, which is
# Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
# by the TrueCrypt License 3.0.
#
# Modifications and additions to the original source code (contained in this file)
# and all other portions of this file are Copyright (c) 2013-2017 AM Crypto
# and are governed by the Apache License 2.0 the full text of which is
# contained in the file License.txt included in VeraCrypt binary and source
# code distribution packages.
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
