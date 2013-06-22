/*
 Copyright (c) 2010 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_DRIVER_DUMP_FILTER
#define TC_HEADER_DRIVER_DUMP_FILTER

#include "Tcdefs.h"
#include <ntdddump.h>

NTSTATUS DumpFilterEntry (PFILTER_EXTENSION filterExtension, PFILTER_INITIALIZATION_DATA filterInitData);
static NTSTATUS DumpFilterStart (PFILTER_EXTENSION filterExtension);
static NTSTATUS DumpFilterWrite (PFILTER_EXTENSION filterExtension, PLARGE_INTEGER diskWriteOffset, PMDL writeMdl);
static NTSTATUS DumpFilterFinish (PFILTER_EXTENSION filterExtension);
static NTSTATUS DumpFilterUnload (PFILTER_EXTENSION filterExtension);

#endif // TC_HEADER_DRIVER_DUMP_FILTER
