/*
 Copyright (c) 2008-2009 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Common_Wipe
#define TC_HEADER_Common_Wipe

#include "Tcdefs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
	/* WARNING: As these values are written to config files, if they or their meanings
	are changed, incompatiblity with other versions may arise (upgrade, downgrade, etc.).
	When adding a new constant, verify that the value is unique within this block. */
	TC_WIPE_NONE = 0,
	TC_WIPE_1_RAND = 100,
	TC_WIPE_3_DOD_5220 = 300,
	TC_WIPE_7_DOD_5220 = 700,
	TC_WIPE_35_GUTMANN = 3500

} WipeAlgorithmId;

#define TC_WIPE_RAND_CHAR_COUNT 3

int GetWipePassCount (WipeAlgorithmId algorithm);
BOOL WipeBuffer (WipeAlgorithmId algorithm, byte randChars[TC_WIPE_RAND_CHAR_COUNT], int pass, byte *buffer, size_t size);

#ifdef __cplusplus
}
#endif

#endif // TC_HEADER_Common_Wipe
