/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of Encryption for the Masses 2.02a, which is
 Copyright (c) 1998-2000 Paul Le Roux and which is governed by the 'License
 Agreement for Encryption for the Masses'. Modifications and additions to
 the original source code (contained in this file) and all other portions
 of this file are Copyright (c) 2003-2008 TrueCrypt Developers Association
 and are governed by the TrueCrypt License 3.0 the full text of which is
 contained in the file License.txt included in TrueCrypt binary and source
 code distribution packages. */

#include "Tcdefs.h"
#include "Crypto.h"
#include "Fat.h"
#include "Volumes.h"
#include "Apidrvr.h"
#include "Common.h"
#include "Cache.h"

Password CachedPasswords[CACHE_SIZE];
int cacheEmpty = 1;
static int nPasswordIdx = 0;

int ReadVolumeHeaderWCache (BOOL bBoot, BOOL bCache, char *header, Password *password, PCRYPTO_INFO *retInfo)
{
	int nReturnCode = ERR_PASSWORD_WRONG;
	int i;

	/* Attempt to recognize volume using mount password */
	if (password->Length > 0)
	{
		nReturnCode = ReadVolumeHeader (bBoot, header, password, retInfo, NULL);

		/* Save mount passwords back into cache if asked to do so */
		if (bCache && (nReturnCode == 0 || nReturnCode == ERR_CIPHER_INIT_WEAK_KEY))
		{
			for (i = 0; i < CACHE_SIZE; i++)
			{
				if (memcmp (&CachedPasswords[i], password, sizeof (Password)) == 0)
					break;
			}

			if (i == CACHE_SIZE)
			{
				/* Store the password */
				CachedPasswords[nPasswordIdx] = *password;

				/* Try another slot */
				nPasswordIdx = (nPasswordIdx + 1) % CACHE_SIZE;

				cacheEmpty = 0;
			}
		}
	}
	else if (!cacheEmpty)
	{
		/* Attempt to recognize volume using cached passwords */
		for (i = 0; i < CACHE_SIZE; i++)
		{
			if (CachedPasswords[i].Length > 0)
			{
				nReturnCode = ReadVolumeHeader (bBoot, header, &CachedPasswords[i], retInfo, NULL);

				if (nReturnCode != ERR_PASSWORD_WRONG)
					break;
			}
		}
	}

	return nReturnCode;
}


void AddPasswordToCache (Password *password)
{
	int i;
	for (i = 0; i < CACHE_SIZE; i++)
	{
		if (memcmp (&CachedPasswords[i], password, sizeof (Password)) == 0)
			return;
	}

	CachedPasswords[nPasswordIdx] = *password;
	nPasswordIdx = (nPasswordIdx + 1) % CACHE_SIZE;
	cacheEmpty = 0;
}


void WipeCache ()
{
	burn (CachedPasswords, sizeof (CachedPasswords));
	nPasswordIdx = 0;
	cacheEmpty = 1;
}
