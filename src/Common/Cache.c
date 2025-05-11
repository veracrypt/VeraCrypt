/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of TrueCrypt 7.1a, which is
 Copyright (c) 2003-2012 TrueCrypt Developers Association and which is
 governed by the TrueCrypt License 3.0, also from the source code of
 Encryption for the Masses 2.02a, which is Copyright (c) 1998-2000 Paul Le Roux
 and which is governed by the 'License Agreement for Encryption for the Masses'
 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2025 AM Crypto
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages. */

#include "Tcdefs.h"
#include "Crypto.h"
#include "Fat.h"
#include "Volumes.h"
#include "Apidrvr.h"
#include "Common.h"
#include "Cache.h"

Password CachedPasswords[CACHE_SIZE];
int	 CachedPim[CACHE_SIZE];
int cacheEmpty = 1;
static int nPasswordIdx = 0;

uint64 VcGetPasswordEncryptionID (Password* pPassword)
{
	return ((uint64) pPassword->Text) + ((uint64) pPassword);
}

void VcProtectPassword (Password* pPassword, uint64 encID)
{
	VcProtectMemory (encID, (unsigned char*) pPassword->Text, sizeof(pPassword->Text), (unsigned char*) &pPassword->Length, sizeof (pPassword->Length));
}

void VcUnprotectPassword (Password* pPassword, uint64 encID)
{
	VcProtectPassword (pPassword, encID);
}

int ReadVolumeHeaderWCache (BOOL bBoot, BOOL bCache, BOOL bCachePim, unsigned char *header, Password *password, int pkcs5_prf, int pim, PCRYPTO_INFO *retInfo)
{
	int nReturnCode = ERR_PASSWORD_WRONG;
	int i, effectivePim;

	/* Attempt to recognize volume using mount password */
	if (password->Length > 0)
	{
		nReturnCode = ReadVolumeHeader (bBoot, header, password, pkcs5_prf, pim, retInfo, NULL);

		/* Save mount passwords back into cache if asked to do so */
		if (bCache && (nReturnCode == 0 || nReturnCode == ERR_CIPHER_INIT_WEAK_KEY))
		{
			Password tmpPass;
			for (i = 0; i < CACHE_SIZE; i++)
			{
				Password* pCurrentPassword = &CachedPasswords[i];
				if (IsRamEncryptionEnabled())
				{
					memcpy (&tmpPass, pCurrentPassword, sizeof (Password));
					VcUnprotectPassword (&tmpPass, VcGetPasswordEncryptionID (pCurrentPassword));
					pCurrentPassword = &tmpPass;
				}
				if (memcmp (pCurrentPassword, password, sizeof (Password)) == 0)
					break;
			}

			if (IsRamEncryptionEnabled())
				burn (&tmpPass, sizeof (Password));

			if (i == CACHE_SIZE)
			{
				/* Store the password */
				CachedPasswords[nPasswordIdx] = *password;
				if (IsRamEncryptionEnabled ())
					VcProtectPassword (&CachedPasswords[nPasswordIdx], VcGetPasswordEncryptionID (&CachedPasswords[nPasswordIdx]));

				/* Store also PIM if requested, otherwise set to default */
				if (bCachePim && (pim > 0))
					CachedPim[nPasswordIdx] = pim;
				else
					CachedPim[nPasswordIdx] = 0;

				/* Try another slot */
				nPasswordIdx = (nPasswordIdx + 1) % CACHE_SIZE;

				cacheEmpty = 0;
			}
			else if (bCachePim)
			{
				CachedPim[i] = pim > 0? pim : 0;
			}
		}
	}
	else if (!cacheEmpty)
	{
		Password tmpPass;
		/* Attempt to recognize volume using cached passwords */
		for (i = 0; i < CACHE_SIZE; i++)
		{
			Password* pCurrentPassword = &CachedPasswords[i];
			if (IsRamEncryptionEnabled())
			{
				memcpy (&tmpPass, pCurrentPassword, sizeof (Password));
				VcUnprotectPassword (&tmpPass, VcGetPasswordEncryptionID (pCurrentPassword));
				pCurrentPassword = &tmpPass;
			}

			if ((pCurrentPassword->Length > 0) && (pCurrentPassword->Length <= (unsigned int) ((bBoot? MAX_LEGACY_PASSWORD: MAX_PASSWORD))))
			{
				if (pim == -1)
					effectivePim = CachedPim[i];
				else
					effectivePim = pim;
				nReturnCode = ReadVolumeHeader (bBoot, header, pCurrentPassword, pkcs5_prf, effectivePim, retInfo, NULL);

				if (nReturnCode != ERR_PASSWORD_WRONG)
					break;
			}
		}

		if (IsRamEncryptionEnabled())
			burn (&tmpPass, sizeof (Password));

	}

	return nReturnCode;
}


void AddPasswordToCache (Password *password, int pim, BOOL bCachePim)
{
	Password tmpPass;
	int i;
	for (i = 0; i < CACHE_SIZE; i++)
	{
		Password* pCurrentPassword = &CachedPasswords[i];
		if (IsRamEncryptionEnabled())
		{
			memcpy (&tmpPass, pCurrentPassword, sizeof (Password));
			VcUnprotectPassword (&tmpPass, VcGetPasswordEncryptionID (pCurrentPassword));
			pCurrentPassword = &tmpPass;
		}

		if (memcmp (pCurrentPassword, password, sizeof (Password)) == 0)
			break;
	}

	if (i == CACHE_SIZE)
	{
		CachedPasswords[nPasswordIdx] = *password;
		if (IsRamEncryptionEnabled ())
			VcProtectPassword (&CachedPasswords[nPasswordIdx], VcGetPasswordEncryptionID (&CachedPasswords[nPasswordIdx]));

		/* Store also PIM if requested, otherwise set to default */
		if (bCachePim && (pim > 0))
			CachedPim[nPasswordIdx] = pim;
		else
			CachedPim[nPasswordIdx] = 0;
		nPasswordIdx = (nPasswordIdx + 1) % CACHE_SIZE;
		cacheEmpty = 0;
	}
	else if (bCachePim)
	{
		CachedPim[i] = pim > 0? pim : 0;
	}

	if (IsRamEncryptionEnabled())
		burn (&tmpPass, sizeof (Password));
}

void AddLegacyPasswordToCache (__unaligned PasswordLegacy *password, int pim)
{
	Password inputPass = {0};
	inputPass.Length = password->Length;
	memcpy (inputPass.Text, password->Text, password->Length);

	AddPasswordToCache (&inputPass, pim, TRUE);

	burn (&inputPass, sizeof (inputPass));
}

void WipeCache ()
{
	burn (CachedPasswords, sizeof (CachedPasswords));
	burn (CachedPim, sizeof (CachedPim));
	nPasswordIdx = 0;
	cacheEmpty = 1;
}
