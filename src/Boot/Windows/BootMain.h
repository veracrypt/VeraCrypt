/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2017 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifndef TC_HEADER_Boot_BootMain
#define TC_HEADER_Boot_BootMain

#include "TCdefs.h"
#include "Platform.h"

static uint8 AskPassword (Password &password, int& pim);
static int AskSelection (const char *options[], size_t optionCount);
static bool AskYesNo (const char *message);
static uint8 BootEncryptedDrive ();
static void BootMenu ();
static void ExecuteBootSector (uint8 drive, uint8 *sectorBuffer);
static void InitScreen ();
static bool IsMenuKey (uint8 scanCode);
static bool MountVolume (uint8 drive, uint8 &exitKey);
static bool OpenVolume (uint8 drive, Password &password, CRYPTO_INFO **cryptoInfo, uint32 *headerSaltCrc32 = nullptr, bool skipNormal = false, bool skipHidden = false);
static void PrintMainMenu ();
static void RepairMenu ();

#define TC_MENU_KEY_REPAIR				TC_BIOS_KEY_F8

#endif // TC_HEADER_Boot_BootMain
