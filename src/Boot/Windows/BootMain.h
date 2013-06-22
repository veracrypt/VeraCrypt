/*
 Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
*/

#ifndef TC_HEADER_Boot_BootMain
#define TC_HEADER_Boot_BootMain

#include "TCdefs.h"
#include "Platform.h"

static byte AskPassword (Password &password);
static int AskSelection (const char *options[], size_t optionCount);
static bool AskYesNo (const char *message);
static byte BootEncryptedDrive ();
static void BootMenu ();
static void ExecuteBootSector (byte drive, byte *sectorBuffer);
static void InitScreen ();
static bool IsMenuKey (byte scanCode);
static bool MountVolume (byte drive, byte &exitKey);
static bool OpenVolume (byte drive, Password &password, CRYPTO_INFO **cryptoInfo, uint32 *headerSaltCrc32 = nullptr, bool skipNormal = false, bool skipHidden = false);
static void PrintMainMenu ();
static void RepairMenu ();

#define TC_MENU_KEY_REPAIR				TC_BIOS_KEY_F8

#endif // TC_HEADER_Boot_BootMain
