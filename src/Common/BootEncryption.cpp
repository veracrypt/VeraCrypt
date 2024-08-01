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

#include "Tcdefs.h"
#include "Platform/Finally.h"
#include "Platform/ForEach.h"
#include <devguid.h>
#include <io.h>
#include <shlobj.h>
#include <atlbase.h>
#include "BootEncryption.h"
#include "Boot/Windows/BootCommon.h"
#include "Common/Resource.h"
#include "Crc.h"
#include "Crypto.h"
#include "Dlgcode.h"
#include "Endian.h"
#include "Language.h"
#include "Random.h"
#include "Registry.h"
#include "Volumes.h"
#include "Xml.h"
#include "zip.h"

#ifdef VOLFORMAT
#include "Format/FormatCom.h"
#elif defined (TCMOUNT)
#include "Mount/MainCom.h"
#endif

#include <algorithm>
#include <Strsafe.h>

static unsigned char g_pbEFIDcsPK[1385] = {
	0xA1, 0x59, 0xC0, 0xA5, 0xE4, 0x94, 0xA7, 0x4A, 0x87, 0xB5, 0xAB, 0x15,
	0x5C, 0x2B, 0xF0, 0x72, 0x69, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x4D, 0x05, 0x00, 0x00, 0x85, 0xBB, 0x45, 0x82, 0xB6, 0xD2, 0xAD, 0x41,
	0x84, 0x8D, 0xDD, 0x3A, 0x83, 0x0F, 0x82, 0x78, 0x30, 0x82, 0x05, 0x39,
	0x30, 0x82, 0x03, 0x21, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x10, 0x32,
	0xDC, 0x46, 0x30, 0x87, 0xE5, 0x4F, 0xB1, 0x43, 0x0F, 0x58, 0x9E, 0xC0,
	0xDA, 0x58, 0xF8, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7,
	0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x30, 0x23, 0x31, 0x21, 0x30, 0x1F,
	0x06, 0x03, 0x55, 0x04, 0x03, 0x1E, 0x18, 0x00, 0x44, 0x00, 0x43, 0x00,
	0x53, 0x00, 0x5F, 0x00, 0x70, 0x00, 0x6C, 0x00, 0x61, 0x00, 0x74, 0x00,
	0x66, 0x00, 0x6F, 0x00, 0x72, 0x00, 0x6D, 0x30, 0x1E, 0x17, 0x0D, 0x31,
	0x36, 0x30, 0x38, 0x30, 0x39, 0x30, 0x38, 0x33, 0x38, 0x31, 0x31, 0x5A,
	0x17, 0x0D, 0x33, 0x31, 0x30, 0x38, 0x30, 0x39, 0x30, 0x38, 0x33, 0x38,
	0x31, 0x30, 0x5A, 0x30, 0x23, 0x31, 0x21, 0x30, 0x1F, 0x06, 0x03, 0x55,
	0x04, 0x03, 0x1E, 0x18, 0x00, 0x44, 0x00, 0x43, 0x00, 0x53, 0x00, 0x5F,
	0x00, 0x70, 0x00, 0x6C, 0x00, 0x61, 0x00, 0x74, 0x00, 0x66, 0x00, 0x6F,
	0x00, 0x72, 0x00, 0x6D, 0x30, 0x82, 0x02, 0x22, 0x30, 0x0D, 0x06, 0x09,
	0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03,
	0x82, 0x02, 0x0F, 0x00, 0x30, 0x82, 0x02, 0x0A, 0x02, 0x82, 0x02, 0x01,
	0x00, 0xAF, 0x5B, 0x97, 0x06, 0x70, 0x4F, 0x3B, 0x2E, 0x50, 0x6A, 0xD1,
	0x47, 0xCB, 0x70, 0x20, 0xF4, 0x77, 0x79, 0x06, 0xCA, 0xA9, 0xA2, 0x13,
	0x75, 0xAD, 0x07, 0x66, 0x94, 0xC2, 0xBB, 0xCA, 0x7E, 0xFC, 0x6C, 0x19,
	0x16, 0x5D, 0x60, 0x77, 0x6E, 0xCB, 0xF3, 0x8A, 0xC2, 0xF6, 0x53, 0xC7,
	0xC2, 0xB1, 0x87, 0x5F, 0x8E, 0xFA, 0x20, 0xDF, 0xBA, 0x00, 0xCE, 0xBA,
	0xA7, 0xC8, 0x65, 0x7E, 0xFC, 0xA8, 0xF8, 0x50, 0x9E, 0xD7, 0x7D, 0x8E,
	0x4F, 0xB1, 0x1B, 0x60, 0xC0, 0xD2, 0xBC, 0x4A, 0xB4, 0x46, 0xA5, 0x0E,
	0x90, 0x38, 0xA5, 0x7B, 0x58, 0xEE, 0x16, 0xD9, 0xBA, 0x73, 0xAD, 0x69,
	0x2A, 0xA4, 0xB4, 0x51, 0x0C, 0x21, 0x8C, 0x3D, 0x0E, 0x40, 0x44, 0x20,
	0x2E, 0xE2, 0xEF, 0x16, 0x25, 0xE8, 0x1C, 0xE8, 0xD2, 0x76, 0x66, 0x8E,
	0xA1, 0xB8, 0x29, 0x28, 0x23, 0xA2, 0x9F, 0xCA, 0xAB, 0x0D, 0x81, 0x4A,
	0xE0, 0xF9, 0x87, 0x7B, 0xD6, 0xDA, 0x2E, 0x10, 0x21, 0xBD, 0x69, 0x9C,
	0x86, 0x45, 0xD2, 0xE8, 0xCD, 0xA1, 0xF6, 0xC2, 0x09, 0x93, 0x68, 0x06,
	0xA0, 0x5D, 0xB7, 0x2C, 0xD7, 0x83, 0x0B, 0xCC, 0xFE, 0x91, 0x90, 0x1E,
	0x85, 0x96, 0x72, 0xBC, 0x3E, 0x9C, 0xD4, 0x1C, 0xDF, 0xC4, 0x85, 0xB3,
	0xD7, 0x00, 0x43, 0xDD, 0xA8, 0x7C, 0xD1, 0xDE, 0x89, 0xDB, 0x2A, 0x70,
	0x27, 0x6F, 0x46, 0xF9, 0x3A, 0x9E, 0x55, 0x10, 0x5A, 0x82, 0x42, 0x72,
	0x42, 0xEA, 0x83, 0x0F, 0x39, 0x3A, 0x50, 0x67, 0xFE, 0x4F, 0x9D, 0x91,
	0x50, 0x93, 0xB3, 0xC6, 0x12, 0x60, 0xAE, 0x3A, 0x5A, 0xB7, 0xB7, 0x9C,
	0x83, 0xA0, 0xD2, 0xFF, 0xFF, 0x23, 0xC3, 0x95, 0x66, 0x79, 0x20, 0xA0,
	0x09, 0x02, 0x74, 0x15, 0x34, 0x2A, 0x0A, 0x6E, 0x80, 0x36, 0x13, 0xC7,
	0x9B, 0x77, 0x81, 0x35, 0x45, 0xDD, 0xEC, 0x11, 0xC3, 0x43, 0xA6, 0x48,
	0xF8, 0xDB, 0xC0, 0x3C, 0x12, 0x86, 0x37, 0x68, 0xF4, 0xEA, 0x70, 0x41,
	0x66, 0x6D, 0x56, 0x7C, 0xFC, 0xE8, 0x61, 0xD7, 0x82, 0x02, 0xC6, 0xFD,
	0xA5, 0x74, 0xCE, 0xA6, 0x39, 0xFB, 0xD2, 0x21, 0x61, 0x15, 0x6B, 0x6E,
	0x0B, 0xD6, 0x65, 0xF5, 0x8C, 0x5A, 0x52, 0x5E, 0x16, 0x96, 0x02, 0x09,
	0x81, 0x28, 0x32, 0xBF, 0x2C, 0x1E, 0x0F, 0xAD, 0x1E, 0xE5, 0xAD, 0x3B,
	0x19, 0x24, 0xED, 0xC1, 0xA7, 0x60, 0xC9, 0x2D, 0xE4, 0x15, 0xA7, 0xAF,
	0x91, 0x35, 0x07, 0x5A, 0x31, 0x39, 0xB1, 0xA5, 0x3C, 0xE3, 0x59, 0x9A,
	0x85, 0xC8, 0x6F, 0x83, 0x6F, 0xFF, 0x3C, 0x81, 0xC1, 0x8F, 0xF6, 0x2E,
	0x3C, 0x1B, 0xF5, 0x9A, 0x21, 0x5D, 0xAD, 0x3A, 0x9B, 0x7F, 0x18, 0x4F,
	0x62, 0x09, 0xEA, 0x2F, 0x5D, 0x15, 0xFD, 0x9D, 0x73, 0x78, 0x95, 0x76,
	0x47, 0x15, 0x1C, 0x9A, 0x3F, 0x19, 0xB7, 0xCE, 0x03, 0x46, 0x6C, 0x61,
	0xCF, 0xC4, 0xBD, 0x0D, 0x1A, 0x9F, 0xB4, 0xAA, 0x03, 0x84, 0x8D, 0x15,
	0x3E, 0x8F, 0xBA, 0x28, 0x94, 0x09, 0x35, 0x28, 0xE5, 0x15, 0xBC, 0xAF,
	0x33, 0xBA, 0x67, 0xF2, 0x06, 0x79, 0xEE, 0x50, 0x0F, 0x14, 0x98, 0xFC,
	0x95, 0xEC, 0x65, 0x40, 0x88, 0xA8, 0x1A, 0x0C, 0x10, 0x74, 0x79, 0x42,
	0x3B, 0xCD, 0xE1, 0xD1, 0xAD, 0x7E, 0x29, 0x41, 0xC4, 0x39, 0x75, 0xC5,
	0xCB, 0x0F, 0xB1, 0x6F, 0x30, 0xD3, 0xAE, 0x53, 0x59, 0xD6, 0x86, 0x34,
	0x31, 0x8B, 0x96, 0x82, 0xDF, 0xA4, 0x01, 0x32, 0xB4, 0x29, 0xDC, 0x9C,
	0x28, 0x53, 0x72, 0xAE, 0x96, 0x37, 0xE3, 0x65, 0x59, 0x91, 0x84, 0x95,
	0xB3, 0x2D, 0x3F, 0x84, 0x12, 0xD2, 0x52, 0x85, 0x8D, 0x85, 0xD5, 0x2E,
	0x2A, 0x3E, 0xEB, 0x0C, 0x11, 0xA4, 0x4F, 0xED, 0x29, 0x02, 0x03, 0x01,
	0x00, 0x01, 0xA3, 0x69, 0x30, 0x67, 0x30, 0x0F, 0x06, 0x03, 0x55, 0x1D,
	0x13, 0x01, 0x01, 0xFF, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xFF, 0x30,
	0x54, 0x06, 0x03, 0x55, 0x1D, 0x01, 0x04, 0x4D, 0x30, 0x4B, 0x80, 0x10,
	0x8F, 0x11, 0x13, 0x21, 0xAA, 0xC0, 0xFA, 0xB1, 0x63, 0xD5, 0xE6, 0x00,
	0x9B, 0x78, 0x67, 0x40, 0xA1, 0x25, 0x30, 0x23, 0x31, 0x21, 0x30, 0x1F,
	0x06, 0x03, 0x55, 0x04, 0x03, 0x1E, 0x18, 0x00, 0x44, 0x00, 0x43, 0x00,
	0x53, 0x00, 0x5F, 0x00, 0x70, 0x00, 0x6C, 0x00, 0x61, 0x00, 0x74, 0x00,
	0x66, 0x00, 0x6F, 0x00, 0x72, 0x00, 0x6D, 0x82, 0x10, 0x32, 0xDC, 0x46,
	0x30, 0x87, 0xE5, 0x4F, 0xB1, 0x43, 0x0F, 0x58, 0x9E, 0xC0, 0xDA, 0x58,
	0xF8, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01,
	0x01, 0x0B, 0x05, 0x00, 0x03, 0x82, 0x02, 0x01, 0x00, 0x7D, 0x03, 0x2A,
	0x49, 0x7E, 0x0C, 0x43, 0x4E, 0xAE, 0x45, 0xDD, 0xE2, 0x62, 0xB2, 0x31,
	0x55, 0xEB, 0x6C, 0xF8, 0x96, 0xFC, 0x5A, 0x5F, 0xA7, 0xD2, 0x26, 0xA5,
	0x10, 0x15, 0x85, 0x1D, 0xDE, 0xCD, 0x97, 0xFB, 0x6D, 0x19, 0xED, 0x03,
	0x93, 0x83, 0x94, 0x04, 0x1B, 0xE6, 0x00, 0xBA, 0x41, 0xCF, 0xAB, 0xB7,
	0x46, 0x17, 0x3F, 0x8E, 0x3B, 0x2D, 0xC4, 0x54, 0x67, 0x31, 0x11, 0x0D,
	0xA4, 0x35, 0x1E, 0xC4, 0x09, 0xC2, 0xCB, 0xFD, 0x19, 0x1B, 0x5B, 0x2A,
	0x19, 0x6A, 0xB9, 0x72, 0x3E, 0x27, 0x8A, 0x0A, 0xBD, 0xB4, 0x68, 0x5D,
	0xA9, 0x72, 0xC7, 0x0E, 0x28, 0x06, 0xC9, 0x4C, 0xE1, 0x56, 0xEB, 0x15,
	0x16, 0xC1, 0xD2, 0x86, 0x63, 0x57, 0xB1, 0xAA, 0x01, 0xF9, 0x26, 0xBC,
	0xA7, 0xED, 0x0D, 0x02, 0x80, 0xA7, 0x77, 0x57, 0xE9, 0xA5, 0x3B, 0x72,
	0xC2, 0xAA, 0x6D, 0x7B, 0xA8, 0x40, 0xA3, 0x34, 0x7B, 0x73, 0x40, 0x90,
	0xFC, 0x43, 0x00, 0x29, 0x97, 0x7C, 0x41, 0xB2, 0xCA, 0x31, 0xA7, 0x86,
	0x08, 0xDF, 0x67, 0xCA, 0x1B, 0xEC, 0x0C, 0x53, 0xD4, 0x0B, 0x4A, 0x22,
	0x40, 0x44, 0xA8, 0xE9, 0x9D, 0x49, 0x01, 0xC6, 0x77, 0x15, 0x6E, 0x8A,
	0x1F, 0xFF, 0x42, 0xF3, 0xDE, 0xF7, 0x93, 0xFA, 0x81, 0x8F, 0x98, 0x6B,
	0x75, 0x27, 0xA8, 0xBE, 0xE9, 0x2C, 0x70, 0x0F, 0xE6, 0xA5, 0xDD, 0x5D,
	0xA5, 0x33, 0x54, 0xEE, 0xFE, 0x6F, 0x91, 0xE8, 0xB4, 0x1A, 0x55, 0x77,
	0xA1, 0x98, 0x56, 0x48, 0x9C, 0xF2, 0xA3, 0x96, 0xD7, 0xB2, 0x86, 0x15,
	0xA9, 0xCA, 0xBD, 0x04, 0x1B, 0x14, 0x11, 0xBE, 0x5D, 0xC5, 0x2C, 0x5E,
	0x5B, 0x57, 0x87, 0x9B, 0xCA, 0xE8, 0xA1, 0x7F, 0x6D, 0xED, 0x79, 0x2D,
	0x89, 0x3E, 0x70, 0x3C, 0x9E, 0x5C, 0x0F, 0x26, 0xCD, 0x2D, 0xE3, 0x47,
	0x6E, 0x89, 0x05, 0x5C, 0x73, 0x03, 0x87, 0x8C, 0x44, 0xE5, 0xC5, 0x6C,
	0x09, 0x8B, 0x93, 0xBC, 0x1E, 0x0F, 0x56, 0x80, 0x45, 0xDD, 0xDA, 0x96,
	0x01, 0x48, 0x7C, 0xD2, 0xC0, 0x86, 0xD1, 0x8D, 0x7C, 0xBF, 0x48, 0x74,
	0x97, 0x8F, 0x4A, 0xBE, 0xC2, 0x71, 0x29, 0x91, 0xCF, 0x6A, 0x39, 0xBE,
	0xD8, 0x50, 0x75, 0xCF, 0x24, 0x8D, 0x5A, 0x12, 0x16, 0xA8, 0x5C, 0x6C,
	0x88, 0x3E, 0x9F, 0x38, 0xDE, 0x04, 0x7F, 0x89, 0xE7, 0x5A, 0x36, 0x6D,
	0xAB, 0xF3, 0xC8, 0x32, 0x64, 0x91, 0x95, 0x12, 0x69, 0x7E, 0x71, 0x09,
	0xD1, 0xDA, 0xC9, 0x5E, 0xFC, 0xF4, 0x6C, 0x38, 0x71, 0x21, 0x62, 0x50,
	0xC8, 0x14, 0x47, 0x25, 0x94, 0x67, 0xD2, 0x20, 0x45, 0xC3, 0x50, 0x43,
	0x81, 0x1D, 0x56, 0xAC, 0x2A, 0x02, 0x6E, 0x6D, 0x06, 0xCA, 0x42, 0xC9,
	0x65, 0x4C, 0xF7, 0x94, 0xF7, 0x67, 0x9C, 0x24, 0x98, 0x20, 0x55, 0x6A,
	0x0D, 0x85, 0x47, 0x2F, 0x3D, 0xFC, 0xA1, 0x28, 0xFE, 0xDF, 0x6F, 0xB1,
	0x31, 0x62, 0x22, 0x8F, 0x74, 0x3E, 0x1C, 0xE0, 0x02, 0xEF, 0xF9, 0x6B,
	0x10, 0x32, 0xC5, 0xF5, 0x08, 0x51, 0xC7, 0x23, 0xE7, 0x53, 0xEA, 0x89,
	0x3A, 0xB2, 0xD9, 0x8A, 0x5E, 0xB0, 0x35, 0x06, 0x0A, 0x4F, 0xEE, 0x48,
	0x79, 0x7A, 0xEE, 0xEE, 0xAF, 0x9D, 0xF6, 0x59, 0xD6, 0x25, 0x86, 0xAC,
	0x05, 0x9D, 0xA7, 0x61, 0x31, 0xE3, 0xC1, 0xD0, 0x78, 0x9F, 0x83, 0x1F,
	0x7C, 0x17, 0x50, 0x05, 0xAD, 0x40, 0x1A, 0x0C, 0x19, 0x9E, 0xE1, 0x5D,
	0x83, 0xE2, 0xAB, 0x83, 0x17, 0x84, 0x13, 0x76, 0x4F, 0x29, 0xBC, 0xA6,
	0x3F, 0xAE, 0x0D, 0xF9, 0x79, 0x11, 0xF8, 0x04, 0x79, 0x94, 0x88, 0x3F,
	0x0D, 0x6C, 0x1F, 0x07, 0x61, 0xF6, 0x51, 0xB2, 0xBC, 0xB8, 0xD3, 0x87,
	0xA7, 0x15, 0x12, 0x60, 0x7B
};

static unsigned char g_pbEFIDcsKEK[1137] = {
	0xA1, 0x59, 0xC0, 0xA5, 0xE4, 0x94, 0xA7, 0x4A, 0x87, 0xB5, 0xAB, 0x15,
	0x5C, 0x2B, 0xF0, 0x72, 0x71, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x55, 0x04, 0x00, 0x00, 0x85, 0xBB, 0x45, 0x82, 0xB6, 0xD2, 0xAD, 0x41,
	0x84, 0x8D, 0xDD, 0x3A, 0x83, 0x0F, 0x82, 0x78, 0x30, 0x82, 0x04, 0x41,
	0x30, 0x82, 0x02, 0x29, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x10, 0x8D,
	0x64, 0x69, 0xE0, 0x25, 0x64, 0x87, 0x89, 0x4A, 0x61, 0x9F, 0xC9, 0xE4,
	0x3B, 0xE7, 0x83, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7,
	0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x30, 0x23, 0x31, 0x21, 0x30, 0x1F,
	0x06, 0x03, 0x55, 0x04, 0x03, 0x1E, 0x18, 0x00, 0x44, 0x00, 0x43, 0x00,
	0x53, 0x00, 0x5F, 0x00, 0x70, 0x00, 0x6C, 0x00, 0x61, 0x00, 0x74, 0x00,
	0x66, 0x00, 0x6F, 0x00, 0x72, 0x00, 0x6D, 0x30, 0x1E, 0x17, 0x0D, 0x31,
	0x36, 0x30, 0x38, 0x30, 0x39, 0x30, 0x38, 0x33, 0x38, 0x31, 0x32, 0x5A,
	0x17, 0x0D, 0x33, 0x31, 0x30, 0x38, 0x30, 0x39, 0x30, 0x38, 0x33, 0x38,
	0x31, 0x31, 0x5A, 0x30, 0x2B, 0x31, 0x29, 0x30, 0x27, 0x06, 0x03, 0x55,
	0x04, 0x03, 0x1E, 0x20, 0x00, 0x44, 0x00, 0x43, 0x00, 0x53, 0x00, 0x5F,
	0x00, 0x6B, 0x00, 0x65, 0x00, 0x79, 0x00, 0x5F, 0x00, 0x65, 0x00, 0x78,
	0x00, 0x63, 0x00, 0x68, 0x00, 0x6E, 0x00, 0x61, 0x00, 0x67, 0x00, 0x65,
	0x30, 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
	0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0F, 0x00,
	0x30, 0x82, 0x01, 0x0A, 0x02, 0x82, 0x01, 0x01, 0x00, 0xC7, 0x63, 0x7F,
	0xAF, 0x5D, 0x58, 0x3F, 0xE2, 0x82, 0x9B, 0xD9, 0x09, 0x88, 0x09, 0x0B,
	0x3D, 0x7C, 0x78, 0xC9, 0x6B, 0x8F, 0xDD, 0x2D, 0xE4, 0xD7, 0x4F, 0x5C,
	0x16, 0x61, 0x08, 0x7C, 0x69, 0x42, 0x63, 0xB7, 0x4F, 0xEC, 0xCD, 0xEE,
	0xA0, 0xFC, 0xF6, 0xA8, 0x80, 0x9A, 0x93, 0x8B, 0x2D, 0x67, 0xF3, 0x3F,
	0x93, 0xB7, 0xA5, 0x33, 0x2B, 0x15, 0xF7, 0x07, 0xC1, 0xCF, 0x47, 0xE5,
	0xB1, 0x9D, 0x6D, 0xF5, 0xBB, 0xC2, 0x74, 0x62, 0x10, 0x91, 0xE7, 0xCE,
	0xA3, 0x8F, 0x1B, 0xDA, 0x04, 0xF6, 0x0A, 0x56, 0x32, 0x6B, 0xBC, 0x61,
	0x24, 0x5C, 0x16, 0x8F, 0x60, 0xD8, 0x43, 0xEA, 0xF0, 0x2E, 0x0B, 0x71,
	0x07, 0x60, 0xC6, 0x41, 0xB5, 0x1B, 0xEE, 0x20, 0x3E, 0xE3, 0xAF, 0xF0,
	0xEB, 0x15, 0xE3, 0x0F, 0x49, 0x93, 0x0E, 0x65, 0x0C, 0x44, 0x26, 0x04,
	0xF8, 0x0D, 0x14, 0x43, 0x1E, 0xC2, 0x13, 0xC8, 0x79, 0x4D, 0x9A, 0xD1,
	0x99, 0xA5, 0xC3, 0x70, 0xEA, 0x98, 0xA8, 0x55, 0x9E, 0x0F, 0x8E, 0x41,
	0x1B, 0xFB, 0x32, 0x2D, 0x3D, 0x89, 0x16, 0x8B, 0x81, 0xDA, 0xB0, 0x8D,
	0xD5, 0xC4, 0x3B, 0xC5, 0xD1, 0x12, 0x0B, 0x7A, 0x40, 0xFE, 0xDA, 0x53,
	0xB9, 0xE1, 0xAE, 0xAD, 0x00, 0x00, 0xA2, 0x4A, 0x5E, 0x00, 0x31, 0x8D,
	0x4A, 0xA8, 0x05, 0x83, 0xB7, 0x80, 0x6C, 0xB9, 0x39, 0x17, 0x14, 0x01,
	0x44, 0x84, 0x9F, 0x5D, 0x60, 0x73, 0xE5, 0x9F, 0xBE, 0x09, 0x29, 0x04,
	0x49, 0xDB, 0x0B, 0xC8, 0xE4, 0x03, 0x01, 0xE8, 0xF8, 0xE8, 0x72, 0x42,
	0xE5, 0x68, 0xED, 0x03, 0xB5, 0x4B, 0xB9, 0x59, 0xCE, 0x1F, 0xBE, 0x6E,
	0x3E, 0xE6, 0xAE, 0x5C, 0x88, 0xBB, 0x0E, 0x72, 0xDA, 0xA8, 0x0D, 0x3B,
	0x23, 0x44, 0xDC, 0xC0, 0xF8, 0x4A, 0x7E, 0xB6, 0xEB, 0xF3, 0x1C, 0x20,
	0x39, 0x02, 0x03, 0x01, 0x00, 0x01, 0xA3, 0x69, 0x30, 0x67, 0x30, 0x0F,
	0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x05, 0x30, 0x03,
	0x01, 0x01, 0xFF, 0x30, 0x54, 0x06, 0x03, 0x55, 0x1D, 0x01, 0x04, 0x4D,
	0x30, 0x4B, 0x80, 0x10, 0x8F, 0x11, 0x13, 0x21, 0xAA, 0xC0, 0xFA, 0xB1,
	0x63, 0xD5, 0xE6, 0x00, 0x9B, 0x78, 0x67, 0x40, 0xA1, 0x25, 0x30, 0x23,
	0x31, 0x21, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x04, 0x03, 0x1E, 0x18, 0x00,
	0x44, 0x00, 0x43, 0x00, 0x53, 0x00, 0x5F, 0x00, 0x70, 0x00, 0x6C, 0x00,
	0x61, 0x00, 0x74, 0x00, 0x66, 0x00, 0x6F, 0x00, 0x72, 0x00, 0x6D, 0x82,
	0x10, 0x32, 0xDC, 0x46, 0x30, 0x87, 0xE5, 0x4F, 0xB1, 0x43, 0x0F, 0x58,
	0x9E, 0xC0, 0xDA, 0x58, 0xF8, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48,
	0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x03, 0x82, 0x02, 0x01,
	0x00, 0x78, 0x0F, 0xDF, 0x0C, 0x5D, 0x72, 0xE8, 0x37, 0x65, 0xDF, 0xC1,
	0x23, 0x2C, 0x01, 0x03, 0xA8, 0x96, 0x15, 0xD5, 0xC4, 0xF9, 0x12, 0x83,
	0xF0, 0x5C, 0x5B, 0xD4, 0xF5, 0x9E, 0xF4, 0x0A, 0xAF, 0x2C, 0x31, 0x7E,
	0xE2, 0x34, 0x31, 0x66, 0x47, 0xE7, 0x3C, 0x77, 0x28, 0x0A, 0x7B, 0x33,
	0x53, 0xBC, 0x92, 0x26, 0xE7, 0xD8, 0xE8, 0x90, 0xDC, 0xC1, 0x30, 0x31,
	0xCC, 0x7F, 0xF9, 0x52, 0xAC, 0x9F, 0x3E, 0x1A, 0xCB, 0x56, 0xF7, 0xA3,
	0x45, 0x9F, 0x3C, 0xA9, 0xB1, 0x03, 0xFC, 0x63, 0xDF, 0xE1, 0x9E, 0x94,
	0x0A, 0x07, 0x9B, 0xB3, 0x6A, 0x74, 0x12, 0x2F, 0xC7, 0xBD, 0x29, 0x5F,
	0x03, 0xB7, 0xFA, 0xA8, 0x25, 0xD1, 0x08, 0x57, 0xE5, 0x25, 0xD8, 0xA1,
	0x5A, 0xDD, 0x3D, 0xFB, 0x0E, 0x83, 0xBF, 0x5F, 0xA0, 0xFD, 0x0B, 0x2F,
	0xE1, 0x9E, 0xF6, 0x5E, 0x2B, 0xF0, 0xC5, 0x1C, 0x72, 0x8B, 0x53, 0x34,
	0x28, 0x8F, 0x02, 0xD2, 0xD3, 0x7B, 0x0C, 0x2C, 0xC2, 0x55, 0x28, 0xBD,
	0xFB, 0xD2, 0x4C, 0x8A, 0xD6, 0x33, 0x88, 0x54, 0xE7, 0x25, 0x5F, 0x31,
	0x59, 0x9E, 0x61, 0x3E, 0xC4, 0x9B, 0xF7, 0x09, 0x3C, 0xC6, 0xAD, 0xD0,
	0xD5, 0x65, 0x63, 0x6C, 0x91, 0xA0, 0x66, 0xBA, 0x58, 0x04, 0x6E, 0x26,
	0x31, 0x2F, 0xBB, 0x11, 0xEF, 0x4D, 0xAA, 0xF8, 0x5E, 0xA6, 0x25, 0xD9,
	0x18, 0x75, 0xB0, 0x1F, 0xBF, 0xEA, 0x7F, 0x4D, 0x56, 0x63, 0x4B, 0x86,
	0x8B, 0x5E, 0xFA, 0xAD, 0x47, 0xE7, 0xC5, 0xB2, 0x06, 0xE7, 0x2B, 0x99,
	0x40, 0x2A, 0x4E, 0xFF, 0xE0, 0xDE, 0x07, 0xDE, 0x5D, 0x62, 0x79, 0xE8,
	0xC8, 0x03, 0x26, 0x23, 0x1D, 0x6B, 0xE1, 0x45, 0x11, 0xE8, 0x8B, 0x8B,
	0xF1, 0x08, 0x37, 0x8F, 0xED, 0xB6, 0xE5, 0xAE, 0xE6, 0x28, 0x3F, 0x03,
	0x69, 0x09, 0x3E, 0xAE, 0x63, 0xDE, 0x46, 0x86, 0xCF, 0x28, 0x3E, 0x09,
	0x50, 0xE2, 0x5C, 0x4F, 0x97, 0x4A, 0xAF, 0x24, 0x73, 0xEC, 0xDD, 0xEE,
	0x3D, 0xE8, 0xCD, 0xBC, 0xD7, 0x4B, 0x9F, 0x30, 0x7D, 0xC3, 0x9B, 0xE1,
	0x76, 0xD5, 0x43, 0xBD, 0x56, 0xCB, 0x52, 0x38, 0x0A, 0x12, 0xDD, 0x79,
	0x46, 0xB3, 0x56, 0x25, 0x10, 0x37, 0x75, 0x01, 0x13, 0xF4, 0x43, 0xE6,
	0x7D, 0x63, 0xCA, 0x11, 0xE1, 0xD0, 0xE0, 0x45, 0x4F, 0x55, 0x2C, 0xD0,
	0xDE, 0x9F, 0x93, 0x7B, 0x62, 0xE3, 0x1E, 0x9B, 0x27, 0xCA, 0x0A, 0xAE,
	0x6D, 0x5A, 0xAC, 0x1A, 0xC7, 0xB5, 0x10, 0xEE, 0x17, 0x42, 0xA3, 0xE4,
	0xED, 0x16, 0x27, 0x3F, 0x46, 0xB3, 0x33, 0x83, 0x5B, 0xE7, 0x86, 0xB6,
	0xCB, 0xB5, 0xB8, 0x5F, 0x2B, 0x4B, 0x36, 0xEC, 0xEF, 0x41, 0xB5, 0x05,
	0x0C, 0xF7, 0x0F, 0xD2, 0x05, 0xE0, 0x20, 0x56, 0x29, 0xC1, 0x43, 0x11,
	0x93, 0x62, 0xD3, 0x1D, 0xE5, 0x07, 0x27, 0x26, 0xE3, 0x62, 0x46, 0x1E,
	0x0D, 0xC3, 0x9F, 0xEA, 0x37, 0x7B, 0xCB, 0xC3, 0x65, 0x8D, 0x71, 0xBA,
	0x97, 0xA8, 0x4F, 0x69, 0x25, 0x36, 0x1D, 0x7F, 0x08, 0x54, 0xB2, 0x9A,
	0x56, 0xA0, 0x8B, 0x2F, 0xBC, 0x77, 0x16, 0x89, 0xBF, 0x5C, 0xB0, 0xD2,
	0xB1, 0xDA, 0x3C, 0x08, 0xD1, 0x8A, 0xC5, 0xB5, 0xA0, 0xED, 0xD1, 0xDF,
	0xB1, 0xAE, 0x5F, 0x82, 0x26, 0xA4, 0x0A, 0x12, 0x1E, 0x1F, 0x18, 0x7D,
	0x9E, 0x57, 0xE1, 0xA4, 0xCC, 0x90, 0x15, 0x79, 0xC9, 0x19, 0x95, 0x98,
	0xCB, 0x86, 0x75, 0xC1, 0x45, 0x67, 0xD8, 0x1D, 0x02, 0x84, 0xC6, 0xF3,
	0x50, 0xD7, 0xB8, 0xAB, 0x92, 0xD2, 0x4E, 0xFB, 0xA0, 0xFF, 0x28, 0xB5,
	0x69, 0x17, 0xFD, 0xA9, 0x18, 0x07, 0xAB, 0xD3, 0xCD, 0x3A, 0xE7, 0xE7,
	0x54, 0x61, 0x6B, 0x73, 0x88, 0xF0, 0xD9, 0xB9, 0xD6
};



bool ZipAdd (zip_t *z, const char* name, const unsigned char* pbData, DWORD cbData)
{
	zip_error_t zerr;
	zip_source_t* zin = zip_source_buffer_create (pbData, cbData, 0, &zerr);
	if (!zin)
		return false;

	if (-1 == zip_file_add (z, name, zin, 0))
	{
		zip_source_free (zin);
		return false;
	}

	return true;
}

static BOOL IsWindowsMBR (const uint8 *buffer, size_t bufferSize)
{
	BOOL bRet = FALSE;
	uint8 g_pbMsSignature[4] = {0x33, 0xc0, 0x8e, 0xd0};
	const char* g_szStr1 = "Invalid partition table";
	const char* g_szStr2 = "Error loading operating system";
	const char* g_szStr3 = "Missing operating system";

	if ((0 == memcmp (buffer, g_pbMsSignature, 4)) &&
		(BufferContainsString (buffer, bufferSize, g_szStr1) 
		|| BufferContainsString (buffer, bufferSize, g_szStr2) 
		|| BufferContainsString (buffer, bufferSize, g_szStr3)
		)
		)
	{
		bRet = TRUE;
	}

	return bRet;
}

namespace VeraCrypt
{
#if !defined (SETUP)

	class Elevator
	{
	public:
		
		static void AddReference ()
		{
			++ReferenceCount;
		}


		static void CallDriver (DWORD ioctl, void *input, DWORD inputSize, void *output, DWORD outputSize)
		{
			Elevate();

			CComBSTR inputBstr;
			if (input && inputBstr.AppendBytes ((const char *) input, inputSize) != S_OK)
				throw ParameterIncorrect (SRC_POS);

			CComBSTR outputBstr;
			if (output && outputBstr.AppendBytes ((const char *) output, outputSize) != S_OK)
				throw ParameterIncorrect (SRC_POS);

			DWORD result = ElevatedComInstance->CallDriver (ioctl, inputBstr, &outputBstr);

			if (output)
				memcpy (output, *(void **) &outputBstr, outputSize);

			if (result != ERROR_SUCCESS)
			{
				SetLastError (result);
				throw SystemException(SRC_POS);
			}
		}

		static void CopyFile (const wstring &sourceFile, const wstring &destinationFile)
		{
			Elevate();
			DWORD result;
			CComBSTR sourceFileBstr, destinationFileBstr;
			BSTR bstr = W2BSTR(sourceFile.c_str());
			if (bstr)
			{
				sourceFileBstr.Attach (bstr);

				bstr = W2BSTR(destinationFile.c_str());
				if (bstr)
				{
					destinationFileBstr.Attach (bstr);
					result = ElevatedComInstance->CopyFile (sourceFileBstr, destinationFileBstr);
				}
				else
				{
					result = ERROR_OUTOFMEMORY;
				}
			}
			else
			{
				result = ERROR_OUTOFMEMORY;
			}

			if (result != ERROR_SUCCESS)
			{
				SetLastError (result);
				throw SystemException(SRC_POS);
			}
		}

		static void DeleteFile (const wstring &file)
		{
			Elevate();
			CComBSTR fileBstr;
			DWORD result;
			BSTR bstr = W2BSTR(file.c_str());
			if (bstr)
			{
				fileBstr.Attach (bstr);
				result = ElevatedComInstance->DeleteFile (fileBstr);
			}
			else
			{
				result = ERROR_OUTOFMEMORY;
			}

			if (result != ERROR_SUCCESS)
			{
				SetLastError (result);
				throw SystemException(SRC_POS);
			}
		}

		static void ReadWriteFile (BOOL write, BOOL device, const wstring &filePath, uint8 *buffer, uint64 offset, uint32 size, DWORD *sizeDone)
		{
			Elevate();

			DWORD result;
			CComBSTR bufferBstr, fileBstr;
			if (bufferBstr.AppendBytes ((const char *) buffer, size) != S_OK)
				throw ParameterIncorrect (SRC_POS);
			BSTR bstr = W2BSTR(filePath.c_str());
			if (bstr)
			{
				fileBstr.Attach (bstr);
				result = ElevatedComInstance->ReadWriteFile (write, device, fileBstr, &bufferBstr, offset, size, sizeDone);
			}
			else
			{
				result = ERROR_OUTOFMEMORY;
			}

			if (result != ERROR_SUCCESS)
			{
				SetLastError (result);
				throw SystemException(SRC_POS);
			}

			if (!write)
				memcpy (buffer, (BYTE *) bufferBstr.m_str, size);
		}

		static void GetFileSize (const wstring &filePath, unsigned __int64* pSize)
		{
			Elevate();

			DWORD result;
			CComBSTR fileBstr;
			BSTR bstr = W2BSTR(filePath.c_str());
			if (bstr)
			{
				fileBstr.Attach (bstr);
				result = ElevatedComInstance->GetFileSize (fileBstr, pSize);
			}
			else
			{
				result = ERROR_OUTOFMEMORY;
			}

			if (result != ERROR_SUCCESS)
			{
				SetLastError (result);
				throw SystemException(SRC_POS);
			}
		}

		static BOOL DeviceIoControl (BOOL readOnly, BOOL device, const wstring &filePath, DWORD dwIoControlCode, LPVOID input, DWORD inputSize, 
												LPVOID output, DWORD outputSize)
		{
			Elevate();

			DWORD result;

			BSTR bstr = W2BSTR(filePath.c_str());
			if (bstr)
			{
				CComBSTR inputBstr;
				CComBSTR fileBstr;
				fileBstr.Attach (bstr);

				if (input && inputBstr.AppendBytes ((const char *) input, inputSize) != S_OK)
				{
					SetLastError (ERROR_INVALID_PARAMETER);
					return FALSE;
				}

				CComBSTR outputBstr;
				if (output && outputBstr.AppendBytes ((const char *) output, outputSize) != S_OK)
				{
					SetLastError (ERROR_INVALID_PARAMETER);
					return FALSE;
				}

				result = ElevatedComInstance->DeviceIoControl (readOnly, device, fileBstr, dwIoControlCode, inputBstr, &outputBstr);

				if (output)
					memcpy (output, *(void **) &outputBstr, outputSize);
			}
			else
			{
				result = ERROR_OUTOFMEMORY;
			}

			if (result != ERROR_SUCCESS)
			{
				SetLastError (result);
				return FALSE;
			}
			else
				return TRUE;
		}

		static BOOL IsPagingFileActive (BOOL checkNonWindowsPartitionsOnly)
		{
			Elevate();

			return ElevatedComInstance->IsPagingFileActive (checkNonWindowsPartitionsOnly);
		}

		static void WriteLocalMachineRegistryDwordValue (wchar_t *keyPath, wchar_t *valueName, DWORD value)
		{
			Elevate();
			DWORD result;
			CComBSTR keyPathBstr, valueNameBstr;
			BSTR bstr = W2BSTR(keyPath);
			if (bstr)
			{
				keyPathBstr.Attach (bstr);

				bstr = W2BSTR(valueName);
				if (bstr)
				{
					valueNameBstr.Attach (bstr);

					result = ElevatedComInstance->WriteLocalMachineRegistryDwordValue (keyPathBstr, valueNameBstr, value);
				}
				else
				{
					result = ERROR_OUTOFMEMORY;
				}
			}
			else
			{
				result = ERROR_OUTOFMEMORY;
			}

			if (result != ERROR_SUCCESS)
			{
				SetLastError (result);
				throw SystemException(SRC_POS);
			}
		}

		static void RegisterFilterDriver (bool registerDriver, BootEncryption::FilterType filterType)
		{
			Elevate();

			DWORD result = ElevatedComInstance->RegisterFilterDriver (registerDriver ? TRUE : FALSE, filterType);
			if (result != ERROR_SUCCESS)
			{
				SetLastError (result);
				throw SystemException(SRC_POS);
			}
		}

		static void RegisterSystemFavoritesService (BOOL registerService)
		{
			Elevate();

			DWORD result = ElevatedComInstance->RegisterSystemFavoritesService (registerService);
			if (result != ERROR_SUCCESS)
			{
				SetLastError (result);
				throw SystemException(SRC_POS);
			}
		}

		static void InstallEfiBootLoader (bool preserveUserConfig, bool hiddenOSCreation, int pim, int hashAlg)
		{
			Elevate();

			DWORD result = ElevatedComInstance->InstallEfiBootLoader (preserveUserConfig ? TRUE : FALSE, hiddenOSCreation ? TRUE : FALSE, pim, hashAlg);
			if (result != ERROR_SUCCESS)
			{
				SetLastError (result);
				throw SystemException(SRC_POS);
			}
		}

		static void BackupEfiSystemLoader ()
		{
			Elevate();

			DWORD result = ElevatedComInstance->BackupEfiSystemLoader ();
			if (result != ERROR_SUCCESS)
			{
				if (result == ERROR_CANCELLED)
					throw UserAbort (SRC_POS);
				else
				{
					SetLastError (result);
					throw SystemException(SRC_POS);
				}
			}
		}

		static void RestoreEfiSystemLoader ()
		{
			Elevate();

			DWORD result = ElevatedComInstance->RestoreEfiSystemLoader ();
			if (result != ERROR_SUCCESS)
			{
				SetLastError (result);
				throw SystemException(SRC_POS);
			}
		}

		static void GetEfiBootDeviceNumber (PSTORAGE_DEVICE_NUMBER pSdn)
		{
			Elevate();

			CComBSTR outputBstr;
			if (pSdn && outputBstr.AppendBytes ((const char *) pSdn, sizeof (STORAGE_DEVICE_NUMBER)) != S_OK)
			{
				SetLastError (ERROR_INVALID_PARAMETER);
				throw SystemException(SRC_POS);
			}

			DWORD result = ElevatedComInstance->GetEfiBootDeviceNumber (&outputBstr);

			if (pSdn)
				memcpy (pSdn, *(void **) &outputBstr, sizeof (STORAGE_DEVICE_NUMBER));

			if (result != ERROR_SUCCESS)
			{
				SetLastError (result);
				throw SystemException(SRC_POS);
			}
		}

		static void GetSecureBootConfig (BOOL* pSecureBootEnabled, BOOL *pVeraCryptKeysLoaded)
		{
			Elevate();

			DWORD result = ElevatedComInstance->GetSecureBootConfig (pSecureBootEnabled, pVeraCryptKeysLoaded);

			if (result != ERROR_SUCCESS)
			{
				SetLastError (result);
				throw SystemException(SRC_POS);
			}
		}

		static void WriteEfiBootSectorUserConfig (uint8 userConfig, const string &customUserMessage, int pim, int hashAlg)
		{
			Elevate();

			DWORD result;
			CComBSTR customUserMessageBstr;
			BSTR bstr = A2BSTR(customUserMessage.c_str());
			if (bstr)
			{
				customUserMessageBstr.Attach (bstr);
				result = ElevatedComInstance->WriteEfiBootSectorUserConfig ((DWORD) userConfig, customUserMessageBstr, pim, hashAlg);
			}
			else
			{
				result = ERROR_OUTOFMEMORY;
			}

			if (result != ERROR_SUCCESS)
			{
				SetLastError (result);
				throw SystemException(SRC_POS);
			}
		}

		static void UpdateSetupConfigFile (bool bForInstall)
		{
			Elevate();

			DWORD result = ElevatedComInstance->UpdateSetupConfigFile (bForInstall ? TRUE : FALSE);
			if (result != ERROR_SUCCESS)
			{
				SetLastError (result);
				throw SystemException(SRC_POS);
			}
		}

		static void NotifyService (DWORD dwNotifyCmd)
		{
			Elevate();

			DWORD result = ElevatedComInstance->NotifyService (dwNotifyCmd);
			if (result != ERROR_SUCCESS)
			{
				SetLastError (result);
				throw SystemException(SRC_POS);
			}
		}

		static void Release ()
		{
			if (--ReferenceCount == 0 && ElevatedComInstance)
			{
				ElevatedComInstance->Release();
				ElevatedComInstance = nullptr;
				CoUninitialize ();
			}
		}

		static void SetDriverServiceStartType (DWORD startType)
		{
			Elevate();

			DWORD result = ElevatedComInstance->SetDriverServiceStartType (startType);
			if (result != ERROR_SUCCESS)
			{
				SetLastError (result);
				throw SystemException(SRC_POS);
			}
		}

	protected:
		static void Elevate ()
		{
			if (IsAdmin())
			{
				SetLastError (ERROR_ACCESS_DENIED);
				throw SystemException(SRC_POS);
			}

			if (!ElevatedComInstance || ElevatedComInstanceThreadId != GetCurrentThreadId())
			{
				CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
				ElevatedComInstance = GetElevatedInstance (GetActiveWindow() ? GetActiveWindow() : MainDlg);
				ElevatedComInstanceThreadId = GetCurrentThreadId();
			}
		}

#if defined (TCMOUNT)
		static ITrueCryptMainCom *ElevatedComInstance;
#elif defined (VOLFORMAT)
		static ITrueCryptFormatCom *ElevatedComInstance;
#endif
		static DWORD ElevatedComInstanceThreadId;
		static int ReferenceCount;
	};

#if defined (TCMOUNT)
	ITrueCryptMainCom *Elevator::ElevatedComInstance;
#elif defined (VOLFORMAT)
	ITrueCryptFormatCom *Elevator::ElevatedComInstance;
#endif
	DWORD Elevator::ElevatedComInstanceThreadId;
	int Elevator::ReferenceCount = 0;

#else // SETUP

	class Elevator
	{
	public:
		static void AddReference () { }
		static void CallDriver (DWORD ioctl, void *input, DWORD inputSize, void *output, DWORD outputSize) { throw ParameterIncorrect (SRC_POS); }
		static void ReadWriteFile (BOOL write, BOOL device, const wstring &filePath, uint8 *buffer, uint64 offset, uint32 size, DWORD *sizeDone) { throw ParameterIncorrect (SRC_POS); }
		static void RegisterFilterDriver (bool registerDriver, BootEncryption::FilterType filterType) { throw ParameterIncorrect (SRC_POS); }
		static void Release () { }
		static void SetDriverServiceStartType (DWORD startType) { throw ParameterIncorrect (SRC_POS); }
		static void GetFileSize (const wstring &filePath, unsigned __int64 *pSize) { throw ParameterIncorrect (SRC_POS); }
		static BOOL DeviceIoControl (BOOL readOnly, BOOL device, const wstring &filePath, DWORD dwIoControlCode, LPVOID input, DWORD inputSize, LPVOID output, DWORD outputSize) { throw ParameterIncorrect (SRC_POS); }
		static void InstallEfiBootLoader (bool preserveUserConfig, bool hiddenOSCreation, int pim, int hashAlg) { throw ParameterIncorrect (SRC_POS); }
		static void BackupEfiSystemLoader () { throw ParameterIncorrect (SRC_POS); }
		static void RestoreEfiSystemLoader () { throw ParameterIncorrect (SRC_POS); }
		static void GetEfiBootDeviceNumber (PSTORAGE_DEVICE_NUMBER pSdn) { throw ParameterIncorrect (SRC_POS); }
		static void WriteEfiBootSectorUserConfig (uint8 userConfig, const string &customUserMessage, int pim, int hashAlg) { throw ParameterIncorrect (SRC_POS); }
		static void UpdateSetupConfigFile (bool bForInstall) { throw ParameterIncorrect (SRC_POS); }
		static void GetSecureBootConfig (BOOL* pSecureBootEnabled, BOOL *pVeraCryptKeysLoaded) { throw ParameterIncorrect (SRC_POS); }
	};

#endif // SETUP

	File::File (wstring path, bool readOnly, bool create) : Elevated (false), FileOpen (false), ReadOnly (readOnly), LastError(0)
	{
		Handle = CreateFile (path.c_str(),
			readOnly ? GENERIC_READ : GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, create ? CREATE_ALWAYS : OPEN_EXISTING,
			FILE_FLAG_RANDOM_ACCESS | FILE_FLAG_WRITE_THROUGH, NULL);

		if (Handle != INVALID_HANDLE_VALUE)
		{
			FileOpen = true;
		}
		else
		{
			LastError = GetLastError();
			if (LastError == ERROR_ACCESS_DENIED && IsUacSupported())
			{
				Elevated = true;
				FileOpen = true;
			}
		}

		FilePointerPosition = 0;
		IsDevice = false;
		Path = path;
	}

	void File::Close ()
	{
		if (Handle != INVALID_HANDLE_VALUE)
		{
			CloseHandle (Handle);
			Handle = INVALID_HANDLE_VALUE;
		}

		FileOpen = false;
	}

	DWORD File::Read (uint8 *buffer, DWORD size)
	{
		DWORD bytesRead;

		if (!FileOpen)
		{
			SetLastError (LastError);
			throw SystemException (SRC_POS);
		}

		if (Elevated)
		{
			Elevator::ReadWriteFile (false, IsDevice, Path, buffer, FilePointerPosition, size, &bytesRead);
			FilePointerPosition += bytesRead;
			return bytesRead;
		}

		if (!ReadFile (Handle, buffer, size, &bytesRead, NULL))
		{
			DWORD dwLastError = GetLastError();
			if ((dwLastError == ERROR_INVALID_PARAMETER) && IsDevice && (size % 4096))
			{					
				DWORD remainingSize = (size % 4096);
				DWORD alignedSize = size - remainingSize;
				LARGE_INTEGER offset;

				if (alignedSize)
				{
					if (ReadFile (Handle, buffer, alignedSize, &bytesRead, NULL))
					{
						if (bytesRead < alignedSize)
							return bytesRead;

						buffer += alignedSize;
						size -= alignedSize;
					}
					else
						throw SystemException (SRC_POS);
				}


				if (ReadFile (Handle, ReadBuffer, 4096, &bytesRead, NULL))
				{
					DWORD effectiveSize = min (bytesRead, remainingSize);					
					memcpy (buffer, ReadBuffer, effectiveSize);
					offset.QuadPart = - ((LONGLONG) bytesRead) + (LONGLONG) effectiveSize;
					throw_sys_if (!SetFilePointerEx (Handle, offset, NULL, FILE_CURRENT));
					return alignedSize + effectiveSize;
				}
				else
					throw SystemException (SRC_POS);
			}
			else
				throw SystemException (SRC_POS);
		}

		return bytesRead;
	}

	void File::SeekAt (int64 position)
	{
		if (!FileOpen)
		{
			SetLastError (LastError);
			throw SystemException (SRC_POS);
		}

		FilePointerPosition = position;

		if (!Elevated)
		{
			LARGE_INTEGER pos;
			pos.QuadPart = position;
			throw_sys_if (!SetFilePointerEx (Handle, pos, NULL, FILE_BEGIN));
		}
	}

	void File::GetFileSize (unsigned __int64& size)
	{
		if (!FileOpen)
		{
			SetLastError (LastError);
			throw SystemException (SRC_POS);
		}

		if (Elevated)
		{
			Elevator::GetFileSize (Path, &size);
		}
		else
		{
			LARGE_INTEGER lSize;
			lSize.QuadPart = 0;
			throw_sys_if (!GetFileSizeEx (Handle, &lSize));
			size = (unsigned __int64) lSize.QuadPart;
		}
	}

	void File::GetFileSize (DWORD& dwSize)
	{
		unsigned __int64 size64;
		GetFileSize (size64);
		dwSize = (DWORD) size64;
	}

	void File::Write (uint8 *buffer, DWORD size)
	{
		DWORD bytesWritten;

		if (!FileOpen)
		{
			SetLastError (LastError);
			throw SystemException (SRC_POS);
		}

		try
		{
			if (Elevated)
			{
				Elevator::ReadWriteFile (true, IsDevice, Path, buffer, FilePointerPosition, size, &bytesWritten);
				FilePointerPosition += bytesWritten;
				throw_sys_if (bytesWritten != size);
			}
			else
			{
				if (!WriteFile (Handle, buffer, size, &bytesWritten, NULL))
				{
					DWORD dwLastError = GetLastError ();
					if ((ERROR_INVALID_PARAMETER == dwLastError) && IsDevice && !ReadOnly && (size % 4096))
					{
						bool bSuccess = false;						
						DWORD remainingSize = (size % 4096);
						DWORD alignedSize = size - remainingSize;
						DWORD bytesRead = 0;
						bytesWritten = 0;
						if (alignedSize)
						{
							if (WriteFile (Handle, buffer, alignedSize, &bytesWritten, NULL))
							{
								throw_sys_if (bytesWritten != alignedSize);
								buffer += alignedSize;
								size -= alignedSize;
							}
							else
							{
								bytesWritten = 0;
								dwLastError = GetLastError ();
							}
						}

						if (!alignedSize || (alignedSize && bytesWritten))
						{
							LARGE_INTEGER offset;

							throw_sys_if (!ReadFile (Handle, ReadBuffer, 4096, &bytesRead, NULL) || (bytesRead != 4096));
							offset.QuadPart = -4096;
							throw_sys_if (!SetFilePointerEx (Handle, offset, NULL, FILE_CURRENT));

							memcpy (ReadBuffer, buffer, remainingSize);

							if (WriteFile (Handle, ReadBuffer, 4096, &bytesWritten, NULL))
							{
								throw_sys_if (bytesWritten != 4096);
								bSuccess = true;
							}
							else
							{
								dwLastError = GetLastError ();
							}
						}

						if (!bSuccess)
						{
							SetLastError (dwLastError);
							throw SystemException (SRC_POS);
						}
					}
					else
						throw SystemException (SRC_POS);
				}
				else
					throw_sys_if (bytesWritten != size);				
			}
		}
		catch (SystemException &e)
		{
			if (!IsDevice || e.ErrorCode != ERROR_WRITE_PROTECT)
				throw;

			BootEncryption bootEnc (NULL);

			while (size >= TC_SECTOR_SIZE_BIOS)
			{
				bootEnc.WriteBootDriveSector (FilePointerPosition, buffer);

				FilePointerPosition += TC_SECTOR_SIZE_BIOS;
				buffer += TC_SECTOR_SIZE_BIOS;
				size -= TC_SECTOR_SIZE_BIOS;
			}
		}
	}

	bool File::IoCtl(DWORD code, void* inBuf, DWORD inBufSize, void* outBuf, DWORD outBufSize)
	{
		if (!FileOpen)
		{
			SetLastError (LastError);
			throw SystemException (SRC_POS);
		}

		if (Elevated)
		{
			return TRUE == Elevator::DeviceIoControl (ReadOnly, IsDevice, Path, code, inBuf, inBufSize, outBuf, outBufSize);
		}
		else
		{
			DWORD bytesReturned = 0;
			return TRUE == DeviceIoControl(Handle, code, inBuf, inBufSize, outBuf, outBufSize, &bytesReturned, NULL);
		}
	}

	void Show (HWND parent, const wstring &str)
	{
		MessageBox (parent, str.c_str(), NULL, 0);
	}


	Device::Device (wstring path, bool readOnly)
	{
		wstring effectivePath;
		FileOpen = false;
		Elevated = false;

		if (path.find(L"\\\\?\\") == 0)
			effectivePath = path;
		else
			effectivePath = wstring (L"\\\\.\\") + path;

		Handle = CreateFile (effectivePath.c_str(),
			readOnly ? GENERIC_READ : GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
			FILE_FLAG_RANDOM_ACCESS | FILE_FLAG_WRITE_THROUGH, NULL);

		if (Handle != INVALID_HANDLE_VALUE)
		{
			FileOpen = true;
		}
		else
		{
			LastError = GetLastError ();
			if (LastError == ERROR_ACCESS_DENIED && IsUacSupported())
			{
				Elevated = true;
				FileOpen = true;
			}
		}

		FilePointerPosition = 0;
		IsDevice = true;
		Path = path;
		ReadOnly = readOnly;
	}

	static EfiBoot EfiBootInst;

	BootEncryption::BootEncryption (HWND parent, bool postOOBE, bool setBootEntry, bool forceFirstBootEntry, bool setBootNext)
		: DriveConfigValid (false),
		ParentWindow (parent),
		RealSystemDriveSizeValid (false),
		RescueIsoImage (nullptr),
		RescueZipData (nullptr),
		RescueZipSize (0),
		RescueVolumeHeaderValid (false),
		SelectedEncryptionAlgorithmId (0),
		SelectedPrfAlgorithmId (0),
		VolumeHeaderValid (false),
		PostOOBEMode (postOOBE),
		SetBootNext (setBootNext),
		SetBootEntry (setBootEntry),
		ForceFirstBootEntry (forceFirstBootEntry)
	{
      HiddenOSCandidatePartition.IsGPT = FALSE;
      HiddenOSCandidatePartition.Number = (size_t) -1;
      DriveConfig.DriveNumber = -1;
      DriveConfig.ExtraBootPartitionPresent = false;
      DriveConfig.SystemLoaderPresent = false;
      DriveConfig.InitialUnallocatedSpace = 0;
      DriveConfig.TotalUnallocatedSpace = 0;
		Elevator::AddReference();
	}


	BootEncryption::~BootEncryption ()
	{
		if (RescueIsoImage)
		{
			burn (RescueIsoImage, RescueIsoImageSize);
			delete[] RescueIsoImage;
		}
		if (RescueZipData)
		{
			burn (RescueZipData, RescueZipSize);
			delete [] RescueZipData;
		}

		Elevator::Release();
	}


	void BootEncryption::CallDriver (DWORD ioctl, void *input, DWORD inputSize, void *output, DWORD outputSize)
	{
		try
		{
			DWORD bytesReturned;
			throw_sys_if (!DeviceIoControl (hDriver, ioctl, input, inputSize, output, outputSize, &bytesReturned, NULL));
		}
		catch (SystemException &)
		{
			if (GetLastError() == ERROR_ACCESS_DENIED && IsUacSupported())
				Elevator::CallDriver (ioctl, input, inputSize, output, outputSize);
			else
				throw;
		}
	}


	// Finds the first partition physically located behind the active one and returns its properties
	Partition BootEncryption::GetPartitionForHiddenOS ()
	{
		Partition candidatePartition;

		memset (&candidatePartition, 0, sizeof(candidatePartition));

		// The user may have modified/added/deleted partitions since the time the partition table was last scanned
		InvalidateCachedSysDriveProperties();

		SystemDriveConfiguration config = GetSystemDriveConfiguration ();
		bool activePartitionFound = false;
		bool candidateForHiddenOSFound = false;

 		if (!config.SystemPartition.IsGPT)
		{
//				throw ParameterIncorrect (SRC_POS);	// It is assumed that CheckRequirements() had been called

			// Find the first active partition on the system drive
			foreach (const Partition &partition, config.Partitions)
			{
				if (partition.Info.BootIndicator)
				{
					if (partition.Info.PartitionNumber != config.SystemPartition.Number)
					{
						// If there is an extra boot partition, the system partition must be located right behind it
						if (config.ExtraBootPartitionPresent)
						{
							int64 minOffsetFound = config.DrivePartition.Info.PartitionLength.QuadPart;
							Partition bootPartition = partition;
							Partition partitionBehindBoot;

							foreach (const Partition &partition, config.Partitions)
							{
								if (partition.Info.StartingOffset.QuadPart > bootPartition.Info.StartingOffset.QuadPart
									&& partition.Info.StartingOffset.QuadPart < minOffsetFound)
								{
									minOffsetFound = partition.Info.StartingOffset.QuadPart;
									partitionBehindBoot = partition;
								}
							}

							if (minOffsetFound != config.DrivePartition.Info.PartitionLength.QuadPart
								&& partitionBehindBoot.Number == config.SystemPartition.Number)
							{
								activePartitionFound = true;
								break;
							}
						}

						throw ErrorException (wstring (GetString ("SYSTEM_PARTITION_NOT_ACTIVE"))
							+ GetRemarksOnHiddenOS(), SRC_POS);
					}

					activePartitionFound = true;
					break;
				}
			}
		} else {
			// For GPT
			activePartitionFound = true;
		}
		/* WARNING: Note that the partition number at the end of a device path (\Device\HarddiskY\PartitionX) must
		NOT be used to find the first partition physically located behind the active one. The reason is that the
		user may have deleted and created partitions during this session and e.g. the second partition could have
		a higer number than the third one. */


		// Find the first partition physically located behind the active partition
		if (activePartitionFound)
		{
			int64 minOffsetFound = config.DrivePartition.Info.PartitionLength.QuadPart;

			foreach (const Partition &partition, config.Partitions)
			{
				if (partition.Info.StartingOffset.QuadPart > config.SystemPartition.Info.StartingOffset.QuadPart
					&& partition.Info.StartingOffset.QuadPart < minOffsetFound)
				{
					minOffsetFound = partition.Info.StartingOffset.QuadPart;

					candidatePartition = partition;

					candidateForHiddenOSFound = true;
				}
			}

			if (!candidateForHiddenOSFound)
			{
				throw ErrorException (wstring (GetString ("NO_PARTITION_FOLLOWS_BOOT_PARTITION"))
					+ GetRemarksOnHiddenOS(), SRC_POS);
			}

			if (config.SystemPartition.Info.PartitionLength.QuadPart > TC_MAX_FAT_SECTOR_COUNT * TC_SECTOR_SIZE_BIOS)
			{
				if ((double) candidatePartition.Info.PartitionLength.QuadPart / config.SystemPartition.Info.PartitionLength.QuadPart < MIN_HIDDENOS_DECOY_PARTITION_SIZE_RATIO_NTFS)
				{
					throw ErrorException (wstring (GetString ("PARTITION_TOO_SMALL_FOR_HIDDEN_OS_NTFS"))
						+ GetRemarksOnHiddenOS(), SRC_POS);
				}
			}
			else if ((double) candidatePartition.Info.PartitionLength.QuadPart / config.SystemPartition.Info.PartitionLength.QuadPart < MIN_HIDDENOS_DECOY_PARTITION_SIZE_RATIO_FAT)
			{
				throw ErrorException (wstring (GetString ("PARTITION_TOO_SMALL_FOR_HIDDEN_OS"))
					+ GetRemarksOnHiddenOS(), SRC_POS);
			}
		}
		else
		{
			// No active partition on the system drive
			throw ErrorException ("SYSTEM_PARTITION_NOT_ACTIVE", SRC_POS);
		}

		HiddenOSCandidatePartition = candidatePartition;
		return candidatePartition;
	}


	DWORD BootEncryption::GetDriverServiceStartType ()
	{
		DWORD startType;
		throw_sys_if (!ReadLocalMachineRegistryDword (L"SYSTEM\\CurrentControlSet\\Services\\veracrypt", L"Start", &startType));
		return startType;
	}


	wstring BootEncryption::GetRemarksOnHiddenOS ()
	{
		return (wstring (L"\n\n")
				+ GetString ("TWO_SYSTEMS_IN_ONE_PARTITION_REMARK")
				+ L"\n\n"
				+ GetString ("FOR_MORE_INFO_ON_PARTITIONS"));
	}


	void BootEncryption::SetDriverServiceStartType (DWORD startType)
	{
		if (!IsAdmin() && IsUacSupported())
		{
			Elevator::SetDriverServiceStartType (startType);
			return;
		}

		BOOL startOnBoot = (startType == SERVICE_BOOT_START);

		SC_HANDLE serviceManager = OpenSCManager (NULL, NULL, SC_MANAGER_ALL_ACCESS);
		throw_sys_if (!serviceManager);

		finally_do_arg (SC_HANDLE, serviceManager, { CloseServiceHandle (finally_arg); });

		SC_HANDLE service = OpenService (serviceManager, L"veracrypt", SERVICE_CHANGE_CONFIG);
		throw_sys_if (!service);

		finally_do_arg (SC_HANDLE, service, { CloseServiceHandle (finally_arg); });

		throw_sys_if (!ChangeServiceConfig (service, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
			startOnBoot ? SERVICE_ERROR_SEVERE : SERVICE_ERROR_NORMAL,
			NULL,
			startOnBoot ? L"Filter" : NULL,
			NULL, NULL, NULL, NULL, NULL));

		// ChangeServiceConfig() rejects SERVICE_BOOT_START with ERROR_INVALID_PARAMETER
		throw_sys_if (!WriteLocalMachineRegistryDword (L"SYSTEM\\CurrentControlSet\\Services\\veracrypt", L"Start", startType));
	}


	void BootEncryption::ProbeRealSystemDriveSize ()
	{
		if (RealSystemDriveSizeValid)
			return;

		GetSystemDriveConfiguration();

		ProbeRealDriveSizeRequest request;
		StringCchCopyW (request.DeviceName, ARRAYSIZE (request.DeviceName), DriveConfig.DrivePartition.DevicePath.c_str());

		CallDriver (TC_IOCTL_PROBE_REAL_DRIVE_SIZE, &request, sizeof (request), &request, sizeof (request));
		DriveConfig.DrivePartition.Info.PartitionLength = request.RealDriveSize;

		RealSystemDriveSizeValid = true;

		if (request.TimeOut)
			throw TimeOut (SRC_POS);
	}


	void BootEncryption::InvalidateCachedSysDriveProperties ()
	{
		DriveConfigValid = false;
		RealSystemDriveSizeValid = false;
	}


	PartitionList BootEncryption::GetDrivePartitions (int driveNumber)
	{
		PartitionList partList;

		for (int partNumber = 0; partNumber < 64; ++partNumber)
		{
			wstringstream partPath;
			partPath << L"\\Device\\Harddisk" << driveNumber << L"\\Partition" << partNumber;

			DISK_PARTITION_INFO_STRUCT diskPartInfo = {0};
			StringCchCopyW (diskPartInfo.deviceName, ARRAYSIZE (diskPartInfo.deviceName), partPath.str().c_str());

			try
			{
				CallDriver (TC_IOCTL_GET_DRIVE_PARTITION_INFO, &diskPartInfo, sizeof (diskPartInfo), &diskPartInfo, sizeof (diskPartInfo));
			}
			catch (...)
			{
				continue;
			}

			if (	(diskPartInfo.IsGPT == TRUE || diskPartInfo.IsGPT == FALSE)
				&&	(diskPartInfo.IsDynamic == TRUE || diskPartInfo.IsDynamic == FALSE)
				&&	(diskPartInfo.partInfo.BootIndicator == TRUE || diskPartInfo.partInfo.BootIndicator == FALSE)
				&&	(diskPartInfo.partInfo.RecognizedPartition == TRUE || diskPartInfo.partInfo.RecognizedPartition == FALSE)
				&&	(diskPartInfo.partInfo.RewritePartition == TRUE || diskPartInfo.partInfo.RewritePartition == FALSE)
				&&	(diskPartInfo.partInfo.StartingOffset.QuadPart >= 0)
				&&	(diskPartInfo.partInfo.PartitionLength.QuadPart >= 0)
				)
			{
				Partition part;
				part.DevicePath = partPath.str();
				part.Number = partNumber;
				part.Info = diskPartInfo.partInfo;
				part.IsGPT = diskPartInfo.IsGPT;

				// Mount point
				int driveNumber = GetDiskDeviceDriveLetter ((wchar_t *) partPath.str().c_str());

				if (driveNumber >= 0)
				{
					part.MountPoint += (wchar_t) (driveNumber + L'A');
					part.MountPoint += L":";
				}

				// Volume ID
				wchar_t volumePath[TC_MAX_PATH];
				if (ResolveSymbolicLink ((wchar_t *) partPath.str().c_str(), volumePath, sizeof(volumePath)))
				{
					wchar_t volumeName[TC_MAX_PATH];
					HANDLE fh = FindFirstVolumeW (volumeName, array_capacity (volumeName));
					if (fh != INVALID_HANDLE_VALUE)
					{
						do
						{
							wstring volumeNameStr = volumeName;
							wchar_t devicePath[TC_MAX_PATH];

							if (QueryDosDeviceW (volumeNameStr.substr (4, volumeNameStr.size() - 1 - 4).c_str(), devicePath, array_capacity (devicePath)) != 0
								&& wcscmp (volumePath, devicePath) == 0)
							{
								part.VolumeNameId = volumeName;
								break;
							}

						} while (FindNextVolumeW (fh, volumeName, array_capacity (volumeName)));

						FindVolumeClose (fh);
					}
				}

				partList.push_back (part);
			}
		}

		return partList;
	}


#ifndef SETUP

	DISK_GEOMETRY_EX BootEncryption::GetDriveGeometry (int driveNumber)
	{
		wstringstream devName;
		devName << L"\\Device\\Harddisk" << driveNumber << L"\\Partition0";

		DISK_GEOMETRY_EX geometry;
		throw_sys_if (!::GetDriveGeometry (devName.str().c_str(), &geometry));
		return geometry;
	}
#endif // !SETUP

	wstring BootEncryption::GetWindowsDirectory ()
	{
		wchar_t buf[MAX_PATH];
		throw_sys_if (GetSystemDirectory (buf, ARRAYSIZE (buf)) == 0);

		return wstring (buf);
	}



	uint16 BootEncryption::GetInstalledBootLoaderVersion ()
	{
		uint16 version;
		CallDriver (TC_IOCTL_GET_BOOT_LOADER_VERSION, NULL, 0, &version, sizeof (version));
		return version;
	}

	void BootEncryption::GetInstalledBootLoaderFingerprint (uint8 fingerprint[WHIRLPOOL_DIGESTSIZE + SHA512_DIGESTSIZE])
	{
		BootLoaderFingerprintRequest request;
		CallDriver (VC_IOCTL_GET_BOOT_LOADER_FINGERPRINT, NULL, 0, &request, sizeof (request));
		memcpy (fingerprint, request.Fingerprint, sizeof (request.Fingerprint));
	}

#ifndef SETUP
	// Note that this does not require admin rights (it just requires the driver to be running)
	bool BootEncryption::IsBootLoaderOnDrive (wchar_t *devicePath)
	{
		try
		{
			OPEN_TEST_STRUCT openTestStruct;
			memset (&openTestStruct, 0, sizeof (openTestStruct));
			DWORD dwResult;

			StringCchCopyW (&openTestStruct.wszFileName[0], ARRAYSIZE(openTestStruct.wszFileName),devicePath);

			openTestStruct.bDetectTCBootLoader = TRUE;

			return (DeviceIoControl (hDriver, TC_IOCTL_OPEN_TEST,
				   &openTestStruct, sizeof (OPEN_TEST_STRUCT),
				   &openTestStruct, sizeof (OPEN_TEST_STRUCT),
				   &dwResult, NULL) && openTestStruct.TCBootLoaderDetected);
		}
		catch (...)
		{
			return false;
		}
	}

#endif

	BootEncryptionStatus BootEncryption::GetStatus ()
	{
		/* IMPORTANT: Do NOT add any potentially time-consuming operations to this function. */

		BootEncryptionStatus status;
		memset (&status, 0, sizeof(status));
		CallDriver (TC_IOCTL_GET_BOOT_ENCRYPTION_STATUS, NULL, 0, &status, sizeof (status));
		return status;
	}


	void BootEncryption::GetVolumeProperties (VOLUME_PROPERTIES_STRUCT *properties)
	{
		if (properties == NULL)
			throw ParameterIncorrect (SRC_POS);

		CallDriver (TC_IOCTL_GET_BOOT_DRIVE_VOLUME_PROPERTIES, NULL, 0, properties, sizeof (*properties));
	}


	bool BootEncryption::IsHiddenSystemRunning ()
	{
		int hiddenSystemStatus;

		CallDriver (TC_IOCTL_IS_HIDDEN_SYSTEM_RUNNING, nullptr, 0, &hiddenSystemStatus, sizeof (hiddenSystemStatus));
		return hiddenSystemStatus != 0;
	}


	bool BootEncryption::SystemDriveContainsPartitionType (uint8 type)
	{
		Device device (GetSystemDriveConfiguration().DevicePath, true);
		device.CheckOpened (SRC_POS);

		uint8 mbrBuf[TC_SECTOR_SIZE_BIOS];
		device.SeekAt (0);
		device.Read (mbrBuf, sizeof (mbrBuf));

		MBR *mbr = reinterpret_cast <MBR *> (mbrBuf);
		if (mbr->Signature != 0xaa55)
			throw ParameterIncorrect (SRC_POS);

		for (size_t i = 0; i < array_capacity (mbr->Partitions); ++i)
		{
			if (mbr->Partitions[i].Type == type)
				return true;
		}

		return false;
	}


	bool BootEncryption::SystemDriveContainsExtendedPartition ()
	{
		return SystemDriveContainsPartitionType (PARTITION_EXTENDED) || SystemDriveContainsPartitionType (PARTITION_XINT13_EXTENDED);
	}


	bool BootEncryption::SystemDriveContainsNonStandardPartitions ()
	{
		for (int partitionType = 1; partitionType <= 0xff; ++partitionType)
		{
			switch (partitionType)
			{
			case PARTITION_FAT_12:
			case PARTITION_FAT_16:
			case PARTITION_EXTENDED:
			case PARTITION_HUGE:
			case PARTITION_IFS:
			case PARTITION_FAT32:
			case PARTITION_FAT32_XINT13:
			case PARTITION_XINT13:
			case PARTITION_XINT13_EXTENDED:
				continue;
			}

			if (SystemDriveContainsPartitionType ((uint8) partitionType))
				return true;
		}

		return false;
	}


	bool BootEncryption::SystemDriveIsDynamic ()
	{
		GetSystemDriveConfigurationRequest request;
		memset (&request, 0, sizeof (request));
		StringCchCopyW (request.DevicePath, ARRAYSIZE (request.DevicePath), GetSystemDriveConfiguration().DeviceKernelPath.c_str());

		CallDriver (TC_IOCTL_GET_SYSTEM_DRIVE_CONFIG, &request, sizeof (request), &request, sizeof (request));
		return request.DriveIsDynamic ? true : false;
	}


	SystemDriveConfiguration BootEncryption::GetSystemDriveConfiguration ()
	{
		if (DriveConfigValid)
			return DriveConfig;

		SystemDriveConfiguration config;

		wstring winDir = GetWindowsDirectory();

		// Scan all drives
		for (int driveNumber = 0; driveNumber < 32; ++driveNumber)
		{
			bool windowsFound = false;
			bool activePartitionFound = false;
			config.ExtraBootPartitionPresent = false;
			config.SystemLoaderPresent = false;

			PartitionList partitions = GetDrivePartitions (driveNumber);
			foreach (const Partition &part, partitions)
			{
				if (!part.MountPoint.empty()
					&& (_waccess ((part.MountPoint + L"\\bootmgr").c_str(), 0) == 0 || _waccess ((part.MountPoint + L"\\ntldr").c_str(), 0) == 0))
				{
					config.SystemLoaderPresent = true;
				}
				else if (!part.VolumeNameId.empty()
					&& (_waccess ((part.VolumeNameId + L"\\bootmgr").c_str(), 0) == 0 || _waccess ((part.VolumeNameId + L"\\ntldr").c_str(), 0) == 0))
				{
					config.SystemLoaderPresent = true;
				}

				if (!windowsFound && !part.MountPoint.empty() && ToUpperCase (winDir).find (ToUpperCase (part.MountPoint)) == 0)
				{
					config.SystemPartition = part;
					windowsFound = true;
				}

				if (!activePartitionFound && part.Info.BootIndicator)
				{
					activePartitionFound = true;

					if (part.Info.PartitionLength.QuadPart > 0 && part.Info.PartitionLength.QuadPart <= TC_MAX_EXTRA_BOOT_PARTITION_SIZE)
						config.ExtraBootPartitionPresent = true;
				}
			}

			if (windowsFound)
			{
				config.DriveNumber = driveNumber;

				wstringstream ss;
				ss << L"PhysicalDrive" << driveNumber;
				config.DevicePath = ss.str();

				wstringstream kernelPath;
				kernelPath << L"\\Device\\Harddisk" << driveNumber << L"\\Partition0";
				config.DeviceKernelPath = kernelPath.str();

				config.DrivePartition = partitions.front();
				partitions.pop_front();
				config.Partitions = partitions;

				config.InitialUnallocatedSpace = 0x7fffFFFFffffFFFFull;
				config.TotalUnallocatedSpace = config.DrivePartition.Info.PartitionLength.QuadPart;

				foreach (const Partition &part, config.Partitions)
				{
					if (part.Info.StartingOffset.QuadPart < config.InitialUnallocatedSpace)
						config.InitialUnallocatedSpace = part.Info.StartingOffset.QuadPart;

					config.TotalUnallocatedSpace -= part.Info.PartitionLength.QuadPart;
				}

				DriveConfig = config;
				DriveConfigValid = true;
				return DriveConfig;
			}
		}

		throw ParameterIncorrect (SRC_POS);
	}


	bool BootEncryption::SystemPartitionCoversWholeDrive ()
	{
		SystemDriveConfiguration config = GetSystemDriveConfiguration();

		if (config.Partitions.size() == 2
			&& config.ExtraBootPartitionPresent
			&& config.DrivePartition.Info.PartitionLength.QuadPart - config.SystemPartition.Info.PartitionLength.QuadPart < 164 * BYTES_PER_MB)
		{
			return true;
		}

		return config.Partitions.size() == 1
			&& config.DrivePartition.Info.PartitionLength.QuadPart - config.SystemPartition.Info.PartitionLength.QuadPart < 64 * BYTES_PER_MB;
	}


	uint32 BootEncryption::GetChecksum (uint8 *data, size_t size)
	{
		uint32 sum = 0;

		while (size-- > 0)
		{
			sum += *data++;
			sum = _rotl (sum, 1);
		}

		return sum;
	}


	void BootEncryption::CreateBootLoaderInMemory (uint8 *buffer, size_t bufferSize, bool rescueDisk, bool hiddenOSCreation)
	{
		if (bufferSize < TC_BOOT_LOADER_AREA_SIZE - TC_BOOT_ENCRYPTION_VOLUME_HEADER_SIZE)
			throw ParameterIncorrect (SRC_POS);

		ZeroMemory (buffer, bufferSize);

		int ea = 0;
		int pkcs5_prf = 0;
		BOOL bIsGPT = GetSystemDriveConfiguration().SystemPartition.IsGPT;
		if (GetStatus().DriveMounted)
		{
			try
			{
				GetBootEncryptionAlgorithmNameRequest request;
				// since we added new field to GetBootEncryptionAlgorithmNameRequest since version 1.0f
				// we zero all the structure so that if we are talking to an older driver, the field
				// BootPrfAlgorithmName will be an empty string
				ZeroMemory(&request, sizeof(request));
				CallDriver (TC_IOCTL_GET_BOOT_ENCRYPTION_ALGORITHM_NAME, NULL, 0, &request, sizeof (request));

				if (_stricmp (request.BootEncryptionAlgorithmName, "AES") == 0)
					ea = AES;
                        #ifndef WOLFCRYPT_BACKEND
				else if (_stricmp (request.BootEncryptionAlgorithmName, "Camellia") == 0)
					ea = CAMELLIA;	
                                else if (_stricmp (request.BootEncryptionAlgorithmName, "Serpent") == 0)
					ea = SERPENT;
				else if (_stricmp (request.BootEncryptionAlgorithmName, "Twofish") == 0)
					ea = TWOFISH;
                        #endif
				if (_stricmp(request.BootPrfAlgorithmName, "SHA-256") == 0)
					pkcs5_prf = SHA256;
                              else if (_stricmp(request.BootPrfAlgorithmName, "SHA-512") == 0)
					pkcs5_prf = SHA512;
                        #ifndef WOLFCRYPT_BACKEND
				else if (_stricmp(request.BootPrfAlgorithmName, "BLAKE2s-256") == 0)
					pkcs5_prf = BLAKE2S;	
				else if (_stricmp(request.BootPrfAlgorithmName, "Whirlpool") == 0)
					pkcs5_prf = WHIRLPOOL;
				else if (_stricmp(request.BootPrfAlgorithmName, "Streebog") == 0)
					pkcs5_prf = STREEBOG;
                        #endif
				else if (strlen(request.BootPrfAlgorithmName) == 0) // case of version < 1.0f
					pkcs5_prf = BLAKE2S;
			}
			catch (...)
			{
				try
				{
					VOLUME_PROPERTIES_STRUCT properties;
					GetVolumeProperties (&properties);
					ea = properties.ea;
					pkcs5_prf = properties.pkcs5;
				}
				catch (...) { }
			}

			if (pkcs5_prf == 0)
				throw ParameterIncorrect (SRC_POS);
		}
		else
		{
			if (SelectedEncryptionAlgorithmId == 0 || SelectedPrfAlgorithmId == 0)
				throw ParameterIncorrect (SRC_POS);

			ea = SelectedEncryptionAlgorithmId;
			pkcs5_prf = SelectedPrfAlgorithmId;
		}

		// Only BLAKE2s and SHA-256 are supported for MBR boot loader		
		if (!bIsGPT && pkcs5_prf != BLAKE2S && pkcs5_prf != SHA256)
			throw ParameterIncorrect (SRC_POS);

		int bootSectorId = 0;
		int bootLoaderId = 0;

		if (pkcs5_prf == SHA256)
		{
			bootSectorId = rescueDisk ? IDR_RESCUE_BOOT_SECTOR_SHA2 : IDR_BOOT_SECTOR_SHA2;
			bootLoaderId = rescueDisk ? IDR_RESCUE_LOADER_SHA2 : IDR_BOOT_LOADER_SHA2;
		}
		else
		{
			bootSectorId = rescueDisk ? IDR_RESCUE_BOOT_SECTOR : IDR_BOOT_SECTOR;
			bootLoaderId = rescueDisk ? IDR_RESCUE_LOADER : IDR_BOOT_LOADER;
		}

		switch (ea)
		{
		case AES:
			if (pkcs5_prf == SHA256)
			{
				bootSectorId = rescueDisk ? IDR_RESCUE_BOOT_SECTOR_AES_SHA2 : IDR_BOOT_SECTOR_AES_SHA2;
				bootLoaderId = rescueDisk ? IDR_RESCUE_LOADER_AES_SHA2 : IDR_BOOT_LOADER_AES_SHA2;
			}
			else
			{
				bootSectorId = rescueDisk ? IDR_RESCUE_BOOT_SECTOR_AES : IDR_BOOT_SECTOR_AES;
				bootLoaderId = rescueDisk ? IDR_RESCUE_LOADER_AES : IDR_BOOT_LOADER_AES;
			}
			break;

		case SERPENT:
			if (pkcs5_prf == SHA256)
			{
				bootSectorId = rescueDisk ? IDR_RESCUE_BOOT_SECTOR_SERPENT_SHA2 : IDR_BOOT_SECTOR_SERPENT_SHA2;
				bootLoaderId = rescueDisk ? IDR_RESCUE_LOADER_SERPENT_SHA2 : IDR_BOOT_LOADER_SERPENT_SHA2;
			}
			else
			{
				bootSectorId = rescueDisk ? IDR_RESCUE_BOOT_SECTOR_SERPENT : IDR_BOOT_SECTOR_SERPENT;
				bootLoaderId = rescueDisk ? IDR_RESCUE_LOADER_SERPENT : IDR_BOOT_LOADER_SERPENT;
			}
			break;

		case TWOFISH:
			if (pkcs5_prf == SHA256)
			{
				bootSectorId = rescueDisk ? IDR_RESCUE_BOOT_SECTOR_TWOFISH_SHA2 : IDR_BOOT_SECTOR_TWOFISH_SHA2;
				bootLoaderId = rescueDisk ? IDR_RESCUE_LOADER_TWOFISH_SHA2 : IDR_BOOT_LOADER_TWOFISH_SHA2;
			}
			else
			{
				bootSectorId = rescueDisk ? IDR_RESCUE_BOOT_SECTOR_TWOFISH : IDR_BOOT_SECTOR_TWOFISH;
				bootLoaderId = rescueDisk ? IDR_RESCUE_LOADER_TWOFISH : IDR_BOOT_LOADER_TWOFISH;
			}
			break;
			
		case CAMELLIA:
			if (pkcs5_prf == SHA256)
			{
				bootSectorId = rescueDisk ? IDR_RESCUE_BOOT_SECTOR_CAMELLIA_SHA2 : IDR_BOOT_SECTOR_CAMELLIA_SHA2;
				bootLoaderId = rescueDisk ? IDR_RESCUE_LOADER_CAMELLIA_SHA2 : IDR_BOOT_LOADER_CAMELLIA_SHA2;
			}
			else
			{
				bootSectorId = rescueDisk ? IDR_RESCUE_BOOT_SECTOR_CAMELLIA : IDR_BOOT_SECTOR_CAMELLIA;
				bootLoaderId = rescueDisk ? IDR_RESCUE_LOADER_CAMELLIA : IDR_BOOT_LOADER_CAMELLIA;
			}
			break;
		}

		// Boot sector
		DWORD size;
		uint8 *bootSecResourceImg = MapResource (L"BIN", bootSectorId, &size);
		if (!bootSecResourceImg || size != TC_SECTOR_SIZE_BIOS)
			throw ParameterIncorrect (SRC_POS);

		memcpy (buffer, bootSecResourceImg, size);

		*(uint16 *) (buffer + TC_BOOT_SECTOR_VERSION_OFFSET) = BE16 (VERSION_NUM);

		buffer[TC_BOOT_SECTOR_CONFIG_OFFSET] |= TC_BOOT_CFG_FLAG_WINDOWS_VISTA_OR_LATER;

		if (rescueDisk && (ReadDriverConfigurationFlags() & TC_DRIVER_CONFIG_DISABLE_HARDWARE_ENCRYPTION))
			buffer[TC_BOOT_SECTOR_CONFIG_OFFSET] |= TC_BOOT_CFG_FLAG_RESCUE_DISABLE_HW_ENCRYPTION;

		// Checksum of the backup header of the outer volume for the hidden system
		if (hiddenOSCreation)
		{
			Device device (GetSystemDriveConfiguration().DevicePath);
			device.CheckOpened (SRC_POS);
			uint8 headerSector[TC_SECTOR_SIZE_BIOS];

			device.SeekAt (HiddenOSCandidatePartition.Info.StartingOffset.QuadPart + HiddenOSCandidatePartition.Info.PartitionLength.QuadPart - TC_VOLUME_HEADER_GROUP_SIZE + TC_VOLUME_HEADER_EFFECTIVE_SIZE);
			device.Read (headerSector, sizeof (headerSector));

			*(uint32 *) (buffer + TC_BOOT_SECTOR_OUTER_VOLUME_BAK_HEADER_CRC_OFFSET) = GetCrc32 (headerSector, sizeof (headerSector));
		}

		// Decompressor
		uint8 *decompressor = MapResource (L"BIN", IDR_BOOT_LOADER_DECOMPRESSOR, &size);
		if (!decompressor || size > TC_BOOT_LOADER_DECOMPRESSOR_SECTOR_COUNT * TC_SECTOR_SIZE_BIOS)
			throw ParameterIncorrect (SRC_POS);

		memcpy (buffer + TC_SECTOR_SIZE_BIOS, decompressor, size);

		// Compressed boot loader
		uint8 *bootLoader = MapResource (L"BIN", bootLoaderId, &size);
		if (!bootLoader || size > TC_MAX_BOOT_LOADER_SECTOR_COUNT * TC_SECTOR_SIZE_BIOS)
			throw ParameterIncorrect (SRC_POS);

		memcpy (buffer + TC_SECTOR_SIZE_BIOS + TC_BOOT_LOADER_DECOMPRESSOR_SECTOR_COUNT * TC_SECTOR_SIZE_BIOS, bootLoader, size);

		// Boot loader and decompressor checksum
		*(uint16 *) (buffer + TC_BOOT_SECTOR_LOADER_LENGTH_OFFSET) = static_cast <uint16> (size);
		*(uint32 *) (buffer + TC_BOOT_SECTOR_LOADER_CHECKSUM_OFFSET) = GetChecksum (buffer + TC_SECTOR_SIZE_BIOS,
			TC_BOOT_LOADER_DECOMPRESSOR_SECTOR_COUNT * TC_SECTOR_SIZE_BIOS + size);

		// Backup of decompressor and boot loader
		if (size + TC_BOOT_LOADER_DECOMPRESSOR_SECTOR_COUNT * TC_SECTOR_SIZE_BIOS <= TC_BOOT_LOADER_BACKUP_SECTOR_COUNT * TC_SECTOR_SIZE_BIOS)
		{
			memcpy (buffer + TC_SECTOR_SIZE_BIOS + TC_BOOT_LOADER_BACKUP_SECTOR_COUNT * TC_SECTOR_SIZE_BIOS,
				buffer + TC_SECTOR_SIZE_BIOS, TC_BOOT_LOADER_BACKUP_SECTOR_COUNT * TC_SECTOR_SIZE_BIOS);

			buffer[TC_BOOT_SECTOR_CONFIG_OFFSET] |= TC_BOOT_CFG_FLAG_BACKUP_LOADER_AVAILABLE;
		}
		else if (!rescueDisk && bootLoaderId != IDR_BOOT_LOADER && bootLoaderId != IDR_BOOT_LOADER_SHA2)
		{
			throw ParameterIncorrect (SRC_POS);
		}
	}

	// return false when the user cancel an elevation request
	bool BootEncryption::ReadBootSectorConfig (uint8 *config, size_t bufLength, uint8 *userConfig, string *customUserMessage, uint16 *bootLoaderVersion)
	{
		bool bCanceled = false, bExceptionOccured = false;
		try
		{
			if (GetSystemDriveConfiguration().SystemPartition.IsGPT)
			{
				// for now, we don't support any boot config flags, like hidden OS one
				if (config)
					memset (config, 0, bufLength);

				// call ReadESPFile only when needed since it requires elevation
				if (userConfig || customUserMessage || bootLoaderVersion)
				{
					std::string confContent = ReadESPFile (L"\\EFI\\VeraCrypt\\DcsProp", true);

					EfiBootConf conf;
					conf.Load ((char*) confContent.c_str());

					if (userConfig)
					{
						*userConfig = 0;
						if (!conf.requestPim)
							*userConfig |= TC_BOOT_USER_CFG_FLAG_DISABLE_PIM;
						if (!conf.requestHash)
							*userConfig |= TC_BOOT_USER_CFG_FLAG_STORE_HASH;

					}

					if (customUserMessage)
						customUserMessage->clear();

					if (bootLoaderVersion)
					{
						*bootLoaderVersion = GetStatus().BootLoaderVersion;
					}
				}
			}
			else
			{
				if (config && bufLength < TC_BOOT_CFG_FLAG_AREA_SIZE)
					throw ParameterIncorrect (SRC_POS);

				GetSystemDriveConfigurationRequest request;
				memset (&request, 0, sizeof (request));
				StringCchCopyW (request.DevicePath, ARRAYSIZE (request.DevicePath), GetSystemDriveConfiguration().DeviceKernelPath.c_str());

				CallDriver (TC_IOCTL_GET_SYSTEM_DRIVE_CONFIG, &request, sizeof (request), &request, sizeof (request));
				if (config)
					*config = request.Configuration;

				if (userConfig)
					*userConfig = request.UserConfiguration;
				
				if (customUserMessage)
				{
					request.CustomUserMessage[TC_BOOT_SECTOR_USER_MESSAGE_MAX_LENGTH] = 0;
					*customUserMessage = request.CustomUserMessage;
				}

				if (bootLoaderVersion)
					*bootLoaderVersion = request.BootLoaderVersion;
			}
		}
		catch (UserAbort&)
		{
			bCanceled = true;
			bExceptionOccured= true;
		}
		catch (...)
		{
			bExceptionOccured = true;
		}

		if (bExceptionOccured)
		{
			if (config)
				*config = 0;

			if (userConfig)
				*userConfig = 0;
			
			if (customUserMessage)
				customUserMessage->clear();

			if (bootLoaderVersion)
				*bootLoaderVersion = 0;
		}

		return !bCanceled;
	}


	void BootEncryption::WriteBootSectorConfig (const uint8 newConfig[])
	{
		Device device (GetSystemDriveConfiguration().DevicePath);
		device.CheckOpened (SRC_POS);
		uint8 mbr[TC_SECTOR_SIZE_BIOS];

		device.SeekAt (0);
		device.Read (mbr, sizeof (mbr));

		memcpy (mbr + TC_BOOT_SECTOR_CONFIG_OFFSET, newConfig, TC_BOOT_CFG_FLAG_AREA_SIZE);

		device.SeekAt (0);
		device.Write (mbr, sizeof (mbr));

		uint8 mbrVerificationBuf[TC_SECTOR_SIZE_BIOS];
		device.SeekAt (0);
		device.Read (mbrVerificationBuf, sizeof (mbr));

		if (memcmp (mbr, mbrVerificationBuf, sizeof (mbr)) != 0)
			throw ErrorException ("ERROR_MBR_PROTECTED", SRC_POS);
	}

	void BootEncryption::WriteEfiBootSectorUserConfig (uint8 userConfig, const string &customUserMessage, int pim, int hashAlg)
	{
		if (!IsAdmin() && IsUacSupported())
		{
			Elevator::WriteEfiBootSectorUserConfig (userConfig, customUserMessage, pim, hashAlg);
		}
		else
		{
			EfiBootInst.PrepareBootPartition();

			if (! (userConfig & TC_BOOT_USER_CFG_FLAG_DISABLE_PIM))
				pim = -1;
			if (! (userConfig & TC_BOOT_USER_CFG_FLAG_STORE_HASH))
				hashAlg = -1;				

			EfiBootInst.UpdateConfig (L"\\EFI\\VeraCrypt\\DcsProp", pim, hashAlg, ParentWindow);
		}
	}

	void BootEncryption::WriteBootSectorUserConfig (uint8 userConfig, const string &customUserMessage, int pim, int hashAlg)
	{
		if (GetSystemDriveConfiguration().SystemPartition.IsGPT)
		{
			WriteEfiBootSectorUserConfig (userConfig, customUserMessage, pim, hashAlg);
		}
		else
		{
			Device device (GetSystemDriveConfiguration().DevicePath);
			device.CheckOpened (SRC_POS);
			uint8 mbr[TC_SECTOR_SIZE_BIOS];

			device.SeekAt (0);
			device.Read (mbr, sizeof (mbr));

			if (!BufferContainsString (mbr, sizeof (mbr), TC_APP_NAME)
				|| BE16 (*(uint16 *) (mbr + TC_BOOT_SECTOR_VERSION_OFFSET)) != VERSION_NUM)
			{
				return;
			}

			mbr[TC_BOOT_SECTOR_USER_CONFIG_OFFSET] = userConfig;

			memset (mbr + TC_BOOT_SECTOR_USER_MESSAGE_OFFSET, 0, TC_BOOT_SECTOR_USER_MESSAGE_MAX_LENGTH);

			if (!customUserMessage.empty())
			{
				if (customUserMessage.size() > TC_BOOT_SECTOR_USER_MESSAGE_MAX_LENGTH)
					throw ParameterIncorrect (SRC_POS);

				memcpy (mbr + TC_BOOT_SECTOR_USER_MESSAGE_OFFSET, customUserMessage.c_str(), customUserMessage.size());
			}
			
			if (userConfig & TC_BOOT_USER_CFG_FLAG_DISABLE_PIM)
			{
				// PIM for pre-boot authentication can be encoded on two bytes since its maximum
				// value is 65535 (0xFFFF)
				memcpy (mbr + TC_BOOT_SECTOR_PIM_VALUE_OFFSET, &pim, TC_BOOT_SECTOR_PIM_VALUE_SIZE);
			}
			else
				memset (mbr + TC_BOOT_SECTOR_PIM_VALUE_OFFSET, 0, TC_BOOT_SECTOR_PIM_VALUE_SIZE);

			device.SeekAt (0);
			device.Write (mbr, sizeof (mbr));

			uint8 mbrVerificationBuf[TC_SECTOR_SIZE_BIOS];
			device.SeekAt (0);
			device.Read (mbrVerificationBuf, sizeof (mbr));

			if (memcmp (mbr, mbrVerificationBuf, sizeof (mbr)) != 0)
				throw ErrorException ("ERROR_MBR_PROTECTED", SRC_POS);
		}
	}


	unsigned int BootEncryption::GetHiddenOSCreationPhase ()
	{
		uint8 configFlags [TC_BOOT_CFG_FLAG_AREA_SIZE];

		ReadBootSectorConfig (configFlags, sizeof(configFlags));

		return (configFlags[0] & TC_BOOT_CFG_MASK_HIDDEN_OS_CREATION_PHASE);
	}


	void BootEncryption::SetHiddenOSCreationPhase (unsigned int newPhase)
	{
#if TC_BOOT_CFG_FLAG_AREA_SIZE != 1
#	error TC_BOOT_CFG_FLAG_AREA_SIZE != 1; revise GetHiddenOSCreationPhase() and SetHiddenOSCreationPhase()
#endif
		uint8 configFlags [TC_BOOT_CFG_FLAG_AREA_SIZE];

		ReadBootSectorConfig (configFlags, sizeof(configFlags));

		configFlags[0] &= (uint8) ~TC_BOOT_CFG_MASK_HIDDEN_OS_CREATION_PHASE;

		configFlags[0] |= newPhase;

		WriteBootSectorConfig (configFlags);
	}


#ifndef SETUP

	void BootEncryption::StartDecoyOSWipe (WipeAlgorithmId wipeAlgorithm)
	{
		if (!IsHiddenOSRunning())
			throw ParameterIncorrect (SRC_POS);

		WipeDecoySystemRequest request;
		ZeroMemory (&request, sizeof (request));

		request.WipeAlgorithm = wipeAlgorithm;
		
		if (Randinit() != ERR_SUCCESS)
		{
			if (CryptoAPILastError == ERROR_SUCCESS)
				throw RandInitFailed (SRC_POS, GetLastError ());
			else
				throw CryptoApiFailed (SRC_POS, CryptoAPILastError);
		}

		/* force the display of the random enriching dialog */
		SetRandomPoolEnrichedByUserStatus (FALSE);

		UserEnrichRandomPool (ParentWindow);

		if (!RandgetBytes (ParentWindow, request.WipeKey, sizeof (request.WipeKey), TRUE))
			throw ParameterIncorrect (SRC_POS);

		CallDriver (TC_IOCTL_START_DECOY_SYSTEM_WIPE, &request, sizeof (request), NULL, 0);

		burn (&request, sizeof (request));
	}


	void BootEncryption::AbortDecoyOSWipe ()
	{
		CallDriver (TC_IOCTL_ABORT_DECOY_SYSTEM_WIPE);
	}

	
	DecoySystemWipeStatus BootEncryption::GetDecoyOSWipeStatus ()
	{
		DecoySystemWipeStatus status;
		CallDriver (TC_IOCTL_GET_DECOY_SYSTEM_WIPE_STATUS, NULL, 0, &status, sizeof (status));
		return status;
	}


	void BootEncryption::CheckDecoyOSWipeResult ()
	{
		CallDriver (TC_IOCTL_GET_DECOY_SYSTEM_WIPE_RESULT);
	}


	void BootEncryption::WipeHiddenOSCreationConfig ()
	{
		if (IsHiddenOSRunning())
			throw ParameterIncorrect (SRC_POS);

		if (Randinit() != ERR_SUCCESS)
		{
			if (CryptoAPILastError == ERROR_SUCCESS)
				throw RandInitFailed (SRC_POS, GetLastError ());
			else
				throw CryptoApiFailed (SRC_POS, CryptoAPILastError);
		}

		Device device (GetSystemDriveConfiguration().DevicePath);
		device.CheckOpened(SRC_POS);
		uint8 mbr[TC_SECTOR_SIZE_BIOS];

		device.SeekAt (0);
		device.Read (mbr, sizeof (mbr));
		
		finally_do_arg (BootEncryption *, this,
		{
			try
			{
				finally_arg->SetHiddenOSCreationPhase (TC_HIDDEN_OS_CREATION_PHASE_NONE);
			} catch (...) { }
		});

#if PRAND_DISK_WIPE_PASSES > RNG_POOL_SIZE
#	error PRAND_DISK_WIPE_PASSES > RNG_POOL_SIZE
#endif

		uint8 randData[PRAND_DISK_WIPE_PASSES];
		if (!RandgetBytes (ParentWindow, randData, sizeof (randData), FALSE))
			throw ParameterIncorrect (SRC_POS);

		for (int wipePass = 0; wipePass < PRAND_DISK_WIPE_PASSES; wipePass++)
		{
			for (int i = 0; i < TC_BOOT_SECTOR_OUTER_VOLUME_BAK_HEADER_CRC_SIZE; ++i)
			{
				mbr[TC_BOOT_SECTOR_OUTER_VOLUME_BAK_HEADER_CRC_OFFSET + i] = randData[wipePass];
			}

			mbr[TC_BOOT_SECTOR_CONFIG_OFFSET] &= (uint8) ~TC_BOOT_CFG_MASK_HIDDEN_OS_CREATION_PHASE;
			mbr[TC_BOOT_SECTOR_CONFIG_OFFSET] |= randData[wipePass] & TC_BOOT_CFG_MASK_HIDDEN_OS_CREATION_PHASE;

			if (wipePass == PRAND_DISK_WIPE_PASSES - 1)
				memset (mbr + TC_BOOT_SECTOR_OUTER_VOLUME_BAK_HEADER_CRC_OFFSET, 0, TC_BOOT_SECTOR_OUTER_VOLUME_BAK_HEADER_CRC_SIZE);

			device.SeekAt (0);
			device.Write (mbr, sizeof (mbr));
		}

		for (int wipePass = 0; wipePass < PRAND_DISK_WIPE_PASSES/4 + 1; wipePass++)
		{
			SetHiddenOSCreationPhase (TC_HIDDEN_OS_CREATION_PHASE_NONE);
			SetHiddenOSCreationPhase (TC_HIDDEN_OS_CREATION_PHASE_CLONING);
			SetHiddenOSCreationPhase (TC_HIDDEN_OS_CREATION_PHASE_WIPING);
			SetHiddenOSCreationPhase (TC_HIDDEN_OS_CREATION_PHASE_WIPED);
		}
		SetHiddenOSCreationPhase (TC_HIDDEN_OS_CREATION_PHASE_NONE);
	}

#endif // !SETUP


	EfiBootConf::EfiBootConf() : passwordType (0),
		passwordMsg ("Password: "),
		passwordPicture ("login.bmp"),
		hashMsg ("(0) TEST ALL (1) SHA512 (2) WHIRLPOOL (3) SHA256 (4) BLAKE2S (5) STREEBOG\nHash: "),
		hashAlgo (0),
		requestHash (0),
		pimMsg ("PIM (Leave empty for default): "),
		pim (0),
		requestPim (1),
		authorizeVisible (0),
		authorizeRetry (10),
		bmlLockFlags (0),
		bmlDriverEnabled (0)
	{

	}

	BOOL EfiBootConf::ReadConfigValue (char* configContent, const char *configKey, char *configValue, int maxValueSize)
	{
		char *xml;

		xml = configContent;
		if (xml != NULL)
		{
			xml = XmlFindElementByAttributeValue (xml, "config", "key", configKey);
			if (xml != NULL)
			{
				XmlGetNodeText (xml, configValue, maxValueSize);
				return TRUE;
			}
		}

		return FALSE;
	}


	int EfiBootConf::ReadConfigInteger (char* configContent, const char *configKey, int defaultValue)
	{
		char s[32];
		int iRet;
		if (ReadConfigValue (configContent, configKey, s, sizeof (s)))
			iRet = atoi (s);
		else
			iRet = defaultValue;
		burn (s, sizeof (s));
		return iRet;
	}


	char* EfiBootConf::ReadConfigString (char* configContent, const char *configKey, char *defaultValue, char *str, int maxLen)
	{
		if (ReadConfigValue (configContent, configKey, str, maxLen))
			return str;
		else
		{
			StringCbCopyA (str, maxLen, defaultValue);
			return defaultValue;
		}
	}

	BOOL EfiBootConf::WriteConfigString (FILE* configFile, char* configContent, const char *configKey, const char *configValue)
	{
		
		BOOL bRet = FALSE;
		if (configFile)
		{
			char *c;
			// Mark previous config value as updated
			if (configContent != NULL)
			{
				c = XmlFindElementByAttributeValue (configContent, "config", "key", configKey);
				if (c != NULL)
					c[1] = '!';
			}

			if ( 0 != fwprintf (
					configFile, L"\n\t\t<config key=\"%hs\">%hs</config>",
					configKey, configValue))
			{
				bRet = TRUE;
			}
		}
		return bRet;
	}

	BOOL EfiBootConf::WriteConfigInteger (FILE* configFile, char* configContent, const char *configKey, int configValue)
	{
		BOOL bRet = FALSE;
		if (configFile)
		{
			char val[32];
			StringCbPrintfA (val, sizeof(val), "%d", configValue);
			bRet = WriteConfigString (configFile, configContent, configKey, val);
			burn (val, sizeof (val));
		}
		return bRet;
	}

	BOOL EfiBootConf::Load (const wchar_t* fileName)
	{
		DWORD size = 0;
		char* configContent = LoadFile (fileName, &size);
		if (configContent)
		{
			Load (configContent);
			burn (configContent, size);
			free (configContent);
			return TRUE;
		}
		else
			return FALSE;
	}

	void EfiBootConf::Load (char* configContent)
	{
		char buffer[1024];

		passwordType = ReadConfigInteger (configContent, "PasswordType", 0);
		passwordMsg = ReadConfigString (configContent, "PasswordMsg", "Password: ", buffer, sizeof (buffer));
		passwordPicture = ReadConfigString (configContent, "PasswordPicture", "\\EFI\\VeraCrypt\\login.bmp", buffer, sizeof (buffer));
		//hashMsg = ReadConfigString (configContent, "HashMsg", "(0) TEST ALL (1) SHA512 (2) WHIRLPOOL (3) SHA256 (4) BLAKE2S (5) STREEBOG\nHash: ", buffer, sizeof (buffer));
		hashAlgo = ReadConfigInteger (configContent, "Hash", 0);
		requestHash = ReadConfigInteger (configContent, "HashRqt", 1);
		pimMsg = ReadConfigString (configContent, "PimMsg", "PIM: ", buffer, sizeof (buffer));
		pim = ReadConfigInteger (configContent, "Pim", 0);
		requestPim = ReadConfigInteger (configContent, "PimRqt", 1);
		authorizeVisible = ReadConfigInteger (configContent, "AuthorizeVisible", 0);
		authorizeRetry = ReadConfigInteger (configContent, "AuthorizeRetry", 0);
		bmlLockFlags = ReadConfigInteger (configContent, "DcsBmlLockFlags", 0);
		bmlDriverEnabled = ReadConfigInteger (configContent, "DcsBmlDriver", 0);
		actionSuccessValue = ReadConfigString (configContent, "ActionSuccess", "postexec file(EFI\\Microsoft\\Boot\\bootmgfw_ms.vc)", buffer, sizeof (buffer));

		burn (buffer, sizeof (buffer));
	}

	BOOL EfiBootConf::Save (const wchar_t* fileName, HWND hwnd)
	{

		BOOL bRet = FALSE;
		DWORD size = 0;
		char* configContent = LoadFile (fileName, &size);

		FILE *configFile = _wfopen (fileName, L"w,ccs=UTF-8");
		if (configFile == NULL) {
			burn (configContent, size);
			free (configContent);
			return FALSE;
		}
		

		XmlWriteHeader (configFile);
		fputws (L"\n\t<configuration>", configFile);

		WriteConfigInteger (configFile, configContent, "PasswordType", passwordType);
		WriteConfigString (configFile, configContent, "PasswordMsg", passwordMsg.c_str());
		WriteConfigString (configFile, configContent, "PasswordPicture", passwordPicture.c_str());
		WriteConfigString (configFile, configContent, "HashMsg", hashMsg.c_str());
		WriteConfigInteger (configFile, configContent, "Hash", hashAlgo);
		WriteConfigInteger (configFile, configContent, "HashRqt", requestHash);
		WriteConfigString (configFile, configContent, "PimMsg", pimMsg.c_str());
		WriteConfigInteger (configFile, configContent, "Pim", pim);
		WriteConfigInteger (configFile, configContent, "PimRqt", requestPim);
		WriteConfigInteger (configFile, configContent, "AuthorizeVisible", authorizeVisible);
		WriteConfigInteger (configFile, configContent, "AuthorizeRetry", authorizeRetry);
		WriteConfigInteger (configFile, configContent, "DcsBmlLockFlags", bmlLockFlags);
		WriteConfigInteger (configFile, configContent, "DcsBmlDriver", bmlDriverEnabled);

		string fieldValue;
		if (IsPostExecFileField(actionSuccessValue, fieldValue) && (0 == _stricmp(fieldValue.c_str(), "\\EFI\\Microsoft\\Boot\\bootmgfw.efi")))
		{
			// fix wrong configuration file since bootmgfw.efi is now a copy of VeraCrypt and if we don't fix the DcsProp
			// file, veraCrypt bootloader will call itself
			// We first check if bootmgfw.efi is original Microsoft one. If yes, we don't do anything, otherwise we set the field to bootmgfw_ms.vc
			unsigned __int64 loaderSize = 0;
			bool bModifiedMsBoot = true;
			EfiBootInst.GetFileSize(L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi", loaderSize);

			if (loaderSize > 32768)
			{
				std::vector<uint8> bootLoaderBuf ((size_t) loaderSize);

				EfiBootInst.ReadFile(L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi", &bootLoaderBuf[0], (DWORD) loaderSize);

				// look for bootmgfw.efi identifiant string
				const char* g_szMsBootString = "bootmgfw.pdb";
				if (BufferHasPattern (bootLoaderBuf.data (), (size_t) loaderSize, g_szMsBootString, strlen (g_szMsBootString)))
				{
					bModifiedMsBoot = false;
				}
			}

			if (bModifiedMsBoot)
				actionSuccessValue = "postexec file(EFI\\Microsoft\\Boot\\bootmgfw_ms.vc)";
		}

		WriteConfigString (configFile, configContent, "ActionSuccess", actionSuccessValue.c_str());

		// Write unmodified values
		char* xml = configContent;
		char key[128], value[2048];
		while (xml && (xml = XmlFindElement (xml, "config")))
		{
			XmlGetAttributeText (xml, "key", key, sizeof (key));
			XmlGetNodeText (xml, value, sizeof (value));

			fwprintf (configFile, L"\n\t\t<config key=\"%hs\">%hs</config>", key, value);
			xml++;
		}

		fputws (L"\n\t</configuration>", configFile);
		XmlWriteFooter (configFile);

		TCFlushFile (configFile);

		bRet = CheckFileStreamWriteErrors (hwnd, configFile, fileName);

		fclose (configFile);

		if (configContent != NULL)
		{
			burn (configContent, size);
			free (configContent);
		}

		return bRet;
	}

	BOOL EfiBootConf::IsPostExecFileField (const string& fieldValue, string& filePath)
	{
		BOOL bRet = FALSE;
		filePath = "";

		if (!fieldValue.empty() && strlen (fieldValue.c_str()))
		{
			string  copieValue = fieldValue;
			std::transform(copieValue.begin(), copieValue.end(), copieValue.begin(), ::tolower);

			if (strstr (copieValue.c_str(), "postexec") && strstr (copieValue.c_str(), "file("))
			{
				char c;
				const char* ptr = strstr (copieValue.c_str(), "file(");

				filePath = "\\";
				ptr += 5;
				while ((c = *ptr))
				{
					if (c == ')')
						break;
					if (c == '/')
						c = '\\';
					filePath += c;
					ptr++;
				}

				if (c == ')')
					bRet = TRUE;									
				else
					filePath = "";
			}
		}

		return bRet;
	}

	BOOL EfiBootConf::IsPostExecFileField (const string& fieldValue, wstring& filePath)
	{
		string aPath;
		BOOL bRet = IsPostExecFileField (fieldValue, aPath);
		if (bRet)
			filePath = wstring(aPath.begin(), aPath.end());
		else
			filePath = L"";

		return bRet;
	}

	static const wchar_t*	EfiVarGuid = L"{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}";

	void 
	GetVolumeESP(wstring& path, wstring& bootVolumePath) 
	{
		static wstring g_EspPath;
		static wstring g_BootVolumePath;
		static bool g_EspPathInitialized = false;

		if (!g_EspPathInitialized)
		{
			ULONG    len;
			NTSTATUS res;
			WCHAR tempBuf[1024];
			NtQuerySystemInformationFn NtQuerySystemInformationPtr = (NtQuerySystemInformationFn) GetProcAddress (GetModuleHandle (L"ntdll.dll"), "NtQuerySystemInformation");
			memset(tempBuf, 0, sizeof(tempBuf));

			// Load NtQuerySystemInformation function point
			if (!NtQuerySystemInformationPtr)
			{
				throw SystemException (SRC_POS);
			}

			res = NtQuerySystemInformationPtr((SYSTEM_INFORMATION_CLASS)SYSPARTITIONINFORMATION, tempBuf, sizeof(tempBuf), &len);
			if (res != S_OK)
			{
				/* try to convert the returned NTSTATUS to a WIN32 system error using RtlNtStatusToDosError */
				RtlNtStatusToDosErrorFn RtlNtStatusToDosErrorPtr = (RtlNtStatusToDosErrorFn) GetProcAddress (GetModuleHandle (L"ntdll.dll"), "RtlNtStatusToDosError");
				if (RtlNtStatusToDosErrorPtr)
				{
					ULONG win32err = RtlNtStatusToDosErrorPtr (res);
					if (win32err != ERROR_MR_MID_NOT_FOUND)
						res = (NTSTATUS) win32err;
				}

				SetLastError (res);
				throw SystemException (SRC_POS);
			}		

			PUNICODE_STRING pStr = (PUNICODE_STRING) tempBuf;

			g_BootVolumePath = pStr->Buffer;
			g_EspPath = L"\\\\?";
			g_EspPath += &pStr->Buffer[7];
			g_EspPathInitialized = true;
		}

		path = g_EspPath;
		bootVolumePath = g_BootVolumePath;
	}

	std::string ReadESPFile (LPCWSTR szFilePath, bool bSkipUTF8BOM)
	{
		if (!szFilePath || !szFilePath[0])
			throw ParameterIncorrect (SRC_POS);

		ByteArray fileContent;
		DWORD dwSize = 0, dwOffset = 0;
		std::wstring pathESP, bootVolumePath;

		GetVolumeESP(pathESP, bootVolumePath);
		if (szFilePath[0] != L'\\')
			pathESP += L"\\";
		File f(pathESP + szFilePath, true);
		f.GetFileSize(dwSize);
		fileContent.resize(dwSize + 1);
		fileContent[dwSize] = 0;
		f.Read(fileContent.data(), dwSize);
		f.Close();

		if (bSkipUTF8BOM)
		{
			// remove UTF-8 BOM if any
			if (0 == memcmp (fileContent.data(), "\xEF\xBB\xBF", 3))
			{
				dwOffset = 3;
			}
		}

		return (const char*) &fileContent[dwOffset];
	}

	void WriteESPFile (LPCWSTR szFilePath, LPBYTE pbData, DWORD dwDataLen, bool bAddUTF8BOM)
	{
		if (!szFilePath || !szFilePath[0] || !pbData || !dwDataLen)
			throw ParameterIncorrect (SRC_POS);

		ByteArray fileContent;
		DWORD dwSize = dwDataLen, dwOffset = 0;
		std::wstring pathESP, bootVolumePath;

		if (bAddUTF8BOM)
		{
			dwSize += 3;
			dwOffset = 3;
		}

		GetVolumeESP(pathESP, bootVolumePath);
		if (szFilePath[0] != L'\\')
			pathESP += L"\\";

		fileContent.resize(dwSize);
		if (bAddUTF8BOM)
			memcpy (fileContent.data(), "\xEF\xBB\xBF", 3);
		memcpy (&fileContent[dwOffset], pbData, dwDataLen);

		File f(pathESP + szFilePath, false, true);
		f.Write(fileContent.data(), dwSize);
		f.Close();

	}

	EfiBoot::EfiBoot() {
		ZeroMemory (&sdn, sizeof (sdn));
		ZeroMemory (&partInfo, sizeof (partInfo));
		m_bMounted = false;
		bDeviceInfoValid = false;
	}

	void EfiBoot::PrepareBootPartition(bool bDisableException) {
		
		GetVolumeESP (EfiBootPartPath, BootVolumePath);

		std::wstring devicePath = L"\\\\?\\GLOBALROOT";
		devicePath += BootVolumePath;
		Device  dev(devicePath.c_str(), TRUE);

		try
		{
			dev.CheckOpened(SRC_POS);
		}
		catch (...)
		{
			if (!bDisableException)
				throw;
		}
		
		if (dev.IsOpened())
		{
			bDeviceInfoValid = dev.IoCtl(IOCTL_STORAGE_GET_DEVICE_NUMBER, NULL, 0, &sdn, sizeof(sdn))
								&& dev.IoCtl(IOCTL_DISK_GET_PARTITION_INFO_EX, NULL, 0, &partInfo, sizeof(partInfo));
			DWORD dwLastError = GetLastError ();
			dev.Close();
			if (!bDeviceInfoValid && !bDisableException)
			{
				SetLastError (dwLastError);
				throw SystemException(SRC_POS);
			}		
		}
	}

	bool EfiBoot::IsEfiBoot() {
		DWORD BootOrderLen;
		BootOrderLen = GetFirmwareEnvironmentVariable(L"BootOrder", EfiVarGuid, tempBuf, sizeof(tempBuf));
		return BootOrderLen != 0;
	}

	void EfiBoot::DeleteStartExec(uint16 statrtOrderNum, wchar_t* type) {
		SetPrivilege(SE_SYSTEM_ENVIRONMENT_NAME, TRUE);
		// Check EFI
		if (!IsEfiBoot()) {
			throw ErrorException(L"can not detect EFI environment", SRC_POS);
		}
		wchar_t	varName[256];
		StringCchPrintfW(varName, ARRAYSIZE (varName), L"%s%04X", type == NULL ? L"Boot" : type, statrtOrderNum);
		SetFirmwareEnvironmentVariable(varName, EfiVarGuid, NULL, 0);

		wstring order = L"Order";
		order.insert(0, type == NULL ? L"Boot" : type);
		uint32 startOrderLen = GetFirmwareEnvironmentVariable(order.c_str(), EfiVarGuid, tempBuf, sizeof(tempBuf));
		uint32 startOrderNumPos = UINT_MAX;
		bool	startOrderUpdate = false;
		uint16*	startOrder = (uint16*)tempBuf;
		for (uint32 i = 0; i < startOrderLen / 2; i++) {
			if (startOrder[i] == statrtOrderNum) {
				startOrderNumPos = i;
				break;
			}
		}

		// delete entry if present
		if (startOrderNumPos != UINT_MAX) {
			for (uint32 i = startOrderNumPos; i < ((startOrderLen / 2) - 1); ++i) {
				startOrder[i] = startOrder[i + 1];
			}
			startOrderLen -= 2;
			startOrderUpdate = true;
		}

		if (startOrderUpdate) {
			SetFirmwareEnvironmentVariable(order.c_str(), EfiVarGuid, startOrder, startOrderLen);

			// remove ourselves from BootNext value
			uint16 bootNextValue = 0;
			wstring next = L"Next";
			next.insert(0, type == NULL ? L"Boot" : type);

			if (	(GetFirmwareEnvironmentVariable(next.c_str(), EfiVarGuid, &bootNextValue, 2) == 2)
				&&	(bootNextValue == statrtOrderNum)
				)
			{
				SetFirmwareEnvironmentVariable(next.c_str(), EfiVarGuid, startOrder, 0);
			}
		}
	}

	void EfiBoot::SetStartExec(wstring description, wstring execPath, bool setBootEntry, bool forceFirstBootEntry, bool setBootNext, uint16 statrtOrderNum , wchar_t* type, uint32 attr) {
		SetPrivilege(SE_SYSTEM_ENVIRONMENT_NAME, TRUE);
		// Check EFI
		if (!IsEfiBoot()) {
			throw ErrorException(L"can not detect EFI environment", SRC_POS);
		}
		
		if (bDeviceInfoValid)
		{
			uint32 varSize = 56;
			varSize += ((uint32) description.length()) * 2 + 2;
			varSize += ((uint32) execPath.length()) * 2 + 2;
			uint8 *startVar = new uint8[varSize];
			uint8 *pVar = startVar;

			// Attributes (1b Active, 1000b - Hidden)
			*(uint32 *)pVar = attr;
			pVar += sizeof(uint32);

			// Size Of device path + file path
			*(uint16 *)pVar = (uint16)(50 + execPath.length() * 2 + 2);
			pVar += sizeof(uint16);

			// description
			for (uint32 i = 0; i < description.length(); i++) {
				*(uint16 *)pVar = description[i];
				pVar += sizeof(uint16);
			}
			*(uint16 *)pVar = 0;
			pVar += sizeof(uint16);

			/* EFI_DEVICE_PATH_PROTOCOL (HARDDRIVE_DEVICE_PATH \ FILE_PATH \ END) */

			// Type
			*(uint8 *)pVar = 0x04;
			pVar += sizeof(uint8);

			// SubType
			*(uint8 *)pVar = 0x01;
			pVar += sizeof(uint8);

			// HDD dev path length
			*(uint16 *)pVar = 0x2A; // 42
			pVar += sizeof(uint16);
		
			// PartitionNumber
			*(uint32 *)pVar = (uint32)partInfo.PartitionNumber;
			pVar += sizeof(uint32);

			// PartitionStart
			*(uint64 *)pVar = partInfo.StartingOffset.QuadPart >> 9;
			pVar += sizeof(uint64);

			// PartitiontSize
			*(uint64 *)pVar = partInfo.PartitionLength.QuadPart >> 9;
			pVar += sizeof(uint64);

			// GptGuid
			memcpy(pVar, &partInfo.Gpt.PartitionId, 16);
			pVar += 16;

			// MbrType
			*(uint8 *)pVar = 0x02;
			pVar += sizeof(uint8);

			// SigType
			*(uint8 *)pVar = 0x02;
			pVar += sizeof(uint8);

			// Type and sub type 04 04 (file path)
			*(uint16 *)pVar = 0x0404;
			pVar += sizeof(uint16);

			// SizeOfFilePath ((CHAR16)FullPath.length + sizeof(EndOfrecord marker) )
			*(uint16 *)pVar = (uint16)(execPath.length() * 2 + 2 + sizeof(uint32));
			pVar += sizeof(uint16);

			// FilePath
			for (uint32 i = 0; i < execPath.length(); i++) {
				*(uint16 *)pVar = execPath[i];
				pVar += sizeof(uint16);
			}
			*(uint16 *)pVar = 0;
			pVar += sizeof(uint16);

			// EndOfrecord
			*(uint32 *)pVar = 0x04ff7f;
			pVar += sizeof(uint32);

			// Set variable
			wchar_t	varName[256];
			StringCchPrintfW(varName, ARRAYSIZE (varName), L"%s%04X", type == NULL ? L"Boot" : type, statrtOrderNum);

			// only set value if it doesn't already exist
			uint8* existingVar = new uint8[varSize];
			DWORD existingVarLen = GetFirmwareEnvironmentVariableW (varName, EfiVarGuid, existingVar, varSize);
			if ((existingVarLen != varSize) || (0 != memcmp (existingVar, startVar, varSize)))
				SetFirmwareEnvironmentVariable(varName, EfiVarGuid, startVar, varSize);
			delete [] startVar;
			delete [] existingVar;
		}

		// Update order
		wstring order = L"Order";
		order.insert(0, type == NULL ? L"Boot" : type);

		uint32 startOrderLen = GetFirmwareEnvironmentVariable(order.c_str(), EfiVarGuid, tempBuf, sizeof(tempBuf));
		uint32 startOrderNumPos = UINT_MAX;
		bool	startOrderUpdate = false;
		uint16*	startOrder = (uint16*)tempBuf;
		for (uint32 i = 0; i < startOrderLen / 2; i++) {
			if (startOrder[i] == statrtOrderNum) {
				startOrderNumPos = i;
				break;
			}
		}

		if (setBootEntry)
		{
			// check if first entry in BootOrder is Windows one
			bool bFirstEntryIsWindows = false;
			if (startOrderNumPos != 0)
			{
				wchar_t	varName[256];
				StringCchPrintfW(varName, ARRAYSIZE (varName), L"%s%04X", type == NULL ? L"Boot" : type, startOrder[0]);

				uint8* existingVar = new uint8[512];
				DWORD existingVarLen = GetFirmwareEnvironmentVariableW (varName, EfiVarGuid, existingVar, 512);
				if (existingVarLen > 0)
				{
					if (BufferContainsWideString (existingVar, existingVarLen, L"EFI\\Microsoft\\Boot\\bootmgfw.efi"))
						bFirstEntryIsWindows = true;
				}

				delete [] existingVar;
			}


			// Create new entry if absent
			if (startOrderNumPos == UINT_MAX) {
				if (bDeviceInfoValid)
				{
					if (forceFirstBootEntry && bFirstEntryIsWindows)
					{
						for (uint32 i = startOrderLen / 2; i > 0; --i) {
							startOrder[i] = startOrder[i - 1];
						}
						startOrder[0] = statrtOrderNum;
					}
					else
					{
						startOrder[startOrderLen/2] = statrtOrderNum;
					}
					startOrderLen += 2;
					startOrderUpdate = true;
				}
			} else if ((startOrderNumPos > 0) && forceFirstBootEntry && bFirstEntryIsWindows) {
				for (uint32 i = startOrderNumPos; i > 0; --i) {
					startOrder[i] = startOrder[i - 1];
				}
				startOrder[0] = statrtOrderNum;
				startOrderUpdate = true;
			}

			if (startOrderUpdate) {
				SetFirmwareEnvironmentVariable(order.c_str(), EfiVarGuid, startOrder, startOrderLen);
			}
		}

		if (setBootNext)
		{
			// set BootNext value
			wstring next = L"Next";
			next.insert(0, type == NULL ? L"Boot" : type);

			SetFirmwareEnvironmentVariable(next.c_str(), EfiVarGuid, &statrtOrderNum, 2);

		}
	}

	bool EfiBoot::CompareFiles (const wchar_t* fileName1, const wchar_t* fileName2)
	{
		bool bRet = false;
		File f1 (fileName1, true);
		File f2 (fileName2, true);

		if (f1.IsOpened() && f2.IsOpened())
		{
			try
			{
				DWORD size1, size2;
				f1.GetFileSize (size1);
				f2.GetFileSize (size2);

				if (size1 == size2)
				{
					// same size, so now we compare content
					std::vector<uint8> file1Buf (8096);
					std::vector<uint8> file2Buf (8096);
					DWORD remainingBytes = size1, dataToRead;

					while (remainingBytes)
					{
						dataToRead = VC_MIN (remainingBytes, (DWORD) file1Buf.size());
						DWORD f1Bytes = f1.Read (file1Buf.data(), dataToRead);
						DWORD f2Bytes = f2.Read (file2Buf.data(), dataToRead);

						if ((f1Bytes != f2Bytes) || memcmp (file1Buf.data(), file2Buf.data(), (size_t) f1Bytes))
						{
							break;
						}
						else
						{
							remainingBytes -= f1Bytes;
						}
					}

					if (0 == remainingBytes)
					{
						// content is the same
						bRet = true;
					}
				}
			}
			catch (...) {}
		}

		f1.Close();
		f2.Close();

		return bRet;
	}

	bool EfiBoot::CompareFileData (const wchar_t* fileName, const uint8* data, DWORD size)
	{
		bool bRet = false;

		File f(fileName, true);
		if (f.IsOpened ())
		{
			try
			{
				// check if the file has the same content
				// if yes, don't perform any write operation to avoid changing its timestamp
				DWORD existingSize = 0;

				f.GetFileSize(existingSize);				
				
				if (existingSize == size)
				{
					std::vector<uint8> fileBuf (8096);
					DWORD remainingBytes = size, dataOffset = 0, dataToRead;

					while (remainingBytes)
					{
						dataToRead = VC_MIN (remainingBytes, (DWORD) fileBuf.size());
						dataToRead = f.Read (fileBuf.data(), dataToRead);

						if (memcmp (data + dataOffset, fileBuf.data(), (size_t) dataToRead))
						{
							break;
						}
						else
						{
							dataOffset += dataToRead;
							remainingBytes -= dataToRead;
						}
					}

					if (0 == remainingBytes)
					{
						// content is the same
						bRet = true;
					}
				}			
			}
			catch (...){}
		}
		
		f.Close();

		return bRet;
	}

	void EfiBoot::SaveFile(const wchar_t* name, uint8* data, DWORD size) {
		wstring path = EfiBootPartPath;
		path += name;

		if (!CompareFileData (path.c_str(), data, size))
		{
			File f(path, false, true);
			f.Write(data, size);
			f.Close();
		}
	}

	bool EfiBoot::FileExists(const wchar_t* name) {
		wstring path = EfiBootPartPath;
		path += name;
		File f(path, true);
		bool bRet = f.IsOpened ();
		f.Close();
		return bRet;
	}

	void EfiBoot::GetFileSize(const wchar_t* name, unsigned __int64& size) {
		wstring path = EfiBootPartPath;
		path += name;
		File f(path, true);
		f.GetFileSize(size);
		f.Close();
	}

	void EfiBoot::ReadFile(const wchar_t* name, uint8* data, DWORD size) {
		wstring path = EfiBootPartPath;
		path += name;
		File f(path, true);
		f.Read(data, size);
		f.Close();
	}

	void EfiBoot::CopyFile(const wchar_t* name, const wchar_t* targetName) {
		wstring path = EfiBootPartPath;
		path += name;
		wstring targetPath;
		if (targetName[0] == L'\\')
		{
			targetPath = EfiBootPartPath;
			targetPath += targetName;
		}
		else
			targetPath = targetName;

		// if both files are the same, we don't perform copy operation
		if (!CompareFiles (path.c_str(), targetPath.c_str()))
			throw_sys_if (!::CopyFileW (path.c_str(), targetPath.c_str(), FALSE));
	}

	BOOL EfiBoot::RenameFile(const wchar_t* name, const wchar_t* nameNew, BOOL bForce) {
		wstring path = EfiBootPartPath;
		path += name;
		wstring pathNew = EfiBootPartPath;
		pathNew += nameNew;
		
		BOOL bRet;
		if (CompareFiles (path.c_str(), pathNew.c_str()))
		{
			// files identical. Delete source file only
			bRet = DeleteFile (path.c_str());
		}
		else
			bRet = MoveFileExW(path.c_str(), pathNew.c_str(), bForce? MOVEFILE_REPLACE_EXISTING : 0);
		return bRet;
	}

	BOOL EfiBoot::DelFile(const wchar_t* name) {
		wstring path = EfiBootPartPath;
		path += name;
		return DeleteFile(path.c_str());
	}

	BOOL EfiBoot::MkDir(const wchar_t* name, bool& bAlreadyExists) {
		wstring path = EfiBootPartPath;
		path += name;
		bAlreadyExists = false;
		BOOL bRet = CreateDirectory(path.c_str(), NULL);
		if (!bRet && (GetLastError () == ERROR_ALREADY_EXISTS))
		{
			bRet = TRUE;
			bAlreadyExists = true;
		}
		return bRet;
	}

	BOOL EfiBoot::DelDir(const wchar_t* name) {
		wstring path = EfiBootPartPath;
		path += name;
		return DeleteDirectory (path.c_str());
	}

	BOOL EfiBoot::ReadConfig (const wchar_t* name, EfiBootConf& conf)
	{
		wstring path = EfiBootPartPath;
		path += name;

		return conf.Load (path.c_str());
	}

	BOOL EfiBoot::UpdateConfig (const wchar_t* name, int pim, int hashAlgo, HWND hwndDlg)
	{
		BOOL bRet = FALSE;
		EfiBootConf conf;
		wstring path = EfiBootPartPath;
		path += name;

		if (conf.Load (path.c_str()))
		{
			if (pim >= 0)
			{
				conf.pim = pim;
				conf.requestPim = 0;
			}
			else
			{
				conf.pim = 0;
				conf.requestPim = 1;
			}

			if (hashAlgo >= 0)
			{
				conf.hashAlgo = hashAlgo;
				conf.requestHash = 0;
			}
			else
			{
				conf.hashAlgo = 0;
				conf.requestHash = 1;
			}

			return conf.Save (path.c_str(), hwndDlg);
		}

		return bRet;
	}

	BOOL EfiBoot::WriteConfig (const wchar_t* name, bool preserveUserConfig, int pim, int hashAlgo, const char* passPromptMsg, HWND hwndDlg)
	{
		EfiBootConf conf;
		wstring path = EfiBootPartPath;
		path += name;

		if (preserveUserConfig)
		{
			conf.Load (path.c_str());
			if (pim >= 0 && (conf.requestPim == 0))
			{
				conf.pim = pim;
			}
			if (hashAlgo >= 0 && (conf.requestHash == 0))
			{
				conf.hashAlgo = hashAlgo;
			}
		}
		else
		{
			if (pim >= 0)
			{
				conf.pim = pim;
				conf.requestPim = 0;
			}
			else
			{
				conf.pim = 0;
				conf.requestPim = 1;
			}

			if (hashAlgo >= 0)
			{
				conf.hashAlgo = hashAlgo;
				conf.requestHash = 0;
			}
			else
			{
				conf.hashAlgo = 0;
				conf.requestHash = 1;
			}
		}

		if (passPromptMsg && strlen (passPromptMsg))
		{
			conf.passwordMsg = passPromptMsg;
		}

		return conf.Save (path.c_str(), hwndDlg);
	}

	void BootEncryption::UpdateSetupConfigFile (bool bForInstall)
	{
		// starting from Windows 10 1607 (Build 14393), ReflectDrivers in Setupconfig.ini is supported
		if (IsOSVersionAtLeast (WIN_10, 0) && CurrentOSBuildNumber >= 14393)
		{
			wchar_t szInstallPath [TC_MAX_PATH];
			wchar_t szSetupconfigLocation [TC_MAX_PATH + 20];

			if (bForInstall)
			{
				GetInstallationPath (NULL, szInstallPath, ARRAYSIZE (szInstallPath), NULL);
				// remove ending backslash
				if (szInstallPath [wcslen (szInstallPath) - 1] == L'\\')
				{
					szInstallPath [wcslen (szInstallPath) - 1] = 0;
				}
			}
			if (GetSetupconfigLocation (szSetupconfigLocation, ARRAYSIZE (szSetupconfigLocation)))
			{
				if (bForInstall)
					::CreateDirectoryW (szSetupconfigLocation, NULL);

				StringCchCatW (szSetupconfigLocation, ARRAYSIZE (szSetupconfigLocation), L"SetupConfig.ini");

				if (bForInstall)
				{
					/* Before updating files, we check first if they already have the expected content. If yes, then we don't perform
					 * any write operation to avoid modifying file timestamps Unnecessarily.
					 */
					bool bSkipWrite = false;
					wchar_t wszBuffer [2 * TC_MAX_PATH] = {0};
					wstring szPathParam = L"\"";
					szPathParam += szInstallPath;
					szPathParam += L"\"";

					if (	(0 < GetPrivateProfileStringW (L"SetupConfig", L"ReflectDrivers", L"", wszBuffer, ARRAYSIZE (wszBuffer), szSetupconfigLocation))
						&&	(_wcsicmp (wszBuffer, szInstallPath) == 0)
						)
					{
						bSkipWrite = true;
					}

					if (!bSkipWrite)
						WritePrivateProfileStringW (L"SetupConfig", L"ReflectDrivers", szPathParam.c_str(), szSetupconfigLocation);

					bSkipWrite = false;
					szPathParam = GetProgramConfigPath (L"SetupComplete.cmd");

					wstring wszExpectedValue = L"\"";
					wszExpectedValue += szInstallPath;
					wszExpectedValue += L"\\VeraCrypt.exe\" /PostOOBE";

					FILE* scriptFile = _wfopen (szPathParam.c_str(), L"r");
					if (scriptFile)
					{
						long fileSize = _filelength (_fileno (scriptFile));
						if (fileSize < (2 * TC_MAX_PATH))
						{
							fgetws (wszBuffer, ARRAYSIZE (wszBuffer), scriptFile);

							if (wszBuffer[wcslen (wszBuffer) - 1] == L'\n')
								wszBuffer[wcslen (wszBuffer) - 1] = 0;

							bSkipWrite = (0 == _wcsicmp (wszBuffer, wszExpectedValue.c_str()));
						}
						fclose (scriptFile);
					}

					if (!bSkipWrite)
					{
						scriptFile = _wfopen (szPathParam.c_str(), L"w");
						if (scriptFile)
						{
							fwprintf (scriptFile, L"%s\n", wszExpectedValue.c_str());
							fclose (scriptFile);
						}
					}

					bSkipWrite = false;

					if (	(0 < GetPrivateProfileStringW (L"SetupConfig", L"PostOOBE", L"", wszBuffer, ARRAYSIZE (wszBuffer), szSetupconfigLocation))
						&&	(_wcsicmp (wszBuffer, szPathParam.c_str()) == 0)
						)
					{
						bSkipWrite = true;
					}

					if (!bSkipWrite)
						WritePrivateProfileStringW (L"SetupConfig", L"PostOOBE", szPathParam.c_str(), szSetupconfigLocation);
				}
				else
				{
					if (FileExists (szSetupconfigLocation))
					{
						WritePrivateProfileStringW (L"SetupConfig", L"ReflectDrivers", NULL, szSetupconfigLocation);
						WritePrivateProfileStringW (L"SetupConfig", L"PostOOBE", NULL, szSetupconfigLocation);
					}

					wstring scriptFilePath = GetProgramConfigPath (L"SetupComplete.cmd");
					if (FileExists (scriptFilePath.c_str()))
					{
						::DeleteFileW (scriptFilePath.c_str());
					}
				}
			}
		}
	}

	void BootEncryption::InstallBootLoader (bool preserveUserConfig, bool hiddenOSCreation, int pim, int hashAlg)
	{
		Device device (GetSystemDriveConfiguration().DevicePath);
		device.CheckOpened (SRC_POS);

		InstallBootLoader (device, preserveUserConfig, hiddenOSCreation, pim, hashAlg);
	}

	void BootEncryption::InstallBootLoader (Device& device, bool preserveUserConfig, bool hiddenOSCreation, int pim, int hashAlg)
	{
		SystemDriveConfiguration config = GetSystemDriveConfiguration();

		if (config.SystemPartition.IsGPT) {
			if (!IsAdmin()) {
				if (IsUacSupported())
				{
					Elevator::InstallEfiBootLoader (preserveUserConfig, hiddenOSCreation, pim, hashAlg);
					return;
				}
				else
				{
					Warning ("ADMIN_PRIVILEGES_WARN_DEVICES", ParentWindow);
				}
			}
			DWORD sizeDcsBoot;
#ifdef _WIN64
			uint8 *dcsBootImg = MapResource(L"BIN", IDR_EFI_DCSBOOT, &sizeDcsBoot);
#else
			uint8 *dcsBootImg = MapResource(L"BIN", Is64BitOs()? IDR_EFI_DCSBOOT : IDR_EFI_DCSBOOT32, &sizeDcsBoot);
#endif
			if (!dcsBootImg)
				throw ErrorException(L"Out of resource DcsBoot", SRC_POS);
			DWORD sizeDcsInt;
#ifdef _WIN64
			uint8 *dcsIntImg = MapResource(L"BIN", IDR_EFI_DCSINT, &sizeDcsInt);
#else
			uint8 *dcsIntImg = MapResource(L"BIN", Is64BitOs()? IDR_EFI_DCSINT: IDR_EFI_DCSINT32, &sizeDcsInt);
#endif
			if (!dcsIntImg)
				throw ErrorException(L"Out of resource DcsInt", SRC_POS);
			DWORD sizeDcsCfg;
#ifdef _WIN64
			uint8 *dcsCfgImg = MapResource(L"BIN", IDR_EFI_DCSCFG, &sizeDcsCfg);
#else
			uint8 *dcsCfgImg = MapResource(L"BIN", Is64BitOs()? IDR_EFI_DCSCFG: IDR_EFI_DCSCFG32, &sizeDcsCfg);
#endif
			if (!dcsCfgImg)
				throw ErrorException(L"Out of resource DcsCfg", SRC_POS);
			DWORD sizeLegacySpeaker;
#ifdef _WIN64
			uint8 *LegacySpeakerImg = MapResource(L"BIN", IDR_EFI_LEGACYSPEAKER, &sizeLegacySpeaker);
#else
			uint8 *LegacySpeakerImg = MapResource(L"BIN", Is64BitOs()? IDR_EFI_LEGACYSPEAKER: IDR_EFI_LEGACYSPEAKER32, &sizeLegacySpeaker);
#endif
			if (!LegacySpeakerImg)
				throw ErrorException(L"Out of resource LegacySpeaker", SRC_POS);
#ifdef VC_EFI_CUSTOM_MODE
			DWORD sizeBootMenuLocker;
#ifdef _WIN64
			uint8 *BootMenuLockerImg = MapResource(L"BIN", IDR_EFI_DCSBML, &sizeBootMenuLocker);
#else
			uint8 *BootMenuLockerImg = MapResource(L"BIN", Is64BitOs()? IDR_EFI_DCSBML: IDR_EFI_DCSBML32, &sizeBootMenuLocker);
#endif
			if (!BootMenuLockerImg)
				throw ErrorException(L"Out of resource DcsBml", SRC_POS);
#endif
			DWORD sizeDcsInfo;
#ifdef _WIN64
			uint8 *DcsInfoImg = MapResource(L"BIN", IDR_EFI_DCSINFO, &sizeDcsInfo);
#else
			uint8 *DcsInfoImg = MapResource(L"BIN", Is64BitOs()? IDR_EFI_DCSINFO: IDR_EFI_DCSINFO32, &sizeDcsInfo);
#endif
			if (!DcsInfoImg)
				throw ErrorException(L"Out of resource DcsInfo", SRC_POS);

			EfiBootInst.PrepareBootPartition(PostOOBEMode);			

			try
			{
				// Save modules
				bool bAlreadyExist;
				const char* g_szMsBootString = "bootmgfw.pdb";
				unsigned __int64 loaderSize = 0;
				const wchar_t * szStdEfiBootloader = Is64BitOs()? L"\\EFI\\Boot\\bootx64.efi": L"\\EFI\\Boot\\bootia32.efi";
				const wchar_t * szBackupEfiBootloader = Is64BitOs()? L"\\EFI\\Boot\\original_bootx64.vc_backup": L"\\EFI\\Boot\\original_bootia32.vc_backup";

				if (preserveUserConfig)
				{
					bool bModifiedMsBoot = true, bMissingMsBoot = false;;
					if (EfiBootInst.FileExists (L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi"))
						EfiBootInst.GetFileSize(L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi", loaderSize);
					else
						bMissingMsBoot = true;

					// restore boot menu entry in case of PostOOBE
					if (PostOOBEMode)
						EfiBootInst.SetStartExec(L"VeraCrypt BootLoader (DcsBoot)", L"\\EFI\\VeraCrypt\\DcsBoot.efi", SetBootEntry, ForceFirstBootEntry, SetBootNext);

					if (EfiBootInst.FileExists (L"\\EFI\\Microsoft\\Boot\\bootmgfw_ms.vc"))
					{
						if (loaderSize > 32768)
						{
							std::vector<uint8> bootLoaderBuf ((size_t) loaderSize);

							EfiBootInst.ReadFile(L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi", &bootLoaderBuf[0], (DWORD) loaderSize);

							// look for bootmgfw.efi identifiant string
							if (BufferHasPattern (bootLoaderBuf.data (), (size_t) loaderSize, g_szMsBootString, strlen (g_szMsBootString)))
							{
								bModifiedMsBoot = false;
								// replace the backup with this version
								EfiBootInst.RenameFile (L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi", L"\\EFI\\Microsoft\\Boot\\bootmgfw_ms.vc", TRUE);
							}
						}
					}
					else
					{						
						// DcsBoot.efi is always smaller than 32KB
						if (loaderSize > 32768)
						{
							std::vector<uint8> bootLoaderBuf ((size_t) loaderSize);

							EfiBootInst.ReadFile(L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi", &bootLoaderBuf[0], (DWORD) loaderSize);

							// look for bootmgfw.efi identifiant string
							if (BufferHasPattern (bootLoaderBuf.data (), (size_t) loaderSize, g_szMsBootString, strlen (g_szMsBootString)))
								bModifiedMsBoot = false;
						}

						if (!bModifiedMsBoot)
						{
							EfiBootInst.RenameFile (L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi", L"\\EFI\\Microsoft\\Boot\\bootmgfw_ms.vc", TRUE);
						}
						else
						{
							bool bFound = false;
							EfiBootConf conf;
							if (EfiBootInst.ReadConfig (L"\\EFI\\VeraCrypt\\DcsProp", conf) && strlen (conf.actionSuccessValue.c_str()))
							{
								wstring loaderPath;
								if (EfiBootConf::IsPostExecFileField (conf.actionSuccessValue, loaderPath))
								{
									// check that it is not bootmgfw.efi
									if (	(0 != _wcsicmp (loaderPath.c_str(), L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi"))
										&&	(EfiBootInst.FileExists (loaderPath.c_str()))
										)
									{
										// look for bootmgfw.efi identifiant string
										EfiBootInst.GetFileSize(loaderPath.c_str(), loaderSize);
										std::vector<uint8> bootLoaderBuf ((size_t) loaderSize);

										EfiBootInst.ReadFile(loaderPath.c_str(), &bootLoaderBuf[0], (DWORD) loaderSize);

										// look for bootmgfw.efi identifiant string
										if (BufferHasPattern (bootLoaderBuf.data (), (size_t) loaderSize, g_szMsBootString, strlen (g_szMsBootString)))
										{
											bFound = true;
											EfiBootInst.RenameFile(loaderPath.c_str(), L"\\EFI\\Microsoft\\Boot\\bootmgfw_ms.vc", TRUE);
										}
									}
								}
							}

							if (!bFound && !PostOOBEMode)
								throw ErrorException ("WINDOWS_EFI_BOOT_LOADER_MISSING", SRC_POS);
						}
					}

					if (PostOOBEMode && EfiBootInst.FileExists (L"\\EFI\\VeraCrypt\\DcsBoot.efi"))
					{						
						// check if bootmgfw.efi has been set again to Microsoft version
						// if yes, replace it with our bootloader after it was copied to bootmgfw_ms.vc
						if (!bModifiedMsBoot || bMissingMsBoot)
							EfiBootInst.CopyFile (L"\\EFI\\VeraCrypt\\DcsBoot.efi", L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi");

						if (EfiBootInst.FileExists (szStdEfiBootloader))
						{
							// check if standard bootloader under EFI\Boot has been set to Microsoft version
							// if yes, replace it with our bootloader
							EfiBootInst.GetFileSize(szStdEfiBootloader, loaderSize);
							if (loaderSize > 32768)
							{
								std::vector<uint8> bootLoaderBuf ((size_t) loaderSize);

								EfiBootInst.ReadFile(szStdEfiBootloader, &bootLoaderBuf[0], (DWORD) loaderSize);

								// look for bootmgfw.efi identifiant string
								if (BufferHasPattern (bootLoaderBuf.data (), (size_t) loaderSize, g_szMsBootString, strlen (g_szMsBootString)))
								{
									EfiBootInst.RenameFile (szStdEfiBootloader, szBackupEfiBootloader, TRUE);
									EfiBootInst.CopyFile (L"\\EFI\\VeraCrypt\\DcsBoot.efi", szStdEfiBootloader);
								}
							}
						}
						return;
					}
				}

				EfiBootInst.MkDir(L"\\EFI\\VeraCrypt", bAlreadyExist);
				EfiBootInst.SaveFile(L"\\EFI\\VeraCrypt\\DcsBoot.efi", dcsBootImg, sizeDcsBoot);
				EfiBootInst.SaveFile(L"\\EFI\\VeraCrypt\\DcsInt.dcs", dcsIntImg, sizeDcsInt);
				EfiBootInst.SaveFile(L"\\EFI\\VeraCrypt\\DcsCfg.dcs", dcsCfgImg, sizeDcsCfg);
				EfiBootInst.SaveFile(L"\\EFI\\VeraCrypt\\LegacySpeaker.dcs", LegacySpeakerImg, sizeLegacySpeaker);
#ifdef VC_EFI_CUSTOM_MODE
				EfiBootInst.SaveFile(L"\\EFI\\VeraCrypt\\DcsBml.dcs", BootMenuLockerImg, sizeBootMenuLocker);
#endif
				EfiBootInst.SaveFile(L"\\EFI\\VeraCrypt\\DcsInfo.dcs", DcsInfoImg, sizeDcsInfo);
				if (!preserveUserConfig)
					EfiBootInst.DelFile(L"\\EFI\\VeraCrypt\\PlatformInfo");
				EfiBootInst.SetStartExec(L"VeraCrypt BootLoader (DcsBoot)", L"\\EFI\\VeraCrypt\\DcsBoot.efi", SetBootEntry, ForceFirstBootEntry, SetBootNext);

				if (EfiBootInst.FileExists (szStdEfiBootloader))
				{
					// check if standard bootloader under EFI\Boot is Microsoft one or if it is ours
					// if both cases, replace it with our bootloader otherwise do nothing
					EfiBootInst.GetFileSize(szStdEfiBootloader, loaderSize);
					std::vector<uint8> bootLoaderBuf ((size_t) loaderSize);
					EfiBootInst.ReadFile(szStdEfiBootloader, &bootLoaderBuf[0], (DWORD) loaderSize);

					// look for bootmgfw.efi or VeraCrypt identifiant strings
					if (	((loaderSize > 32768) && BufferHasPattern (bootLoaderBuf.data (), (size_t) loaderSize, g_szMsBootString, strlen (g_szMsBootString)))
						)
					{
						EfiBootInst.RenameFile (szStdEfiBootloader, szBackupEfiBootloader, TRUE);
						EfiBootInst.SaveFile(szStdEfiBootloader, dcsBootImg, sizeDcsBoot);
					}
					if (	((loaderSize <= 32768) && BufferHasPattern (bootLoaderBuf.data (), (size_t) loaderSize, _T(TC_APP_NAME), strlen (TC_APP_NAME) * 2))
						)
					{
						EfiBootInst.SaveFile(szStdEfiBootloader, dcsBootImg, sizeDcsBoot);
					}
				}
				EfiBootInst.SaveFile(L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi", dcsBootImg, sizeDcsBoot);
				// move configuration file from old location (if it exists) to new location
				// we don't force the move operation if the new location already exists
				EfiBootInst.RenameFile (L"\\DcsProp", L"\\EFI\\VeraCrypt\\DcsProp", FALSE);
				EfiBootInst.RenameFile (L"\\DcsBoot", L"\\EFI\\VeraCrypt\\DcsBoot", FALSE);

				// move the original bootloader backup from old location (if it exists) to new location
				// we don't force the move operation if the new location already exists
				if (Is64BitOs())
					EfiBootInst.RenameFile (L"\\EFI\\Boot\\original_bootx64_vc_backup.efi", L"\\EFI\\Boot\\original_bootx64.vc_backup", FALSE);
				else
					EfiBootInst.RenameFile (L"\\EFI\\Boot\\original_bootia32_vc_backup.efi", L"\\EFI\\Boot\\original_bootia32.vc_backup", FALSE);

				// Clean beta9
				EfiBootInst.DelFile(L"\\DcsBoot.efi");
				EfiBootInst.DelFile(L"\\DcsInt.efi");
				EfiBootInst.DelFile(L"\\DcsCfg.efi");
				EfiBootInst.DelFile(L"\\LegacySpeaker.efi");
				EfiBootInst.DelFile(L"\\DcsBoot");
				EfiBootInst.DelFile(L"\\DcsProp");
#ifndef VC_EFI_CUSTOM_MODE
				// remove DcsBml if it exists since we don't use it in non-custom SecureBoot mode
				EfiBootInst.DelFile(L"\\EFI\\VeraCrypt\\DcsBml.dcs");
#endif
			}
			catch (...)
			{
				throw;
			}

			EfiBootInst.WriteConfig (L"\\EFI\\VeraCrypt\\DcsProp", preserveUserConfig, pim, hashAlg, NULL, ParentWindow);
		}
		else
		{
			try
			{
				uint8 bootLoaderBuf[TC_BOOT_LOADER_AREA_SIZE - TC_BOOT_ENCRYPTION_VOLUME_HEADER_SIZE] = {0};
				CreateBootLoaderInMemory (bootLoaderBuf, sizeof (bootLoaderBuf), false, hiddenOSCreation);

				// Write MBR
				uint8 mbr[TC_SECTOR_SIZE_BIOS];

				device.SeekAt (0);
				device.Read (mbr, sizeof (mbr));

				if (preserveUserConfig && BufferContainsString (mbr, sizeof (mbr), TC_APP_NAME))
				{
					uint16 version = BE16 (*(uint16 *) (mbr + TC_BOOT_SECTOR_VERSION_OFFSET));
					if (version != 0)
					{
						bootLoaderBuf[TC_BOOT_SECTOR_USER_CONFIG_OFFSET] = mbr[TC_BOOT_SECTOR_USER_CONFIG_OFFSET];
						memcpy (bootLoaderBuf + TC_BOOT_SECTOR_USER_MESSAGE_OFFSET, mbr + TC_BOOT_SECTOR_USER_MESSAGE_OFFSET, TC_BOOT_SECTOR_USER_MESSAGE_MAX_LENGTH);

						if (bootLoaderBuf[TC_BOOT_SECTOR_USER_CONFIG_OFFSET] & TC_BOOT_USER_CFG_FLAG_DISABLE_PIM)
						{
							if (pim >= 0)
							{
								memcpy (bootLoaderBuf + TC_BOOT_SECTOR_PIM_VALUE_OFFSET, &pim, TC_BOOT_SECTOR_PIM_VALUE_SIZE);
							}
							else
								memcpy (bootLoaderBuf + TC_BOOT_SECTOR_PIM_VALUE_OFFSET, mbr + TC_BOOT_SECTOR_PIM_VALUE_OFFSET, TC_BOOT_SECTOR_PIM_VALUE_SIZE);
						}
					}
				}

				// perform actual write only if content is different and either we are not in PostOOBE mode or the MBR contains VeraCrypt/Windows signature.
				// this last check is done to avoid interfering with multi-boot configuration where MBR belongs to a boot manager like Grub
				if (memcmp (mbr, bootLoaderBuf, TC_MAX_MBR_BOOT_CODE_SIZE) 
					&& (!PostOOBEMode || BufferContainsString (mbr, sizeof (mbr), TC_APP_NAME) || IsWindowsMBR (mbr, sizeof (mbr))))
				{
					memcpy (mbr, bootLoaderBuf, TC_MAX_MBR_BOOT_CODE_SIZE);

					device.SeekAt (0);
					device.Write (mbr, sizeof (mbr));

					uint8 mbrVerificationBuf[TC_SECTOR_SIZE_BIOS];
					device.SeekAt (0);
					device.Read (mbrVerificationBuf, sizeof (mbr));

					if (memcmp (mbr, mbrVerificationBuf, sizeof (mbr)) != 0)
						throw ErrorException ("ERROR_MBR_PROTECTED", SRC_POS);
				}

				if (!PostOOBEMode)
				{
					// Write boot loader
					device.SeekAt (TC_SECTOR_SIZE_BIOS);
					device.Write (bootLoaderBuf + TC_SECTOR_SIZE_BIOS, sizeof (bootLoaderBuf) - TC_SECTOR_SIZE_BIOS);
				}
			}
			catch (...)
			{
				if (!PostOOBEMode)
					throw;
			}
		}

		if (!IsAdmin() && IsUacSupported())
		{
			Elevator::UpdateSetupConfigFile (true);
		}
		else
		{
			UpdateSetupConfigFile (true);
		}
	}

#ifndef SETUP
	bool BootEncryption::CheckBootloaderFingerprint (bool bSilent)
	{
		SystemDriveConfiguration config = GetSystemDriveConfiguration();

		// return true for now when EFI system encryption is used until we implement
		// a dedicated EFI fingerprinting mechanism in VeraCrypt driver
		if (config.SystemPartition.IsGPT)
			return true;

		uint8 bootLoaderBuf[TC_BOOT_LOADER_AREA_SIZE - TC_BOOT_ENCRYPTION_VOLUME_HEADER_SIZE] = {0};
		uint8 fingerprint[WHIRLPOOL_DIGESTSIZE + SHA512_DIGESTSIZE];
		uint8 expectedFingerprint[WHIRLPOOL_DIGESTSIZE + SHA512_DIGESTSIZE];
		bool bRet = false;

		try
		{
			// read bootloader fingerprint
			GetInstalledBootLoaderFingerprint (fingerprint);

			// compute expected fingerprint
			CreateBootLoaderInMemory (bootLoaderBuf, sizeof (bootLoaderBuf), false, false);
			::ComputeBootloaderFingerprint (bootLoaderBuf, sizeof (bootLoaderBuf), expectedFingerprint);

			// compare values
			if (0 == memcmp (fingerprint, expectedFingerprint, sizeof (expectedFingerprint)))
			{
				bRet = true;
			}
		}
		catch (SystemException &e)
		{
			if (!bSilent && (GetLastError () != ERROR_INVALID_IMAGE_HASH))
				e.Show (ParentWindow);
		}
		catch (Exception& e)
		{
			if (!bSilent)
				e.Show (ParentWindow);
		}

		return bRet;
	}
#endif

	wstring BootEncryption::GetSystemLoaderBackupPath ()
	{
		WCHAR pathBuf[MAX_PATH];

		throw_sys_if (!SUCCEEDED (SHGetFolderPath (NULL, CSIDL_COMMON_APPDATA | CSIDL_FLAG_CREATE, NULL, 0, pathBuf)));
		
		wstring path = wstring (pathBuf) + L"\\" _T(TC_APP_NAME);
		CreateDirectory (path.c_str(), NULL);

		return path + L'\\' + TC_SYS_BOOT_LOADER_BACKUP_NAME;
	}


	void BootEncryption::RenameDeprecatedSystemLoaderBackup ()
	{
		WCHAR pathBuf[MAX_PATH];

		if (SUCCEEDED (SHGetFolderPath (NULL, CSIDL_COMMON_APPDATA, NULL, 0, pathBuf)))
		{
			wstring path = wstring (pathBuf) + L"\\" _T(TC_APP_NAME) + L'\\' + TC_SYS_BOOT_LOADER_BACKUP_NAME_LEGACY;

			if (FileExists (path.c_str()) && !FileExists (GetSystemLoaderBackupPath().c_str()))
				throw_sys_if (_wrename (path.c_str(), GetSystemLoaderBackupPath().c_str()) != 0);
		}
	}


#ifndef SETUP
	void BootEncryption::CreateRescueIsoImage (bool initialSetup, const wstring &isoImagePath)
	{
		BootEncryptionStatus encStatus = GetStatus();
		if (encStatus.SetupInProgress)
			throw ParameterIncorrect (SRC_POS);
		BOOL bIsGPT = GetSystemDriveConfiguration().SystemPartition.IsGPT;
		if (bIsGPT)
		{
			// create EFI disk structure
			DWORD sizeDcsBoot;
#ifdef _WIN64
			uint8 *dcsBootImg = MapResource(L"BIN", IDR_EFI_DCSBOOT, &sizeDcsBoot);
#else
			uint8 *dcsBootImg = MapResource(L"BIN", Is64BitOs()? IDR_EFI_DCSBOOT : IDR_EFI_DCSBOOT32, &sizeDcsBoot);
#endif
			if (!dcsBootImg)
				throw ParameterIncorrect (SRC_POS);
			DWORD sizeDcsInt;
#ifdef _WIN64
			uint8 *dcsIntImg = MapResource(L"BIN", IDR_EFI_DCSINT, &sizeDcsInt);
#else
			uint8 *dcsIntImg = MapResource(L"BIN", Is64BitOs()? IDR_EFI_DCSINT: IDR_EFI_DCSINT32, &sizeDcsInt);
#endif
			if (!dcsIntImg)
				throw ParameterIncorrect (SRC_POS);
			DWORD sizeDcsCfg;
#ifdef _WIN64
			uint8 *dcsCfgImg = MapResource(L"BIN", IDR_EFI_DCSCFG, &sizeDcsCfg);
#else
			uint8 *dcsCfgImg = MapResource(L"BIN", Is64BitOs()? IDR_EFI_DCSCFG: IDR_EFI_DCSCFG32, &sizeDcsCfg);
#endif
			if (!dcsCfgImg)
				throw ParameterIncorrect (SRC_POS);
			DWORD sizeLegacySpeaker;
#ifdef _WIN64
			uint8 *LegacySpeakerImg = MapResource(L"BIN", IDR_EFI_LEGACYSPEAKER, &sizeLegacySpeaker);
#else
			uint8 *LegacySpeakerImg = MapResource(L"BIN", Is64BitOs()? IDR_EFI_LEGACYSPEAKER: IDR_EFI_LEGACYSPEAKER32, &sizeLegacySpeaker);
#endif
			if (!LegacySpeakerImg)
				throw ParameterIncorrect (SRC_POS);
#ifdef VC_EFI_CUSTOM_MODE
			DWORD sizeBootMenuLocker;
#ifdef _WIN64
			uint8 *BootMenuLockerImg = MapResource(L"BIN", IDR_EFI_DCSBML, &sizeBootMenuLocker);
#else
			uint8 *BootMenuLockerImg = MapResource(L"BIN", Is64BitOs()? IDR_EFI_DCSBML: IDR_EFI_DCSBML32, &sizeBootMenuLocker);
#endif
			if (!BootMenuLockerImg)
				throw ParameterIncorrect (SRC_POS);
#endif
			DWORD sizeDcsRescue;
#ifdef _WIN64
			uint8 *DcsRescueImg = MapResource(L"BIN", IDR_EFI_DCSRE, &sizeDcsRescue);
#else
			uint8 *DcsRescueImg = MapResource(L"BIN", Is64BitOs()? IDR_EFI_DCSRE: IDR_EFI_DCSRE32, &sizeDcsRescue);
#endif
			if (!DcsRescueImg)
				throw ParameterIncorrect (SRC_POS);
			DWORD sizeDcsInfo;
#ifdef _WIN64
			uint8 *DcsInfoImg = MapResource(L"BIN", IDR_EFI_DCSINFO, &sizeDcsInfo);
#else
			uint8 *DcsInfoImg = MapResource(L"BIN", Is64BitOs()? IDR_EFI_DCSINFO: IDR_EFI_DCSINFO32, &sizeDcsInfo);
#endif
			if (!DcsInfoImg)
				throw ParameterIncorrect (SRC_POS);

			WCHAR szTmpPath[MAX_PATH + 1], szTmpFilePath[MAX_PATH + 1];
			if (!GetTempPathW (MAX_PATH, szTmpPath))
				throw SystemException (SRC_POS);
			if (!GetTempFileNameW (szTmpPath, L"_vrd", 0, szTmpFilePath))
				throw SystemException (SRC_POS);

			finally_do_arg (WCHAR*, szTmpFilePath,  { DeleteFileW (finally_arg);});

			int ierr;

			// convert szTmpFilePath to UTF-8 since this is what zip_open expected
			char szUtf8Path[2*MAX_PATH + 1];
			int utf8Len = WideCharToMultiByte (CP_UTF8, 0, szTmpFilePath, -1, szUtf8Path, sizeof (szUtf8Path), NULL, NULL);
			if (utf8Len <= 0)
				throw SystemException (SRC_POS);

			zip_t* z = zip_open (szUtf8Path, ZIP_CREATE | ZIP_TRUNCATE | ZIP_CHECKCONS, &ierr);
			if (!z)
				throw ParameterIncorrect (SRC_POS);

			finally_do_arg (zip_t**, &z, { if (*finally_arg) zip_discard (*finally_arg);});

			if (!ZipAdd (z, Is64BitOs()? "EFI/Boot/bootx64.efi": "EFI/Boot/bootia32.efi", DcsRescueImg, sizeDcsRescue))
				throw ParameterIncorrect (SRC_POS);
#ifdef VC_EFI_CUSTOM_MODE
			if (!ZipAdd (z, "EFI/VeraCrypt/DcsBml.dcs", BootMenuLockerImg, sizeBootMenuLocker))
				throw ParameterIncorrect (SRC_POS);
#endif
			if (!ZipAdd (z, "EFI/VeraCrypt/DcsBoot.efi", dcsBootImg, sizeDcsBoot))
				throw ParameterIncorrect (SRC_POS);
			if (!ZipAdd (z, "EFI/VeraCrypt/DcsCfg.dcs", dcsCfgImg, sizeDcsCfg))
				throw ParameterIncorrect (SRC_POS);
			if (!ZipAdd (z, "EFI/VeraCrypt/DcsInt.dcs", dcsIntImg, sizeDcsInt))
				throw ParameterIncorrect (SRC_POS);
			if (!ZipAdd (z, "EFI/VeraCrypt/LegacySpeaker.dcs", LegacySpeakerImg, sizeLegacySpeaker))
				throw ParameterIncorrect (SRC_POS);
			if (!ZipAdd (z, "EFI/VeraCrypt/DcsInfo.dcs", DcsInfoImg, sizeDcsInfo))
				throw ParameterIncorrect (SRC_POS);

			Buffer volHeader(TC_BOOT_ENCRYPTION_VOLUME_HEADER_SIZE);

			// Volume header
			if (initialSetup)
			{
				if (!RescueVolumeHeaderValid)
					throw ParameterIncorrect (SRC_POS);

				memcpy (volHeader.Ptr (), RescueVolumeHeader, TC_BOOT_ENCRYPTION_VOLUME_HEADER_SIZE);
			}
			else
			{
				Device bootDevice (GetSystemDriveConfiguration().DevicePath, true);
				bootDevice.CheckOpened (SRC_POS);
				bootDevice.SeekAt (TC_BOOT_VOLUME_HEADER_SECTOR_OFFSET);
				bootDevice.Read (volHeader.Ptr (), TC_BOOT_ENCRYPTION_VOLUME_HEADER_SIZE);
			}

			if (!ZipAdd (z, "EFI/VeraCrypt/svh_bak", volHeader.Ptr (), TC_BOOT_ENCRYPTION_VOLUME_HEADER_SIZE))
				throw ParameterIncorrect (SRC_POS);

			// Original system loader
			Buffer fileBuf (0);
			bool bLoadAdded = false;
			try
			{
				DWORD fileSize = 0;
				File sysBakFile (GetSystemLoaderBackupPath(), true);
				sysBakFile.CheckOpened (SRC_POS);
				sysBakFile.GetFileSize(fileSize);
				fileBuf.Resize ((DWORD) fileSize);
				DWORD sizeLoader = sysBakFile.Read (fileBuf.Ptr (), fileSize);
				bLoadAdded = ZipAdd (z, Is64BitOs()? "EFI/Boot/original_bootx64.vc_backup": "EFI/Boot/original_bootia32.vc_backup", fileBuf.Ptr (), sizeLoader);				
			}
			catch (Exception &e)
			{
				e.Show (ParentWindow);
				Warning ("SYS_LOADER_UNAVAILABLE_FOR_RESCUE_DISK", ParentWindow);
			}

			if (!bLoadAdded)
				throw ParameterIncorrect (SRC_POS);			

			EfiBootConf conf;
			Buffer propBuf (0);
			wstring dcsPropFileName = GetTempPathString() + L"_dcsproprescue";
			finally_do_arg (wstring, dcsPropFileName, { DeleteFileW (finally_arg.c_str()); });
			if (conf.Save(dcsPropFileName.c_str(), ParentWindow))
			{
				DWORD fileSize = 0;
				File propFile (dcsPropFileName, true, false);
				propFile.CheckOpened (SRC_POS);
				propFile.GetFileSize(fileSize);
				propBuf.Resize (fileSize);
				DWORD sizeDcsProp = propFile.Read (propBuf.Ptr (), fileSize);

				if (!ZipAdd (z, "EFI/VeraCrypt/DcsProp", propBuf.Ptr (), sizeDcsProp))
					throw ParameterIncorrect (SRC_POS);
			}
			else
				throw ParameterIncorrect (SRC_POS);

			// flush the zip content to the temporary file
			if (zip_close (z) < 0)
				throw ParameterIncorrect (SRC_POS);

			z = NULL;

			// read the zip data from the temporary file
			FILE* ftmpFile = _wfopen (szTmpFilePath, L"rb");
			if (!ftmpFile)
				throw ParameterIncorrect (SRC_POS);

			finally_do_arg (FILE*, ftmpFile, { fclose (finally_arg); });

			unsigned long ulZipSize = (unsigned long) _filelength (_fileno (ftmpFile));
			RescueZipData = new uint8[ulZipSize];
			if (!RescueZipData)
				throw bad_alloc();

			if (ulZipSize != fread (RescueZipData, 1, ulZipSize, ftmpFile))
			{
				delete [] RescueZipData;
				RescueZipData = NULL;
				throw ParameterIncorrect (SRC_POS);
			}

			RescueZipSize = ulZipSize;

			if (!isoImagePath.empty())
			{
				File isoFile (isoImagePath, false, true);
				isoFile.Write (RescueZipData, RescueZipSize);
			}
		}
		else
		{
			Buffer imageBuf (RescueIsoImageSize);
		
			uint8 *image = imageBuf.Ptr();
			memset (image, 0, RescueIsoImageSize);

			// Primary volume descriptor
			const char* szPrimVolDesc = "\001CD001\001";
			const char* szPrimVolLabel = "VeraCrypt Rescue Disk           ";
			memcpy (image + 0x8000, szPrimVolDesc, strlen(szPrimVolDesc) + 1);
			memcpy (image + 0x7fff + 41, szPrimVolLabel, strlen(szPrimVolLabel) + 1);
			*(uint32 *) (image + 0x7fff + 81) = RescueIsoImageSize / 2048;
			*(uint32 *) (image + 0x7fff + 85) = BE32 (RescueIsoImageSize / 2048);
			image[0x7fff + 121] = 1;
			image[0x7fff + 124] = 1;
			image[0x7fff + 125] = 1;
			image[0x7fff + 128] = 1;
			image[0x7fff + 130] = 8;
			image[0x7fff + 131] = 8;

			image[0x7fff + 133] = 10;
			image[0x7fff + 140] = 10;
			image[0x7fff + 141] = 0x14;
			image[0x7fff + 157] = 0x22;
			image[0x7fff + 159] = 0x18;

			// Boot record volume descriptor
			const char* szBootRecDesc = "CD001\001EL TORITO SPECIFICATION";
			memcpy (image + 0x8801, szBootRecDesc, strlen(szBootRecDesc) + 1);
			image[0x8800 + 0x47] = 0x19;

			// Volume descriptor set terminator
			const char* szVolDescTerm = "\377CD001\001";
			memcpy (image + 0x9000, szVolDescTerm, strlen(szVolDescTerm) + 1);

			// Path table
			image[0xA000 + 0] = 1;
			image[0xA000 + 2] = 0x18;
			image[0xA000 + 6] = 1;

			// Root directory
			image[0xc000 + 0] = 0x22;
			image[0xc000 + 2] = 0x18;
			image[0xc000 + 9] = 0x18;
			image[0xc000 + 11] = 0x08;
			image[0xc000 + 16] = 0x08;
			image[0xc000 + 25] = 0x02;
			image[0xc000 + 28] = 0x01;
			image[0xc000 + 31] = 0x01;
			image[0xc000 + 32] = 0x01;
			image[0xc000 + 34] = 0x22;
			image[0xc000 + 36] = 0x18;
			image[0xc000 + 43] = 0x18;
			image[0xc000 + 45] = 0x08;
			image[0xc000 + 50] = 0x08;
			image[0xc000 + 59] = 0x02;
			image[0xc000 + 62] = 0x01;
			*(uint32 *) (image + 0xc000 + 65) = 0x010101;

			// Validation entry
			image[0xc800] = 1;
			int offset = 0xc800 + 0x1c;
			image[offset++] = 0xaa;
			image[offset++] = 0x55;
			image[offset++] = 0x55;
			image[offset] = 0xaa;

			// Initial entry
			offset = 0xc820;
			image[offset++] = 0x88;
			image[offset++] = 2;
			image[0xc820 + 6] = 1;
			image[0xc820 + 8] = TC_CD_BOOT_LOADER_SECTOR;

			// TrueCrypt Boot Loader
			CreateBootLoaderInMemory (image + TC_CD_BOOTSECTOR_OFFSET, TC_BOOT_LOADER_AREA_SIZE, true);

			// Volume header
			if (initialSetup)
			{
				if (!RescueVolumeHeaderValid)
					throw ParameterIncorrect (SRC_POS);

				memcpy (image + TC_CD_BOOTSECTOR_OFFSET + TC_BOOT_VOLUME_HEADER_SECTOR_OFFSET, RescueVolumeHeader, TC_BOOT_ENCRYPTION_VOLUME_HEADER_SIZE);
			}
			else
			{
				Device bootDevice (GetSystemDriveConfiguration().DevicePath, true);
				bootDevice.CheckOpened (SRC_POS);
				bootDevice.SeekAt (TC_BOOT_VOLUME_HEADER_SECTOR_OFFSET);
				bootDevice.Read (image + TC_CD_BOOTSECTOR_OFFSET + TC_BOOT_VOLUME_HEADER_SECTOR_OFFSET, TC_BOOT_ENCRYPTION_VOLUME_HEADER_SIZE);
			}

			// Original system loader
			try
			{
				File sysBakFile (GetSystemLoaderBackupPath(), true);
				sysBakFile.CheckOpened (SRC_POS);
				sysBakFile.Read (image + TC_CD_BOOTSECTOR_OFFSET + TC_ORIG_BOOT_LOADER_BACKUP_SECTOR_OFFSET, TC_BOOT_LOADER_AREA_SIZE);
			
				image[TC_CD_BOOTSECTOR_OFFSET + TC_BOOT_SECTOR_CONFIG_OFFSET] |= TC_BOOT_CFG_FLAG_RESCUE_DISK_ORIG_SYS_LOADER;
			}
			catch (Exception &e)
			{
				e.Show (ParentWindow);
				Warning ("SYS_LOADER_UNAVAILABLE_FOR_RESCUE_DISK", ParentWindow);
			}
		
			// Boot loader backup
			CreateBootLoaderInMemory (image + TC_CD_BOOTSECTOR_OFFSET + TC_BOOT_LOADER_BACKUP_RESCUE_DISK_SECTOR_OFFSET, TC_BOOT_LOADER_AREA_SIZE, false);

			RescueIsoImage = new uint8[RescueIsoImageSize];
			if (!RescueIsoImage)
				throw bad_alloc();
			memcpy (RescueIsoImage, image, RescueIsoImageSize);

			if (!isoImagePath.empty())
			{
				File isoFile (isoImagePath, false, true);
				isoFile.Write (image, RescueIsoImageSize);
			}
		}
	}
#endif


	bool BootEncryption::IsCDRecorderPresent ()
	{
		ICDBurn* pICDBurn;
		BOOL bHasRecorder = FALSE;

		if (SUCCEEDED( CoCreateInstance (CLSID_CDBurn, NULL,CLSCTX_INPROC_SERVER,IID_ICDBurn,(LPVOID*)&pICDBurn)))
		{
			if (pICDBurn->HasRecordableDrive (&bHasRecorder) != S_OK)
			{
				bHasRecorder = FALSE;
			}
			pICDBurn->Release();
		}
		return bHasRecorder? true : false;
	}


	bool BootEncryption::VerifyRescueDisk ()
	{
		BOOL bIsGPT = GetSystemDriveConfiguration().SystemPartition.IsGPT;
		if ((bIsGPT && !RescueZipData) || (!bIsGPT && !RescueIsoImage))
			throw ParameterIncorrect (SRC_POS);

		if (bIsGPT)
		{
			const wchar_t* efi64Files[] = {
				L"EFI/Boot/bootx64.efi",
#ifdef VC_EFI_CUSTOM_MODE
				L"EFI/VeraCrypt/DcsBml.dcs",
#endif
				L"EFI/VeraCrypt/DcsBoot.efi",
				L"EFI/VeraCrypt/DcsCfg.dcs",
				L"EFI/VeraCrypt/DcsInt.dcs",
				L"EFI/VeraCrypt/LegacySpeaker.dcs",
				L"EFI/VeraCrypt/svh_bak",
				L"EFI/Boot/original_bootx64.vc_backup"
			};
			
			const wchar_t* efi32Files[] = {
				L"EFI/Boot/bootia32.efi",
#ifdef VC_EFI_CUSTOM_MODE
				L"EFI/VeraCrypt/DcsBml.dcs",
#endif
				L"EFI/VeraCrypt/DcsBoot.efi",
				L"EFI/VeraCrypt/DcsCfg.dcs",
				L"EFI/VeraCrypt/DcsInt.dcs",
				L"EFI/VeraCrypt/LegacySpeaker.dcs",
				L"EFI/VeraCrypt/svh_bak",
				L"EFI/Boot/original_bootia32.vc_backup"
			};

			zip_error_t zerr;
			zip_source_t* zsrc = zip_source_buffer_create (RescueZipData, RescueZipSize, 0, &zerr);
			if (!zsrc)
				throw ParameterIncorrect (SRC_POS);
			zip_t* z = zip_open_from_source (zsrc, ZIP_CHECKCONS | ZIP_RDONLY, &zerr);
			if (!z)
			{
				zip_source_free (zsrc);
				throw ParameterIncorrect (SRC_POS);
			}

			finally_do_arg (zip_t*, z, { zip_close (finally_arg); });

			for (WCHAR drive = L'Z'; drive >= L'C'; --drive)
			{
				try
				{
					WCHAR rootPath[4] = { drive, L':', L'\\', 0};
					UINT driveType = GetDriveType (rootPath);
					if (DRIVE_REMOVABLE == driveType)
					{
						// check if it is FAT/FAT32
						WCHAR szNameBuffer[TC_MAX_PATH];
						if (GetVolumeInformationW (rootPath, NULL, 0, NULL, NULL, NULL, szNameBuffer, ARRAYSIZE(szNameBuffer))
								&& !wcsncmp (szNameBuffer, L"FAT", 3))
						{
							int i;		
							const wchar_t** efiFiles = Is64BitOs()? efi64Files: efi32Files;
							int efiFilesSize = Is64BitOs()? ARRAYSIZE(efi64Files): ARRAYSIZE(efi32Files);
							for (i = 0; i < efiFilesSize; i++)
							{
								bool bMatch = false;
								zip_int64_t index = zip_name_locate (z, WideToUtf8String (efiFiles[i]).c_str(), ZIP_FL_NOCASE);
								if (index >= 0)
								{
									zip_stat_t stat;
									if ((0 == zip_stat_index (z, index, ZIP_FL_NOCASE, &stat)) && (stat.valid & ZIP_STAT_SIZE))
									{
										// check that the file exists on the disk and that it has the same content
										StringCbCopyW (szNameBuffer, sizeof (szNameBuffer), rootPath);
										StringCbCatW (szNameBuffer, sizeof (szNameBuffer), efiFiles[i]);

										try
										{
											DWORD dwSize = 0;
											File diskFile (szNameBuffer, true);
											diskFile.CheckOpened (SRC_POS);
											diskFile.GetFileSize (dwSize);
											if (dwSize == (DWORD) stat.size)
											{
												Buffer fileBuf (dwSize);
												if (dwSize == diskFile.Read (fileBuf.Ptr (), dwSize))
												{
													Buffer efiBuf (dwSize);
													zip_file_t* zf = zip_fopen_index (z, index, 0);
													if (zf)
													{
														if (0 < zip_fread (zf, efiBuf.Ptr (), stat.size))
														{
															bMatch = (memcmp (efiBuf.Ptr(), fileBuf.Ptr(), dwSize) == 0);
														}
														zip_fclose (zf);														
													}
												}
											}										
										}
										catch (...)
										{
										}
									}
								}
								else
								{
									// entry not found in our Rescue ZIP image. Skip it.
									bMatch = true;
								}

								if (!bMatch)
									break;
							}

							if (i == efiFilesSize)
							{
								// All entries processed
								return true;
							}
						}
					}
				}
				catch (...) { }
			}
		}
		else
		{
			size_t verifiedSectorCount = (TC_CD_BOOTSECTOR_OFFSET + TC_ORIG_BOOT_LOADER_BACKUP_SECTOR_OFFSET + TC_BOOT_LOADER_AREA_SIZE) / 2048;
			Buffer buffer ((verifiedSectorCount + 1) * 2048);
			for (WCHAR drive = L'Z'; drive >= L'C'; --drive)
			{
				try
				{
					WCHAR rootPath[4] = { drive, L':', L'\\', 0};
					UINT driveType = GetDriveType (rootPath);
					// check that it is a CD/DVD drive or a removable media in case a bootable
					// USB key was created from the rescue disk ISO file
					if ((DRIVE_CDROM == driveType) || (DRIVE_REMOVABLE == driveType)) 
					{
						rootPath[2] = 0; // remove trailing backslash

						Device driveDevice (rootPath, true);
						driveDevice.CheckOpened (SRC_POS);

						DWORD bytesRead = driveDevice.Read (buffer.Ptr(), (DWORD) buffer.Size());
						if (bytesRead != buffer.Size())
							continue;

						if (memcmp (buffer.Ptr(), RescueIsoImage, buffer.Size()) == 0)
							return true;
					}
				}
				catch (...) { }
			}
		}

		return false;
	}

	bool BootEncryption::VerifyRescueDiskImage (const wchar_t* imageFile)
	{
		BOOL bIsGPT = GetSystemDriveConfiguration().SystemPartition.IsGPT;
		if ((bIsGPT && !RescueZipData) || (!bIsGPT && !RescueIsoImage))
			throw ParameterIncorrect (SRC_POS);

		if (bIsGPT)
		{
			try
			{
				DWORD dwSize = 0;
				File rescueFile (imageFile, true);
				rescueFile.CheckOpened (SRC_POS);
				rescueFile.GetFileSize (dwSize);
				Buffer rescueData (dwSize);

				if (dwSize == rescueFile.Read (rescueData.Ptr (), dwSize))
				{
					zip_error_t zerr;
					zip_source_t* zsrc = zip_source_buffer_create (rescueData.Ptr (), dwSize, 0, &zerr);
					if (!zsrc)
						return false;
					zip_t* zFile = zip_open_from_source (zsrc, ZIP_CHECKCONS | ZIP_RDONLY, &zerr);
					if (!zFile)
					{
						zip_source_free (zsrc);
						throw ParameterIncorrect (SRC_POS);
					}

					finally_do_arg (zip_t*, zFile, { zip_close (finally_arg); });

					zsrc = zip_source_buffer_create (RescueZipData, RescueZipSize, 0, &zerr);
					if (!zsrc)
						return false;
					zip_t* zMem = zip_open_from_source (zsrc, ZIP_CHECKCONS | ZIP_RDONLY, &zerr);
					if (!zMem)
					{
						zip_source_free (zsrc);
						throw ParameterIncorrect (SRC_POS);
					}

					finally_do_arg (zip_t*, zMem, { zip_close (finally_arg); });

					const wchar_t* efi64Files[] = {
						L"EFI/Boot/bootx64.efi",
#ifdef VC_EFI_CUSTOM_MODE
						L"EFI/VeraCrypt/DcsBml.dcs",
#endif
						L"EFI/VeraCrypt/DcsBoot.efi",
						L"EFI/VeraCrypt/DcsCfg.dcs",
						L"EFI/VeraCrypt/DcsInt.dcs",
						L"EFI/VeraCrypt/LegacySpeaker.dcs",
						L"EFI/VeraCrypt/svh_bak",
						L"EFI/Boot/original_bootx64.vc_backup"
					};
					
					const wchar_t* efi32Files[] = {
						L"EFI/Boot/bootia32.efi",
#ifdef VC_EFI_CUSTOM_MODE
						L"EFI/VeraCrypt/DcsBml.dcs",
#endif
						L"EFI/VeraCrypt/DcsBoot.efi",
						L"EFI/VeraCrypt/DcsCfg.dcs",
						L"EFI/VeraCrypt/DcsInt.dcs",
						L"EFI/VeraCrypt/LegacySpeaker.dcs",
						L"EFI/VeraCrypt/svh_bak",
						L"EFI/Boot/original_bootia32.vc_backup"
					};

					int i;
					zip_stat_t statMem, statFile;
					zip_int64_t indexMem, indexFile;
					const wchar_t** efiFiles = Is64BitOs()? efi64Files: efi32Files;
					int efiFilesSize = Is64BitOs()? ARRAYSIZE(efi64Files): ARRAYSIZE(efi32Files);
					for (i = 0; i < efiFilesSize; i++)
					{
						bool bMatch = false;
						indexMem = zip_name_locate (zMem, WideToUtf8String (efiFiles[i]).c_str(), ZIP_FL_NOCASE);
						if (indexMem >= 0)
						{									
							if ((0 == zip_stat_index (zMem, indexMem, ZIP_FL_NOCASE, &statMem)) && (statMem.valid & ZIP_STAT_SIZE))
							{
								indexFile = zip_name_locate (zFile, WideToUtf8String (efiFiles[i]).c_str(), ZIP_FL_NOCASE);
								if (indexFile >= 0)
								{
									if ((0 == zip_stat_index (zFile, indexFile, ZIP_FL_NOCASE, &statFile)) && (statFile.valid & ZIP_STAT_SIZE))
									{
										if (statMem.size == statFile.size)
										{
											Buffer fileBuf ((size_t) statFile.size);
											Buffer memBuf ((size_t) statMem.size);

											zip_file_t* zfMem = zip_fopen_index (zMem, indexMem, 0);
											if (zfMem)
											{
												if (0 < zip_fread (zfMem, memBuf.Ptr (), statMem.size))
												{
													zip_file_t* zfFile = zip_fopen_index (zFile, indexFile, 0);
													if (zfFile)
													{
														if (0 < zip_fread (zfFile, fileBuf.Ptr (), statFile.size))
														{
															bMatch = (memcmp (memBuf.Ptr(), fileBuf.Ptr(), (size_t) statFile.size) == 0);
														}
														zip_fclose (zfFile);
													}															
												}
												zip_fclose (zfMem);														
											}
										}
									}
								}
							}
						}
						else
						{
							// entry not found in our internal Rescue ZIP image. Skip it.
							bMatch = true;
						}

						if (!bMatch)
							break;
					}

					if (i == efiFilesSize)
					{
						// All entries processed
						return true;
					}
				}
			}
			catch (...) { }
		}
		else
		{
			try
			{
				File rescueFile (imageFile, true);
				rescueFile.CheckOpened (SRC_POS);
				size_t verifiedSectorCount = (TC_CD_BOOTSECTOR_OFFSET + TC_ORIG_BOOT_LOADER_BACKUP_SECTOR_OFFSET + TC_BOOT_LOADER_AREA_SIZE) / 2048;
				Buffer buffer ((verifiedSectorCount + 1) * 2048);

				DWORD bytesRead = rescueFile.Read (buffer.Ptr(), (DWORD) buffer.Size());
				if (	(bytesRead == buffer.Size()) 
					&& (memcmp (buffer.Ptr(), RescueIsoImage, buffer.Size()) == 0)
					)
				{
					return true;
				}
			}
			catch (...) { }
		}

		return false;
	}


#ifndef SETUP

	void BootEncryption::CreateVolumeHeader (uint64 volumeSize, uint64 encryptedAreaStart, Password *password, int ea, int mode, int pkcs5, int pim)
	{
		PCRYPTO_INFO cryptoInfo = NULL;

		if (!IsRandomNumberGeneratorStarted())
			throw ParameterIncorrect (SRC_POS);

		throw_sys_if (CreateVolumeHeaderInMemory (ParentWindow, TRUE, (char *) VolumeHeader, ea, mode, password, pkcs5, pim, NULL, &cryptoInfo,
			volumeSize, 0, encryptedAreaStart, 0, TC_SYSENC_KEYSCOPE_MIN_REQ_PROG_VERSION, TC_HEADER_FLAG_ENCRYPTED_SYSTEM, TC_SECTOR_SIZE_BIOS, FALSE) != 0);

		finally_do_arg (PCRYPTO_INFO*, &cryptoInfo, { crypto_close (*finally_arg); });

		// Initial rescue disk assumes encryption of the drive has been completed (EncryptedAreaLength == volumeSize)
		memcpy (RescueVolumeHeader, VolumeHeader, sizeof (RescueVolumeHeader));
		if (0 != ReadVolumeHeader (TRUE, (char *) RescueVolumeHeader, password, pkcs5, pim, NULL, cryptoInfo))
			throw ParameterIncorrect (SRC_POS);

		DecryptBuffer (RescueVolumeHeader + HEADER_ENCRYPTED_DATA_OFFSET, HEADER_ENCRYPTED_DATA_SIZE, cryptoInfo);

		if (GetHeaderField32 (RescueVolumeHeader, TC_HEADER_OFFSET_MAGIC) != 0x56455241)
			throw ParameterIncorrect (SRC_POS);

		uint8 *fieldPos = RescueVolumeHeader + TC_HEADER_OFFSET_ENCRYPTED_AREA_LENGTH;
		mputInt64 (fieldPos, volumeSize);

		// CRC of the header fields
		uint32 crc = GetCrc32 (RescueVolumeHeader + TC_HEADER_OFFSET_MAGIC, TC_HEADER_OFFSET_HEADER_CRC - TC_HEADER_OFFSET_MAGIC);
		fieldPos = RescueVolumeHeader + TC_HEADER_OFFSET_HEADER_CRC;
		mputLong (fieldPos, crc);

		EncryptBuffer (RescueVolumeHeader + HEADER_ENCRYPTED_DATA_OFFSET, HEADER_ENCRYPTED_DATA_SIZE, cryptoInfo);

		VolumeHeaderValid = true;
		RescueVolumeHeaderValid = true;
	}


	void BootEncryption::InstallVolumeHeader ()
	{
		if (!VolumeHeaderValid)
			throw ParameterIncorrect (SRC_POS);

		Device device (GetSystemDriveConfiguration().DevicePath);
		device.CheckOpened (SRC_POS);

		device.SeekAt (TC_BOOT_VOLUME_HEADER_SECTOR_OFFSET);
		device.Write ((uint8 *) VolumeHeader, sizeof (VolumeHeader));
	}


	// For synchronous operations use AbortSetupWait()
	void BootEncryption::AbortSetup ()
	{
		CallDriver (TC_IOCTL_ABORT_BOOT_ENCRYPTION_SETUP);
	}


	// For asynchronous operations use AbortSetup()
	void BootEncryption::AbortSetupWait ()
	{
		CallDriver (TC_IOCTL_ABORT_BOOT_ENCRYPTION_SETUP);

		BootEncryptionStatus encStatus = GetStatus();

		while (encStatus.SetupInProgress)
		{
			Sleep (TC_ABORT_TRANSFORM_WAIT_INTERVAL);
			encStatus = GetStatus();
		}
	}

	void BootEncryption::BackupSystemLoader ()
	{
		if (GetSystemDriveConfiguration().SystemPartition.IsGPT)
		{
			if (!IsAdmin()) {
				if (IsUacSupported())
				{
					Elevator::BackupEfiSystemLoader ();
					return;
				}
				else
				{
					Warning ("ADMIN_PRIVILEGES_WARN_DEVICES", ParentWindow);
				}
			}
			unsigned __int64 loaderSize = 0;
			std::vector<uint8> bootLoaderBuf;
			const wchar_t * szStdMsBootloader = L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi";
			const wchar_t * szBackupMsBootloader = L"\\EFI\\Microsoft\\Boot\\bootmgfw_ms.vc";
			const char* g_szMsBootString = "bootmgfw.pdb";
			bool bModifiedMsBoot = true;

			EfiBootInst.PrepareBootPartition();		

			EfiBootInst.GetFileSize(szStdMsBootloader, loaderSize);
			bootLoaderBuf.resize ((size_t) loaderSize);
			EfiBootInst.ReadFile(szStdMsBootloader, &bootLoaderBuf[0], (DWORD) loaderSize);

			// DcsBoot.efi is always smaller than 32KB
			if (loaderSize > 32768)
			{
				// look for bootmgfw.efi identifiant string
				if (BufferHasPattern (bootLoaderBuf.data (), (size_t) loaderSize, g_szMsBootString, strlen (g_szMsBootString)))
					bModifiedMsBoot = false;
			}
			else
			{
				if (BufferHasPattern (bootLoaderBuf.data (), (size_t) loaderSize, _T(TC_APP_NAME), wcslen (_T(TC_APP_NAME)) * 2))
				{
					if (AskWarnNoYes ("TC_BOOT_LOADER_ALREADY_INSTALLED", ParentWindow) == IDNO)
						throw UserAbort (SRC_POS);

					// check if backup exists already and if it has bootmgfw signature
					if (EfiBootInst.FileExists (szBackupMsBootloader))
					{
						EfiBootInst.GetFileSize(szBackupMsBootloader, loaderSize);
						bootLoaderBuf.resize ((size_t) loaderSize);
						EfiBootInst.ReadFile(szBackupMsBootloader, &bootLoaderBuf[0], (DWORD) loaderSize);

						if (BufferHasPattern (bootLoaderBuf.data (), (size_t) loaderSize, g_szMsBootString, strlen (g_szMsBootString)))
						{
							// copy it to original location
							EfiBootInst.CopyFile (szBackupMsBootloader, szStdMsBootloader);
							bModifiedMsBoot = false;
						}
					}

					if (bModifiedMsBoot)
						return;
				}
			}

			if (bModifiedMsBoot)
			{
				Error ("WINDOWS_EFI_BOOT_LOADER_MISSING", ParentWindow);
				throw UserAbort (SRC_POS);
			}

			EfiBootInst.CopyFile (szStdMsBootloader, szBackupMsBootloader);
			EfiBootInst.CopyFile (szStdMsBootloader, GetSystemLoaderBackupPath().c_str());

		}
		else
		{
			Device device (GetSystemDriveConfiguration().DevicePath, true);
			device.CheckOpened (SRC_POS);
			uint8 bootLoaderBuf[TC_BOOT_LOADER_AREA_SECTOR_COUNT * TC_SECTOR_SIZE_BIOS];

			device.SeekAt (0);
			device.Read (bootLoaderBuf, sizeof (bootLoaderBuf));

			// Prevent TrueCrypt loader from being backed up
			for (size_t i = 0; i < sizeof (bootLoaderBuf) - strlen (TC_APP_NAME); ++i)
			{
				if (memcmp (bootLoaderBuf + i, TC_APP_NAME, strlen (TC_APP_NAME)) == 0)
				{
					if (AskWarnNoYes ("TC_BOOT_LOADER_ALREADY_INSTALLED", ParentWindow) == IDNO)
						throw UserAbort (SRC_POS);
					return;
				}
			}

			File backupFile (GetSystemLoaderBackupPath(), false, true);
			backupFile.Write (bootLoaderBuf, sizeof (bootLoaderBuf));
		}
	}


	void BootEncryption::RestoreSystemLoader ()
	{
		SystemDriveConfiguration config = GetSystemDriveConfiguration();
		if (config.SystemPartition.IsGPT) {
			if (!IsAdmin()) {
				if (IsUacSupported())
				{
					Elevator::RestoreEfiSystemLoader ();
					return;
				}
				else
				{
					Warning ("ADMIN_PRIVILEGES_WARN_DEVICES", ParentWindow);
				}
			}

			EfiBootInst.PrepareBootPartition();			

			EfiBootInst.DeleteStartExec();
			EfiBootInst.DeleteStartExec(0xDC5B, L"Driver"); // remove DcsBml boot driver it was installed
			if (Is64BitOs())
				EfiBootInst.RenameFile(L"\\EFI\\Boot\\original_bootx64.vc_backup", L"\\EFI\\Boot\\bootx64.efi", TRUE);
			else
				EfiBootInst.RenameFile(L"\\EFI\\Boot\\original_bootia32.vc_backup", L"\\EFI\\Boot\\bootia32.efi", TRUE);

			if (!EfiBootInst.RenameFile(L"\\EFI\\Microsoft\\Boot\\bootmgfw_ms.vc", L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi", TRUE))
			{
				EfiBootConf conf;
				if (EfiBootInst.ReadConfig (L"\\EFI\\VeraCrypt\\DcsProp", conf) && strlen (conf.actionSuccessValue.c_str()))
				{
					wstring loaderPath;
					if (EfiBootConf::IsPostExecFileField (conf.actionSuccessValue, loaderPath))
					{
						// check that it is not bootmgfw_ms.vc or bootmgfw.efi
						if (	(0 != _wcsicmp (loaderPath.c_str(), L"\\EFI\\Microsoft\\Boot\\bootmgfw_ms.vc"))
							&&	(0 != _wcsicmp (loaderPath.c_str(), L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi"))
							)
						{
							const char* g_szMsBootString = "bootmgfw.pdb";
							unsigned __int64 loaderSize = 0;
							EfiBootInst.GetFileSize(loaderPath.c_str(), loaderSize);
							std::vector<uint8> bootLoaderBuf ((size_t) loaderSize);

							EfiBootInst.ReadFile(loaderPath.c_str(), &bootLoaderBuf[0], (DWORD) loaderSize);

							// look for bootmgfw.efi identifiant string
							if (BufferHasPattern (bootLoaderBuf.data (), (size_t) loaderSize, g_szMsBootString, strlen (g_szMsBootString)))
							{
								EfiBootInst.RenameFile(loaderPath.c_str(), L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi", TRUE);
							}
						}
					}
				}
			}


			EfiBootInst.DelFile(L"\\DcsBoot.efi");
			EfiBootInst.DelFile(L"\\DcsInt.efi");
			EfiBootInst.DelFile(L"\\DcsCfg.efi");
			EfiBootInst.DelFile(L"\\LegacySpeaker.efi");
			EfiBootInst.DelFile(L"\\DcsBoot");
			EfiBootInst.DelFile(L"\\DcsProp");
			EfiBootInst.DelFile(L"\\EFI\\VeraCrypt\\DcsBoot.efi");
			EfiBootInst.DelFile(L"\\EFI\\VeraCrypt\\DcsInt.dcs");
			EfiBootInst.DelFile(L"\\EFI\\VeraCrypt\\DcsCfg.dcs");
			EfiBootInst.DelFile(L"\\EFI\\VeraCrypt\\LegacySpeaker.dcs");
			EfiBootInst.DelFile(L"\\EFI\\VeraCrypt\\DcsBml.dcs");
			EfiBootInst.DelFile(L"\\EFI\\VeraCrypt\\DcsBoot");
			EfiBootInst.DelFile(L"\\EFI\\VeraCrypt\\DcsInfo.dcs");
			EfiBootInst.DelFile(L"\\EFI\\VeraCrypt\\PlatformInfo");
			EfiBootInst.DelFile(L"\\EFI\\VeraCrypt\\DcsProp");
			EfiBootInst.DelDir (L"\\EFI\\VeraCrypt");
		}
		else
		{
			uint8 bootLoaderBuf[TC_BOOT_LOADER_AREA_SECTOR_COUNT * TC_SECTOR_SIZE_BIOS];

			File backupFile (GetSystemLoaderBackupPath(), true);
			backupFile.CheckOpened(SRC_POS);
			if (backupFile.Read (bootLoaderBuf, sizeof (bootLoaderBuf)) != sizeof (bootLoaderBuf))
				throw ParameterIncorrect (SRC_POS);

			Device device (GetSystemDriveConfiguration().DevicePath);
			device.CheckOpened (SRC_POS);

			// Preserve current partition table
			uint8 mbr[TC_SECTOR_SIZE_BIOS];
			device.SeekAt (0);
			device.Read (mbr, sizeof (mbr));
			memcpy (bootLoaderBuf + TC_MAX_MBR_BOOT_CODE_SIZE, mbr + TC_MAX_MBR_BOOT_CODE_SIZE, sizeof (mbr) - TC_MAX_MBR_BOOT_CODE_SIZE);

			device.SeekAt (0);
			device.Write (bootLoaderBuf, sizeof (bootLoaderBuf));
		}

		if (!IsAdmin() && IsUacSupported())
		{
			Elevator::UpdateSetupConfigFile (false);
		}
		else
		{
			UpdateSetupConfigFile (false);
		}
	}

#endif // SETUP

	static bool CompareMultiString (const char* str1, const char* str2)
	{
		size_t l1, l2;
		if (!str1 || !str2)
			return false;
		while (true)
		{
			l1 = strlen (str1);
			l2 = strlen (str2);
			if (l1 == l2)
			{
				if (l1 == 0)
					break; // we reached the end
				if (_stricmp (str1, str2) == 0)
				{
					str1 += l1 + 1;
					str2 += l2 + 1;
				}
				else
					return false;
			}
			else
				return false;

		}

		return true;
	}

	static void AppendToMultiString (char* mszDest, DWORD dwMaxDesSize, DWORD& dwDestSize, const char* input)
	{
		// find the index of the end of the last string
		DWORD dwInputSize = (DWORD) strlen (input) + 1;
		DWORD index = dwDestSize;
		while (index > 0 && mszDest[index - 1] == 0)
			index--;

		if (dwMaxDesSize > (index + 1 + dwInputSize + 1))
		{
			if (index == 0)
			{
				StringCchCopyA ((char *) mszDest, dwMaxDesSize, input);
				mszDest [dwInputSize] = 0;
				dwDestSize = dwInputSize + 1;
			}
			else
			{
				mszDest[index] = 0;
				StringCchCopyA ((char *) &mszDest[index + 1], dwMaxDesSize - index - 1, input);
				mszDest [index + 1 + dwInputSize] = 0;
				dwDestSize = index + 1 + dwInputSize + 1;
			}
		}
	}

	// mszDest is guaranteed to be double zero terminated
	static bool RemoveFromMultiString (char* mszDest, DWORD& dwDestSize, const char* input)
	{
		bool bRet = false;
		if (mszDest && input)
		{
			DWORD offset, remainingSize = dwDestSize;
			while (*mszDest)
			{
				if (_stricmp (mszDest, input) == 0)
				{
					offset = (DWORD) strlen (input) + 1;
					memmove (mszDest, mszDest + offset, remainingSize - offset);
					dwDestSize -= offset;
					bRet = true;
					break;
				}
				offset = (DWORD) strlen (mszDest) + 1;
				mszDest += offset;
				remainingSize -= offset;
			}
		}

		return bRet;
	}

	void BootEncryption::RegisterFilter (bool registerFilter, FilterType filterType, const GUID *deviceClassGuid)
	{
		string filter;
		string filterReg;
		HKEY regKey;

		switch (filterType)
		{
		case DriveFilter:
		case VolumeFilter:
			filter = "veracrypt";
			filterReg = "UpperFilters";
			regKey = OpenDeviceClassRegKey (deviceClassGuid);
			throw_sys_if (regKey == INVALID_HANDLE_VALUE);

			break;

		case DumpFilter:
			filter = "veracrypt.sys";
			filterReg = "DumpFilters";
			SetLastError (RegOpenKeyEx (HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\CrashControl", 0, KEY_READ | KEY_WRITE, &regKey));
			throw_sys_if (GetLastError() != ERROR_SUCCESS);

			break;

		default:
			throw ParameterIncorrect (SRC_POS);
		}

		finally_do_arg (HKEY, regKey, { RegCloseKey (finally_arg); });

		if (registerFilter)
		{
			if (filterType != DumpFilter)
			{
				// Register class filter below all other filters in the stack

				size_t strSize = filter.size() + 1;
				uint8 regKeyBuf[65536];
				DWORD size = (DWORD) (sizeof (regKeyBuf) - strSize);

				// SetupInstallFromInfSection() does not support prepending of values so we have to modify the registry directly
				StringCchCopyA ((char *) regKeyBuf, ARRAYSIZE(regKeyBuf), filter.c_str());

				if (RegQueryValueExA (regKey, filterReg.c_str(), NULL, NULL, regKeyBuf + strSize, &size) != ERROR_SUCCESS)
					size = 1;

				SetLastError (RegSetValueExA (regKey, filterReg.c_str(), 0, REG_MULTI_SZ, regKeyBuf, (DWORD) strSize + size));
				throw_sys_if (GetLastError() != ERROR_SUCCESS);
			}
			else
			{
				// workaround rare SetupInstallFromInfSection which overwrite value instead of appending new value
				// read initial value
				DWORD strSize = (DWORD) filter.size() + 1, expectedSize;
				Buffer expectedRegKeyBuf(65536), outputRegKeyBuf(65536);
				uint8* pbExpectedRegKeyBuf = expectedRegKeyBuf.Ptr ();
				uint8* pbOutputRegKeyBuf = outputRegKeyBuf.Ptr ();
				DWORD initialSize = (DWORD) (expectedRegKeyBuf.Size() - strSize - 2);				

				if (RegQueryValueExA (regKey, filterReg.c_str(), NULL, NULL, pbExpectedRegKeyBuf, &initialSize) != ERROR_SUCCESS)
				{
					StringCchCopyA ((char *) pbExpectedRegKeyBuf, expectedRegKeyBuf.Size(), filter.c_str());
					pbExpectedRegKeyBuf [strSize] = 0;
					expectedSize = strSize + 1;
				}
				else
				{
					expectedSize = initialSize;
					AppendToMultiString ((char *) pbExpectedRegKeyBuf, (DWORD) expectedRegKeyBuf.Size(), expectedSize, filter.c_str());
				}

				RegisterDriverInf (registerFilter, filter, filterReg, ParentWindow, regKey);

				// check if operation successful
				initialSize = (DWORD) outputRegKeyBuf.Size() - 2;
				if (RegQueryValueExA (regKey, filterReg.c_str(), NULL, NULL, pbOutputRegKeyBuf, &initialSize) != ERROR_SUCCESS)
				{
					pbOutputRegKeyBuf [0] = 0;
					pbOutputRegKeyBuf [1] = 0;
				}
				else
				{
					// append two \0 at the end if they are missing
					if (pbOutputRegKeyBuf [initialSize - 1] != 0)
					{
						pbOutputRegKeyBuf [initialSize] = 0;
						pbOutputRegKeyBuf [initialSize + 1] = 0;
					}
					else if (pbOutputRegKeyBuf [initialSize - 2] != 0)
					{
						pbOutputRegKeyBuf [initialSize] = 0;
					}
				}

				if (!CompareMultiString ((char *) pbExpectedRegKeyBuf, (char *) pbOutputRegKeyBuf))
				{
					// Set value manually
					SetLastError (RegSetValueExA (regKey, filterReg.c_str(), 0, REG_MULTI_SZ, pbExpectedRegKeyBuf, expectedSize));
					throw_sys_if (GetLastError() != ERROR_SUCCESS);
				}
			}
		}
		else
		{
			RegisterDriverInf (registerFilter, filter, filterReg, ParentWindow, regKey);

			// remove value in case it was not done properly
			Buffer regKeyBuf(65536);
			uint8* pbRegKeyBuf = regKeyBuf.Ptr ();

			DWORD initialSize = (DWORD) regKeyBuf.Size() - 2;				

			if (		(RegQueryValueExA (regKey, filterReg.c_str(), NULL, NULL, pbRegKeyBuf, &initialSize) == ERROR_SUCCESS)
					&& (initialSize >= ((DWORD) filter.size()))
				)
			{
				// append two \0 at the end if they are missing
				if (pbRegKeyBuf [initialSize - 1] != 0)
				{
					pbRegKeyBuf [initialSize] = 0;
					pbRegKeyBuf [initialSize + 1] = 0;
					initialSize += 2;
				}
				else if (pbRegKeyBuf [initialSize - 2] != 0)
				{
					pbRegKeyBuf [initialSize] = 0;
					initialSize ++;
				}

				if (RemoveFromMultiString ((char*) pbRegKeyBuf, initialSize, filter.c_str()))
				{
					// Set value manually
					SetLastError (RegSetValueExA (regKey, filterReg.c_str(), 0, REG_MULTI_SZ, pbRegKeyBuf, initialSize));
					throw_sys_if (GetLastError() != ERROR_SUCCESS);
				}
			}
		}
	}

	void BootEncryption::RegisterFilterDriver (bool registerDriver, FilterType filterType)
	{
		if (!IsAdmin() && IsUacSupported())
		{
			Elevator::RegisterFilterDriver (registerDriver, filterType);
			return;
		}

		switch (filterType)
		{
		case DriveFilter:
			RegisterFilter (registerDriver, filterType, &GUID_DEVCLASS_DISKDRIVE);
			break;

		case VolumeFilter:
			RegisterFilter (registerDriver, filterType, &GUID_DEVCLASS_VOLUME);
			RegisterFilter (registerDriver, filterType, &GUID_DEVCLASS_FLOPPYDISK);
			break;

		case DumpFilter:
			RegisterFilter (registerDriver, filterType);
			break;

		default:
			throw ParameterIncorrect (SRC_POS);
		}
	}

	void BootEncryption::RegisterSystemFavoritesService (BOOL registerService, BOOL noFileHandling)
	{
		SC_HANDLE scm = OpenSCManager (NULL, NULL, SC_MANAGER_ALL_ACCESS);
		throw_sys_if (!scm);
		finally_do_arg (SC_HANDLE, scm, { CloseServiceHandle (finally_arg); });

		wstring servicePath = GetServiceConfigPath (_T(TC_APP_NAME) L".exe", false);
		wstring serviceLegacyPath = GetServiceConfigPath (_T(TC_APP_NAME) L".exe", true);

		if (registerService)
		{
			// check if service already exists.
			// If yes then start it immediatly after reinstalling it
			bool bAlreadyExists = false;
			SC_HANDLE service = OpenService (scm, TC_SYSTEM_FAVORITES_SERVICE_NAME, GENERIC_READ);
			if (service)
			{
				bAlreadyExists = true;
				CloseServiceHandle (service);
			}

			try
			{
				RegisterSystemFavoritesService (FALSE, noFileHandling);
			}
			catch (...) { }

			if (!noFileHandling)
			{
				wchar_t appPath[TC_MAX_PATH];
				throw_sys_if (!GetModuleFileName (NULL, appPath, ARRAYSIZE (appPath)));
				/* explicitely specify VeraCrypt.exe as the file to copy and don't rely
				 * on the fact we will be always called by VeraCrypt.exe because it's not
				 * always true.
				 */
				wchar_t* ptr = wcsrchr (appPath, L'\\');
				if (ptr)
					ptr[1] = 0;
				StringCchCatW (appPath, ARRAYSIZE (appPath), _T(TC_APP_NAME) L".exe");
		
				throw_sys_if (!CopyFile (appPath, servicePath.c_str(), FALSE));
			}

			service = CreateService (scm,
				TC_SYSTEM_FAVORITES_SERVICE_NAME,
				_T(TC_APP_NAME) L" System Favorites",
				SERVICE_ALL_ACCESS,
				SERVICE_WIN32_OWN_PROCESS,
				SERVICE_AUTO_START,
				SERVICE_ERROR_NORMAL,
				(wstring (L"\"") + servicePath + L"\" " TC_SYSTEM_FAVORITES_SERVICE_CMDLINE_OPTION).c_str(),
				TC_SYSTEM_FAVORITES_SERVICE_LOAD_ORDER_GROUP,
				NULL,
				NULL,
				NULL,
				NULL);

			throw_sys_if (!service);

			SERVICE_DESCRIPTION description;
			description.lpDescription = L"Mounts VeraCrypt system favorite volumes.";
			ChangeServiceConfig2 (service, SERVICE_CONFIG_DESCRIPTION, &description);

			// start the service immediatly if it already existed before
			if (bAlreadyExists)
				StartService (service, 0, NULL);

			CloseServiceHandle (service);

			try
			{
				WriteLocalMachineRegistryString (L"SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\" TC_SYSTEM_FAVORITES_SERVICE_NAME, NULL, L"Service", FALSE);
				WriteLocalMachineRegistryString (L"SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\" TC_SYSTEM_FAVORITES_SERVICE_NAME, NULL, L"Service", FALSE);
			}
			catch (...)
			{
				try
				{
					RegisterSystemFavoritesService (FALSE, noFileHandling);
				}
				catch (...) { }

				throw;
			}
		}
		else
		{
			DeleteLocalMachineRegistryKey (L"SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal", TC_SYSTEM_FAVORITES_SERVICE_NAME);
			DeleteLocalMachineRegistryKey (L"SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network", TC_SYSTEM_FAVORITES_SERVICE_NAME);

			SC_HANDLE service = OpenService (scm, TC_SYSTEM_FAVORITES_SERVICE_NAME, SERVICE_ALL_ACCESS);
			throw_sys_if (!service);

			SERVICE_STATUS serviceStatus = {0};
			ControlService (service, SERVICE_CONTROL_STOP, &serviceStatus);

			throw_sys_if (!DeleteService (service));
			CloseServiceHandle (service);

			if (!noFileHandling)
			{
				DeleteFile (servicePath.c_str());
				if (serviceLegacyPath != servicePath)
					DeleteFile (serviceLegacyPath.c_str());
			}
		}
	}

	bool BootEncryption::IsSystemFavoritesServiceRunning ()
	{
		bool bRet = false;
		SC_HANDLE scm = OpenSCManager (NULL, NULL, SC_MANAGER_CONNECT);
		if (scm)
		{
			SC_HANDLE service = OpenService(scm, TC_SYSTEM_FAVORITES_SERVICE_NAME, GENERIC_READ);
			if (service)
			{
				SERVICE_STATUS status;
				if (QueryServiceStatus(service, &status))
				{
					bRet = (status.dwCurrentState == SERVICE_RUNNING);
				}

				CloseServiceHandle(service);
			}

			CloseServiceHandle (scm);
		}

		return bRet;
	}

	void BootEncryption::UpdateSystemFavoritesService ()
	{
		SC_HANDLE scm = OpenSCManager (NULL, NULL, SC_MANAGER_ALL_ACCESS);
		throw_sys_if (!scm);

		finally_do_arg (SC_HANDLE, scm, { CloseServiceHandle (finally_arg); });

		wstring servicePath = GetServiceConfigPath (_T(TC_APP_NAME) L".exe", false);

		// check if service exists
		SC_HANDLE service = OpenService (scm, TC_SYSTEM_FAVORITES_SERVICE_NAME, SERVICE_ALL_ACCESS);
		if (service)
		{
			finally_do_arg (SC_HANDLE, service, { CloseServiceHandle (finally_arg); });
			// ensure that its parameters are correct
			throw_sys_if (!ChangeServiceConfig (service,
				SERVICE_WIN32_OWN_PROCESS,
				SERVICE_AUTO_START,
				SERVICE_ERROR_NORMAL,
				(wstring (L"\"") + servicePath + L"\" " TC_SYSTEM_FAVORITES_SERVICE_CMDLINE_OPTION).c_str(),
				TC_SYSTEM_FAVORITES_SERVICE_LOAD_ORDER_GROUP,
				NULL,
				NULL,
				NULL,
				NULL,
				_T(TC_APP_NAME) L" System Favorites"));

		}
		else
		{
			RegisterSystemFavoritesService (TRUE, TRUE);
		}
	}

	void BootEncryption::SetDriverConfigurationFlag (uint32 flag, bool state)
	{
		DWORD configMap = ReadDriverConfigurationFlags();

		if (state)
			configMap |= flag;
		else
			configMap &= ~flag;
#ifdef SETUP
		WriteLocalMachineRegistryDword (L"SYSTEM\\CurrentControlSet\\Services\\veracrypt", TC_DRIVER_CONFIG_REG_VALUE_NAME, configMap);
#else
		WriteLocalMachineRegistryDwordValue (L"SYSTEM\\CurrentControlSet\\Services\\veracrypt", TC_DRIVER_CONFIG_REG_VALUE_NAME, configMap);
#endif
	}

	void BootEncryption::SetServiceConfigurationFlag (uint32 flag, bool state)
	{
		DWORD configMap = ReadServiceConfigurationFlags();

		if (state)
			configMap |= flag;
		else
			configMap &= ~flag;
#ifdef SETUP
		WriteLocalMachineRegistryDword (L"SYSTEM\\CurrentControlSet\\Services\\" TC_SYSTEM_FAVORITES_SERVICE_NAME, TC_SYSTEM_FAVORITES_SERVICE_NAME L"Config", configMap);
#else
		WriteLocalMachineRegistryDwordValue (L"SYSTEM\\CurrentControlSet\\Services\\" TC_SYSTEM_FAVORITES_SERVICE_NAME, TC_SYSTEM_FAVORITES_SERVICE_NAME L"Config", configMap);
#endif
	}

#ifndef SETUP

	void BootEncryption::RegisterSystemFavoritesService (BOOL registerService)
	{
		if (!IsAdmin() && IsUacSupported())
		{
			Elevator::RegisterSystemFavoritesService (registerService);
			return;
		}

		RegisterSystemFavoritesService (registerService, FALSE);
	}

	void BootEncryption::GetEfiBootDeviceNumber (PSTORAGE_DEVICE_NUMBER pSdn)
	{
		SystemDriveConfiguration config = GetSystemDriveConfiguration ();
		if (config.SystemPartition.IsGPT && pSdn)
		{
			if (!IsAdmin() && IsUacSupported())
			{
				Elevator::GetEfiBootDeviceNumber (pSdn);
			}
			else
			{
				EfiBootInst.PrepareBootPartition();		
				memcpy (pSdn, EfiBootInst.GetStorageDeviceNumber(), sizeof (STORAGE_DEVICE_NUMBER));
			}
		}
		else
		{
			SetLastError (ERROR_INVALID_PARAMETER);
			throw SystemException (SRC_POS);
		}
	}
#endif

#if defined(VC_EFI_CUSTOM_MODE) || !defined(SETUP)
	void BootEncryption::GetSecureBootConfig (BOOL* pSecureBootEnabled, BOOL *pVeraCryptKeysLoaded)
	{
		SystemDriveConfiguration config = GetSystemDriveConfiguration ();
		if (config.SystemPartition.IsGPT && pSecureBootEnabled && pVeraCryptKeysLoaded)
		{
			if (!IsAdmin() && IsUacSupported())
			{
				Elevator::GetSecureBootConfig (pSecureBootEnabled, pVeraCryptKeysLoaded);
			}
			else
			{
				ByteArray varValue ((ByteArray::size_type) 4096);

				*pSecureBootEnabled = FALSE;
				*pVeraCryptKeysLoaded = FALSE;

				SetPrivilege(SE_SYSTEM_ENVIRONMENT_NAME, TRUE);
				DWORD dwLen = GetFirmwareEnvironmentVariable (L"SecureBoot", EfiVarGuid, varValue.data(), (DWORD) varValue.size());
				if ((dwLen >= 1) && (varValue[0] == 1))
				{
					*pSecureBootEnabled = TRUE;
					dwLen = GetFirmwareEnvironmentVariable (L"PK", EfiVarGuid, varValue.data(), (DWORD) varValue.size());
					if ((dwLen == sizeof (g_pbEFIDcsPK)) && (0 == memcmp (varValue.data(), g_pbEFIDcsPK, dwLen)))
					{
						dwLen = GetFirmwareEnvironmentVariable (L"KEK", EfiVarGuid, varValue.data(), (DWORD) varValue.size());
						if ((dwLen == sizeof (g_pbEFIDcsKEK)) && (0 == memcmp (varValue.data(), g_pbEFIDcsKEK, dwLen)))
						{
							*pVeraCryptKeysLoaded = TRUE;
						}
					}
				}
			}
		}
		else
		{
			SetLastError (ERROR_INVALID_PARAMETER);
			throw SystemException (SRC_POS);
		}
	}
#endif
#ifndef SETUP
	void BootEncryption::CheckRequirements ()
	{ 
		if (CurrentOSMajor == 6 && CurrentOSMinor == 0 && CurrentOSServicePack < 1)
			throw ErrorException ("SYS_ENCRYPTION_UNSUPPORTED_ON_VISTA_SP0", SRC_POS);

		if (IsARM())
			throw ErrorException ("SYS_ENCRYPTION_UNSUPPORTED_ON_CURRENT_OS", SRC_POS);

		if (IsNonInstallMode())
			throw ErrorException ("FEATURE_REQUIRES_INSTALLATION", SRC_POS);

		/* check if the system drive is already encrypted by BitLocker */
		wchar_t windowsDrive = (wchar_t) towupper (GetWindowsDirectory()[0]);
		BitLockerEncryptionStatus bitLockerStatus = GetBitLockerEncryptionStatus (windowsDrive);
		if (bitLockerStatus == BL_Status_Protected)
			throw ErrorException ("SYSENC_BITLOCKER_CONFLICT", SRC_POS);

		SystemDriveConfiguration config = GetSystemDriveConfiguration ();

		if (SystemDriveIsDynamic())
			throw ErrorException ("SYSENC_UNSUPPORTED_FOR_DYNAMIC_DISK", SRC_POS);

		if (config.InitialUnallocatedSpace < TC_BOOT_LOADER_AREA_SIZE)
			throw ErrorException ("NO_SPACE_FOR_BOOT_LOADER", SRC_POS);

		DISK_GEOMETRY_EX geometry = GetDriveGeometry (config.DriveNumber);

		if (geometry.Geometry.BytesPerSector != TC_SECTOR_SIZE_BIOS)
			throw ErrorException ("SYSENC_UNSUPPORTED_SECTOR_SIZE_BIOS", SRC_POS);

		bool activePartitionFound = false;
		if (config.SystemPartition.IsGPT)
		{
			STORAGE_DEVICE_NUMBER sdn;
#ifdef VC_EFI_CUSTOM_MODE
			BOOL bSecureBootEnabled = FALSE, bVeraCryptKeysLoaded = FALSE;
			GetSecureBootConfig (&bSecureBootEnabled, &bVeraCryptKeysLoaded);
			if (bSecureBootEnabled && !bVeraCryptKeysLoaded)
			{
				throw ErrorException ("SYSENC_EFI_UNSUPPORTED_SECUREBOOT", SRC_POS);
			}
#endif
			GetEfiBootDeviceNumber (&sdn);
			activePartitionFound = (config.DriveNumber == (int) sdn.DeviceNumber);
		}
		else
		{
			// Determine whether there is an Active partition on the system drive
			foreach (const Partition &partition, config.Partitions)
			{
				if (partition.Info.BootIndicator)
				{
					activePartitionFound = true;
					break;
				}
			}
		}

		if ((!config.SystemLoaderPresent && !config.SystemPartition.IsGPT) || !activePartitionFound)
		{
			static bool confirmed = false;

			if (!confirmed && AskWarnNoYes ("WINDOWS_NOT_ON_BOOT_DRIVE_ERROR", ParentWindow) == IDNO)
				throw UserAbort (SRC_POS);

			confirmed = true;
		}
	}


	void BootEncryption::CheckRequirementsHiddenOS ()
	{
		// It is assumed that CheckRequirements() had been called (so we don't check e.g. whether it's GPT).

		// The user may have modified/added/deleted partitions since the partition table was last scanned.
		InvalidateCachedSysDriveProperties ();

		GetPartitionForHiddenOS ();
	}


	void BootEncryption::InitialSecurityChecksForHiddenOS ()
	{
		wchar_t windowsDrive = (wchar_t) towupper (GetWindowsDirectory()[0]);

		// Paging files
		bool pagingFilesOk = !IsPagingFileActive (TRUE);

		wchar_t pagingFileRegData[65536];
		DWORD pagingFileRegDataSize = sizeof (pagingFileRegData);

		if (ReadLocalMachineRegistryMultiString (L"System\\CurrentControlSet\\Control\\Session Manager\\Memory Management", L"PagingFiles", pagingFileRegData, &pagingFileRegDataSize)
			&& pagingFileRegDataSize > 8)
		{
			for (size_t i = 1; i < pagingFileRegDataSize/2 - 2; ++i)
			{
				if (wmemcmp (pagingFileRegData + i, L":\\", 2) == 0 && towupper (pagingFileRegData[i - 1]) != windowsDrive)
				{
					pagingFilesOk = false;
					break;
				}
			}
		}

		if (!pagingFilesOk)
		{
			if (AskWarnYesNoString ((wchar_t *) (wstring (GetString ("PAGING_FILE_NOT_ON_SYS_PARTITION")) 
				+ GetString ("LEAKS_OUTSIDE_SYSPART_UNIVERSAL_EXPLANATION")
				+ L"\n\n\n"
				+ GetString ("RESTRICT_PAGING_FILES_TO_SYS_PARTITION")
				).c_str(), ParentWindow) == IDYES)
			{
				RestrictPagingFilesToSystemPartition();
				RestartComputer();
				AbortProcessSilent();
			}

			throw ErrorException (wstring (GetString ("PAGING_FILE_NOT_ON_SYS_PARTITION")) 
				+ GetString ("LEAKS_OUTSIDE_SYSPART_UNIVERSAL_EXPLANATION"), SRC_POS);
		}

		// User profile
		wchar_t *configPath = GetConfigPath (L"dummy");
		if (configPath && towupper (configPath[0]) != windowsDrive)
		{
			throw ErrorException (wstring (GetString ("USER_PROFILE_NOT_ON_SYS_PARTITION")) 
				+ GetString ("LEAKS_OUTSIDE_SYSPART_UNIVERSAL_EXPLANATION"), SRC_POS);
		}

		// Temporary files
		if (towupper (GetTempPathString()[0]) != windowsDrive)
		{
			throw ErrorException (wstring (GetString ("TEMP_NOT_ON_SYS_PARTITION")) 
				+ GetString ("LEAKS_OUTSIDE_SYSPART_UNIVERSAL_EXPLANATION"), SRC_POS);
		}
	}


	// This operation may take a long time when an antivirus is installed and its real-time protection enabled.
	// Therefore, if calling it without the wizard displayed, it should be called with displayWaitDialog set to true.
	void BootEncryption::Deinstall (bool displayWaitDialog)
	{
		BootEncryptionStatus encStatus = GetStatus();

		if (encStatus.DriveEncrypted || encStatus.DriveMounted)
			throw ParameterIncorrect (SRC_POS);

		SystemDriveConfiguration config = GetSystemDriveConfiguration ();

      if (!config.SystemPartition.IsGPT) {
         if (encStatus.VolumeHeaderPresent)
         {
            // Verify CRC of header salt
            Device device(config.DevicePath, true);
            device.CheckOpened(SRC_POS);
            uint8 header[TC_BOOT_ENCRYPTION_VOLUME_HEADER_SIZE];

            device.SeekAt(TC_BOOT_VOLUME_HEADER_SECTOR_OFFSET);
            device.Read(header, sizeof(header));

            if (encStatus.VolumeHeaderSaltCrc32 != GetCrc32((uint8 *)header, PKCS5_SALT_SIZE))
               throw ParameterIncorrect(SRC_POS);
         }
      }

		try
		{
			RegisterFilterDriver (false, DriveFilter);
			RegisterFilterDriver (false, VolumeFilter);
			RegisterFilterDriver (false, DumpFilter);
			SetDriverServiceStartType (SERVICE_SYSTEM_START);
		}
		catch (...)
		{
			try
			{
				RegisterBootDriver (IsHiddenSystemRunning());
			}
			catch (...) { }

			throw;
		}

		SetHiddenOSCreationPhase (TC_HIDDEN_OS_CREATION_PHASE_NONE);	// In case RestoreSystemLoader() fails

		try
		{
			RegisterSystemFavoritesService (FALSE);
		}
		catch (...) { }

		try
		{
			if (displayWaitDialog)
				DisplayStaticModelessWaitDlg (ParentWindow);

			finally_do_arg (bool, displayWaitDialog, { if (finally_arg) CloseStaticModelessWaitDlg(); });

			RestoreSystemLoader ();
		}
		catch (Exception &e)
		{
			e.Show (ParentWindow);
			throw ErrorException ("SYS_LOADER_RESTORE_FAILED", SRC_POS);
		}
	}


	int BootEncryption::ChangePassword (Password *oldPassword, int old_pkcs5, int old_pim, Password *newPassword, int pkcs5, int pim, int wipePassCount, HWND hwndDlg)
	{
		BootEncryptionStatus encStatus = GetStatus();

		if (encStatus.SetupInProgress || (wipePassCount <= 0))
			throw ParameterIncorrect (SRC_POS);

		SystemDriveConfiguration config = GetSystemDriveConfiguration ();

		char header[TC_BOOT_ENCRYPTION_VOLUME_HEADER_SIZE];
		Device device (config.DevicePath);
		device.CheckOpened (SRC_POS);

		// Only one algorithm is currently supported
		if (pkcs5 != 0)
			throw ParameterIncorrect (SRC_POS);

		int64 headerOffset = TC_BOOT_VOLUME_HEADER_SECTOR_OFFSET;
		int64 backupHeaderOffset = -1;

		if (encStatus.HiddenSystem)
		{
			headerOffset = encStatus.HiddenSystemPartitionStart + TC_HIDDEN_VOLUME_HEADER_OFFSET;

			// Find hidden system partition
			foreach (const Partition &partition, config.Partitions)
			{
				if (partition.Info.StartingOffset.QuadPart == encStatus.HiddenSystemPartitionStart)
				{
					backupHeaderOffset = partition.Info.StartingOffset.QuadPart + partition.Info.PartitionLength.QuadPart - TC_VOLUME_HEADER_SIZE;
					break;
				}
			}

			if (backupHeaderOffset == -1)
				throw ParameterIncorrect (SRC_POS);
		}

		device.SeekAt (headerOffset);
		device.Read ((uint8 *) header, sizeof (header));

		PCRYPTO_INFO cryptoInfo = NULL;
		
		int status = ReadVolumeHeader (!encStatus.HiddenSystem, header, oldPassword, old_pkcs5, old_pim, &cryptoInfo, NULL);
		finally_do_arg (PCRYPTO_INFO, cryptoInfo, { if (finally_arg) crypto_close (finally_arg); });

		// if the XTS master key is vulnerable, return error and do not allow the user to change the password since the master key will not be changed
		if (cryptoInfo->bVulnerableMasterKey)
			status = ERR_SYSENC_XTS_MASTERKEY_VULNERABLE;

		if (status != 0)
		{
			handleError (hwndDlg, status, SRC_POS);
			return status;
		}

		// Change the PKCS-5 PRF if requested by user
		if (pkcs5 != 0)
		{
			cryptoInfo->pkcs5 = pkcs5;
			RandSetHashFunction (pkcs5);
		}

		if (Randinit() != 0)
		{
			if (CryptoAPILastError == ERROR_SUCCESS)
				throw RandInitFailed (SRC_POS, GetLastError ());
			else
				throw CryptoApiFailed (SRC_POS, CryptoAPILastError);
		}
		finally_do ({ RandStop (FALSE); });

		/* force the display of the random enriching dialog */
		SetRandomPoolEnrichedByUserStatus (FALSE);

		NormalCursor();
		UserEnrichRandomPool (hwndDlg);
		WaitCursor();

		/* The header will be re-encrypted wipePassCount times to prevent adversaries from using 
		techniques such as magnetic force microscopy or magnetic force scanning tunnelling microscopy
		to recover the overwritten header. According to Peter Gutmann, data should be overwritten 22
		times (ideally, 35 times) using non-random patterns and pseudorandom data. However, as users might
		impatiently interupt the process (etc.) we will not use the Gutmann's patterns but will write the
		valid re-encrypted header, i.e. pseudorandom data, and there will be many more passes than Guttman
		recommends. During each pass we will write a valid working header. Each pass will use the same master
		key, and also the same header key, secondary key (XTS), etc., derived from the new password. The only
		item that will be different for each pass will be the salt. This is sufficient to cause each "version"
		of the header to differ substantially and in a random manner from the versions written during the
		other passes. */

		bool headerUpdated = false;
		int result = ERR_SUCCESS;

		try
		{
			BOOL backupHeader = FALSE;
			while (TRUE)
			{
				for (int wipePass = 0; wipePass < wipePassCount; wipePass++)
				{
					PCRYPTO_INFO tmpCryptoInfo = NULL;

					status = CreateVolumeHeaderInMemory (hwndDlg, !encStatus.HiddenSystem,
						header,
						cryptoInfo->ea,
						cryptoInfo->mode,
						newPassword,
						cryptoInfo->pkcs5,
						pim,
						(char *) cryptoInfo->master_keydata,
						&tmpCryptoInfo,
						cryptoInfo->VolumeSize.Value,
						cryptoInfo->hiddenVolumeSize,
						cryptoInfo->EncryptedAreaStart.Value,
						cryptoInfo->EncryptedAreaLength.Value,
						cryptoInfo->RequiredProgramVersion,
						cryptoInfo->HeaderFlags | TC_HEADER_FLAG_ENCRYPTED_SYSTEM,
						cryptoInfo->SectorSize,
						wipePass < wipePassCount - 1);

					if (tmpCryptoInfo)
						crypto_close (tmpCryptoInfo);

					if (status != 0)
					{
						handleError (hwndDlg, status, SRC_POS);
						return status;
					}

					device.SeekAt (headerOffset);
					device.Write ((uint8 *) header, sizeof (header));
					headerUpdated = true;
				}

				if (!encStatus.HiddenSystem || backupHeader)
					break;

				backupHeader = TRUE;
				headerOffset = backupHeaderOffset;
			}
		}
		catch (Exception &e)
		{
			e.Show (hwndDlg);
			result = ERR_OS_ERROR;
		}

		if (headerUpdated)
		{
			bool storedPimUpdateNeeded = false;
			ReopenBootVolumeHeaderRequest reopenRequest;
			reopenRequest.VolumePassword = *newPassword;
			reopenRequest.pkcs5_prf = cryptoInfo->pkcs5;
			reopenRequest.pim = pim;
			finally_do_arg (ReopenBootVolumeHeaderRequest*, &reopenRequest, { burn (finally_arg, sizeof (*finally_arg)); });

			if (old_pim != pim)
			{
				try
				{
					// check if PIM is stored in MBR
					uint8 userConfig = 0;
					if (	ReadBootSectorConfig (nullptr, 0, &userConfig)
						&& (userConfig & TC_BOOT_USER_CFG_FLAG_DISABLE_PIM)
						)
					{
						storedPimUpdateNeeded = true;
					}
				}
				catch (...)
				{
				}
			}

			try
			{
				// force update of bootloader if fingerprint doesn't match or if the stored PIM changed
				if (storedPimUpdateNeeded || !CheckBootloaderFingerprint (true))
					InstallBootLoader (device, true, false, pim, cryptoInfo->pkcs5);
			}
			catch (...)
			{}

			CallDriver (TC_IOCTL_REOPEN_BOOT_VOLUME_HEADER, &reopenRequest, sizeof (reopenRequest));
		}

		return result;
	}


	void BootEncryption::CheckEncryptionSetupResult ()
	{
		CallDriver (TC_IOCTL_GET_BOOT_ENCRYPTION_SETUP_RESULT);
	}


	void BootEncryption::Install (bool hiddenSystem, int hashAlgo)
	{
		BootEncryptionStatus encStatus = GetStatus();
		if (encStatus.DriveMounted)
			throw ParameterIncorrect (SRC_POS);

		try
		{
			InstallBootLoader (false, hiddenSystem, -1, hashAlgo);

			if (!hiddenSystem)
				InstallVolumeHeader ();

			RegisterBootDriver (hiddenSystem);

			RegisterSystemFavoritesService (TRUE);
		}
		catch (Exception &)
		{
			try
			{
				RestoreSystemLoader ();
			}
			catch (Exception &e)
			{
				e.Show (ParentWindow);
			}

			throw;
		}
	}


	void BootEncryption::PrepareHiddenOSCreation (int ea, int mode, int pkcs5)
	{
		BootEncryptionStatus encStatus = GetStatus();
		if (encStatus.DriveMounted)
			throw ParameterIncorrect (SRC_POS);

		CheckRequirements();
		BackupSystemLoader();

		SelectedEncryptionAlgorithmId = ea;
		SelectedPrfAlgorithmId = pkcs5;
	}


	void BootEncryption::PrepareInstallation (bool systemPartitionOnly, Password &password, int ea, int mode, int pkcs5, int pim, const wstring &rescueIsoImagePath)
	{
		BootEncryptionStatus encStatus = GetStatus();
		if (encStatus.DriveMounted)
			throw ParameterIncorrect (SRC_POS);

		CheckRequirements ();

		SystemDriveConfiguration config = GetSystemDriveConfiguration();

		// Some chipset drivers may prevent access to the last sector of the drive
		if (!systemPartitionOnly)
		{
			DISK_GEOMETRY_EX geometry = GetDriveGeometry (config.DriveNumber);
			if ((geometry.Geometry.BytesPerSector > 0) && (geometry.Geometry.BytesPerSector < TC_MAX_VOLUME_SECTOR_SIZE))
			{
				Buffer sector (geometry.Geometry.BytesPerSector);

				Device device (config.DevicePath);
				device.CheckOpened (SRC_POS);

				try
				{
					device.SeekAt (config.DrivePartition.Info.PartitionLength.QuadPart - geometry.Geometry.BytesPerSector);
					device.Read (sector.Ptr(), (DWORD) sector.Size());
				}
				catch (SystemException &e)
				{
					if (e.ErrorCode != ERROR_CRC)
					{
						e.Show (ParentWindow);
						Error ("WHOLE_DRIVE_ENCRYPTION_PREVENTED_BY_DRIVERS", ParentWindow);
						throw UserAbort (SRC_POS);
					}
				}
			}
		}

		BackupSystemLoader ();

		uint64 volumeSize;
		uint64 encryptedAreaStart;

		if (systemPartitionOnly)
		{
			volumeSize = config.SystemPartition.Info.PartitionLength.QuadPart;
			encryptedAreaStart = config.SystemPartition.Info.StartingOffset.QuadPart;
		}
		else
		{
			volumeSize = config.DrivePartition.Info.PartitionLength.QuadPart - TC_BOOT_LOADER_AREA_SIZE;
			encryptedAreaStart = config.DrivePartition.Info.StartingOffset.QuadPart + TC_BOOT_LOADER_AREA_SIZE;
		}

		SelectedEncryptionAlgorithmId = ea;
		SelectedPrfAlgorithmId = pkcs5;
		CreateVolumeHeader (volumeSize, encryptedAreaStart, &password, ea, mode, pkcs5, pim);
		
		if (!rescueIsoImagePath.empty())
			CreateRescueIsoImage (true, rescueIsoImagePath);

		// check if Fast Startup is enabled and if yes then offer to disable it
		BOOL bHibernateEnabled = FALSE, bHiberbootEnabled = FALSE;
		if (GetHibernateStatus (bHibernateEnabled, bHiberbootEnabled) && bHiberbootEnabled)
		{
			if (AskWarnYesNo ("CONFIRM_DISABLE_FAST_STARTUP", ParentWindow) == IDYES)
			{
				WriteLocalMachineRegistryDwordValue (L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power", L"HiberbootEnabled", 0);
			}
		}
	}

	bool BootEncryption::IsPagingFileActive (BOOL checkNonWindowsPartitionsOnly)
	{
		if (!IsAdmin() && IsUacSupported())
			return Elevator::IsPagingFileActive (checkNonWindowsPartitionsOnly) ? true : false;

		return ::IsPagingFileActive (checkNonWindowsPartitionsOnly) ? true : false;
	}

	void BootEncryption::RestrictPagingFilesToSystemPartition ()
	{
		wchar_t pagingFiles[128] = {0};
		StringCchCopyW (pagingFiles, ARRAYSIZE(pagingFiles), L"X:\\pagefile.sys 0 0");
		pagingFiles[0] = GetWindowsDirectory()[0];

		throw_sys_if (!WriteLocalMachineRegistryMultiString (L"System\\CurrentControlSet\\Control\\Session Manager\\Memory Management", L"PagingFiles", pagingFiles, (DWORD) (wcslen (pagingFiles) + 2) * sizeof (wchar_t)));
	}

	void BootEncryption::WriteLocalMachineRegistryDwordValue (wchar_t *keyPath, wchar_t *valueName, DWORD value)
	{
		if (!IsAdmin() && IsUacSupported())
		{
			Elevator::WriteLocalMachineRegistryDwordValue (keyPath, valueName, value);
			return;
		}

		throw_sys_if (!WriteLocalMachineRegistryDword (keyPath, valueName, value));
	}

	void BootEncryption::NotifyService (DWORD dwNotifyCmd)
	{
		if (!IsAdmin() && IsUacSupported())
		{
			Elevator::NotifyService (dwNotifyCmd);
			return;
		}

		DWORD dwRet = SendServiceNotification(dwNotifyCmd);
		if (dwRet != ERROR_SUCCESS)
		{
			SetLastError(dwRet);
			throw SystemException (SRC_POS);
		}
	}

	void BootEncryption::StartDecryption (BOOL discardUnreadableEncryptedSectors)
	{
		BootEncryptionStatus encStatus = GetStatus();

		if (!encStatus.DeviceFilterActive || !encStatus.DriveMounted || encStatus.SetupInProgress)
			throw ParameterIncorrect (SRC_POS);

		BootEncryptionSetupRequest request;
		ZeroMemory (&request, sizeof (request));
		
		request.SetupMode = SetupDecryption;
		request.DiscardUnreadableEncryptedSectors = discardUnreadableEncryptedSectors;

		CallDriver (TC_IOCTL_BOOT_ENCRYPTION_SETUP, &request, sizeof (request), NULL, 0);
	}

	void BootEncryption::StartEncryption (WipeAlgorithmId wipeAlgorithm, bool zeroUnreadableSectors)
	{
		BootEncryptionStatus encStatus = GetStatus();

		if (!encStatus.DeviceFilterActive || !encStatus.DriveMounted || encStatus.SetupInProgress)
			throw ParameterIncorrect (SRC_POS);

		BootEncryptionSetupRequest request;
		ZeroMemory (&request, sizeof (request));
		
		request.SetupMode = SetupEncryption;
		request.WipeAlgorithm = wipeAlgorithm;
		request.ZeroUnreadableSectors = zeroUnreadableSectors;

		CallDriver (TC_IOCTL_BOOT_ENCRYPTION_SETUP, &request, sizeof (request), NULL, 0);
	}

	void BootEncryption::CopyFileAdmin (const wstring &sourceFile, const wstring &destinationFile)
	{
		if (!IsAdmin())
		{
			if (!IsUacSupported())
			{
				SetLastError (ERROR_ACCESS_DENIED);
				throw SystemException(SRC_POS);
			}
			else
				Elevator::CopyFile (sourceFile, destinationFile);
		}
		else
			throw_sys_if (!::CopyFile (sourceFile.c_str(), destinationFile.c_str(), FALSE));
	}

	void BootEncryption::DeleteFileAdmin (const wstring &file)
	{
		if (!IsAdmin() && IsUacSupported())
			Elevator::DeleteFile (file);
		else
			throw_sys_if (!::DeleteFile (file.c_str()));
	}

#endif // !SETUP

	uint32 BootEncryption::ReadDriverConfigurationFlags ()
	{
		DWORD configMap;

		if (!ReadLocalMachineRegistryDword (L"SYSTEM\\CurrentControlSet\\Services\\veracrypt", TC_DRIVER_CONFIG_REG_VALUE_NAME, &configMap))
			configMap = 0;

		return configMap;
	}

	uint32 BootEncryption::ReadServiceConfigurationFlags ()
	{
		DWORD configMap;

		if (!ReadLocalMachineRegistryDword (L"SYSTEM\\CurrentControlSet\\Services\\" TC_SYSTEM_FAVORITES_SERVICE_NAME, TC_SYSTEM_FAVORITES_SERVICE_NAME L"Config", &configMap))
			configMap = 0;

		return configMap;
	}

	void BootEncryption::WriteBootDriveSector (uint64 offset, uint8 *data)
	{
		WriteBootDriveSectorRequest request;
		request.Offset.QuadPart = offset;
		memcpy (request.Data, data, sizeof (request.Data));

		CallDriver (TC_IOCTL_WRITE_BOOT_DRIVE_SECTOR, &request, sizeof (request), NULL, 0);
	}

	void BootEncryption::RegisterBootDriver (bool hiddenSystem)
	{
		SetDriverServiceStartType (SERVICE_BOOT_START);

		try
		{
			RegisterFilterDriver (false, DriveFilter);
			RegisterFilterDriver (false, VolumeFilter);
			RegisterFilterDriver (false, DumpFilter);
		}
		catch (...) { }

		try
		{
			RegisterFilterDriver (true, DriveFilter);

			if (hiddenSystem)
				RegisterFilterDriver (true, VolumeFilter);

			RegisterFilterDriver (true, DumpFilter);
		}
		catch (...)
		{
			try { RegisterFilterDriver (false, DriveFilter); } catch (...) { }
			try { RegisterFilterDriver (false, VolumeFilter); } catch (...) { }
			try { RegisterFilterDriver (false, DumpFilter); } catch (...) { }
			try { SetDriverServiceStartType (SERVICE_SYSTEM_START); } catch (...) { }

			throw;
		}
	}

	bool BootEncryption::RestartComputer (BOOL bShutdown)
	{
		return (::RestartComputer(bShutdown) != FALSE);
	}

	bool BootEncryption::IsUsingUnsupportedAlgorithm(LONG driverVersion)
	{
		bool bRet = false;

		try
		{
			if (driverVersion <= 0x125)
			{
				// version 1.25 is last version to support RIPEMD160 and GOST89
				static int GOST89_EA = 5;
				static int RIPEMD160_PRF = 4;

				VOLUME_PROPERTIES_STRUCT props = {0};
				GetVolumeProperties(&props);

				//
				if (props.ea == GOST89_EA || props.pkcs5 == RIPEMD160_PRF)
					bRet = true;
			}
		}
		catch(...)
		{

		}

		return bRet;
	}
}
