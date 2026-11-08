/*
 * MUSCLE SmartCard Development ( https://pcsclite.apdu.fr/ )
 *
 * Copyright (C) 1999-2005
 *  David Corcoran <corcoran@musclecard.com>
 * Copyright (C) 2005-2009
 *  Ludovic Rousseau <ludovic.rousseau@free.fr>
 *
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
3. The name of the author may not be used to endorse or promote products
   derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file
 * @brief This keeps a list of defines shared between the driver and the application
 */

#ifndef __reader_h__
#define __reader_h__

/*
 * Tags for requesting card and reader attributes
 */

#define SCARD_ATTR_VALUE(Class, Tag) ((((ULONG)(Class)) << 16) | ((ULONG)(Tag)))

#define SCARD_CLASS_VENDOR_INFO     1   /**< Vendor information definitions */
#define SCARD_CLASS_COMMUNICATIONS  2   /**< Communication definitions */
#define SCARD_CLASS_PROTOCOL        3   /**< Protocol definitions */
#define SCARD_CLASS_POWER_MGMT      4   /**< Power Management definitions */
#define SCARD_CLASS_SECURITY        5   /**< Security Assurance definitions */
#define SCARD_CLASS_MECHANICAL      6   /**< Mechanical characteristic definitions */
#define SCARD_CLASS_VENDOR_DEFINED  7   /**< Vendor specific definitions */
#define SCARD_CLASS_IFD_PROTOCOL    8   /**< Interface Device Protocol options */
#define SCARD_CLASS_ICC_STATE       9   /**< ICC State specific definitions */
#define SCARD_CLASS_SYSTEM     0x7fff   /**< System-specific definitions */

#define SCARD_ATTR_VENDOR_NAME SCARD_ATTR_VALUE(SCARD_CLASS_VENDOR_INFO, 0x0100) /**< Vendor name. */
#define SCARD_ATTR_VENDOR_IFD_TYPE SCARD_ATTR_VALUE(SCARD_CLASS_VENDOR_INFO, 0x0101) /**< Vendor-supplied interface device type (model designation of reader). */
#define SCARD_ATTR_VENDOR_IFD_VERSION SCARD_ATTR_VALUE(SCARD_CLASS_VENDOR_INFO, 0x0102) /**< Vendor-supplied interface device version (DWORD in the form 0xMMmmbbbb where MM = major version, mm = minor version, and bbbb = build number). */
#define SCARD_ATTR_VENDOR_IFD_SERIAL_NO SCARD_ATTR_VALUE(SCARD_CLASS_VENDOR_INFO, 0x0103) /**< Vendor-supplied interface device serial number. */
#define SCARD_ATTR_CHANNEL_ID SCARD_ATTR_VALUE(SCARD_CLASS_COMMUNICATIONS, 0x0110) /**< DWORD encoded as 0xDDDDCCCC, where DDDD = data channel type and CCCC = channel number */
#define SCARD_ATTR_ASYNC_PROTOCOL_TYPES SCARD_ATTR_VALUE(SCARD_CLASS_PROTOCOL, 0x0120) /**< FIXME */
#define SCARD_ATTR_DEFAULT_CLK SCARD_ATTR_VALUE(SCARD_CLASS_PROTOCOL, 0x0121) /**< Default clock rate, in kHz. */
#define SCARD_ATTR_MAX_CLK SCARD_ATTR_VALUE(SCARD_CLASS_PROTOCOL, 0x0122) /**< Maximum clock rate, in kHz. */
#define SCARD_ATTR_DEFAULT_DATA_RATE SCARD_ATTR_VALUE(SCARD_CLASS_PROTOCOL, 0x0123) /**< Default data rate, in bps. */
#define SCARD_ATTR_MAX_DATA_RATE SCARD_ATTR_VALUE(SCARD_CLASS_PROTOCOL, 0x0124) /**< Maximum data rate, in bps. */
#define SCARD_ATTR_MAX_IFSD SCARD_ATTR_VALUE(SCARD_CLASS_PROTOCOL, 0x0125) /**< Maximum bytes for information file size device. */
#define SCARD_ATTR_SYNC_PROTOCOL_TYPES SCARD_ATTR_VALUE(SCARD_CLASS_PROTOCOL, 0x0126) /**< FIXME */
#define SCARD_ATTR_POWER_MGMT_SUPPORT SCARD_ATTR_VALUE(SCARD_CLASS_POWER_MGMT, 0x0131) /**< Zero if device does not support power down while smart card is inserted. Nonzero otherwise. */
#define SCARD_ATTR_USER_TO_CARD_AUTH_DEVICE SCARD_ATTR_VALUE(SCARD_CLASS_SECURITY, 0x0140) /**< FIXME */
#define SCARD_ATTR_USER_AUTH_INPUT_DEVICE SCARD_ATTR_VALUE(SCARD_CLASS_SECURITY, 0x0142) /**< FIXME */
#define SCARD_ATTR_CHARACTERISTICS SCARD_ATTR_VALUE(SCARD_CLASS_MECHANICAL, 0x0150) /**< DWORD indicating which mechanical characteristics are supported. If zero, no special characteristics are supported. Note that multiple bits can be set */

#define SCARD_ATTR_CURRENT_PROTOCOL_TYPE SCARD_ATTR_VALUE(SCARD_CLASS_IFD_PROTOCOL, 0x0201) /**< FIXME */
#define SCARD_ATTR_CURRENT_CLK SCARD_ATTR_VALUE(SCARD_CLASS_IFD_PROTOCOL, 0x0202) /**< Current clock rate, in kHz. */
#define SCARD_ATTR_CURRENT_F SCARD_ATTR_VALUE(SCARD_CLASS_IFD_PROTOCOL, 0x0203) /**< Clock conversion factor. */
#define SCARD_ATTR_CURRENT_D SCARD_ATTR_VALUE(SCARD_CLASS_IFD_PROTOCOL, 0x0204) /**< Bit rate conversion factor. */
#define SCARD_ATTR_CURRENT_N SCARD_ATTR_VALUE(SCARD_CLASS_IFD_PROTOCOL, 0x0205) /**< Current guard time. */
#define SCARD_ATTR_CURRENT_W SCARD_ATTR_VALUE(SCARD_CLASS_IFD_PROTOCOL, 0x0206) /**< Current work waiting time. */
#define SCARD_ATTR_CURRENT_IFSC SCARD_ATTR_VALUE(SCARD_CLASS_IFD_PROTOCOL, 0x0207) /**< Current byte size for information field size card. */
#define SCARD_ATTR_CURRENT_IFSD SCARD_ATTR_VALUE(SCARD_CLASS_IFD_PROTOCOL, 0x0208) /**< Current byte size for information field size device. */
#define SCARD_ATTR_CURRENT_BWT SCARD_ATTR_VALUE(SCARD_CLASS_IFD_PROTOCOL, 0x0209) /**< Current block waiting time. */
#define SCARD_ATTR_CURRENT_CWT SCARD_ATTR_VALUE(SCARD_CLASS_IFD_PROTOCOL, 0x020a) /**< Current character waiting time. */
#define SCARD_ATTR_CURRENT_EBC_ENCODING SCARD_ATTR_VALUE(SCARD_CLASS_IFD_PROTOCOL, 0x020b) /**< Current error block control encoding. */
#define SCARD_ATTR_EXTENDED_BWT SCARD_ATTR_VALUE(SCARD_CLASS_IFD_PROTOCOL, 0x020c) /**< FIXME */

#define SCARD_ATTR_ICC_PRESENCE SCARD_ATTR_VALUE(SCARD_CLASS_ICC_STATE, 0x0300) /**< Single byte indicating smart card presence */
#define SCARD_ATTR_ICC_INTERFACE_STATUS SCARD_ATTR_VALUE(SCARD_CLASS_ICC_STATE, 0x0301) /**< Single byte. Zero if smart card electrical contact is not active; nonzero if contact is active. */
#define SCARD_ATTR_CURRENT_IO_STATE SCARD_ATTR_VALUE(SCARD_CLASS_ICC_STATE, 0x0302) /**< FIXME */
#define SCARD_ATTR_ATR_STRING SCARD_ATTR_VALUE(SCARD_CLASS_ICC_STATE, 0x0303) /**< Answer to reset (ATR) string. */
#define SCARD_ATTR_ICC_TYPE_PER_ATR SCARD_ATTR_VALUE(SCARD_CLASS_ICC_STATE, 0x0304) /**< Single byte indicating smart card type */

#define SCARD_ATTR_ESC_RESET SCARD_ATTR_VALUE(SCARD_CLASS_VENDOR_DEFINED, 0xA000) /**< FIXME */
#define SCARD_ATTR_ESC_CANCEL SCARD_ATTR_VALUE(SCARD_CLASS_VENDOR_DEFINED, 0xA003) /**< FIXME */
#define SCARD_ATTR_ESC_AUTHREQUEST SCARD_ATTR_VALUE(SCARD_CLASS_VENDOR_DEFINED, 0xA005) /**< FIXME */
#define SCARD_ATTR_MAXINPUT SCARD_ATTR_VALUE(SCARD_CLASS_VENDOR_DEFINED, 0xA007) /**< FIXME */

#define SCARD_ATTR_DEVICE_UNIT SCARD_ATTR_VALUE(SCARD_CLASS_SYSTEM, 0x0001) /**< Instance of this vendor's reader attached to the computer. The first instance will be device unit 0, the next will be unit 1 (if it is the same brand of reader) and so on. Two different brands of readers will both have zero for this value. */
#define SCARD_ATTR_DEVICE_IN_USE SCARD_ATTR_VALUE(SCARD_CLASS_SYSTEM, 0x0002) /**< Reserved for future use. */
#define SCARD_ATTR_DEVICE_FRIENDLY_NAME_A SCARD_ATTR_VALUE(SCARD_CLASS_SYSTEM, 0x0003)
#define SCARD_ATTR_DEVICE_SYSTEM_NAME_A SCARD_ATTR_VALUE(SCARD_CLASS_SYSTEM, 0x0004)
#define SCARD_ATTR_DEVICE_FRIENDLY_NAME_W SCARD_ATTR_VALUE(SCARD_CLASS_SYSTEM, 0x0005)
#define SCARD_ATTR_DEVICE_SYSTEM_NAME_W SCARD_ATTR_VALUE(SCARD_CLASS_SYSTEM, 0x0006)
#define SCARD_ATTR_SUPRESS_T1_IFS_REQUEST SCARD_ATTR_VALUE(SCARD_CLASS_SYSTEM, 0x0007) /**< FIXME */

#ifdef UNICODE
#define SCARD_ATTR_DEVICE_FRIENDLY_NAME SCARD_ATTR_DEVICE_FRIENDLY_NAME_W /**< Reader's display name. */
#define SCARD_ATTR_DEVICE_SYSTEM_NAME SCARD_ATTR_DEVICE_SYSTEM_NAME_W /**< Reader's system name. */
#else
#define SCARD_ATTR_DEVICE_FRIENDLY_NAME SCARD_ATTR_DEVICE_FRIENDLY_NAME_A /**< Reader's display name. */
#define SCARD_ATTR_DEVICE_SYSTEM_NAME SCARD_ATTR_DEVICE_SYSTEM_NAME_A /**< Reader's system name. */
#endif

/**
 * Provide source compatibility on different platforms
 */
#define SCARD_CTL_CODE(code) (0x42000000 + (code))

/**
 * PC/SC part 10 v2.02.07 March 2010 reader tags
 */
#define CM_IOCTL_GET_FEATURE_REQUEST SCARD_CTL_CODE(3400)

#define FEATURE_VERIFY_PIN_START         0x01
#define FEATURE_VERIFY_PIN_FINISH        0x02
#define FEATURE_MODIFY_PIN_START         0x03
#define FEATURE_MODIFY_PIN_FINISH        0x04
#define FEATURE_GET_KEY_PRESSED          0x05
#define FEATURE_VERIFY_PIN_DIRECT        0x06 /**< Verify PIN */
#define FEATURE_MODIFY_PIN_DIRECT        0x07 /**< Modify PIN */
#define FEATURE_MCT_READER_DIRECT        0x08
#define FEATURE_MCT_UNIVERSAL            0x09
#define FEATURE_IFD_PIN_PROPERTIES       0x0A /**< retrieve properties of the IFD regarding PIN handling */
#define FEATURE_ABORT                    0x0B
#define FEATURE_SET_SPE_MESSAGE          0x0C
#define FEATURE_VERIFY_PIN_DIRECT_APP_ID 0x0D
#define FEATURE_MODIFY_PIN_DIRECT_APP_ID 0x0E
#define FEATURE_WRITE_DISPLAY            0x0F
#define FEATURE_GET_KEY                  0x10
#define FEATURE_IFD_DISPLAY_PROPERTIES   0x11
#define FEATURE_GET_TLV_PROPERTIES       0x12
#define FEATURE_CCID_ESC_COMMAND         0x13
#define FEATURE_EXECUTE_PACE             0x20

/* structures used (but not defined) in PC/SC Part 10:
 * "IFDs with Secure Pin Entry Capabilities" */

#include <inttypes.h>

/* Set structure elements alignment on bytes
 * http://gcc.gnu.org/onlinedocs/gcc/Structure_002dPacking-Pragmas.html */
#if defined(__APPLE__) || defined(sun) || defined(__NetBSD__)
#pragma pack(1)
#else
#pragma pack(push, 1)
#endif

/** the structure must be 6-bytes long */
typedef struct
{
	uint8_t tag;
	uint8_t length;
	uint32_t value;	/**< This value is always in BIG ENDIAN format as documented in PCSC v2 part 10 ch 2.2 page 2. You can use ntohl() for example */
} PCSC_TLV_STRUCTURE;

/** Since CCID 1.4.1 (revision 5252) the byte order is no more important
 * These macros are now deprecated and should be removed in the future */
#define HOST_TO_CCID_16(x) (x)
#define HOST_TO_CCID_32(x) (x)

/** structure used with \ref FEATURE_VERIFY_PIN_DIRECT */
typedef struct
{
	uint8_t bTimerOut;	/**< timeout is seconds (00 means use default timeout) */
	uint8_t bTimerOut2; /**< timeout in seconds after first key stroke */
	uint8_t bmFormatString; /**< formatting options */
	uint8_t bmPINBlockString; /**< bits 7-4 bit size of PIN length in APDU,
	                        * bits 3-0 PIN block size in bytes after
	                        * justification and formatting */
	uint8_t bmPINLengthFormat; /**< bits 7-5 RFU,
	                         * bit 4 set if system units are bytes, clear if
	                         * system units are bits,
	                         * bits 3-0 PIN length position in system units */
	uint16_t wPINMaxExtraDigit; /**< 0xXXYY where XX is minimum PIN size in digits,
	                            and YY is maximum PIN size in digits */
	uint8_t bEntryValidationCondition; /**< Conditions under which PIN entry should
	                                 * be considered complete */
	uint8_t bNumberMessage; /**< Number of messages to display for PIN verification */
	uint16_t wLangId; /**< Language for messages. https://docs.microsoft.com/en-us/windows/win32/intl/language-identifier-constants-and-strings */
	uint8_t bMsgIndex; /**< Message index (should be 00) */
	uint8_t bTeoPrologue[3]; /**< T=1 block prologue field to use (fill with 00) */
	uint32_t ulDataLength; /**< length of Data to be sent to the ICC */
	uint8_t abData
#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L)
	[] /* valid C99 code */
#else
	[0] /* non-standard, but usually working code */
#endif
	; /**< Data to send to the ICC */
} PIN_VERIFY_STRUCTURE;

/** structure used with \ref FEATURE_MODIFY_PIN_DIRECT */
typedef struct
{
	uint8_t bTimerOut;	/**< timeout is seconds (00 means use default timeout) */
	uint8_t bTimerOut2; /**< timeout in seconds after first key stroke */
	uint8_t bmFormatString; /**< formatting options */
	uint8_t bmPINBlockString; /**< bits 7-4 bit size of PIN length in APDU,
	                        * bits 3-0 PIN block size in bytes after
	                        * justification and formatting */
	uint8_t bmPINLengthFormat; /**< bits 7-5 RFU,
	                         * bit 4 set if system units are bytes, clear if
	                         * system units are bits,
	                         * bits 3-0 PIN length position in system units */
	uint8_t bInsertionOffsetOld; /**< Insertion position offset in bytes for
	                             the current PIN */
	uint8_t bInsertionOffsetNew; /**< Insertion position offset in bytes for
	                             the new PIN */
	uint16_t wPINMaxExtraDigit;
	                         /**< 0xXXYY where XX is minimum PIN size in digits,
	                            and YY is maximum PIN size in digits */
	uint8_t bConfirmPIN; /**< Flags governing need for confirmation of new PIN */
	uint8_t bEntryValidationCondition; /**< Conditions under which PIN entry should
	                                 * be considered complete */
	uint8_t bNumberMessage; /**< Number of messages to display for PIN verification*/
	uint16_t wLangId; /**< Language for messages. https://docs.microsoft.com/en-us/windows/win32/intl/language-identifier-constants-and-strings */
	uint8_t bMsgIndex1; /**< index of 1st prompting message */
	uint8_t bMsgIndex2; /**< index of 2d prompting message */
	uint8_t bMsgIndex3; /**< index of 3d prompting message */
	uint8_t bTeoPrologue[3]; /**< T=1 block prologue field to use (fill with 00) */
	uint32_t ulDataLength; /**< length of Data to be sent to the ICC */
	uint8_t abData
#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L)
	[] /* valid C99 code */
#else
	[0] /* non-standard, but usually working code */
#endif
	; /**< Data to send to the ICC */
} PIN_MODIFY_STRUCTURE;

/** structure used with \ref FEATURE_IFD_PIN_PROPERTIES */
typedef struct {
	uint16_t wLcdLayout; /**< display characteristics */
	uint8_t bEntryValidationCondition;
	uint8_t bTimeOut2;
} PIN_PROPERTIES_STRUCTURE;

/* restore default structure elements alignment */
#if defined(__APPLE__) || defined(sun) || defined(__NetBSD__)
#pragma pack()
#else
#pragma pack(pop)
#endif

/* properties returned by FEATURE_GET_TLV_PROPERTIES */
#define PCSCv2_PART10_PROPERTY_wLcdLayout 1
#define PCSCv2_PART10_PROPERTY_bEntryValidationCondition 2
#define PCSCv2_PART10_PROPERTY_bTimeOut2 3
#define PCSCv2_PART10_PROPERTY_wLcdMaxCharacters 4
#define PCSCv2_PART10_PROPERTY_wLcdMaxLines 5
#define PCSCv2_PART10_PROPERTY_bMinPINSize 6
#define PCSCv2_PART10_PROPERTY_bMaxPINSize 7
#define PCSCv2_PART10_PROPERTY_sFirmwareID 8
#define PCSCv2_PART10_PROPERTY_bPPDUSupport 9
#define PCSCv2_PART10_PROPERTY_dwMaxAPDUDataSize 10
#define PCSCv2_PART10_PROPERTY_wIdVendor 11
#define PCSCv2_PART10_PROPERTY_wIdProduct 12

#endif

