/*
 * VeraCrypt Format SDK
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * This file provides a C-style DLL interface for creating VeraCrypt file containers
 * and formatting non-system partitions. It serves as a headless, thread-safe wrapper
 * around the core logic from Tcformat.c and related VeraCrypt source files.
 *
 * First created by Mounir IDRASSI (mounir.idrassi@amcrypto.jp)
 * 
 */

#pragma once

#include <stdint.h>

#ifdef VCSDK_EXPORTS
#define VCF_API __declspec(dllexport)
#else
#define VCF_API __declspec(dllimport)
#endif

#define VC_MAX_PASSWORD		128		// Maximum possible password length
#define VC_MAX_PIM_VALUE	2147468 // Maximum value to have a positive 32-bit result for formula 15000 + (PIM x 1000)

#ifdef __cplusplus
extern "C" {
#endif

// --- Public Data Structures and Callbacks ---
/**
* @brief enum with all the drive letters aviables
*/
typedef enum DriveLetter {
		DRIVE_LETTER_A = 0,
		DRIVE_LETTER_B,
		DRIVE_LETTER_C,
		DRIVE_LETTER_D,
		DRIVE_LETTER_E,
		DRIVE_LETTER_F,
		DRIVE_LETTER_G,
		DRIVE_LETTER_H,
		DRIVE_LETTER_I,
		DRIVE_LETTER_J,
		DRIVE_LETTER_K,
		DRIVE_LETTER_L,
		DRIVE_LETTER_M,
		DRIVE_LETTER_N,
		DRIVE_LETTER_O,
		DRIVE_LETTER_P,
		DRIVE_LETTER_Q,
		DRIVE_LETTER_R,
		DRIVE_LETTER_S,
		DRIVE_LETTER_T,
		DRIVE_LETTER_U,
		DRIVE_LETTER_V,
		DRIVE_LETTER_W,
		DRIVE_LETTER_X,
		DRIVE_LETTER_Y,
		DRIVE_LETTER_Z
};
/**
* @brief enum with all the encryption algorithms aviables for volumen creation
*/
typedef enum VolumeEncryptionAlgorithm{
	VERACRYPT_VOLUME_ENCRYPTION_AES = 0,
	VERACRYPT_VOLUME_ENCRYPTION_Serpent,
	VERACRYPT_VOLUME_ENCRYPTION_Twofish,
	VERACRYPT_VOLUME_ENCRYPTION_Camellia,
	VERACRYPT_VOLUME_ENCRYPTION_Kuznyechik,
	VERACRYPT_VOLUME_ENCRYPTION_AES_Twofish_Serpent,
	VERACRYPT_VOLUME_ENCRYPTION_AES_Serpent,
	VERACRYPT_VOLUME_ENCRYPTION_Serpent_Twofish_AES,
	VERACRYPT_VOLUME_ENCRYPTION_Serpent_Twofish,
	VERACRYPT_VOLUME_ENCRYPTION_Kuznyechik_Camellia,
	VERACRYPT_VOLUME_ENCRYPTION_Twofish_Kuznyechik,
	VERACRYPT_VOLUME_ENCRYPTION_Serpent_Camellia,
	VERACRYPT_VOLUME_ENCRYPTION_AES_Kuznyechik,
	VERACRYPT_VOLUME_ENCRYPTION_Camellia_Serpent_Kuznyechik
};
/**
* @brief enum with all the hash algorithms aviables for volumen creation
*/
typedef enum HashAlgorithm{
	VERACRYPT_HASH_SHA_512 = 0,
	VERACRYPT_HASH_SHA_256,
	VERACRYPT_HASH_RIPEMD_160,
	VERACRYPT_HASH_Whirlpool,
	VERACRYPT_HASH_BLAKE2s_256
};
/**
* @brief enum with all the filesystem format options aviables for volumen creation
*/
typedef enum FileSystemFormat{
	VERACRYPT_FILESYSTEM_FORMAT_NTFS = 0,
	VERACRYPT_FILESYSTEM_FORMAT_FAT,
	VERACRYPT_FILESYSTEM_FORMAT_ExFAT,
	VERACRYPT_FILESYSTEM_FORMAT_ReFS,
	VERACRYPT_FILESYSTEM_FORMAT_None
};
/**
* @brief enum with all the size measure unity options aviables for volumen creation
*/
typedef enum SizeMeasureUnity{
	Kilobytes = 0,
	Megabytes,
	Gigabytes
};
/**
 * @brief Defines the parameters for creating a VeraCrypt volume.
 */
typedef struct _VeraCryptFormatOptions
{
	/** The full path to the file container to be created, or the device path (e.g., "\Device\Harddisk1\Partition1"). */
	const wchar_t* path;

	/** Set to TRUE if the path points to a device/partition, FALSE for a file container. */
	BOOL isDevice;

	/** The password for the new volume. Can be NULL if keyfiles are used. Must be UTF-8 encoded. */
	const char* password;

	/** A NULL-terminated array of wide-char strings, each being a full path to a keyfile. Set to NULL if no keyfiles are used. */
	const wchar_t** keyfiles;

	/** The Personal Iterations Multiplier (PIM). Use 0 for default PIM. */
	int pim;

	/** size measure unity */
	SizeMeasureUnity sizeMeasureUnity;

	/** The size of the volume in bytes. This is only used for file containers (when isDevice is FALSE). Must be a multiple of 512. */
	uint64_t size;

	/** The encryption algorithm to use. E.g., AES, Serpent, Twofish, AES_Twofish_Serpent. */
	VolumeEncryptionAlgorithm encryptionAlgorithm;

	/** The header key derivation and random pool hash algorithm. E.g., SHA_512, RIPEMD_160, Whirlpool, BLAKE2s_256, SHA_256. */
	HashAlgorithm hashAlgorithm;

	/** The filesystem for the new volume. E.g., NTFS, FAT, ExFAT, ReFS, or None. */
	FileSystemFormat filesystem;

	/** The cluster size in sectors (e.g., 1, 2, 4, 8...). Use 0 for default. */
	int clusterSize;
	
	/** If TRUE, performs a quick format. This is faster but less secure as old data is not overwritten. */
	BOOL quickFormat;
	
	/** If TRUE, creates a dynamically-expanding (sparse) file container. Only for file containers. Implies quickFormat=TRUE. */
	BOOL dynamicFormat;

	/** If TRUE, creates a file container very quickly without waiting for random pool to be filled. Less secure. Only for file containers. Implies quickFormat=TRUE. */
	BOOL fastCreateFile;

	/** A callback function to receive progress updates. Can be NULL. It can return FALSE to abort the operation. */
	BOOL (CALLBACK *progressCallback)(int percentComplete, void* userData);

	/** User-defined data to be passed to the progress callback. */
	void* progressUserData;

} VeraCryptFormatOptions;
/**
* @brief Defines the parameters for mount a volume
*/
typedef struct _VeraCryptMountOptions {
	int pim;
	DriveLetter letter;
	const char* password;
	const char* protectedHidVolPassword;/* Password of hidden volume to protect against overwriting */
	wchar_t* path;
	VolumeEncryptionAlgorithm encryptionAlgorithm;
	const wchar_t** keyfiles;
	BOOL autoDetectEncryptionAlgorithm;
	BOOL ReadOnly;
	BOOL Removable;
	BOOL ProtectHiddenVolume;
	BOOL PreserveTimestamp;
	BOOL PartitionInInactiveSysEncScope;	/* If TRUE, we are to attempt to mount a partition located on an encrypted system drive without pre-boot authentication. */
	BOOL UseBackupHeader;
	BOOL RecoveryMode;
	int ProtectedHidVolPkcs5Prf;
	int ProtectedHidVolPim;
	wchar_t Label[33]; /* maximum label length is 32 for NTFS and 11 for FAT32 */
	BOOL DisableMountManager;
	BOOL SkipCachedPasswords;
	BOOL cachePassword;
	BOOL cachePim;
	BOOL sharedAccess;
} VeraCryptMountOptions;
/**
 * @brief Progress callback function pointer type.
 * @param percentComplete The percentage of the format operation that is complete (0-100).
 * @param userData The user-defined data pointer passed in VeraCryptFormatOptions.
 * @return Returns TRUE to continue the operation, or FALSE to abort it.
 */
typedef BOOL (CALLBACK *VeraCrypt_Progress_Callback)(int percentComplete, void* userData);
// --- Public Error Codes ---
#define VCF_SUCCESS                             0
#define VCF_ERROR_GENERIC                       1   // A generic or unknown error occurred.
#define VCF_ERROR_INVALID_PARAMETER             2   // An invalid parameter was passed (e.g. NULL path).
#define VCF_ERROR_PASSWORD_OR_KEYFILE_REQUIRED  3   // A password and/or keyfile must be provided.
#define VCF_ERROR_INVALID_ENCRYPTION_ALGORITHM  4
#define VCF_ERROR_INVALID_HASH_ALGORITHM        5
#define VCF_ERROR_INVALID_FILESYSTEM            6
#define VCF_ERROR_PASSWORD_POLICY               7   // Password is too long or violates other policies.
#define VCF_ERROR_KEYFILE_ERROR                 8   // Error reading or processing a keyfile.
#define VCF_ERROR_OUT_OF_MEMORY                 9
#define VCF_ERROR_OS_ERROR                      10  // A Windows API call failed.
#define VCF_ERROR_CANNOT_GET_DEVICE_SIZE        11
#define VCF_ERROR_VOLUME_SIZE_TOO_SMALL         12
#define VCF_ERROR_RNG_INIT_FAILED               13
#define VCF_ERROR_NO_DRIVER                     14  // VeraCrypt driver is not running.
#define VCF_ERROR_SELF_TEST_FAILED              15
#define VCF_ERROR_USER_ABORT                    16  // Should not occur in SDK, but mapped for completeness.
#define VCF_ERROR_INITIALIZATION_FAILED         17
#define VCF_ERROR_NOT_INITIALIZED               18
#define VCF_ERROR_INVALID_VOLUME_SIZE           19  // e.g., not a multiple of sector size.
#define VCF_ERROR_FILESYSTEM_INVALID_FOR_SIZE   21  // The selected filesystem cannot be used for the given volume size.
#define VCF_ERROR_CONTAINER_TOO_LARGE_FOR_HOST  22  // The file container is larger than the available free space.
#define VCF_ERROR_ACCESS_DENIED                 23  // The target path is read-only or cannot be created.
#define VCF_ERROR_FULL_PATH_GETTING_ERROR		24
#define VCF_ERROR_DRIVE_LETTER_UNAVIABLE		25
// --- Public API Functions ---

/**
 * @brief Initializes the VeraCrypt Format SDK.
 * This function must be called once per process before any other SDK functions.
 * It attaches to the VeraCrypt driver, runs self-tests, and seeds the RNG.
 * This function is thread-safe.
 *
 * @return Returns VCF_SUCCESS (0) on success, or a non-zero VCF_ERROR_* code on failure.
 */
VCF_API int __cdecl VeraCryptFormat_Initialize();

/**
 * @brief Shuts down the VeraCrypt Format SDK.
 * Call this function when the SDK is no longer needed to release resources.
 */
VCF_API void __cdecl VeraCryptFormat_Shutdown();

/**
 * @brief Creates a VeraCrypt volume (file container or formatted partition).
 * This is the main entry point for the VeraCrypt Format SDK.
 * This function is synchronous and will block until the format operation is complete.
 * It is thread-safe, but operations are serialized internally.
 * VeraCryptFormat_Initialize() must be called successfully before using this function.
 *
 * @param options A pointer to a VeraCryptFormatOptions struct containing all parameters for the operation.
 * @return Returns VCF_SUCCESS (0) on success, or a non-zero VCF_ERROR_* code on failure.
 */
VCF_API int __cdecl VeraCryptFormat(const VeraCryptFormatOptions* options);
/**
* @brief get the absolute path into the absolutePath parameter
*/
VCF_API int __cdecl GetAbsolutePath(const wchar_t* relativePath, wchar_t* absolutePath, DWORD absolutePathSize);
/**
* @brief Get the absolute path to a device mounted at the given drive letter
*/
VCF_API int __cdecl GetDevicePath(DriveLetter letter, wchar_t* devicePath, DWORD devicePathSize);
/**
* @brief Mount a a VeraCrypt volume. VeraCryptFormat_Initialize() must be called successfully
* before using this function.
* @param options A pointer to a VeraCryptMountOptions struct containing all parameters for the operation.
* @return Return VCF_SUCCESS (0) on success, or a non-zero VCF_ERROR_* code on failure
*/
VCF_API int __cdecl VeraCryptMount(const VeraCryptMountOptions* options);
/**
* @brief Dismount a VeraCrypt volume. VeraCryptFormat_Initialize() must be called successfully
* before using this function.
* @param letter The drive letter where the volume is mounted
* @param force Tells if the unmount operation will be forced
* @return Return VCF_SUCCESS (0) on success, or a non-zero VCF_ERROR_* code on failure
*/
VCF_API int __cdecl VeraCryptDismount(DriveLetter letter, BOOL force);
#ifdef __cplusplus
}
#endif