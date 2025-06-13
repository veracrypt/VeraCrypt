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

	/** The size of the volume in bytes. This is only used for file containers (when isDevice is FALSE). Must be a multiple of 512. */
	uint64_t size;

	/** The encryption algorithm to use. E.g., L"AES", L"Serpent", L"Twofish", L"AES-Twofish-Serpent". */
	const wchar_t* encryptionAlgorithm;

	/** The header key derivation and random pool hash algorithm. E.g., L"SHA-512", L"RIPEMD-160", L"Whirlpool", L"BLAKE2s-256", L"SHA-256". */
	const wchar_t* hashAlgorithm;

	/** The filesystem for the new volume. E.g., L"NTFS", L"FAT", L"ExFAT", L"ReFS", or L"None". */
	const wchar_t* filesystem;

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

#ifdef __cplusplus
}
#endif