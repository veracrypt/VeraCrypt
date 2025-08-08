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

#include "Tcdefs.h"
#include <string>
#include <vector>
#include <mutex>
#include <atomic>
#include <Strsafe.h>

#include "Dlgcode.h"
#include "Crypto.h"
#include "Apidrvr.h"
#include "Common/Common.h"
#include "Common/Dictionary.h"
#include "Common/Pkcs5.h"
#include "Platform/Finally.h"
#include "Random.h"
#include "Format.h"
#include "Volumes.h"
#include "Keyfiles.h"
#include "Password.h"
#include "Tests.h"
#include "Wipe.h"
#include "VeraCryptFormatSdk.h"


// Global variables from Tcformat.c we need to control
extern BOOL bDevice;
extern unsigned __int64 nVolumeSize;
extern int nVolumeEA;
extern int hash_algo;
extern int volumePim;
extern volatile int fileSystem;
extern volatile int clusterSize;
extern volatile BOOL quickFormat;
extern volatile BOOL fastCreateFile;
extern volatile BOOL dynamicFormat;
extern Password volumePassword;
extern KeyFile *FirstKeyFile;
extern wchar_t szDiskFile[TC_MAX_PATH+1];
extern HINSTANCE hInst;
extern BOOL bGuiMode;

// Core formatting function from Format.c
int TCFormatVolume (volatile FORMAT_VOL_PARAMETERS *volParams);

// Helper functions from other parts of VeraCrypt
void WipePasswordsAndKeyfiles (bool bFull);
int DriverAttach ();
BOOL AutoTestAlgorithms();
extern "C" DWORD GetFormatSectorSize();
void InitApp (HINSTANCE hInstance, wchar_t *lpszCommandLine);
void cleanup ();

// Global mutex to ensure that volume creation operations are serialized,
// as the underlying code uses extensive global state.
static std::mutex g_sdkMutex;
static std::atomic<bool> g_isInitialized = false;
static HINSTANCE g_hDllInstance = NULL;

// Helper to map string representations to internal VeraCrypt EA IDs
static int MapEncryptionAlgorithm(const wchar_t* algoName)
{
	if (!algoName) return 0;
	wchar_t buf[100];
	for (int ea = EAGetFirst(); ea != 0; ea = EAGetNext(ea))
	{
		if (EAIsFormatEnabled(ea) && _wcsicmp(algoName, EAGetName(buf, ARRAYSIZE(buf), ea, 1)) == 0)
		{
			return ea;
		}
	}
	return 0; // Not found
}

// Helper to map string representations to internal VeraCrypt Hash IDs
static int MapHashAlgorithm(const wchar_t* hashName)
{
	if (!hashName) return 0;
	for (int id = FIRST_PRF_ID; id <= LAST_PRF_ID; ++id)
	{
		if (!HashIsDeprecated(id) && _wcsicmp(hashName, HashGetName(id)) == 0)
		{
			return id;
		}
	}
	// Check for aliases
	if (_wcsicmp(hashName, L"BLAKE2s") == 0) return BLAKE2S;
	if (_wcsicmp(hashName, L"sha256") == 0) return SHA256;
	if (_wcsicmp(hashName, L"sha512") == 0) return SHA512;
	if (_wcsicmp(hashName, L"argon2") == 0) return ARGON2;
	return 0; // Not found
}

// Helper to map string representations to internal VeraCrypt Filesystem IDs
static int MapFilesystem(const wchar_t* fsName)
{
	if (!fsName || _wcsicmp(fsName, L"None") == 0) return FILESYS_NONE;
	if (_wcsicmp(fsName, L"FAT") == 0) return FILESYS_FAT;
	if (_wcsicmp(fsName, L"NTFS") == 0) return FILESYS_NTFS;
	if (_wcsicmp(fsName, L"ExFAT") == 0) return FILESYS_EXFAT;
	if (IsOSVersionAtLeast(WIN_10, 0) && _wcsicmp(fsName, L"ReFS") == 0) return FILESYS_REFS;
	return -1; // Invalid filesystem
}

struct SdkProgressContext
{
	VeraCrypt_Progress_Callback UserCallback;
	uint64_t TotalSize;
	void* UserData;
};

// This function is intended to be called by the internal TCFormatVolume function.
// It translates the progress into a percentage and calls the user-provided callback.
static BOOL __cdecl SdkProgressCallback(unsigned __int64 bytesProcessed, void* cbData)
{
	if (!cbData) return FALSE;

	SdkProgressContext* context = static_cast<SdkProgressContext*>(cbData);
	if (context->UserCallback && context->TotalSize > 0)
	{
		int percentage = static_cast<int>((bytesProcessed * 100) / context->TotalSize);
		if (percentage > 100) percentage = 100;

		return context->UserCallback(percentage, context->UserData);
	}

	return TRUE;
}

// The core implementation of the volume creation logic. Not exported.
static int CreateVolumeInternal(const VeraCryptFormatOptions* options)
{
	// --- Parameter validation ---
	if (!options || !options->path || wcslen(options->path) == 0) return VCF_ERROR_INVALID_PARAMETER;
	if (!options->password && (options->keyfiles == nullptr || options->keyfiles[0] == nullptr)) return VCF_ERROR_PASSWORD_OR_KEYFILE_REQUIRED;
	if (!options->isDevice && (options->dynamicFormat || options->fastCreateFile) && options->quickFormat == FALSE) return VCF_ERROR_INVALID_PARAMETER;
    if (options->isDevice && (options->dynamicFormat || options->fastCreateFile)) return VCF_ERROR_INVALID_PARAMETER;

	// Lock the mutex to protect the global state used by VeraCrypt's format code
	std::lock_guard<std::mutex> lock(g_sdkMutex);

	// Use a finally block to ensure cleanup of globals and memory
	finally_do({
		// Clean up all sensitive data from globals
		WipePasswordsAndKeyfiles(true);
		// Reset globals to default state
		KeyFileRemoveAll(&FirstKeyFile);
		FirstKeyFile = nullptr;
		bDevice = FALSE;
		nVolumeSize = 0;
		nVolumeEA = 1;
		hash_algo = DEFAULT_HASH_ALGORITHM;
		volumePim = 0;
		fileSystem = FILESYS_NONE;
		clusterSize = 0;
		quickFormat = FALSE;
		fastCreateFile = FALSE;
		dynamicFormat = FALSE;
		szDiskFile[0] = L'\0';
	});


	// --- Setup VeraCrypt's global state from our options struct ---
	bDevice = options->isDevice;
	nVolumeSize = options->size;

	nVolumeEA = MapEncryptionAlgorithm(options->encryptionAlgorithm);
	if (nVolumeEA == 0) return VCF_ERROR_INVALID_ENCRYPTION_ALGORITHM;
	
	hash_algo = MapHashAlgorithm(options->hashAlgorithm);
	if (hash_algo == 0) return VCF_ERROR_INVALID_HASH_ALGORITHM;
	
	fileSystem = MapFilesystem(options->filesystem);
	if (fileSystem == -1) return VCF_ERROR_INVALID_FILESYSTEM;

	volumePim = options->pim;
	quickFormat = options->quickFormat;
	fastCreateFile = options->fastCreateFile;
	dynamicFormat = options->dynamicFormat;
	clusterSize = options->clusterSize;
	
	if(dynamicFormat || fastCreateFile) quickFormat = TRUE;

	if (options->password)
	{
		if (!CheckPasswordLength(NULL, (int)strlen(options->password), options->pim, FALSE, 0, TRUE, TRUE))
		{
			return VCF_ERROR_PASSWORD_POLICY;
		}
		strcpy_s((char*)volumePassword.Text, sizeof(volumePassword.Text), options->password);
		volumePassword.Length = (unsigned __int32)strlen(options->password);
	}
	else
	{
		volumePassword.Text[0] = 0;
		volumePassword.Length = 0;
	}

	// --- Handle Keyfiles ---
	FirstKeyFile = nullptr;
	if (options->keyfiles)
	{
		for (int i = 0; options->keyfiles[i] != nullptr; ++i)
		{
			KeyFile* kf = (KeyFile*)malloc(sizeof(KeyFile));
			if (!kf)
			{
				KeyFileRemoveAll(&FirstKeyFile);
				return VCF_ERROR_OUT_OF_MEMORY;
			}
			StringCbCopyW(kf->FileName, sizeof(kf->FileName), options->keyfiles[i]);
			FirstKeyFile = KeyFileAdd(FirstKeyFile, kf);
		}
	}

	if (!KeyFilesApply(NULL, &volumePassword, FirstKeyFile, NULL))
	{
		return VCF_ERROR_KEYFILE_ERROR;
	}

	// --- Prepare for TCFormatVolume ---
	StringCbCopyW(szDiskFile, sizeof(szDiskFile), options->path);

	// --- Perform Validation (ported from Tcformat.c) ---
	if (bDevice)
	{
		nVolumeSize = GetDeviceSize(szDiskFile);
		if (nVolumeSize == (uint64_t)-1) return VCF_ERROR_CANNOT_GET_DEVICE_SIZE;
	}
	else // For file containers
	{
		if (nVolumeSize % TC_SECTOR_SIZE_FILE_HOSTED_VOLUME != 0) return VCF_ERROR_INVALID_VOLUME_SIZE;
		if (nVolumeSize < TC_MIN_VOLUME_SIZE) return VCF_ERROR_VOLUME_SIZE_TOO_SMALL;
		
		if (!dynamicFormat)
		{
			wchar_t root[TC_MAX_PATH];
			ULARGE_INTEGER freeSpace;
			if (GetVolumePathName(szDiskFile, root, ARRAYSIZE(root)) && GetDiskFreeSpaceEx(root, &freeSpace, 0, 0))
			{
				if (nVolumeSize > freeSpace.QuadPart) return VCF_ERROR_CONTAINER_TOO_LARGE_FOR_HOST;
			}
		}
	}
    
    // Validate filesystem choice against volume size
	uint64_t dataAreaSize = GetVolumeDataAreaSize(FALSE, nVolumeSize);
	DWORD sectorSize = bDevice ? GetFormatSectorSize() : TC_SECTOR_SIZE_FILE_HOSTED_VOLUME;
	if (fileSystem == FILESYS_NTFS && (dataAreaSize < TC_MIN_NTFS_FS_SIZE || dataAreaSize > TC_MAX_NTFS_FS_SIZE))
		return VCF_ERROR_FILESYSTEM_INVALID_FOR_SIZE;
	if (fileSystem == FILESYS_FAT && (dataAreaSize < TC_MIN_FAT_FS_SIZE || dataAreaSize > (TC_MAX_FAT_SECTOR_COUNT * sectorSize)))
		return VCF_ERROR_FILESYSTEM_INVALID_FOR_SIZE;
	if (fileSystem == FILESYS_EXFAT && (dataAreaSize < TC_MIN_EXFAT_FS_SIZE || dataAreaSize > TC_MAX_EXFAT_FS_SIZE))
		return VCF_ERROR_FILESYSTEM_INVALID_FOR_SIZE;
	if (fileSystem == FILESYS_REFS && (dataAreaSize < TC_MIN_REFS_FS_SIZE || dataAreaSize > TC_MAX_REFS_FS_SIZE))
		return VCF_ERROR_FILESYSTEM_INVALID_FOR_SIZE;


	// --- Prepare parameters for the core formatting function ---
	FORMAT_VOL_PARAMETERS volParams = { 0 };
	volParams.bDevice = bDevice;
	volParams.hiddenVol = FALSE; // SDK does not support hidden volumes
	volParams.volumePath = szDiskFile;
	volParams.size = nVolumeSize;
	volParams.ea = nVolumeEA;
	volParams.pkcs5 = hash_algo;
	volParams.fileSystem = fileSystem;
	volParams.clusterSize = clusterSize;
	volParams.quickFormat = quickFormat;
	volParams.fastCreateFile = fastCreateFile;
	volParams.sparseFileSwitch = dynamicFormat;
	volParams.sectorSize = sectorSize;
	volParams.password = &volumePassword;
	volParams.pim = volumePim;
	volParams.bGuiMode = FALSE;
	volParams.hwndDlg = NULL;
	volParams.bForceOperation = TRUE;

	// Setup progress callback
	SdkProgressContext progressCtx = { 0 };
	if (options->progressCallback)
	{
		progressCtx.UserCallback = options->progressCallback;
		progressCtx.UserData = options->progressUserData;
		progressCtx.TotalSize = GetVolumeDataAreaSize(FALSE, nVolumeSize);

		volParams.progress_callback = SdkProgressCallback;
		volParams.progress_callback_user_data = &progressCtx;
	}
	
	// --- Call the core function ---
	RandSetHashFunction(hash_algo);
	int status = TCFormatVolume(&volParams);

	// --- Return result ---
	if (status == ERR_SUCCESS) return VCF_SUCCESS;
	
	// Map internal errors to public SDK errors
	switch (status)
	{
		case ERR_OUTOFMEMORY: return VCF_ERROR_OUT_OF_MEMORY;
		case ERR_OS_ERROR:
		{
			DWORD lastError = GetLastError();
			if (lastError == ERROR_ACCESS_DENIED) return VCF_ERROR_ACCESS_DENIED;
			return VCF_ERROR_OS_ERROR;
		}
		case ERR_USER_ABORT: return VCF_ERROR_USER_ABORT;
		default: return VCF_ERROR_GENERIC;
	}
}


// --- Public DLL Exported Functions ---

extern "C"
{
	VCF_API int __cdecl VeraCryptFormat_Initialize()
	{
		std::lock_guard<std::mutex> lock(g_sdkMutex);
		if (g_isInitialized)
		{
			return VCF_SUCCESS;
		}
		Silent = TRUE; // We don't want UI
		bGuiMode = FALSE; // Ensure GUI mode is off
		InitApp(g_hDllInstance, L"");

		if (DriverAttach() != 0) return VCF_ERROR_NO_DRIVER;
		if (!AutoTestAlgorithms()) { cleanup(); return VCF_ERROR_SELF_TEST_FAILED; }
		if (Randinit()) { cleanup(); return VCF_ERROR_RNG_INIT_FAILED; }

		g_isInitialized = true;
		return VCF_SUCCESS;
	}

	VCF_API void __cdecl VeraCryptFormat_Shutdown()
	{
		std::lock_guard<std::mutex> lock(g_sdkMutex);
        if (g_isInitialized)
        {
		    RandStop(TRUE);
            cleanup();
		    g_isInitialized = false;
        }
	}

	VCF_API int __cdecl VeraCryptFormat(const VeraCryptFormatOptions* options)
	{
		if (!g_isInitialized)
		{
			return VCF_ERROR_NOT_INITIALIZED;
		}

		// The internal function handles all logic and thread safety.
		return CreateVolumeInternal(options);
	}

	BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
	{
		switch (fdwReason)
		{
		case DLL_PROCESS_ATTACH:
            g_hDllInstance = hinstDLL;
			break;

		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
			break;

		case DLL_PROCESS_DETACH:
			if (g_isInitialized)
			{
				VeraCryptFormat_Shutdown();
			}
			break;
		}
		return TRUE;
	}
}