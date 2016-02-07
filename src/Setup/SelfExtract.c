/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file) 
 and all other portions of this file are Copyright (c) 2013-2016 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include "Tcdefs.h"

#include "Inflate.h"
#include "SelfExtract.h"
#include "Wizard.h"
#include "Setup.h"
#include "Crc.h"
#include "Endian.h"
#include "Dlgcode.h"
#include "Dir.h"
#include "Language.h"
#include "Resource.h"
#include <tchar.h>
#include <Strsafe.h>

#ifndef SRC_POS
#define SRC_POS (__FUNCTION__ ":" TC_TO_STRING(__LINE__))
#endif

#define OutputPackageFile L"VeraCrypt Setup " _T(VERSION_STRING) L".exe"

#define MAG_START_MARKER	"TCINSTRT"
#define MAG_END_MARKER_OBFUSCATED	"T/C/I/N/S/C/R/C"
#define PIPE_BUFFER_LEN	(4 * BYTES_PER_KB)

unsigned char MagEndMarker [sizeof (MAG_END_MARKER_OBFUSCATED)];
wchar_t DestExtractPath [TC_MAX_PATH];
DECOMPRESSED_FILE	Decompressed_Files [NBR_COMPRESSED_FILES];

volatile char *PipeWriteBuf = NULL;
volatile HANDLE hChildStdinWrite = INVALID_HANDLE_VALUE;
unsigned char *DecompressedData = NULL;



void SelfExtractStartupInit (void)
{
	DeobfuscateMagEndMarker ();
}


// The end marker must be included in the self-extracting exe only once, not twice (used e.g. 
// by IsSelfExtractingPackage()) and that's why MAG_END_MARKER_OBFUSCATED is obfuscated and  
// needs to be deobfuscated using this function at startup.
static void DeobfuscateMagEndMarker (void)
{
	int i;

	for (i = 0; i < sizeof (MAG_END_MARKER_OBFUSCATED); i += 2)
		MagEndMarker [i/2] = MAG_END_MARKER_OBFUSCATED [i];

	MagEndMarker [i/2] = 0;
}


static void PkgError (wchar_t *msg)
{
	MessageBox (NULL, msg, L"VeraCrypt", MB_ICONERROR | MB_SETFOREGROUND | MB_TOPMOST);
}


static void PkgWarning (wchar_t *msg)
{
	MessageBox (NULL, msg, L"VeraCrypt", MB_ICONWARNING | MB_SETFOREGROUND | MB_TOPMOST);
}


static void PkgInfo (wchar_t *msg)
{
	MessageBox (NULL, msg, L"VeraCrypt", MB_ICONINFORMATION | MB_SETFOREGROUND | MB_TOPMOST);
}


// Returns 0 if decompression fails or, if successful, returns the size of the decompressed data
static int DecompressBuffer (char *out, char *in, int len)
{
	return (DecompressDeflatedData (out, in, len));		// Inflate
}


static void __cdecl PipeWriteThread (void *len) 
{
	int sendBufSize = PIPE_BUFFER_LEN, bytesSent = 0;
	int bytesToSend = *((int *) len), bytesSentTotal = 0;

	if (PipeWriteBuf == NULL || (HANDLE) hChildStdinWrite == INVALID_HANDLE_VALUE)
	{
		PkgError (L"Failed sending data to the STDIN pipe"); 
		return;
	}

	while (bytesToSend > 0) 
	{ 
		if (bytesToSend < PIPE_BUFFER_LEN)
			sendBufSize = bytesToSend;

		if (!WriteFile ((HANDLE) hChildStdinWrite, (char *) PipeWriteBuf + bytesSentTotal, sendBufSize, &bytesSent, NULL) 
			|| bytesSent == 0
			|| bytesSent != sendBufSize) 
		{
			PkgError (L"Failed sending data to the STDIN pipe"); 
			return;
		}

		bytesToSend -= bytesSent;
		bytesSentTotal += bytesSent;
	}

	// Closing the pipe causes the child process to stop reading from it

	if (!CloseHandle (hChildStdinWrite))
	{
		PkgError (L"Cannot close pipe"); 
		return;
	}
}


// Returns 0 if compression fails or, if successful, the size of the compressed data 
static int CompressBuffer (char *out, char *in, int len)
{
	SECURITY_ATTRIBUTES securityAttrib; 
	DWORD bytesReceived = 0;
	HANDLE hChildStdoutWrite = INVALID_HANDLE_VALUE;
	HANDLE hChildStdoutRead = INVALID_HANDLE_VALUE;
	HANDLE hChildStdinRead = INVALID_HANDLE_VALUE;
	STARTUPINFO startupInfo;
	PROCESS_INFORMATION procInfo; 
	char pipeBuffer [PIPE_BUFFER_LEN]; 
	int res_len = 0;
	BOOL bGzipHeaderRead = FALSE;
	wchar_t szGzipCmd[64];

	ZeroMemory (&startupInfo, sizeof (startupInfo));
	ZeroMemory (&procInfo, sizeof (procInfo));

	// Pipe handle inheritance
	securityAttrib.bInheritHandle = TRUE; 
	securityAttrib.nLength = sizeof (securityAttrib); 
	securityAttrib.lpSecurityDescriptor = NULL; 

	if (!CreatePipe (&hChildStdoutRead, &hChildStdoutWrite, &securityAttrib, 0))
	{
		PkgError (L"Cannot create STDOUT pipe."); 
		return 0;
	}
	SetHandleInformation (hChildStdoutRead, HANDLE_FLAG_INHERIT, 0);

	if (!CreatePipe (&hChildStdinRead, &((HANDLE) hChildStdinWrite), &securityAttrib, 0))
	{
		PkgError (L"Cannot create STDIN pipe.");
		CloseHandle(hChildStdoutWrite);
		CloseHandle(hChildStdoutRead);
		return 0;
	}
	SetHandleInformation (hChildStdinWrite, HANDLE_FLAG_INHERIT, 0);

	// Create a child process that will compress the data

	startupInfo.wShowWindow = SW_HIDE;
	startupInfo.hStdInput = hChildStdinRead;
	startupInfo.hStdOutput = hChildStdoutWrite;
	startupInfo.cb = sizeof (startupInfo); 
	startupInfo.hStdError = hChildStdoutWrite;
	startupInfo.dwFlags |= STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;

	StringCchCopyW (szGzipCmd, ARRAYSIZE (szGzipCmd), L"gzip --best");
	if (!CreateProcess (NULL, szGzipCmd, NULL, NULL, TRUE, 0, NULL, NULL, &startupInfo, &procInfo))
	{
		PkgError (L"Error: Cannot run gzip.\n\nBefore you can create a self-extracting VeraCrypt package, you need to have the open-source 'gzip' compression tool placed in any directory in the search path for executable files (for example, in 'C:\\Windows\\').\n\nNote: gzip can be freely downloaded e.g. from www.gzip.org");
		CloseHandle(hChildStdoutWrite);
		CloseHandle(hChildStdoutRead);
		CloseHandle(hChildStdinRead);
		CloseHandle(hChildStdinWrite);
		return 0;
	}

	CloseHandle (procInfo.hProcess);
	CloseHandle (procInfo.hThread);

	// Start sending the uncompressed data to the pipe (STDIN)
	PipeWriteBuf = in;
	_beginthread (PipeWriteThread, PIPE_BUFFER_LEN * 2, (void *) &len);

	if (!CloseHandle (hChildStdoutWrite))
	{
		PkgError (L"Cannot close STDOUT write"); 
		CloseHandle(hChildStdoutRead);
		CloseHandle(hChildStdinRead);
		return 0;
	}

	bGzipHeaderRead = FALSE;

	// Read the compressed data from the pipe (sent by the child process to STDOUT)
	while (TRUE) 
	{ 
		if (!ReadFile (hChildStdoutRead, pipeBuffer, bGzipHeaderRead ? PIPE_BUFFER_LEN : 10, &bytesReceived, NULL)) 
			break; 

		if (bGzipHeaderRead)
		{
			memcpy (out + res_len, pipeBuffer, bytesReceived);
			res_len += bytesReceived;
		}
		else
			bGzipHeaderRead = TRUE;	// Skip the 10-byte gzip header
	} 

	CloseHandle(hChildStdoutRead);
	CloseHandle(hChildStdinRead);
	return res_len - 8;	// A gzip stream ends with a CRC-32 hash and a 32-bit size (those 8 bytes need to be chopped off)
}


// Clears all bytes that change when an exe file is digitally signed, except the data that are appended. 
// If those bytes weren't cleared, CRC-32 checks would fail after signing.
static void WipeSignatureAreas (char *buffer)
{
	// Clear bytes 0x130-0x1ff
	memset (buffer + 0x130, 0, 0x200 - 0x130);
}


BOOL MakeSelfExtractingPackage (HWND hwndDlg, wchar_t *szDestDir)
{
	int i, x;
	wchar_t inputFile [TC_MAX_PATH];
	wchar_t outputFile [TC_MAX_PATH];
	wchar_t szTmpFilePath [TC_MAX_PATH];
	unsigned char szTmp32bit [4] = {0};
	unsigned char *szTmp32bitPtr = szTmp32bit;
	unsigned char *buffer = NULL, *compressedBuffer = NULL;
	unsigned char *bufIndex = NULL;
	wchar_t tmpStr [2048];
	int bufLen = 0, compressedDataLen = 0, uncompressedDataLen = 0;

	x = wcslen (szDestDir);
	if (x < 2)
		goto err;

	if (szDestDir[x - 1] != L'\\')
		StringCbCatW (szDestDir, MAX_PATH, L"\\");

	GetModuleFileName (NULL, inputFile, ARRAYSIZE (inputFile));

	StringCchCopyW (outputFile, ARRAYSIZE(outputFile), szDestDir);
	StringCchCatW (outputFile, ARRAYSIZE(outputFile), OutputPackageFile);

	// Clone 'VeraCrypt Setup.exe' to create the base of the new self-extracting archive

	if (!TCCopyFile (inputFile, outputFile))
	{
		handleWin32Error (hwndDlg, SRC_POS);
		PkgError (L"Cannot copy 'VeraCrypt Setup.exe' to the package");
		goto err;
	}

	// Determine the buffer size needed for all the files and meta data and check if all required files exist

	bufLen = 0;

	for (i = 0; i < sizeof (szCompressedFiles) / sizeof (szCompressedFiles[0]); i++)
	{
		StringCbPrintfW (szTmpFilePath, sizeof(szTmpFilePath), L"%s%s", szDestDir, szCompressedFiles[i]);

		if (!FileExists (szTmpFilePath))
		{
			wchar_t tmpstr [1000];

			StringCbPrintfW (tmpstr, sizeof(tmpstr), L"File not found:\n\n'%s'", szTmpFilePath);
			if (_wremove (outputFile))
				StringCbCatW (tmpstr, sizeof(tmpstr), L"\nFailed also to delete package file");
			PkgError (tmpstr);
			goto err;
		}

		bufLen += (int) GetFileSize64 (szTmpFilePath);

		bufLen += 2;					// 16-bit filename length
		bufLen += (wcslen(szCompressedFiles[i]) * sizeof (wchar_t));	// Filename
		bufLen += 4;					// CRC-32
		bufLen += 4;					// 32-bit file length
	}

	buffer = malloc (bufLen + 524288);	// + 512K reserve 
	if (buffer == NULL)
	{
		PkgError (L"Cannot allocate memory for uncompressed data");
		if (_wremove (outputFile))
			PkgError (L"Cannot allocate memory for uncompressed data.\nFailed also to delete package file");
		else
			PkgError (L"Cannot allocate memory for uncompressed data");
		goto err;
	}


	// Write the start marker
	if (!SaveBufferToFile (MAG_START_MARKER, outputFile, strlen (MAG_START_MARKER), TRUE, FALSE))
	{		
		if (_wremove (outputFile))
			PkgError (L"Cannot write the start marker\nFailed also to delete package file");
		else
			PkgError (L"Cannot write the start marker");
		goto err;
	}


	bufIndex = buffer;

	// Copy all required files and their meta data to the buffer
	for (i = 0; i < sizeof (szCompressedFiles) / sizeof (szCompressedFiles[0]); i++)
	{
		DWORD tmpFileSize;
		unsigned char *tmpBuffer;

		StringCbPrintfW (szTmpFilePath, sizeof(szTmpFilePath), L"%s%s", szDestDir, szCompressedFiles[i]);

		tmpBuffer = LoadFile (szTmpFilePath, &tmpFileSize);

		if (tmpBuffer == NULL)
		{
			wchar_t tmpstr [1000];

			StringCbPrintfW (tmpstr, sizeof(tmpstr), L"Cannot load file \n'%s'", szTmpFilePath);
			if (_wremove (outputFile))
				StringCbCatW (tmpstr, sizeof(tmpstr), L"\nFailed also to delete package file");
			PkgError (tmpstr);
			goto err;
		}

		// Copy the filename length to the main buffer
		mputWord (bufIndex, (WORD) wcslen(szCompressedFiles[i]));

		// Copy the filename to the main buffer
		wmemcpy ((wchar_t*)bufIndex, szCompressedFiles[i], wcslen(szCompressedFiles[i]));
		bufIndex += (wcslen(szCompressedFiles[i]) * sizeof (wchar_t));

		// Compute CRC-32 hash of the uncompressed file and copy it to the main buffer
		mputLong (bufIndex, GetCrc32 (tmpBuffer, tmpFileSize));

		// Copy the file length to the main buffer
		mputLong (bufIndex, (unsigned __int32) tmpFileSize);

		// Copy the file contents to the main buffer
		memcpy (bufIndex, tmpBuffer, tmpFileSize);
		bufIndex += tmpFileSize;

		free (tmpBuffer);
	}

	// Calculate the total size of the uncompressed data
	uncompressedDataLen = (int) (bufIndex - buffer);

	// Write total size of the uncompressed data
	szTmp32bitPtr = szTmp32bit;
	mputLong (szTmp32bitPtr, (unsigned __int32) uncompressedDataLen);
	if (!SaveBufferToFile (szTmp32bit, outputFile, sizeof (szTmp32bit), TRUE, FALSE))
	{
		if (_wremove (outputFile))
			PkgError (L"Cannot write the total size of the uncompressed data.\nFailed also to delete package file");
		else
			PkgError (L"Cannot write the total size of the uncompressed data");
		goto err;
	}

	// Compress all the files and meta data in the buffer to create a solid archive

	// Test to make Coverity happy. It will always be false
	if (uncompressedDataLen >= (INT_MAX - 524288))
	{
		if (_wremove (outputFile))
			PkgError (L"Cannot allocate memory for compressed data.\nFailed also to delete package file");
		else
			PkgError (L"Cannot allocate memory for compressed data");
		goto err;
	}

	compressedBuffer = malloc (uncompressedDataLen + 524288);	// + 512K reserve
	if (compressedBuffer == NULL)
	{
		if (_wremove (outputFile))
			PkgError (L"Cannot allocate memory for compressed data.\nFailed also to delete package file");
		else
			PkgError (L"Cannot allocate memory for compressed data");
		goto err;
	}

	compressedDataLen = CompressBuffer (compressedBuffer, buffer, uncompressedDataLen);
	if (compressedDataLen <= 0)
	{
		if (_wremove (outputFile))
			PkgError (L"Failed to compress the data.\nFailed also to delete package file");
		else
			PkgError (L"Failed to compress the data");
		goto err;
	}

	free (buffer);
	buffer = NULL;

	// Write the total size of the compressed data
	szTmp32bitPtr = szTmp32bit;
	mputLong (szTmp32bitPtr, (unsigned __int32) compressedDataLen);
	if (!SaveBufferToFile (szTmp32bit, outputFile, sizeof (szTmp32bit), TRUE, FALSE))
	{
		if (_wremove (outputFile))
			PkgError (L"Cannot write the total size of the compressed data.\nFailed also to delete package file");
		else
			PkgError (L"Cannot write the total size of the compressed data");
		goto err;
	}

	// Write the compressed data
	if (!SaveBufferToFile (compressedBuffer, outputFile, compressedDataLen, TRUE, FALSE))
	{
		if (_wremove (outputFile))
			PkgError (L"Cannot write compressed data to the package.\nFailed also to delete package file");
		else
			PkgError (L"Cannot write compressed data to the package");
		goto err;
	}

	// Write the end marker
	if (!SaveBufferToFile (MagEndMarker, outputFile, strlen (MagEndMarker), TRUE, FALSE))
	{
		if (_wremove (outputFile))
			PkgError (L"Cannot write the end marker.\nFailed also to delete package file");
		else
			PkgError (L"Cannot write the end marker");
		goto err;
	}

	free (compressedBuffer);
	compressedBuffer = NULL;

	// Compute and write CRC-32 hash of the entire package
	{
		DWORD tmpFileSize;
		char *tmpBuffer;

		tmpBuffer = LoadFile (outputFile, &tmpFileSize);

		if (tmpBuffer == NULL)
		{
			handleWin32Error (hwndDlg, SRC_POS);
			if (_wremove (outputFile))
				PkgError (L"Cannot load the package to compute CRC.\nFailed also to delete package file");
			else
				PkgError (L"Cannot load the package to compute CRC");
			goto err;
		}

		// Zero all bytes that change when the exe is digitally signed (except appended blocks).
		WipeSignatureAreas (tmpBuffer);

		szTmp32bitPtr = szTmp32bit;
		mputLong (szTmp32bitPtr, GetCrc32 (tmpBuffer, tmpFileSize));
		free (tmpBuffer);

		if (!SaveBufferToFile (szTmp32bit, outputFile, sizeof (szTmp32bit), TRUE, FALSE))
		{
			if (_wremove (outputFile))
				PkgError (L"Cannot write the total size of the compressed data.\nFailed also to delete package file");
			else
				PkgError (L"Cannot write the total size of the compressed data");
			goto err;
		}
	}

	StringCbPrintfW (tmpStr, sizeof(tmpStr), L"Self-extracting package successfully created (%s)", outputFile);
	PkgInfo (tmpStr);
	return TRUE;

err:
	if (buffer)
		free (buffer);
	if (compressedBuffer)
		free (compressedBuffer);

	return FALSE;
}


// Verifies the CRC-32 of the whole self-extracting package (except the digital signature areas, if present)
BOOL VerifyPackageIntegrity (void)
{
	int fileDataEndPos = 0;
	int fileDataStartPos = 0;
	unsigned __int32 crc = 0;
	unsigned char *tmpBuffer;
	int tmpFileSize;
	wchar_t path [TC_MAX_PATH];

	GetModuleFileName (NULL, path, ARRAYSIZE (path));

	fileDataEndPos = (int) FindStringInFile (path, MagEndMarker, strlen (MagEndMarker));
	if (fileDataEndPos < 0)
	{
		Error ("DIST_PACKAGE_CORRUPTED", NULL);
		return FALSE;
	}
	fileDataEndPos--;

	fileDataStartPos = (int) FindStringInFile (path, MAG_START_MARKER, strlen (MAG_START_MARKER));
	if (fileDataStartPos < 0)
	{
		Error ("DIST_PACKAGE_CORRUPTED", NULL);
		return FALSE;
	}
	fileDataStartPos += strlen (MAG_START_MARKER);


	if (!LoadInt32 (path, &crc, fileDataEndPos + strlen (MagEndMarker) + 1))
	{
		Error ("CANT_VERIFY_PACKAGE_INTEGRITY", NULL);
		return FALSE;
	}

	// Compute the CRC-32 hash of the whole file (except the digital signature area, if present)
	tmpBuffer = LoadFile (path, &tmpFileSize);

	if (tmpBuffer == NULL)
	{
		Error ("CANT_VERIFY_PACKAGE_INTEGRITY", NULL);
		return FALSE;
	}

	// Zero all bytes that change when an exe is digitally signed (except appended blocks).
	WipeSignatureAreas (tmpBuffer);

	if (crc != GetCrc32 (tmpBuffer, fileDataEndPos + 1 + strlen (MagEndMarker)))
	{
		free (tmpBuffer);
		Error ("DIST_PACKAGE_CORRUPTED", NULL);
		return FALSE;
	}

	free (tmpBuffer);

	return TRUE;
}


// Determines whether we are a self-extracting package
BOOL IsSelfExtractingPackage (void)
{
	wchar_t path [TC_MAX_PATH];

	GetModuleFileName (NULL, path, ARRAYSIZE (path));

	return (FindStringInFile (path, MagEndMarker, strlen (MagEndMarker)) != -1);
}


static void FreeAllFileBuffers (void)
{
	int fileNo;

	if (DecompressedData != NULL)
	{
		free (DecompressedData);
		DecompressedData = NULL;
	}

	for (fileNo = 0; fileNo < NBR_COMPRESSED_FILES; fileNo++)
	{
		Decompressed_Files[fileNo].fileName = NULL;
		Decompressed_Files[fileNo].fileContent = NULL;
		Decompressed_Files[fileNo].fileNameLength = 0;
		Decompressed_Files[fileNo].fileLength = 0;
		Decompressed_Files[fileNo].crc = 0;
	}
}


// Assumes that VerifyPackageIntegrity() has been used. Returns TRUE, if successful (otherwise FALSE).
// Creates a table of pointers to buffers containing the following objects for each file:
// filename size, filename (not null-terminated!), file size, file CRC-32, uncompressed file contents.
// For details, see the definition of the DECOMPRESSED_FILE structure.
BOOL SelfExtractInMemory (wchar_t *path)
{
	int filePos = 0, fileNo = 0;
	int fileDataEndPos = 0;
	int fileDataStartPos = 0;
	int uncompressedLen = 0;
	int compressedLen = 0;
	unsigned char *compressedData = NULL;
	unsigned char *bufPos = NULL, *bufEndPos = NULL;

	FreeAllFileBuffers();

	fileDataEndPos = (int) FindStringInFile (path, MagEndMarker, strlen (MagEndMarker));
	if (fileDataEndPos < 0)
	{
		Error ("CANNOT_READ_FROM_PACKAGE", NULL);
		return FALSE;
	}

	fileDataEndPos--;

	fileDataStartPos = (int) FindStringInFile (path, MAG_START_MARKER, strlen (MAG_START_MARKER));
	if (fileDataStartPos < 0)
	{
		Error ("CANNOT_READ_FROM_PACKAGE", NULL);
		return FALSE;
	}

	fileDataStartPos += strlen (MAG_START_MARKER);

	filePos = fileDataStartPos;

	// Read the stored total size of the uncompressed data
	if (!LoadInt32 (path, &uncompressedLen, filePos))
	{
		Error ("CANNOT_READ_FROM_PACKAGE", NULL);
		return FALSE;
	}

	filePos += 4;

	// Read the stored total size of the compressed data
	if (!LoadInt32 (path, &compressedLen, filePos))
	{
		Error ("CANNOT_READ_FROM_PACKAGE", NULL);
		return FALSE;
	}

	filePos += 4;

	if (compressedLen != fileDataEndPos - fileDataStartPos - 8 + 1)
	{
		Error ("DIST_PACKAGE_CORRUPTED", NULL);
	}

	DecompressedData = malloc (uncompressedLen + 524288);	// + 512K reserve 
	if (DecompressedData == NULL)
	{
		Error ("ERR_MEM_ALLOC", NULL);
		return FALSE;
	}

	bufPos = DecompressedData;
	bufEndPos = bufPos + uncompressedLen - 1;

	compressedData = LoadFileBlock (path, filePos, compressedLen);

	if (compressedData == NULL)
	{
		free (DecompressedData);
		DecompressedData = NULL;

		Error ("CANNOT_READ_FROM_PACKAGE", NULL);
		return FALSE;
	}

	// Decompress the data
	if (DecompressBuffer (DecompressedData, compressedData, compressedLen) != uncompressedLen)
	{
		Error ("DIST_PACKAGE_CORRUPTED", NULL);
		goto sem_end;
	}

	while (bufPos <= bufEndPos && fileNo < NBR_COMPRESSED_FILES)
	{
		// Filename length
		Decompressed_Files[fileNo].fileNameLength = mgetWord (bufPos);

		// Filename
		Decompressed_Files[fileNo].fileName = (wchar_t*) bufPos;
		bufPos += (Decompressed_Files[fileNo].fileNameLength * sizeof (wchar_t));

		// CRC-32 of the file
		Decompressed_Files[fileNo].crc = mgetLong (bufPos);

		// File length
		Decompressed_Files[fileNo].fileLength = mgetLong (bufPos);

		// File content
		Decompressed_Files[fileNo].fileContent = bufPos;
		bufPos += Decompressed_Files[fileNo].fileLength;

		// Verify CRC-32 of the file (to verify that it didn't get corrupted while creating the solid archive).
		if (Decompressed_Files[fileNo].crc 
			!= GetCrc32 (Decompressed_Files[fileNo].fileContent, Decompressed_Files[fileNo].fileLength))
		{
			Error ("DIST_PACKAGE_CORRUPTED", NULL);
			goto sem_end;
		}

		fileNo++;
	}

	if (fileNo < NBR_COMPRESSED_FILES)
	{
		Error ("DIST_PACKAGE_CORRUPTED", NULL);
		goto sem_end;
	}

	free (compressedData);
	return TRUE;

sem_end:
	FreeAllFileBuffers();
	free (compressedData);
	return FALSE;
}


void __cdecl ExtractAllFilesThread (void *hwndDlg)
{
	int fileNo;
	BOOL bSuccess = FALSE;
	wchar_t packageFile [TC_MAX_PATH];

	InvalidateRect (GetDlgItem (GetParent (hwndDlg), IDD_INSTL_DLG), NULL, TRUE);

	ClearLogWindow (hwndDlg);

	GetModuleFileName (NULL, packageFile, ARRAYSIZE (packageFile));

	if (!(bSuccess = SelfExtractInMemory (packageFile)))
		goto eaf_end;

	if (mkfulldir (DestExtractPath, TRUE) != 0)
	{
		if (mkfulldir (DestExtractPath, FALSE) != 0)
		{
			wchar_t szTmp[TC_MAX_PATH];

			handleWin32Error (hwndDlg, SRC_POS);
			StringCbPrintfW (szTmp, sizeof(szTmp), GetString ("CANT_CREATE_FOLDER"), DestExtractPath);
			MessageBoxW (hwndDlg, szTmp, lpszTitle, MB_ICONHAND);
			bSuccess = FALSE;
			goto eaf_end;
		}
	}

	for (fileNo = 0; fileNo < NBR_COMPRESSED_FILES; fileNo++)
	{
		wchar_t fileName [TC_MAX_PATH] = {0};
		wchar_t filePath [TC_MAX_PATH] = {0};

		// Filename
		StringCchCopyNW (fileName, ARRAYSIZE(fileName), Decompressed_Files[fileNo].fileName, Decompressed_Files[fileNo].fileNameLength);
		StringCchCopyW (filePath, ARRAYSIZE(filePath), DestExtractPath);
		StringCchCatW (filePath, ARRAYSIZE(filePath), fileName);

		StatusMessageParam (hwndDlg, "EXTRACTING_VERB", filePath);

		// Write the file
		if (!SaveBufferToFile (
			Decompressed_Files[fileNo].fileContent,
			filePath,
			Decompressed_Files[fileNo].fileLength,
			FALSE, FALSE))
		{
			wchar_t szTmp[512];

			StringCbPrintfW (szTmp, sizeof (szTmp), GetString ("CANNOT_WRITE_FILE_X"), filePath);
			MessageBoxW (hwndDlg, szTmp, lpszTitle, MB_ICONERROR | MB_SETFOREGROUND | MB_TOPMOST);
			bSuccess = FALSE;
			goto eaf_end;
		}
		UpdateProgressBarProc ((int) (100 * ((float) fileNo / NBR_COMPRESSED_FILES)));
	}

eaf_end:
	FreeAllFileBuffers();

	if (bSuccess)
		PostMessage (MainDlg, TC_APPMSG_EXTRACTION_SUCCESS, 0, 0);
	else
		PostMessage (MainDlg, TC_APPMSG_EXTRACTION_FAILURE, 0, 0);
}

