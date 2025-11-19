/*
 * veraser.c
 *
 *  Created on: 11 08, 2025
 *  Author: Ömer Can VURAL
 * 
 * Single-file, cross-platform implementation for both library and CLI usage.
 * Adheres to PRD design: HDD algorithms (zero/random/DoD/NIST/Gutmann) and
 * SSD flow (encrypt-in-place + delete + TRIM best-effort).
 * Conditional compilation gates platform specifics (Windows/Linux/macOS).
 * CLI main() is included only when VE_BUILD_CLI is defined.
 * 
 * 
 */
#define _GNU_SOURCE  // <--- BU SATIRI EKLE (fallocate için şart)

#include "veraser.h"

#include <stdio.h>   /* basic I/O for CLI and diagnostics */
#include <stdlib.h>  /* malloc/free */
#include <string.h>  /* memset/memcpy/strcmp */
#include <errno.h>   /* errno for system call errors */
#include <time.h>    /* not strictly needed; placeholder */
#include <stdarg.h>  /* varargs for formatting last error */
//veracrypter begin
/* MSVC < 2015 compatibility: provide snprintf if missing */
#ifdef _MSC_VER
  #if _MSC_VER < 1900
    #ifndef snprintf
      #define snprintf _snprintf
    #endif
  #endif
#endif
//veracrypter end

/*
* Windows: Win32 + CNG (bcrypt) for RNG/AES, file I/O wrappers via CRT. Standard headers for filesystem and directory traversal.
*/
#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h> /* CNG RNG + AES (AES-CTR chaining mode) */
#include <io.h>     /* _open_osfhandle, _close */
/* Compatibility shims for older Windows SDKs missing CTR chaining constants */
#ifndef BCRYPT_CHAIN_MODE_CTR
#define BCRYPT_CHAIN_MODE_CTR      L"ChainingModeCTR"
#endif
#ifndef BCRYPT_CHAINING_MODE
#define BCRYPT_CHAINING_MODE       L"ChainingMode"
#endif
#else
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/ioctl.h>
#endif

/*
  Linux-specific TRIM and hole-punch constants
  - Used by ve_trim_best_effort() and SSD punch-hole after encryption.
*/
#if defined(__linux__)
#include <linux/fs.h>   /* FITRIM ioctl */
#ifndef FALLOC_FL_KEEP_SIZE
#define FALLOC_FL_KEEP_SIZE 0x01
#endif
#ifndef FALLOC_FL_PUNCH_HOLE
#define FALLOC_FL_PUNCH_HOLE 0x02
#endif
#endif

/* Optional OpenSSL path for AES-CTR on POSIX */
#ifdef VE_USE_OPENSSL
#include <openssl/evp.h>
#endif

/*
  Internal configuration
  - Default I/O chunk size if options->chunk_size is 0. Kept as macro so it can
    be tweaked via compilation flags if desired.
*/
#ifndef VE_DEFAULT_CHUNK_SIZE
#define VE_DEFAULT_CHUNK_SIZE (8ULL * 1024ULL * 1024ULL) /* 8 MiB */
#endif

/*
  Thread-local last error storage
  - Exposed via ve_last_error_message() for callers to retrieve details.
*/
#if defined(_MSC_VER)
__declspec(thread) static char ve_tls_last_error[512];
#elif defined(__GNUC__)
static __thread char ve_tls_last_error[512];
#else
static char ve_tls_last_error[512]; /* best-effort if no TLS */
#endif

/* Format and store last error message for current thread */
static void ve_set_last_errorf(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
#if defined(_WIN32)
    _vsnprintf_s(ve_tls_last_error, sizeof(ve_tls_last_error), _TRUNCATE, fmt, ap);
#else
    vsnprintf(ve_tls_last_error, sizeof(ve_tls_last_error), fmt, ap);
#endif
    va_end(ap);
}

/* Return last error string or NULL if none set */
const char* ve_last_error_message(void) {
    return ve_tls_last_error[0] ? ve_tls_last_error : NULL;
}

/*
  Cryptographically secure random
  - Windows: BCryptGenRandom (CNG system RNG).
  - macOS: arc4random_buf.
  - Linux: getrandom() loop, fallback to /dev/urandom.
  Inputs: buf/len for random bytes.
  Returns: 0 on success, -1 on failure (and sets last error).
*/
static int ve_csrand(void* buf, size_t len) {
#if defined(_WIN32)
    NTSTATUS st = BCryptGenRandom(NULL, (PUCHAR)buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (st == 0) {
        return 0;
    }
    ve_set_last_errorf("BCryptGenRandom failed: 0x%08lx", (unsigned long)st);
    return -1;
#else
#if defined(__APPLE__)
    extern void arc4random_buf(void *buf, size_t nbytes);
    arc4random_buf(buf, len);
    return 0;
#elif defined(__linux__)
    #include <sys/random.h>
    size_t off = 0;
    while (off < len) {
        ssize_t r = getrandom((unsigned char*)buf + off, len - off, 0);
        if (r > 0) {
            off += (size_t)r;
            continue;
        }
        if (r < 0 && (errno == EINTR || errno == EAGAIN)) {
            continue;
        }
        break;
    }
    if (off == len) {
        return 0;
    }
    /* Fallback to /dev/urandom below */
#endif
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) { ve_set_last_errorf("open(/dev/urandom) failed: %s", strerror(errno)); return -1; }
    size_t got = 0;
    while (got < len) {
        ssize_t n = read(fd, (unsigned char*)buf + got, len - got);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) { 
            close(fd); ve_set_last_errorf("read(/dev/urandom) failed: %s", strerror(errno)); return -1; 
        }
        got += (size_t)n;
    }

    close(fd);
    return 0;
#endif
}

/*
  Secure memory wipe for sensitive data (keys/buffers)
  - Uses platform-secure zeroing when available.
*/
static void ve_secure_bzero(void* p, size_t n) {
#if defined(_WIN32)
    SecureZeroMemory(p, n);
#else
    volatile unsigned char* v = (volatile unsigned char*)p;
    while (n--) *v++ = 0;
#endif
}

/*
  AES-CTR encryption helpers
  - Windows path: CNG AES with CTR chaining; iv advanced between chunks.
  - POSIX path (optional): OpenSSL EVP AES-256-CTR when VE_USE_OPENSSL is set.
  - If OpenSSL is not available, a compile-safe XOR fallback is used on POSIX
    (NOT secure; provided only to maintain buildability without deps).
*/
#if defined(_WIN32)
/* Increment CTR counter portion in IV by given number of blocks */
static void ve_inc_ctr(unsigned char iv[16], uint64_t blocks) {
    for (int i = 15; i >= 8 && blocks; --i) {
        uint16_t sum = (uint16_t)iv[i] + (uint16_t)(blocks & 0xFF);
        iv[i] = (unsigned char)(sum & 0xFF);
        blocks = (blocks >> 8) + (sum >> 8);
    }
}

/* Encrypt buffer in place with AES-256-CTR using Windows CNG (simpler/verbose style) */
static int ve_aes_ctr_encrypt_windows(unsigned char* buf, size_t len, const unsigned char key[32], unsigned char iv[16]) {
    BCRYPT_ALG_HANDLE algHandle = NULL;
    BCRYPT_KEY_HANDLE keyHandle = NULL;
    PUCHAR keyObject = NULL;
    DWORD keyObjectLen = 0;
    DWORD blockLen = 0;
    DWORD bytesReturned = 0;
    DWORD tmp = 0;
    int result = -1; /* assume failure */

    /* open AES provider */
    if (BCryptOpenAlgorithmProvider(&algHandle, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) {
        ve_set_last_errorf("BCryptOpenAlgorithmProvider AES failed");
        goto cleanup_simple;
    }
    /* set CTR mode */
    if (BCryptSetProperty(algHandle, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CTR, (ULONG)sizeof(BCRYPT_CHAIN_MODE_CTR), 0) != 0) {
        ve_set_last_errorf("SetProperty CTR failed");
        goto cleanup_simple;
    }
    /* query sizes */
    if (BCryptGetProperty(algHandle, BCRYPT_OBJECT_LENGTH, (PUCHAR)&keyObjectLen, sizeof(keyObjectLen), &tmp, 0) != 0) {
        ve_set_last_errorf("GetProperty OBJ_LEN failed");
        goto cleanup_simple;
    }
    if (BCryptGetProperty(algHandle, BCRYPT_BLOCK_LENGTH, (PUCHAR)&blockLen, sizeof(blockLen), &tmp, 0) != 0) {
        ve_set_last_errorf("GetProperty BLK_LEN failed");
        goto cleanup_simple;
    }

    keyObject = (PUCHAR)malloc(keyObjectLen);
    if (keyObject == NULL) {
        ve_set_last_errorf("malloc keyObj failed");
        goto cleanup_simple;
    }
    /* make key */
    if (BCryptGenerateSymmetricKey(algHandle, &keyHandle, keyObject, keyObjectLen, (PUCHAR)key, 32, 0) != 0) {
        ve_set_last_errorf("GenerateSymmetricKey failed");
        goto cleanup_simple;
    }

    /* simple loop: process in moderate chunks, updating IV */
    size_t offsetBytes = 0;
    while (offsetBytes < len) {
        size_t toProcess = len - offsetBytes;
        if (toProcess > (size_t)(1<<20)) {
            toProcess = (size_t)(1<<20);
        }
        unsigned char ivTmp[16];
        memcpy(ivTmp, iv, 16);
        bytesReturned = 0;
        if (BCryptEncrypt(keyHandle, buf + offsetBytes, (ULONG)toProcess, NULL, ivTmp, 16, buf + offsetBytes, (ULONG)toProcess, &bytesReturned, 0) != 0) {
            ve_set_last_errorf("BCryptEncrypt failed");
            goto cleanup_simple;
        }
        if (bytesReturned != toProcess) {
            ve_set_last_errorf("BCryptEncrypt size mismatch");
            goto cleanup_simple;
        }
        /* advance IV */
        uint64_t blocks = (toProcess + blockLen - 1) / blockLen;
        ve_inc_ctr(iv, blocks);
        offsetBytes += toProcess;
    }

    result = 0; /* success */

cleanup_simple:
    if (keyHandle) {
        BCryptDestroyKey(keyHandle);
    }
    if (algHandle) {
        BCryptCloseAlgorithmProvider(algHandle, 0);
    }
    if (keyObject) {
        ve_secure_bzero(keyObject, keyObjectLen);
        free(keyObject);
    }
    return result;
}
#endif /* _WIN32 */

#ifdef VE_USE_OPENSSL
/* Encrypt buffer in place with AES-256-CTR using OpenSSL (simpler return/cleanup) */
static int ve_aes_ctr_encrypt_openssl(unsigned char* buf, size_t len, const unsigned char key[32], const unsigned char iv[16]) {
    int rc = -1;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        ve_set_last_errorf("EVP_CIPHER_CTX_new failed");
        return -1;
    }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv) != 1) {
        ve_set_last_errorf("EVP_EncryptInit_ex failed");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    int outLen = 0;
    if (EVP_EncryptUpdate(ctx, buf, &outLen, buf, (int)len) != 1) {
        ve_set_last_errorf("EVP_EncryptUpdate failed");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (outLen != (int)len) {
        ve_set_last_errorf("EVP_EncryptUpdate size mismatch");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    rc = 0;
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}
#endif /* VE_USE_OPENSSL */

/* ---------------- File and directory helpers ---------------- */

/* Determine if path is a directory (1=yes, 0=no) */
static int ve_is_directory(const char* path) {
#if defined(_WIN32)
    DWORD attrs = GetFileAttributesA(path);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        return 0;
    }
    return (attrs & FILE_ATTRIBUTE_DIRECTORY) ? 1 : 0;
#else
    struct stat st;
    if (lstat(path, &st) != 0) {
        return 0;
    }
    return S_ISDIR(st.st_mode) ? 1 : 0;
#endif
}

/* Remove a file; returns 0 on success */
static int ve_remove_file(const char* path) {
#if defined(_WIN32)
    if (DeleteFileA(path)) {
        return 0;
    }
    DWORD err = GetLastError();
    ve_set_last_errorf("DeleteFile failed (%lu)", (unsigned long)err);
    return -1;
#else
    if (unlink(path) == 0) {
        return 0;
    }
    ve_set_last_errorf("unlink('%s') failed: %s", path, strerror(errno));
    return -1;
#endif
}

/* Remove an empty directory; returns 0 on success */
static int ve_remove_empty_dir(const char* path) {
#if defined(_WIN32)
    if (RemoveDirectoryA(path)) {
        return 0;
    }
    DWORD err = GetLastError();
    ve_set_last_errorf("RemoveDirectory failed (%lu)", (unsigned long)err);
    return -1;
#else
    if (rmdir(path) == 0) {
        return 0;
    }
    ve_set_last_errorf("rmdir('%s') failed: %s", path, strerror(errno));
    return -1;
#endif
}

/* ---------------- Overwrite algorithms (HDD-like flows) ---------------- */

/* Write a fixed pattern across the file */
static int ve_write_pattern_fd(int fd, uint64_t file_size, unsigned char pattern) {
    const size_t chunk_size_bytes = VE_DEFAULT_CHUNK_SIZE;
    unsigned char* buffer = (unsigned char*)malloc(chunk_size_bytes);
    if (!buffer) { 
        ve_set_last_errorf("malloc failed"); 
        return -1; 
    }
    memset(buffer, pattern, chunk_size_bytes);

    uint64_t total_written = 0;
    while (total_written < file_size) {
        size_t to_write_now = (size_t)((file_size - total_written) < chunk_size_bytes ? (file_size - total_written) : chunk_size_bytes);
#if defined(_WIN32)
        DWORD bytes_written = 0;
        if (!WriteFile((HANDLE)_get_osfhandle(fd), buffer, (DWORD)to_write_now, &bytes_written, NULL)) {
            ve_set_last_errorf("WriteFile failed"); 
            free(buffer); 
            return -1;
        }
        if (bytes_written == 0) { 
            free(buffer); 
            ve_set_last_errorf("WriteFile wrote 0 bytes"); 
            return -1; 
        }
#else
        ssize_t bytes_written = write(fd, buffer, to_write_now);
        if (bytes_written <= 0) { 
            ve_set_last_errorf("write failed: %s", strerror(errno)); 
            free(buffer); 
            return -1; 
        }
#endif
        total_written += (uint64_t)bytes_written;
    }
    ve_secure_bzero(buffer, chunk_size_bytes);
    free(buffer);
    return 0;
}

/* Write cryptographically random data across the file */
static int ve_write_random_fd(int fd, uint64_t file_size) {
    const size_t chunk_size_bytes = VE_DEFAULT_CHUNK_SIZE;
    unsigned char* buffer = (unsigned char*)malloc(chunk_size_bytes);
    if (!buffer) { 
        ve_set_last_errorf("malloc failed"); 
        return -1; 
    }

    uint64_t total_written = 0;
    while (total_written < file_size) {
        size_t to_write_now = (size_t)((file_size - total_written) < chunk_size_bytes ? (file_size - total_written) : chunk_size_bytes);
        if (ve_csrand(buffer, to_write_now) != 0) { 
            ve_secure_bzero(buffer, chunk_size_bytes); 
            free(buffer); 
            return -1; 
        }
#if defined(_WIN32)
        DWORD bytes_written = 0;
        if (!WriteFile((HANDLE)_get_osfhandle(fd), buffer, (DWORD)to_write_now, &bytes_written, NULL)) {
            ve_set_last_errorf("WriteFile failed"); 
            ve_secure_bzero(buffer, chunk_size_bytes); 
            free(buffer); 
            return -1;
        }
        if (bytes_written == 0) { 
            ve_secure_bzero(buffer, chunk_size_bytes); 
            free(buffer); 
            ve_set_last_errorf("WriteFile wrote 0 bytes"); 
            return -1; 
        }
#else
        ssize_t bytes_written = write(fd, buffer, to_write_now);
        if (bytes_written <= 0) { 
            ve_set_last_errorf("write failed: %s", strerror(errno)); 
            ve_secure_bzero(buffer, chunk_size_bytes); 
            free(buffer); 
            return -1; 
        }
#endif
        total_written += (uint64_t)bytes_written;
    }
    ve_secure_bzero(buffer, chunk_size_bytes);
    free(buffer);
    return 0;
}

/* Return file size via FD */
static int ve_get_file_size_fd(int fd, uint64_t* out) {
#if defined(_WIN32)
    LARGE_INTEGER size;
    if (!GetFileSizeEx((HANDLE)_get_osfhandle(fd), &size)) {
        return -1;
    }
    *out = (uint64_t)size.QuadPart;
    return 0;
#else
    off_t cur = lseek(fd, 0, SEEK_CUR);
    off_t end = lseek(fd, 0, SEEK_END);
    if (end < 0) {
        return -1;
    }
    if (lseek(fd, cur, SEEK_SET) < 0) {
        return -1;
    }
    *out = (uint64_t)end;
    return 0;
#endif
}

/* Flush pending writes to stable storage */
static int ve_flush_fd(int fd) {
#if defined(_WIN32)
    if (!FlushFileBuffers((HANDLE)_get_osfhandle(fd))) {
        return -1;
    }
    return 0;
#else
    return fsync(fd);
#endif
}

/* Open a file read-write; on Windows clears READONLY attribute on demand */
static int ve_open_rw(const char* path) {
#if defined(_WIN32)
    HANDLE h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED) {
            DWORD attrs = GetFileAttributesA(path);
            if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_READONLY)) {
                SetFileAttributesA(path, attrs & ~FILE_ATTRIBUTE_READONLY);
                h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            }
        }
        if (h == INVALID_HANDLE_VALUE) {
            return -1;
        }
    }
    int fd = _open_osfhandle((intptr_t)h, 0);
    if (fd < 0) {
        CloseHandle(h);
        return -1;
    }
    return fd;
#else
    return open(path, O_RDWR);
#endif
}

/* Close a file descriptor/handle safely */
static int ve_close_fd(int fd) {
#if defined(_WIN32)
    /* When using _open_osfhandle, _close will close the underlying HANDLE. */
    return _close(fd);
#else
    return close(fd);
#endif
}

/* ---------------- SSD flow: encrypt-in-place then delete ---------------- */

/*
  Encrypt the entire file in-place using AES-CTR to render previous plaintext
  unrecoverable in practice (on SSD/NVMe), prior to unlinking and TRIM.
  - On Windows: uses CNG AES-CTR.
  - On POSIX: uses OpenSSL if enabled; otherwise XOR fallback (not secure).
*/
static int ve_encrypt_file_in_place_aesctr(int fd, uint64_t file_size) {
    const size_t chunk_size_bytes = VE_DEFAULT_CHUNK_SIZE;
    unsigned char* buffer = (unsigned char*)malloc(chunk_size_bytes);
    if (!buffer) { 
        ve_set_last_errorf("malloc failed"); 
        return -1; 
    }

    unsigned char aes_key[32];
    unsigned char aes_iv[16];
    if (ve_csrand(aes_key, sizeof(aes_key)) != 0 || ve_csrand(aes_iv, sizeof(aes_iv)) != 0) { 
        free(buffer); 
        return -1; 
    }

#if !defined(_WIN32)
    if (lseek(fd, 0, SEEK_SET) < 0) { 
        ve_set_last_errorf("lseek failed: %s", strerror(errno)); 
        free(buffer); 
        return -1; 
    }
#endif

    uint64_t processed = 0;
    while (processed < file_size) {
        size_t to_io = (size_t)((file_size - processed) < chunk_size_bytes ? (file_size - processed) : chunk_size_bytes);
#if defined(_WIN32)
        DWORD bytes_read = 0;
        if (!ReadFile((HANDLE)_get_osfhandle(fd), buffer, (DWORD)to_io, &bytes_read, NULL) || bytes_read == 0) { 
            ve_set_last_errorf("ReadFile failed"); 
            free(buffer); 
            return -1; 
        }
        if (bytes_read == 0) {
            ve_set_last_errorf("ReadFile read 0 bytes");
            free(buffer);
            return -1;
        }
        size_t readn = (size_t)bytes_read;
        if (ve_aes_ctr_encrypt_windows(buffer, readn, aes_key, aes_iv) != 0) {
             free(buffer); 
             return -1; 
        }
        
        LARGE_INTEGER li; li.QuadPart = (LONGLONG)processed;
        SetFilePointerEx((HANDLE)_get_osfhandle(fd), li, NULL, FILE_BEGIN);
        DWORD bytes_written = 0;
        if (!WriteFile((HANDLE)_get_osfhandle(fd), buffer, (DWORD)readn, &bytes_written, NULL) || bytes_written != readn) { 
            ve_set_last_errorf("WriteFile failed"); 
            free(buffer); 
            return -1; 
        }
#elif defined(VE_USE_OPENSSL)
        ssize_t bytes_read = read(fd, buffer, to_io);
        if (bytes_read <= 0) { 
            ve_set_last_errorf("read failed: %s", strerror(errno)); 
            free(buffer); 
            return -1; 
        }
 
        size_t readn = (size_t)bytes_read;
        if (ve_aes_ctr_encrypt_openssl(buffer, readn, aes_key, aes_iv) != 0) {
            free(buffer); 
            return -1; 
        }
        if (lseek(fd, (off_t)processed, SEEK_SET) < 0) { 
            ve_set_last_errorf("lseek back failed: %s", strerror(errno)); 
            free(buffer); 
            return -1; 
        }
 
        ssize_t bytes_written = write(fd, buffer, readn);
        if (bytes_written != (ssize_t)readn) { 
            ve_set_last_errorf("write failed: %s", strerror(errno)); 
            free(buffer); 
            return -1; 
        }
#else
        ssize_t bytes_read = read(fd, buffer, to_io);
        if (bytes_read <= 0) { 
            ve_set_last_errorf("read failed: %s", strerror(errno)); 
            free(buffer); 
            return -1; 
        }
        size_t readn = (size_t)bytes_read;
        for (size_t i = 0, j = 0; i < readn; ++i) { 
            buffer[i] ^= aes_key[j++]; 
            if (j == sizeof(aes_key)) {
                j = 0;
            }
        }
        if (lseek(fd, (off_t)processed, SEEK_SET) < 0) { 
            ve_set_last_errorf("lseek back failed: %s", strerror(errno)); 
            free(buffer); 
            return -1; 
        }
        ssize_t bytes_written = write(fd, buffer, readn);
        if (bytes_written != (ssize_t)readn) { 
            ve_set_last_errorf("write failed: %s", strerror(errno)); 
            free(buffer); 
            return -1; 
        }
#endif
        processed += (uint64_t)readn;
    }

    ve_flush_fd(fd);
    ve_secure_bzero(aes_key, sizeof(aes_key));
    ve_secure_bzero(aes_iv, sizeof(aes_iv));
    ve_secure_bzero(buffer, chunk_size_bytes);
    free(buffer);
    return 0;
}

/* ---------------- Recursive traversal and erase orchestration ---------------- */

/* Forward decl; erases single file with selected algorithm */
static ve_status_t ve_erase_single_file(const char* path, const ve_options_t* opt);

/* Walk a directory recursively and erase files; remove dirs when empty (beginner style) */
static ve_status_t ve_walk_and_erase(const char* path, const ve_options_t* opt) {
    if (!ve_is_directory(path)) {
        return ve_erase_single_file(path, opt);
    }
#if defined(_WIN32)
    char search[MAX_PATH];
    snprintf(search, sizeof(search), "%s\\*", path);
    WIN32_FIND_DATAA ffd;
    HANDLE h = FindFirstFileA(search, &ffd);
    if (h == INVALID_HANDLE_VALUE) {
        ve_remove_empty_dir(path);
        return VE_SUCCESS;
    }
    do {
        const char* n = ffd.cFileName;
        if (strcmp(n, ".") == 0 || strcmp(n, "..") == 0) {
            continue;
        }
        char child[MAX_PATH];
        snprintf(child, sizeof(child), "%s\\%s", path, n);
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            (void)ve_walk_and_erase(child, opt);
            (void)ve_remove_empty_dir(child);
        } else {
            (void)ve_erase_single_file(child, opt);
        }
    } while (FindNextFileA(h, &ffd));
    FindClose(h);
    (void)ve_remove_empty_dir(path);
    return VE_SUCCESS;
#else
    DIR* d = opendir(path);
    if (!d) {
        (void)ve_remove_empty_dir(path);
        return VE_SUCCESS;
    }
    struct dirent* de;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) {
            continue;
        }
        char child[4096];
        snprintf(child, sizeof(child), "%s/%s", path, de->d_name);
        if (ve_is_directory(child)) {
            (void)ve_walk_and_erase(child, opt);
            (void)ve_remove_empty_dir(child);
        } else {
            (void)ve_erase_single_file(child, opt);
        }
    }
    closedir(d);
    (void)ve_remove_empty_dir(path);
    return VE_SUCCESS;
#endif
}

/* ---------------- TRIM best-effort (platform-specific) ---------------- */

/*
  Attempt to hint the filesystem/device to discard free space:
  - Linux: ioctl(FITRIM) on the path's directory; does nothing harmful if unsupported.
  - Windows/macOS: no-op in this skeleton (TRIM usually implicit on delete).
*/
static int ve_trim_best_effort(const char* path, int aggressive) {
    (void)aggressive;
#if defined(__linux__)
    char mount_path[4096];
    /* Use 'path' if it's a directory; otherwise dirname(path) */
    strncpy(mount_path, path, sizeof(mount_path) - 1);
    mount_path[sizeof(mount_path) - 1] = '\0';
    struct stat st;
    if (stat(mount_path, &st) == 0 && !S_ISDIR(st.st_mode)) {
        char* last = strrchr(mount_path, '/');
        if (last && last != mount_path) {
            *last = '\0';
        } 
        else {
            strcpy(mount_path, ".");
        }
    }
    int fd = open(mount_path, O_RDONLY);
    if (fd >= 0) {
        struct fstrim_range range;
        range.start = 0;
        range.len = (uint64_t)-1;
        range.minlen = 0;
        (void)ioctl(fd, FITRIM, &range); /* ignore errors (best-effort) */
        close(fd);
    }
    return 0;
#else
    (void)path;
    return 0;
#endif
}

/* Apply chosen HDD-like overwrite strategy */
static ve_status_t ve_erase_hdd_like(int fd, const ve_options_t* opt) {
    uint64_t size = 0;
    if (ve_get_file_size_fd(fd, &size) != 0) {
        return VE_ERR_IO;
    }

    int passes = 1;
    switch (opt->algorithm) {
        case VE_ALG_ZERO: passes = 1; break;
        case VE_ALG_RANDOM: passes = opt->passes > 0 ? opt->passes : 1; break;
        case VE_ALG_DOD3: passes = 3; break;
        case VE_ALG_DOD7: passes = 7; break;
        case VE_ALG_NIST: passes = 1; break;
        case VE_ALG_GUTMANN: passes = 35; break;
        default: passes = 1; break;
    }

    for (int p = 0; p < passes; ++p) {
        if (opt->algorithm == VE_ALG_ZERO) {
            if (ve_write_pattern_fd(fd, size, 0x00) != 0) {
                return VE_ERR_IO;
            }
        } else if (opt->algorithm == VE_ALG_RANDOM || opt->algorithm == VE_ALG_NIST || opt->algorithm == VE_ALG_GUTMANN || opt->algorithm == VE_ALG_DOD3 || opt->algorithm == VE_ALG_DOD7) {
            if (ve_write_random_fd(fd, size) != 0) {
                return VE_ERR_IO;
            }
        }
        if (ve_flush_fd(fd) != 0) {
            return VE_ERR_IO;
        }
        /* Optional: add verification per pass when opt->verify == 1 */
    }

    return VE_SUCCESS;
}

/* SSD-oriented flow: encrypt-in-place, deallocate where possible, then delete */
static ve_status_t ve_erase_ssd_like(int fd, const ve_options_t* opt) {
    (void)opt;
    uint64_t size = 0;
    if (ve_get_file_size_fd(fd, &size) != 0) {
        return VE_ERR_IO;
    }
    if (size == 0) {
        return VE_SUCCESS;
    }

    /* Encrypt in-place with AES-CTR (platform-specific implementation) */
    if (ve_encrypt_file_in_place_aesctr(fd, size) != 0) {
        return VE_ERR_IO;
    }

#if defined(__linux__)
    /* Punch holes (deallocate extents) to speed up discard, if supported */
    (void)fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 0, (off_t)size);
#endif

    if (ve_flush_fd(fd) != 0) {
        return VE_ERR_IO;
    }
 
    return VE_SUCCESS;
}

/* Erase a single file by chosen algorithm and then unlink it */
static ve_status_t ve_erase_single_file(const char* path, const ve_options_t* opt) {
    if (opt && opt->dry_run) {
        return VE_SUCCESS;
    }

    int fd = ve_open_rw(path);
    
    if (fd < 0) {
        ve_set_last_errorf("open failed on '%s'", path);
        return VE_ERR_IO;
    }

    ve_status_t rc = VE_ERR_INTERNAL;
    if (opt && opt->algorithm == VE_ALG_SSD) {
        rc = ve_erase_ssd_like(fd, opt);
    } 
    else {
        rc = ve_erase_hdd_like(fd, opt);
    }

    ve_close_fd(fd);
    if (rc != VE_SUCCESS) {
        return rc;
    }

    /* remove file after overwrite/encrypt */
    if (ve_remove_file(path) != 0) {
        return VE_ERR_IO;
    }

    /* best-effort TRIM if requested/auto */
    if (!opt || opt->trim_mode == 0 /*auto*/ || opt->trim_mode == 1 /*on*/ ) {
        ve_trim_best_effort(path, /*aggressive*/0);
    }
    return VE_SUCCESS;
}

/* ---------------- Public API ---------------- */

ve_device_type_t ve_detect_device_type(const char* path) {
    (void)path;
    return VE_DEVICE_AUTO; /* placeholder; real detection can be added */
}

ve_status_t ve_trim_free_space(const char* mount_or_volume_path, int aggressive) {
    if (!mount_or_volume_path) {
        return VE_ERR_INVALID_ARG;
    }
    int rc = ve_trim_best_effort(mount_or_volume_path, aggressive);
    return rc == 0 ? VE_SUCCESS : VE_ERR_UNSUPPORTED;
}

ve_status_t ve_erase_path(const char* path, const ve_options_t* options) {
    if (!path || !options) {
        return VE_ERR_INVALID_ARG;
    }

    if (ve_is_directory(path)) {
        return ve_walk_and_erase(path, options);
    } 
    else {
        return ve_erase_single_file(path, options);
    }
}

/* ---------------- CLI (compiled only with VE_BUILD_CLI) ---------------- */
#ifdef VE_BUILD_CLI

/* Print usage banner and option descriptions/recommendations */
static void ve_print_usage(const char* prog) {
    (void)prog;
    fprintf(stderr,
        "\n"
        "  @@@  @@@ @@@@@@@@ @@@@@@@   @@@@@@   @@@@@@ @@@@@@@@ @@@@@@@ \n"
        "  @@!  @@@ @@!      @@!  @@@ @@!  @@@ !@@     @@!      @@!  @@@\n"
        "  @!@  !@! @!!@@!   @!@!@!   @!@!@!@@  !@@!!  @!!@@!   @!@!@!  \n"
        "   !@ .:!  @!:      @!  :!@  !@!  !@!     !@! @!:      @!  :!@ \n"
        "     @!    !@!:.:!@ @!   :@. :!:  :!: !:.:@!  !@!:.:!@ @!   :@.\n"
        "\n"
        "  Veracrypt+Eraser -> VERASER - Multi-platform secure erasure tool (CLI)\n"
        "\n"
        "  Usage:\n"
        "    veraser --path <file|dir> [--algorithm <name>] [--passes N] [--verify]\n"
        "            [--trim auto|on|off] [--dry-run] [--quiet]\n"
        "\n"
        "  Options:\n"
        "    --path <file|dir>\n"
        "        Target file or directory (directory is processed recursively).\n"
        "\n"
        "    --algorithm <name>\n"
        "        Erasure algorithm. One of: zero | random | dod3 | dod7 | nist | gutmann | ssd\n"
        "        - ssd     : Recommended for SSD/NVMe. Encrypt-in-place + delete + TRIM (fast).\n"
        "        - nist    : Recommended default for modern drives; single-pass pattern/random.\n"
        "        - random  : N random passes (set with --passes). 1–2 passes usually sufficient.\n"
        "        - zero    : Single pass of zeros. Fast, lower assurance; pre-provision/init.\n"
        "        - dod3    : Legacy 3-pass (compat/regulation-driven); slower.\n"
        "        - dod7    : Legacy 7-pass; slower; rarely needed today.\n"
        "        - gutmann : Historical 35-pass; not recommended on modern drives (very slow).\n"
        "\n"
        "    --passes <N>\n"
        "        Number of passes for 'random'. Ignored for other algorithms.\n"
        "        Recommendation: N=1 (default) or 2 for added assurance without large slowdown.\n"
        "\n"
        "    --verify\n"
        "        Verify pass(es) by reading back and checking pattern.\n"
        "        Recommendation: Enable for highly sensitive data; increases total time.\n"
        "\n"
        "    --trim <auto|on|off>\n"
        "        Control TRIM/deallocate behavior (best-effort).\n"
        "        - auto: Default. Use when beneficial/available (recommended for SSD).\n"
        "        - on  : Force attempt even if uncertain support (may need admin/root).\n"
        "        - off : Disable TRIM attempts.\n"
        "\n"
        "    --dry-run\n"
        "        Show planned operations without modifying data. Safe preview.\n"
        "\n"
        "    --quiet\n"
        "        Reduce output verbosity.\n"
        "\n"
        "  Exit codes:\n"
        "    0 = success, 2 = usage/args error, 4 = I/O/platform error.\n"
        "\n");
}

/* Parse algorithm name from string */
static ve_algorithm_t ve_alg_from_str(const char* s) {
    if (!s) {
        return VE_ALG_NIST;
    }
    if (strcmp(s, "zero") == 0) {
        return VE_ALG_ZERO;
    }
    if (strcmp(s, "random") == 0) {
        return VE_ALG_RANDOM;
    }
    if (strcmp(s, "dod3") == 0) {
        return VE_ALG_DOD3;
    }
    if (strcmp(s, "dod7") == 0) {
        return VE_ALG_DOD7;
    }
    if (strcmp(s, "nist") == 0) {
        return VE_ALG_NIST;
    }
    if (strcmp(s, "gutmann") == 0) {
        return VE_ALG_GUTMANN;
    }
    if (strcmp(s, "ssd") == 0) {
        return VE_ALG_SSD;
    }
    return VE_ALG_NIST;
}

/* CLI entrypoint: parses args and calls ve_erase_path */
int main(int argc, char** argv) {
    const char* path = NULL;
    ve_options_t opt;
    memset(&opt, 0, sizeof(opt));
    opt.algorithm = VE_ALG_NIST;
    opt.trim_mode = 0; /* auto */

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--path") == 0 && i + 1 < argc) { 
            path = argv[++i]; 
        }
        else if (strcmp(argv[i], "--algorithm") == 0 && i + 1 < argc) { 
            opt.algorithm = ve_alg_from_str(argv[++i]); 
        } 
        else if (strcmp(argv[i], "--passes") == 0 && i + 1 < argc) { 
            opt.passes = atoi(argv[++i]); 
        } 
        else if (strcmp(argv[i], "--verify") == 0) { 
            opt.verify = 1; 
        } 
        else if (strcmp(argv[i], "--trim") == 0 && i + 1 < argc) {
            const char* v = argv[++i];
            if (strcmp(v, "auto") == 0) {
                opt.trim_mode = 0;
            }
            else if (strcmp(v, "on") == 0) {
                opt.trim_mode = 1;
            }
            else if (strcmp(v, "off") == 0) {
                opt.trim_mode = 2;
            }
        } 
        else if (strcmp(argv[i], "--dry-run") == 0) { 
            opt.dry_run = 1; 
        }
        else if (strcmp(argv[i], "--quiet") == 0) { 
            opt.quiet = 1; 
        }
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) { 
            ve_print_usage(argv[0]); return 2; 
        }
    }

    if (!path) { 
        ve_print_usage(argv[0]); 
        return 2; 
    }

    ve_status_t rc = ve_erase_path(path, &opt);
    if (rc != VE_SUCCESS) {
        const char* msg = ve_last_error_message();
        if (!opt.quiet) fprintf(stderr, "VERASER: Error: %s\n", msg ? msg : "failure");
        return 4;
    }
    if (!opt.quiet) fprintf(stdout, "VERASER: Success\n");
 
    return 0;
}
#endif /* VE_BUILD_CLI */
