#ifndef VE_ERASER_H
#define VE_ERASER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/*
  veraser public C API
  ---------------------
  - This header exposes the minimal C interface for integrating the erasure engine
    into other applications (e.g., VeraCrypt) and for building a standalone CLI.
  - The implementation lives in a single .c file to ease static linkage and
    plugin-style embedding on Windows/Linux/macOS.
*/

/*
  ve_status_t
  -------------
  Unified status codes returned by API calls to indicate success or a class of error.
  - VE_SUCCESS: operation completed successfully.
  - VE_ERR_INVALID_ARG: inputs/configuration invalid or missing.
  - VE_ERR_IO: filesystem or device I/O error occurred.
  - VE_ERR_PERM: insufficient permissions (e.g., TRIM may require admin/root).
  - VE_ERR_UNSUPPORTED: requested feature not supported on current platform/FS.
  - VE_ERR_PARTIAL: best-effort operation could not process all items.
  - VE_ERR_INTERNAL: unexpected internal error.
*/
typedef enum {
    VE_SUCCESS = 0,
    VE_ERR_INVALID_ARG = -1,
    VE_ERR_IO = -2,
    VE_ERR_PERM = -3,
    VE_ERR_UNSUPPORTED = -4,
    VE_ERR_PARTIAL = -5,
    VE_ERR_INTERNAL = -128
} ve_status_t;

/*
  ve_device_type_t
  -----------------
  Hint for device type selection. AUTO is default; detection is best-effort.
*/
typedef enum {
    VE_DEVICE_AUTO = 0,
    VE_DEVICE_SSD,
    VE_DEVICE_HDD
} ve_device_type_t;

/*
  ve_algorithm_t
  ---------------
  Erasure algorithm choice. See PRD for behavioral details per algorithm.
  - VE_ALG_SSD route performs encrypt-in-place + delete (+ TRIM best-effort).
*/
typedef enum {
    VE_ALG_ZERO = 0,
    VE_ALG_RANDOM,
    VE_ALG_DOD3,
    VE_ALG_DOD7,
    VE_ALG_NIST,
    VE_ALG_GUTMANN,
    VE_ALG_SSD
} ve_algorithm_t;

/*
  ve_options_t
  -------------
  Per-operation configuration. Callers should zero-initialize the struct,
  then override fields they need. Reasonable defaults:
    - algorithm = VE_ALG_NIST
    - device_type = VE_DEVICE_AUTO
    - trim_mode = 0 (auto)
  Notes:
    - passes: only used for VE_ALG_RANDOM (0 => default).
    - verify: enables read-back verification (not implemented in this skeleton).
    - trim_mode: 0=auto, 1=on, 2=off. TRIM is best-effort and platform-specific.
    - follow_symlinks: when 1, walker may traverse symlinks (default 0 recommended).
    - erase_ads: Windows NTFS Alternate Data Streams best-effort handling (unused here).
    - erase_xattr: extended attributes removal best-effort (unused here).
    - chunk_size: per-I/O buffer size in bytes (0 => built-in default in .c file).
    - threads: reserved for future (0 => single-threaded processing).
    - dry_run: plan/print without modifying anything.
    - quiet: reduce console output (CLI mode only).
*/
typedef struct {
    ve_algorithm_t algorithm;        // Algorithm selection -> zero|random|dod3|dod7|nist|gutmann|ssd
    ve_device_type_t device_type;    // Device hint: auto|ssd|hdd
    int passes;                      // Random passes for VE_ALG_RANDOM (0 => default)
    int verify;                      // 0/1 enable verification (if implemented)
    int trim_mode;                   // 0:auto, 1:on, 2:off
    int follow_symlinks;             // 0/1 follow symlinks during directory walk
    int erase_ads;                   // 0/1 best-effort NTFS ADS (Windows only; not implemented here)
    int erase_xattr;                 // 0/1 best-effort xattr removal (not implemented here)
    uint64_t chunk_size;             // I/O chunk size in bytes (0 => default)
    int threads;                     // reserved for future parallelism (0 => single)
    int dry_run;                     // 0/1 no-op mode (report only)
    int quiet;                       // 0/1 reduce logging in CLI
} ve_options_t;

/*
  ve_erase_path
  --------------
  High-level entry point.
  - If 'path' is a file: applies selected algorithm to the file, then unlinks it.
  - If 'path' is a directory: recursively processes its content; attempts to remove
    directories when empty.
  Inputs:
    - path: UTF-8 or native narrow string path (Windows ANSI for this build).
    - options: required pointer to options (non-NULL). See ve_options_t.
  Returns: ve_status_t per operation result.
*/
ve_status_t ve_erase_path(const char* path, const ve_options_t* options);

/*
  ve_trim_free_space
  -------------------
  Best-effort free-space TRIM for a mount/volume or directory path (platform-specific).
  - On Linux, attempts FITRIM on the directory.
  - On Windows/macOS, this is a stub in this skeleton.
  Inputs:
    - mount_or_volume_path: path string (non-NULL).
    - aggressive: hint flag for stronger attempts (currently unused).
  Returns: VE_SUCCESS on best-effort attempt made, VE_ERR_UNSUPPORTED otherwise.
*/
ve_status_t ve_trim_free_space(const char* mount_or_volume_path, int aggressive);

/*
  ve_detect_device_type
  ----------------------
  Best-effort device type detection heuristic for the given path. Placeholder in
  this skeleton, returns VE_DEVICE_AUTO.
*/
ve_device_type_t ve_detect_device_type(const char* path);

/*
  ve_last_error_message
  ----------------------
  Retrieve a thread-local human-readable description for the last set error in
  the current thread. Returns NULL if no message is available.
*/
const char* ve_last_error_message(void);

#ifdef __cplusplus
}
#endif

#endif // VE_ERASER_H

