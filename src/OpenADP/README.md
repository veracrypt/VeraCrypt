# Ocrypt Integration in VeraCrypt

## Overview

This directory contains the OpenADP (Open Adaptive Data Protection) implementation for VeraCrypt, specifically the Ocrypt distributed cryptographic system. Ocrypt provides enhanced security through distributed key management and threshold cryptography.

## Usage Examples

### Creating an Ocrypt Volume

```bash
# Create a 100MB Ocrypt volume with FAT filesystem
./veracrypt --text --create /path/to/volume.tc --size=100M --volume-type=normal \
  --encryption=AES --prf=Ocrypt --filesystem=FAT --password="your_password" \
  --non-interactive

# Create a 1GB Ocrypt volume with no filesystem (raw)
./veracrypt --text --create /path/to/volume.tc --size=1G --volume-type=normal \
  --encryption=AES --prf=Ocrypt --filesystem=none --password="your_password" \
  --non-interactive

# Create with custom PIM (Personal Iterations Multiplier)
./veracrypt --text --create /path/to/volume.tc --size=500M --volume-type=normal \
  --encryption=AES --prf=Ocrypt --filesystem=exFAT --password="your_password" \
  --pim=0 --non-interactive
```

**Note**: During volume creation, VeraCrypt will:
1. Contact OpenADP servers to register your volume
2. Write the Ocrypt magic string for instant detection
3. Store encrypted metadata in the volume header
4. Create a standard VeraCrypt volume with Ocrypt key derivation

### Mounting an Ocrypt Volume

```bash
# Mount an Ocrypt volume
sudo ./veracrypt --text --mount /path/to/volume.tc /mount/point \
  --password="your_password" --non-interactive

# Mount with verbose output (helpful for debugging)
sudo ./veracrypt --text --mount /path/to/volume.tc /mount/point \
  --password="your_password" --non-interactive --verbose

# Mount and list all mounted volumes
sudo ./veracrypt --text --mount /path/to/volume.tc /mount/point \
  --password="your_password" --non-interactive
./veracrypt --text --list
```

**Note**: During mounting, VeraCrypt will:
1. Detect the Ocrypt magic string instantly
2. Read encrypted metadata from the volume header
3. Contact OpenADP servers to recover your encryption key
4. Decrypt and mount the volume normally

### Unmounting an Ocrypt Volume

```bash
# Unmount a specific volume
sudo ./veracrypt --text --dismount /mount/point --non-interactive

# Unmount all volumes
sudo ./veracrypt --text --dismount --non-interactive

# Force unmount (if regular unmount fails)
sudo ./veracrypt --text --dismount /mount/point --force --non-interactive
```

### Listing Mounted Volumes

```bash
# List all currently mounted volumes
./veracrypt --text --list

# Example output:
# 1: /path/to/volume.tc /dev/mapper/veracrypt1 /mount/point
# 2: /path/to/another.tc /dev/mapper/veracrypt2 /another/mount/point
```

### Volume Information

```bash
# Get detailed information about a volume
./veracrypt --text --volume-properties /path/to/volume.tc

# Check if a volume is an Ocrypt volume (without mounting)
python3 -c "
with open('/path/to/volume.tc', 'rb') as f:
    f.seek(512)
    magic = f.read(16)
    print('Volume type:', 'Ocrypt' if magic.startswith(b'OCRYPT') else 'Traditional')
"
```

### Advanced Examples

```bash
# Create volume with keyfile support
./veracrypt --text --create /path/to/volume.tc --size=1G --volume-type=normal \
  --encryption=AES --prf=Ocrypt --filesystem=ext4 --password="your_password" \
  --keyfiles="/path/to/keyfile1,/path/to/keyfile2" --non-interactive

# Mount with keyfiles
sudo ./veracrypt --text --mount /path/to/volume.tc /mount/point \
  --password="your_password" --keyfiles="/path/to/keyfile1,/path/to/keyfile2" \
  --non-interactive

# Create volume with different encryption algorithm
./veracrypt --text --create /path/to/volume.tc --size=1G --volume-type=normal \
  --encryption=Serpent --prf=Ocrypt --filesystem=NTFS --password="your_password" \
  --non-interactive
```

### Troubleshooting

```bash
# Enable debug output for troubleshooting
./veracrypt --text --create /path/to/volume.tc --size=100M --volume-type=normal \
  --encryption=AES --prf=Ocrypt --filesystem=FAT --password="your_password" \
  --non-interactive --verbose 2>&1 | tee debug_output.log

# Check if OpenADP servers are reachable
curl -v https://ocrypt.io/api/health

# Verify volume structure
hexdump -C /path/to/volume.tc | head -50
```

### Important Notes

1. **Network Required**: Ocrypt volumes require network access to OpenADP servers during creation and mounting
2. **Magic String**: All Ocrypt volumes contain a magic string at byte 512 for instant detection
3. **Compatibility**: Ocrypt volumes are **not compatible** with VeraCrypt's plausible deniability feature
4. **Performance**: First-time operations may take longer due to network communication
5. **Security**: Each volume gets unique cryptographic keys managed by the distributed Ocrypt system

## Current Implementation Status

✅ **Completed Features:**
- Secure random number generation (OpenSSL `RAND_bytes` for cross-platform portability)
- Single-recovery architecture with version byte system
- Atomic metadata updates with rollback safety
- Core integration with VeraCrypt's PRF system
- File handle management for metadata access
- Rollback-safe volume creation (primary header only initially)

⚠️ **Known Limitations:**
- Incompatible with VeraCrypt's plausible deniability feature
- Network access required (problematic for air-gapped systems)
- Complex integration with traditional VeraCrypt workflows

## Architecture Overview

### Volume Layout
```
Bytes 0-63:       Standard VeraCrypt volume header (unencrypted)
Bytes 64-511:     Standard VeraCrypt volume header (encrypted)
Bytes 512-527:    Ocrypt magic string "OCRYPT" + version info (16 bytes, unencrypted)
Byte 528:         Version byte (0=EVEN metadata active, 1=ODD metadata active)
Bytes 529-16912:  EVEN metadata slot (16,384 bytes)
Bytes 16913-33296: ODD metadata slot (16,384 bytes)
Bytes 65536+:     Hidden volume header area (no conflict with Ocrypt)
```

### Key Components

1. **`crypto.cpp`** - Core cryptographic operations (AES-GCM, key derivation)
2. **`ocrypt.cpp`** - Ocrypt protocol implementation 
3. **`OcryptWrapper.cpp`** - C wrapper for integration with VeraCrypt's C codebase
4. **`src/Common/Pkcs5.c`** - Integration with VeraCrypt's PRF system

### Security Features

#### Secure Random Generation
- **All Platforms**: Uses OpenSSL's `RAND_bytes()` for cryptographically secure entropy
- **Portability**: No platform-specific dependencies or file access requirements
- **Fallback**: Hash-based key derivation if OpenSSL RNG fails
- **API**: Exposed via `ocrypt_random_bytes()` wrapper function

#### Single-Recovery Architecture
- **Version Byte System**: Tracks which metadata copy is newer
- **Atomic Updates**: Write new metadata to alternate slot, then toggle version byte
- **Rollback Safety**: Failed operations don't corrupt existing metadata
- **Caching**: Prevents double recovery within same volume operation

## Design Decisions & Trade-offs

### 1. Plausible Deniability vs. Ocrypt Security

**Decision**: Ocrypt metadata stored in unused header space breaks plausible deniability.

**Reasoning**: 
- Ocrypt metadata at byte 529 makes it immediately obvious this is an Ocrypt volume
- No technical solution exists to hide distributed cryptographic metadata
- Security benefits of Ocrypt outweigh plausible deniability for target use cases

**Impact**: Ocrypt and traditional VeraCrypt serve different threat models

### 2. Network Access Requirement

**Challenge**: Ocrypt requires network access to distributed key servers.

**Problem**: VeraCrypt is commonly used in air-gapped environments.

**Current Solution**: Attempt all PRFs including Ocrypt (inefficient, causes timeouts)

**Proposed Solution**: Magic string detection (see Future Plans)

### 3. Integration Complexity

**Current Approach**: Seamless integration with existing VeraCrypt PRF system
- Pros: Familiar workflow, backwards compatibility
- Cons: Complex logic, PIM/keyfile confusion, network timeouts

**Proposed Approach**: Dedicated "Ocrypt Mode" (see Future Plans)
- Pros: Cleaner UX, no air-gap issues, simplified logic
- Cons: More invasive changes, separate code paths

## Security Improvements

### Fixed Vulnerabilities

1. **Weak Entropy Generation** (Fixed in commits `61072832` and latest)
   - **Before**: Used `clock()` and `time()` functions (predictable)
   - **After**: Uses OpenSSL `RAND_bytes()` (cryptographically secure, cross-platform)
   - **Impact**: Each volume gets unique 32-byte random secrets with portable implementation

2. **Double Recovery** (Fixed in commit `87324297`)
   - **Before**: Ocrypt recovery called twice (primary + backup headers)
   - **After**: Single recovery with version byte system
   - **Impact**: Improved performance and reliability

3. **File Handle Access** (Fixed in commit `a54b6da1`)
   - **Before**: `current_volume_path=NULL` prevented metadata access
   - **After**: Proper file handle setup in `Volume::Open()`
   - **Impact**: Enables metadata access during volume operations

## ✅ COMPLETED: Magic String Implementation

### Successfully Implemented Features

The magic string detection system has been fully implemented and tested:

#### 1. Volume Creation (`VolumeCreator.cpp`)
```c
// In CreateVolumeHeaderInMemory() - write magic string at byte 512
memcpy(header + 512, "OCRYPT1.0\0\0\0\0\0\0\0", 16);  // 16 bytes with version info
// Write version byte at 528
header[528] = 0;  // Initial version (EVEN metadata active)
```

#### 2. Volume Detection (`Volume.cpp`)
```c
// In Volume::Open() - check for magic string before attempting PRFs
unsigned char magic_buffer[16];
if (volumeFile.ReadAt(magic_buffer, 16, 512) == 16) {
    if (memcmp(magic_buffer, "OCRYPT", 6) == 0) {
        // This is an Ocrypt volume - only try Ocrypt PRF
        return try_ocrypt_only(volumeFile, password);
    }
}
// Traditional volume - try all other PRFs except Ocrypt
```

#### 3. Header Encryption (`VolumeHeader.cpp`)
```c
// Standard VeraCrypt header encryption remains unchanged
// Magic string at 512-527 stays unencrypted for instant detection
// No changes needed to encryption logic
```

#### 4. Header Decryption (`VolumeHeader.cpp`)
```c
// Standard VeraCrypt header decryption remains unchanged
// Magic string at 512-527 was never encrypted
// No changes needed to decryption logic
```

#### 5. PRF Selection Logic (`Pkcs5.c`)
```c
// In derive_key() - add magic string detection
bool is_ocrypt_volume = detect_ocrypt_magic(volume_path);
if (is_ocrypt_volume && pkcs5_prf != OCRYPT) {
    return 0; // Only try Ocrypt PRF for Ocrypt volumes
}
if (!is_ocrypt_volume && pkcs5_prf == OCRYPT) {
    return 0; // Never try Ocrypt PRF for traditional volumes
}
```

#### 6. Update Metadata Offsets
```c
// Update all metadata access to use new offsets
#define TC_METADATA_VERSION_OFFSET 528
#define TC_METADATA_EVEN_OFFSET 529
#define TC_METADATA_ODD_OFFSET (529 + 16384)  // 16913
```

### Benefits of Magic String Design

1. **Instant Detection**: No expensive PRF attempts needed
2. **Air-Gap Compatibility**: Traditional volumes never attempt network access
3. **Performance**: Fast magic string check vs. full cryptographic operations
4. **Clean Separation**: Distinct handling for different volume types
5. **User Experience**: No timeouts or network errors for traditional volumes

### Implementation Notes

- Magic string `"OCRYPT1.0\0\0\0\0\0\0\0"` is 16 bytes with version info and padding
- Located at bytes 512-527 (after standard 512-byte VeraCrypt header)
- Completely unencrypted for instant detection without password
- Version byte moved to offset 528 (was 512)
- Metadata slots shifted: EVEN at 529, ODD at 16913
- No changes needed to VeraCrypt's header encryption/decryption logic

## Future Plans: "Ocrypt Mode"

### Current Architecture Changes

#### ✅ Magic String Detection (IMPLEMENTED)
```c
// In detect_ocrypt_magic_string() - implemented in Pkcs5.c
int detect_ocrypt_magic_string(const char* volume_path) {
    // Cross-platform file access (Windows/Unix)
    // Read 16 bytes at offset 512
    if (memcmp(magic_buffer, "OCRYPT", 6) == 0) {
        return 1; // This is an Ocrypt volume
    }
    return 0; // Not an Ocrypt volume
}

// In derive_key_ocrypt() - prevents air-gap issues
if (g_current_volume_path) {
    if (!detect_ocrypt_magic_string(g_current_volume_path)) {
        return; // Skip Ocrypt PRF for non-Ocrypt volumes
    }
}
```

#### Simplified Command Interface
```bash
# Volume Creation (Ocrypt Mode)
veracrypt --create-ocrypt /path/to/volume --size=1G
# No PIM, no keyfiles, simplified flow

# Volume Mounting (Ocrypt Mode)  
veracrypt --mount-ocrypt /path/to/volume /mount/point
# Checks magic string first, only attempts Ocrypt if found

# Traditional volumes remain unchanged
veracrypt --create /path/to/volume --size=1G --prf=SHA-512
```

### Benefits of Ocrypt Mode

1. **Air-Gap Compatibility**: Traditional volumes never attempt network access
2. **Simplified UX**: No PIM/keyfile confusion for Ocrypt users
3. **Performance**: Fast magic string detection vs. expensive PRF testing
4. **Clean Separation**: Distinct code paths for different threat models
5. **Reduced Complexity**: Simpler logic, fewer edge cases

### Implementation Plan

1. ✅ **Phase 1**: Add magic string detection to existing system (COMPLETED)
2. **Phase 2**: Implement simplified Ocrypt creation workflow
3. **Phase 3**: Add dedicated Ocrypt mounting commands
4. **Phase 4**: Optimize traditional volume handling (skip Ocrypt PRF)

## Compatibility

### Hidden Volumes
- **Status**: Compatible (no byte range conflicts)
- **Ocrypt metadata**: Bytes 529-33296
- **Hidden volume headers**: Bytes 65536+
- **Limitation**: Ocrypt volumes cannot contain hidden volumes (metadata visibility)

### System Encryption
- **Status**: Not currently supported
- **Blocker**: System encryption requires seamless integration
- **Future**: May be possible with Ocrypt Mode approach

### Legacy Volumes
- **Status**: Fully compatible
- **Behavior**: Traditional volumes unaffected by Ocrypt integration
- **Migration**: Not supported (would require re-encryption)

## Testing

### Verified Scenarios
- ✅ Volume creation with secure random generation
- ✅ Volume mounting and decryption
- ✅ Header backup and recovery
- ✅ Rollback safety during failed operations
- ✅ Cross-platform compatibility (Linux/Windows)

### Test Files (Not Committed)
- `test_*`: Various integration tests
- `*.log`: Debug output from development
- `*.tc`: Test volume files

## Integration Status and Dependencies

### OpenSSL Dependency Challenge

**Current Status**: Ocrypt implementation depends on OpenSSL's `libcrypto` for core cryptographic operations:

- **Elliptic Curve Operations**: 320+ function calls for Ed25519 point arithmetic
- **AES-GCM Encryption**: 70+ function calls for metadata encryption
- **Cryptographic Primitives**: SHA256, HMAC, HKDF, secure random generation

**Discovery**: VeraCrypt already links OpenSSL (`-lssl -lcrypto`) for existing OpenADP support, suggesting precedent for crypto dependencies.

**Path Forward**: We are prepared to work with VeraCrypt maintainers to meet their requirements:

1. **Option 1**: Continue using existing OpenSSL dependency (minimal impact)
2. **Option 2**: Implement crypto abstraction layer for VeraCrypt's native primitives
3. **Option 3**: Implement missing crypto operations (AES-GCM, elliptic curves) in VeraCrypt
4. **Option 4**: Simplified Ocrypt using only VeraCrypt's existing crypto primitives

**Commitment**: We will adapt our implementation to match VeraCrypt's architectural preferences and are committed to long-term maintenance of the integration.

### Next Steps

Before submitting a pull request, we plan to:

1. **Engage with VeraCrypt maintainers** to understand their preferences for crypto dependencies
2. **Implement the preferred solution** based on their feedback
3. **Ensure compatibility** with VeraCrypt's security model and build system
4. **Provide comprehensive testing** on all supported platforms

## Development Notes

### Build Requirements
- OpenSSL (for AES-GCM operations) - *may change based on VeraCrypt requirements*
- Network access for Ocrypt protocol testing
- Standard VeraCrypt build dependencies

### Debug Mode
Debug output can be enabled by defining `DEBUG_OCRYPT` during compilation.

### Code Style
- C++ for core cryptographic operations
- C wrappers for VeraCrypt integration
- Consistent error handling and memory management

## Security Considerations

### Threat Model
Ocrypt is designed for scenarios where:
- **High-value data** requires distributed protection
- **Network access** is available and acceptable
- **Plausible deniability** is not required
- **Recovery assurance** is critical

### Not Suitable For
- Air-gapped environments (without magic string detection)
- Scenarios requiring plausible deniability
- Simple personal data protection (traditional VeraCrypt is simpler)

## Contributing

When working on Ocrypt integration:

1. **Security First**: All crypto operations must be reviewed
2. **Clean Commits**: Separate debug code from production changes
3. **Documentation**: Update this README for significant changes
4. **Testing**: Verify both Ocrypt and traditional volume compatibility

## References

- [OpenADP Specification](https://github.com/OpenADP/spec)
- [VeraCrypt Volume Format](https://www.veracrypt.fr/en/VeraCrypt%20Volume%20Format%20Specification.html)
- [Ocrypt Protocol Documentation](https://ocrypt.io/docs)

---

*This document reflects the current state of Ocrypt integration as of the latest commit. Design decisions may evolve as the implementation matures.* 