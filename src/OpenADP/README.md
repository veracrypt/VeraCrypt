# Ocrypt Integration in VeraCrypt

## Overview

This directory contains the OpenADP (Open Adaptive Data Protection) implementation for VeraCrypt, specifically the Ocrypt distributed cryptographic system. Ocrypt provides enhanced security through distributed key management and threshold cryptography.

## Current Implementation Status

✅ **Completed Features:**
- Secure random number generation (`/dev/urandom` on Linux, `RandgetBytes` on Windows)
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
Bytes 0-511:      Standard VeraCrypt volume header (encrypted)
Bytes 512:        Version byte (0=EVEN metadata active, 1=ODD metadata active)
Bytes 513-16896:  EVEN metadata slot (16,384 bytes)
Bytes 16897-33280: ODD metadata slot (16,384 bytes)
Bytes 65536+:     Hidden volume header area (no conflict with Ocrypt)
```

### Key Components

1. **`crypto.cpp`** - Core cryptographic operations (AES-GCM, key derivation)
2. **`ocrypt.cpp`** - Ocrypt protocol implementation 
3. **`OcryptWrapper.cpp`** - C wrapper for integration with VeraCrypt's C codebase
4. **`src/Common/Pkcs5.c`** - Integration with VeraCrypt's PRF system

### Security Features

#### Secure Random Generation
- **Linux/Unix**: Uses `/dev/urandom` for cryptographically secure entropy
- **Windows**: Uses VeraCrypt's `RandgetBytes` function
- **Fallback**: Hash-based key derivation if RNG fails

#### Single-Recovery Architecture
- **Version Byte System**: Tracks which metadata copy is newer
- **Atomic Updates**: Write new metadata to alternate slot, then toggle version byte
- **Rollback Safety**: Failed operations don't corrupt existing metadata
- **Caching**: Prevents double recovery within same volume operation

## Design Decisions & Trade-offs

### 1. Plausible Deniability vs. Ocrypt Security

**Decision**: Ocrypt metadata stored in unused header space breaks plausible deniability.

**Reasoning**: 
- Ocrypt metadata at byte 513 makes it immediately obvious this is an Ocrypt volume
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

1. **Weak Entropy Generation** (Fixed in commit `61072832`)
   - **Before**: Used `clock()` and `time()` functions (predictable)
   - **After**: Uses `/dev/urandom` (cryptographically secure)
   - **Impact**: Each volume gets unique 32-byte random secrets

2. **Double Recovery** (Fixed in commit `87324297`)
   - **Before**: Ocrypt recovery called twice (primary + backup headers)
   - **After**: Single recovery with version byte system
   - **Impact**: Improved performance and reliability

3. **File Handle Access** (Fixed in commit `a54b6da1`)
   - **Before**: `current_volume_path=NULL` prevented metadata access
   - **After**: Proper file handle setup in `Volume::Open()`
   - **Impact**: Enables metadata access during volume operations

## Future Plans: "Ocrypt Mode"

### Proposed Architecture Changes

#### Magic String Detection
```c
// At byte 512, check for "Ocrypt 1.0" magic string
if (memcmp(buffer + 512, "Ocrypt 1.0", 10) == 0) {
    // This is an Ocrypt volume - use Ocrypt PRF only
    return mount_ocrypt_volume(volume_path, password);
} else {
    // Traditional volume - try all other PRFs except Ocrypt
    return mount_traditional_volume(volume_path, password, pim, keyfiles);
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

1. **Phase 1**: Add magic string detection to existing system
2. **Phase 2**: Implement simplified Ocrypt creation workflow
3. **Phase 3**: Add dedicated Ocrypt mounting commands
4. **Phase 4**: Optimize traditional volume handling (skip Ocrypt PRF)

## Compatibility

### Hidden Volumes
- **Status**: Compatible (no byte range conflicts)
- **Ocrypt metadata**: Bytes 513-33280
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

## Development Notes

### Build Requirements
- OpenSSL (for AES-GCM operations)
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