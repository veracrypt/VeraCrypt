# [RFC] Adding Ocrypt Distributed Key Recovery Support - OpenSSL Dependency Challenge

## Overview

We've successfully implemented **Ocrypt** distributed key recovery as a new PRF option in VeraCrypt. Ocrypt enables enterprise-grade key recovery through distributed cryptography - allowing organizations to recover encrypted volumes through a threshold of authorized parties without storing plaintext keys.

## Current Status ✅

- **Core integration complete**: Ocrypt works as PRF #7 alongside existing algorithms
- **Volume creation**: Successfully creates volumes with Ocrypt metadata
- **Volume mounting**: Successfully recovers and mounts volumes 
- **Security features**: Secure random generation, atomic metadata updates, rollback safety
- **All tests passing**: Volume creation, mounting, and recovery work perfectly

## The Challenge: OpenSSL Dependency

Ocrypt's cryptographic operations currently depend on OpenSSL's `libcrypto` for:

1. **Elliptic Curve Operations** (320+ function calls)
   - Ed25519 point arithmetic for distributed cryptography
   - Big number operations (`BN_*` functions)
   - Critical for the core Ocrypt protocol

2. **AES-GCM Encryption** (70+ function calls)
   - Encrypting/decrypting Ocrypt metadata
   - Currently no GCM mode in VeraCrypt (only XTS/CBC)

3. **Cryptographic Primitives** (20+ function calls)
   - SHA256, HMAC, HKDF, secure random generation
   - Most have VeraCrypt equivalents, but some gaps remain

## Impact & Benefits

**For Users:**
- Enterprise key recovery without compromising security
- Eliminates risk of permanently lost encrypted data
- Maintains plausible deniability and existing VeraCrypt features

**For Organizations:**
- Compliant with data recovery regulations
- Distributed trust model (no single point of failure)
- Integrates seamlessly with existing VeraCrypt workflows

## Potential Solutions

### Option 1: Minimal OpenSSL Integration
- Link only `libcrypto` (not full OpenSSL)
- Significantly smaller than full SSL stack
- Well-tested, battle-hardened crypto implementations
- **Trade-off**: Adds external dependency

### Option 2: Implement Missing Crypto Primitives
- Add AES-GCM mode to VeraCrypt
- Implement elliptic curve operations from scratch
- Pure VeraCrypt solution, no external dependencies
- **Trade-off**: Substantial development effort, security review needed

### Option 3: Crypto Abstraction Layer
- Create abstraction layer for crypto operations
- OpenSSL backend for full features
- VeraCrypt-native backend for reduced functionality
- **Trade-off**: Complexity, potential feature limitations

### Option 4: Conditional Compilation
- Full Ocrypt with OpenSSL in separate build
- Simplified Ocrypt using only VeraCrypt primitives
- **Trade-off**: Maintenance burden, feature fragmentation

## Questions for the Community

1. **Is a `libcrypto` dependency acceptable** for optional functionality like Ocrypt?
2. **Would you prefer a pure VeraCrypt implementation** even if it requires significant development?
3. **Are there existing plans** for adding AES-GCM or elliptic curve support?
4. **What's VeraCrypt's policy** on optional dependencies for advanced features?

## Technical Details

- **Repository**: Our implementation is available for review
- **Code quality**: Follows VeraCrypt coding standards
- **Security**: Comprehensive security review completed
- **Testing**: All functionality tested on multiple platforms
- **Documentation**: Complete API documentation available

## Next Steps

Based on community feedback, we're prepared to:
- Implement the preferred solution
- Submit a complete pull request
- Provide documentation and testing
- Maintain the feature long-term

We believe Ocrypt would be a valuable addition to VeraCrypt's enterprise capabilities, and we're committed to implementing it in a way that aligns with the project's principles and requirements.

---

**Note**: This is not a feature request for review yet - we're seeking guidance on the technical approach before submitting a complete implementation. 