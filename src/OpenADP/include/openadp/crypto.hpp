#pragma once

#include "types.hpp"
#include <openssl/evp.h>
#include <openssl/ec.h>

namespace openadp {
namespace crypto {

// Ed25519 curve operations
class Ed25519 {
public:
    // Hash-to-point function (matches other implementations)
    static Point4D hash_to_point(const Bytes& uid, const Bytes& did, const Bytes& bid, const Bytes& pin);
    
    // Static H function for direct access (matching Go/Python/JS APIs)
    static Point4D H(const Bytes& uid, const Bytes& did, const Bytes& bid, const Bytes& pin);
    
    // Scalar multiplication
    static Point4D scalar_mult(const std::string& scalar_hex, const Point4D& point);
    
    // Point addition
    static Point4D point_add(const Point4D& p1, const Point4D& p2);
    
    // Point compression/decompression
    static Bytes compress(const Point4D& point);
    static Point4D decompress(const Bytes& data);
    
    // Convert between 2D and 4D points
    static Point4D expand(const Point2D& point);
    static Point2D unexpand(const Point4D& point);
    
    // String-based expand/unexpand for compatibility
    static Point4D expand_from_string(const std::string& point_2d);
    static std::string unexpand_to_string(const Point4D& point);
    
    // Validate point is on curve
    static bool is_valid_point(const Point4D& point);
    
    // Multiply point by 8 (cofactor)
    static Point4D point_mul8(const Point4D& point);
};

// Shamir secret sharing
class ShamirSecretSharing {
public:
    // Split secret into shares
    static std::vector<Share> split_secret(const std::string& secret_hex, int threshold, int num_shares);
    
    // Recover secret from shares
    static std::string recover_secret(const std::vector<Share>& shares);
};

// Point-based secret sharing
class PointSecretSharing {
public:
    // Split point into shares
    static std::vector<PointShare> split_point(const Point2D& point, int threshold, int num_shares);
    
    // Recover point from shares
    static Point2D recover_point(const std::vector<PointShare>& shares);
};

// Key derivation
Bytes derive_encryption_key(const Point4D& point);

// Global functions to match Go implementation
Point4D H(const Bytes& uid, const Bytes& did, const Bytes& bid, const Bytes& pin);
bool is_valid_point(const Point4D& point);
Point4D point_mul8(const Point4D& point);
Point4D point_mul(const std::string& scalar_hex, const Point4D& point);
Point4D point_add(const Point4D& p1, const Point4D& p2);
Bytes point_compress(const Point4D& point);
Point4D point_decompress(const Bytes& data);
std::string unexpand(const Point4D& point);
Point4D expand(const std::string& point_2d);

// Utility functions
Bytes sha256_hash(const Bytes& data);
Bytes prefixed(const Bytes& data);
std::string bytes_to_hex(const Bytes& data);
Bytes hex_to_bytes(const std::string& hex);

// AES-GCM encryption/decryption
struct AESGCMResult {
    Bytes ciphertext;
    Bytes tag;
    Bytes nonce;
};

AESGCMResult aes_gcm_encrypt(const Bytes& plaintext, const Bytes& key, const Bytes& associated_data);
AESGCMResult aes_gcm_encrypt(const Bytes& plaintext, const Bytes& key);
AESGCMResult aes_gcm_encrypt(const Bytes& plaintext, const Bytes& key, const Bytes& nonce, const Bytes& associated_data);
Bytes aes_gcm_decrypt(const Bytes& ciphertext, const Bytes& tag, const Bytes& nonce, 
                     const Bytes& key, const Bytes& associated_data);
Bytes aes_gcm_decrypt(const Bytes& ciphertext, const Bytes& tag, const Bytes& nonce, 
                     const Bytes& key);

// HKDF key derivation
Bytes hkdf_derive(const Bytes& input_key, const Bytes& salt, const Bytes& info, size_t output_length);
Bytes hkdf_expand_only(const Bytes& prk, const Bytes& info, size_t output_length);

// HMAC functions
Bytes hmac_sha256(const Bytes& key, const Bytes& data);

// Cryptographically secure random byte generation
Bytes random_bytes(size_t length);

} // namespace crypto
} // namespace openadp 