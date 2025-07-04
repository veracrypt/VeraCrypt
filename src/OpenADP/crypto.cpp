#include "openadp/crypto.hpp"
#include "openadp/types.hpp"
#include "openadp/utils.hpp"
#include "openadp/debug.hpp"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/hmac.h>
#include <cstring>
#include <algorithm>
#include <numeric>
#include <set>
#include <sstream>

namespace openadp {
namespace crypto {

// Helper function to convert hex string to BIGNUM
BIGNUM* hex_to_bn(const std::string& hex) {
    BIGNUM* bn = BN_new();
    BN_hex2bn(&bn, hex.c_str());
    return bn;
}

// Helper function to convert BIGNUM to hex string
std::string bn_to_hex(const BIGNUM* bn) {
    char* hex_str = BN_bn2hex(bn);
    std::string result(hex_str);
    OPENSSL_free(hex_str);
    
    // Convert to lowercase to match expected format
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    
    return result;
}

// Hash function
Bytes sha256_hash(const Bytes& data) {
    Bytes result(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), result.data());
    return result;
}

// Prefixed function (length prefix + data)
Bytes prefixed(const Bytes& data) {
    Bytes result;
    uint16_t length = static_cast<uint16_t>(data.size());
    
    // Little-endian encoding (16-bit)
    result.push_back(length & 0xFF);
    result.push_back((length >> 8) & 0xFF);
    
    result.insert(result.end(), data.begin(), data.end());
    return result;
}

std::string bytes_to_hex(const Bytes& data) {
    return utils::hex_encode(data);
}

Bytes hex_to_bytes(const std::string& hex) {
    return utils::hex_decode(hex);
}

// Ed25519 constants
static BIGNUM* get_ed25519_prime() {
    static BIGNUM* p = nullptr;
    if (!p) {
        p = BN_new();
        // p = 2^255 - 19
        BN_set_word(p, 1);
        BN_lshift(p, p, 255);
        BN_sub_word(p, 19);
    }
    return p;
}

static BIGNUM* get_ed25519_d() {
    static BIGNUM* d = nullptr;
    if (!d) {
        d = BN_new();
        // d = -121665 * inv(121666) mod p
        BIGNUM* inv121666 = BN_new();
        BIGNUM* temp = BN_new();
        BN_CTX* ctx = BN_CTX_new();
        
        BN_set_word(inv121666, 121666);
        BN_mod_inverse(inv121666, inv121666, get_ed25519_prime(), ctx);
        
        BN_set_word(temp, 121665);
        BN_sub(d, get_ed25519_prime(), temp);  // -121665 mod p
        BN_mod_mul(d, d, inv121666, get_ed25519_prime(), ctx);
        
        BN_free(inv121666);
        BN_free(temp);
        BN_CTX_free(ctx);
    }
    return d;
}

static BIGNUM* get_sqrt_m1() {
    static BIGNUM* sqrt_m1 = nullptr;
    if (!sqrt_m1) {
        sqrt_m1 = BN_new();
        // sqrt(-1) = 2^((p-1)/4) mod p
        BIGNUM* exp = BN_new();
        BN_CTX* ctx = BN_CTX_new();
        
        BN_copy(exp, get_ed25519_prime());
        BN_sub_word(exp, 1);
        BN_div_word(exp, 4);
        
        BN_set_word(sqrt_m1, 2);
        BN_mod_exp(sqrt_m1, sqrt_m1, exp, get_ed25519_prime(), ctx);
        
        BN_free(exp);
        BN_CTX_free(ctx);
    }
    return sqrt_m1;
}

// Recover X coordinate from Y coordinate and sign bit
static BIGNUM* recover_x(const BIGNUM* y, int sign) {
    BIGNUM* p = get_ed25519_prime();
    BIGNUM* d = get_ed25519_d();
    BN_CTX* ctx = BN_CTX_new();
    
    if (BN_cmp(y, p) >= 0) {
        BN_CTX_free(ctx);
        return nullptr;
    }
    
    // x^2 = (y^2 - 1) / (d * y^2 + 1)
    BIGNUM* y2 = BN_new();
    BIGNUM* numerator = BN_new();
    BIGNUM* denominator = BN_new();
    BIGNUM* x2 = BN_new();
    BIGNUM* x = BN_new();
    
    BN_mod_sqr(y2, y, p, ctx);
    
    BN_copy(numerator, y2);
    BN_sub_word(numerator, 1);
    BN_mod(numerator, numerator, p, ctx);
    
    BN_mod_mul(denominator, d, y2, p, ctx);
    BN_add_word(denominator, 1);
    BN_mod(denominator, denominator, p, ctx);
    
    BIGNUM* denom_inv = BN_new();
    if (!BN_mod_inverse(denom_inv, denominator, p, ctx)) {
        BN_free(y2); BN_free(numerator); BN_free(denominator);
        BN_free(x2); BN_free(x); BN_free(denom_inv);
        BN_CTX_free(ctx);
        return nullptr;
    }
    
    BN_mod_mul(x2, numerator, denom_inv, p, ctx);
    
    if (BN_is_zero(x2)) {
        if (sign != 0) {
            BN_free(y2); BN_free(numerator); BN_free(denominator);
            BN_free(x2); BN_free(x); BN_free(denom_inv);
            BN_CTX_free(ctx);
            return nullptr;
        }
        BN_zero(x);
        BN_free(y2); BN_free(numerator); BN_free(denominator);
        BN_free(x2); BN_free(denom_inv);
        BN_CTX_free(ctx);
        return x;
    }
    
    // Compute square root of x2
    BIGNUM* exp = BN_new();
    BN_copy(exp, p);
    BN_add_word(exp, 3);
    BN_div_word(exp, 8);
    
    BN_mod_exp(x, x2, exp, p, ctx);
    
    // Check if x^2 == x2
    BIGNUM* x_squared = BN_new();
    BN_mod_sqr(x_squared, x, p, ctx);
    
    if (BN_cmp(x_squared, x2) != 0) {
        BN_mod_mul(x, x, get_sqrt_m1(), p, ctx);
    }
    
    // Verify again
    BN_mod_sqr(x_squared, x, p, ctx);
    if (BN_cmp(x_squared, x2) != 0) {
        BN_free(y2); BN_free(numerator); BN_free(denominator);
        BN_free(x2); BN_free(x); BN_free(denom_inv);
        BN_free(exp); BN_free(x_squared);
        BN_CTX_free(ctx);
        return nullptr;
    }
    
    // Check sign
    if ((int)BN_is_odd(x) != sign) {
        BN_sub(x, p, x);
    }
    
    BN_free(y2); BN_free(numerator); BN_free(denominator);
    BN_free(x2); BN_free(denom_inv); BN_free(exp); BN_free(x_squared);
    BN_CTX_free(ctx);
    return x;
}

// Convert bytes to BIGNUM in little-endian format
static BIGNUM* bytes_to_bn_le(const Bytes& data) {
    BIGNUM* bn = BN_new();
    BN_zero(bn);
    
    for (size_t i = 0; i < data.size(); ++i) {
        for (int bit = 0; bit < 8; ++bit) {
            if ((data[i] >> bit) & 1) {
                BN_set_bit(bn, i * 8 + bit);
            }
        }
    }
    
    return bn;
}

// Reverse bytes for little-endian conversion (matches Go reverseBytes)
static Bytes reverse_bytes(const Bytes& data) {
    Bytes result(data.size());
    for (size_t i = 0; i < data.size(); ++i) {
        result[i] = data[data.size() - 1 - i];
    }
    return result;
}

// XOR two BIGNUMs (proper implementation)
static BIGNUM* bn_xor(const BIGNUM* a, const BIGNUM* b, const BIGNUM* mod) {
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* result = BN_new();
    BIGNUM* temp_a = BN_new();
    BIGNUM* temp_b = BN_new();
    
    // Ensure both numbers are in range [0, mod)
    BN_mod(temp_a, a, mod, ctx);
    BN_mod(temp_b, b, mod, ctx);
    
    // Convert to binary and XOR bit by bit
    int max_bits = BN_num_bits(mod);
    BN_zero(result);
    
    for (int i = 0; i < max_bits; ++i) {
        int bit_a = BN_is_bit_set(temp_a, i) ? 1 : 0;
        int bit_b = BN_is_bit_set(temp_b, i) ? 1 : 0;
        int xor_bit = bit_a ^ bit_b;
        
        if (xor_bit) {
            BN_set_bit(result, i);
        }
    }
    
    BN_free(temp_a);
    BN_free(temp_b);
    BN_CTX_free(ctx);
    return result;
}

// Ed25519 implementation
Point4D Ed25519::hash_to_point(const Bytes& uid, const Bytes& did, const Bytes& bid, const Bytes& pin) {
    // Concatenate all inputs with length prefixes (matching Go implementation)
    Bytes prefixed_uid = prefixed(uid);
    Bytes prefixed_did = prefixed(did);
    Bytes prefixed_bid = prefixed(bid);
    
    Bytes data;
    data.insert(data.end(), prefixed_uid.begin(), prefixed_uid.end());
    data.insert(data.end(), prefixed_did.begin(), prefixed_did.end());
    data.insert(data.end(), prefixed_bid.begin(), prefixed_bid.end());
    data.insert(data.end(), pin.begin(), pin.end());
    
    // Hash and convert to point
    Bytes hash_bytes = sha256_hash(data);
    
    // Convert hash to big integer (little-endian) matching Go
    Bytes reversed_hash = reverse_bytes(hash_bytes);
    BIGNUM* y_base = BN_new();
    BN_bin2bn(reversed_hash.data(), reversed_hash.size(), y_base);
    
    int sign = BN_is_bit_set(y_base, 255) ? 1 : 0;
    BN_clear_bit(y_base, 255);  // Clear sign bit
    
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* counter_bn = BN_new();
    BIGNUM* y = BN_new();
    BIGNUM* prime = get_ed25519_prime();
    
    int counter = 0;
    while (counter < 1000) {
        // XOR with counter to find valid point (proper XOR implementation)
        BN_set_word(counter_bn, counter);
        
        // Proper XOR: y = y_base XOR counter
        BIGNUM* xor_result = bn_xor(y_base, counter_bn, prime);
        BN_copy(y, xor_result);
        BN_free(xor_result);
        
        BIGNUM* x = recover_x(y, sign);
        if (x) {
            // Create point in extended coordinates
            BIGNUM* xy = BN_new();
            BN_mod_mul(xy, x, y, prime, ctx);
            
            Point4D point(bn_to_hex(x), bn_to_hex(y), "1", bn_to_hex(xy));
            
            // Multiply by 8 for cofactor clearing (matches Go pointMul8)
            Point4D result = point_mul8(point);
            
            if (is_valid_point(result)) {
                BN_free(x);
                BN_free(xy);
                BN_free(y_base);
                BN_free(counter_bn);
                BN_free(y);
                BN_CTX_free(ctx);
                return result;
            }
            
            BN_free(x);
            BN_free(xy);
        }
        counter++;
    }
    
    // Fallback to base point G if no valid point found (matches Go)
    BN_free(y_base);
    BN_free(counter_bn);
    BN_free(y);
    BN_CTX_free(ctx);
    
    // Return base point G as fallback - calculate proper G coordinates
    BIGNUM* gy = BN_new();
    BIGNUM* inv5 = BN_new();
    BN_CTX* g_ctx = BN_CTX_new();
    
    // G.y = 4/5 mod p
    BN_set_word(gy, 4);
    BN_set_word(inv5, 5);
    BN_mod_inverse(inv5, inv5, prime, g_ctx);
    BN_mod_mul(gy, gy, inv5, prime, g_ctx);
    
    BIGNUM* gx = recover_x(gy, 0);
    if (!gx) {
        // Fallback if base point calculation fails
        BN_free(gy);
        BN_free(inv5);
        BN_CTX_free(g_ctx);
        return Point4D("0", "1", "1", "0"); // Zero point
    }
    
    BIGNUM* gxy = BN_new();
    BN_mod_mul(gxy, gx, gy, prime, g_ctx);
    
    Point4D base_point(bn_to_hex(gx), bn_to_hex(gy), "1", bn_to_hex(gxy));
    
    BN_free(gx);
    BN_free(gy);
    BN_free(gxy);
    BN_free(inv5);
    BN_CTX_free(g_ctx);
    
    return base_point;
}

Point4D Ed25519::scalar_mult(const std::string& scalar_hex, const Point4D& point) {
    BIGNUM* scalar = hex_to_bn(scalar_hex);
    BN_CTX* ctx = BN_CTX_new();
    
    // Initialize result to zero point (0, 1, 1, 0)
    Point4D result("0", "1", "1", "0");
    Point4D current_point = point;
    
    // Double-and-add algorithm (fixed to match JavaScript/Python order)
    while (!BN_is_zero(scalar)) {
        if (BN_is_odd(scalar)) {
            result = point_add(result, current_point);
        }
        BN_rshift1(scalar, scalar);  // Process bit first
        if (!BN_is_zero(scalar)) {   // Only double if more bits remain
            current_point = point_add(current_point, current_point);  // Double
        }
    }
    
    BN_free(scalar);
    BN_CTX_free(ctx);
    return result;
}

Point4D Ed25519::point_add(const Point4D& p1, const Point4D& p2) {
    // Proper Ed25519 point addition in extended coordinates
    BIGNUM* p = get_ed25519_prime();
    BIGNUM* d = get_ed25519_d();
    BN_CTX* ctx = BN_CTX_new();
    
    BIGNUM* x1 = hex_to_bn(p1.x);
    BIGNUM* y1 = hex_to_bn(p1.y);
    BIGNUM* z1 = hex_to_bn(p1.z);
    BIGNUM* t1 = hex_to_bn(p1.t);
    
    BIGNUM* x2 = hex_to_bn(p2.x);
    BIGNUM* y2 = hex_to_bn(p2.y);
    BIGNUM* z2 = hex_to_bn(p2.z);
    BIGNUM* t2 = hex_to_bn(p2.t);
    
    // A = (Y1 - X1) * (Y2 - X2)
    BIGNUM* a = BN_new();
    BIGNUM* temp1 = BN_new();
    BIGNUM* temp2 = BN_new();
    
    BN_mod_sub(temp1, y1, x1, p, ctx);
    BN_mod_sub(temp2, y2, x2, p, ctx);
    BN_mod_mul(a, temp1, temp2, p, ctx);
    
    // B = (Y1 + X1) * (Y2 + X2)
    BIGNUM* b = BN_new();
    BN_mod_add(temp1, y1, x1, p, ctx);
    BN_mod_add(temp2, y2, x2, p, ctx);
    BN_mod_mul(b, temp1, temp2, p, ctx);
    
    // C = 2 * T1 * T2 * d
    BIGNUM* c = BN_new();
    BN_mod_mul(c, t1, t2, p, ctx);
    BN_mod_mul(c, c, d, p, ctx);
    BN_lshift1(c, c);
    BN_mod(c, c, p, ctx);
    
    // D = 2 * Z1 * Z2
    BIGNUM* dd = BN_new();
    BN_mod_mul(dd, z1, z2, p, ctx);
    BN_lshift1(dd, dd);
    BN_mod(dd, dd, p, ctx);
    
    // E, F, G, H = B - A, D - C, D + C, B + A
    BIGNUM* e = BN_new();
    BIGNUM* f = BN_new();
    BIGNUM* g = BN_new();
    BIGNUM* h = BN_new();
    
    BN_mod_sub(e, b, a, p, ctx);
    BN_mod_sub(f, dd, c, p, ctx);
    BN_mod_add(g, dd, c, p, ctx);
    BN_mod_add(h, b, a, p, ctx);
    
    // Result = (E * F, G * H, F * G, E * H)
    BIGNUM* result_x = BN_new();
    BIGNUM* result_y = BN_new();
    BIGNUM* result_z = BN_new();
    BIGNUM* result_t = BN_new();
    
    BN_mod_mul(result_x, e, f, p, ctx);
    BN_mod_mul(result_y, g, h, p, ctx);
    BN_mod_mul(result_z, f, g, p, ctx);
    BN_mod_mul(result_t, e, h, p, ctx);
    
    Point4D result(bn_to_hex(result_x), bn_to_hex(result_y), 
                   bn_to_hex(result_z), bn_to_hex(result_t));
    
    // Cleanup
    BN_free(x1); BN_free(y1); BN_free(z1); BN_free(t1);
    BN_free(x2); BN_free(y2); BN_free(z2); BN_free(t2);
    BN_free(a); BN_free(b); BN_free(c); BN_free(dd);
    BN_free(e); BN_free(f); BN_free(g); BN_free(h);
    BN_free(temp1); BN_free(temp2);
    BN_free(result_x); BN_free(result_y); BN_free(result_z); BN_free(result_t);
    BN_CTX_free(ctx);
    
    return result;
}

Bytes Ed25519::compress(const Point4D& point) {
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* p = get_ed25519_prime();
    
    BIGNUM* x = hex_to_bn(point.x);
    BIGNUM* y = hex_to_bn(point.y);
    BIGNUM* z = hex_to_bn(point.z);
    
    // Convert to affine coordinates
    BIGNUM* z_inv = BN_new();
    BN_mod_inverse(z_inv, z, p, ctx);
    
    BIGNUM* affine_x = BN_new();
    BIGNUM* affine_y = BN_new();
    
    BN_mod_mul(affine_x, x, z_inv, p, ctx);
    BN_mod_mul(affine_y, y, z_inv, p, ctx);
    
    // Set sign bit if x is odd
    if (BN_is_odd(affine_x)) {
        BN_set_bit(affine_y, 255);
    }
    
    // Convert to 32-byte little-endian format
    Bytes result(32, 0);
    
    // Use BN_bn2lebinpad for proper little-endian conversion
    if (BN_bn2lebinpad(affine_y, result.data(), 32) != 32) {
        // Fallback to manual conversion if BN_bn2lebinpad not available
        int num_bytes = BN_num_bytes(affine_y);
        Bytes y_bytes(num_bytes);
        BN_bn2bin(affine_y, y_bytes.data());
        
        // Convert to little-endian
        for (int i = 0; i < num_bytes && i < 32; ++i) {
            result[i] = y_bytes[num_bytes - 1 - i];
        }
    }
    
    BN_free(x); BN_free(y); BN_free(z);
    BN_free(z_inv); BN_free(affine_x); BN_free(affine_y);
    BN_CTX_free(ctx);
    
    return result;
}

Point4D Ed25519::decompress(const Bytes& data) {
    if (data.size() != 32) {
        throw OpenADPError("Invalid input length for decompression");
    }
    
    // Convert from little-endian to BIGNUM
    BIGNUM* y = bytes_to_bn_le(data);
    
    int sign = BN_is_bit_set(y, 255) ? 1 : 0;
    BN_clear_bit(y, 255);  // Clear sign bit
    
    BIGNUM* x = recover_x(y, sign);
    if (!x) {
        BN_free(y);
        throw OpenADPError("Invalid point for decompression");
    }
    
    // Create point in extended coordinates
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* xy = BN_new();
    BN_mod_mul(xy, x, y, get_ed25519_prime(), ctx);
    
    Point4D point(bn_to_hex(x), bn_to_hex(y), "1", bn_to_hex(xy));
    
    // Validate the decompressed point
    if (!is_valid_point(point)) {
        BN_free(x); BN_free(y); BN_free(xy);
        BN_CTX_free(ctx);
        throw OpenADPError("Invalid point: failed validation");
    }
    
    BN_free(x); BN_free(y); BN_free(xy);
    BN_CTX_free(ctx);
    
    return point;
}

Point4D Ed25519::expand(const Point2D& point) {
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* x = hex_to_bn(point.x);
    BIGNUM* y = hex_to_bn(point.y);
    
    // T = X * Y mod p
    BIGNUM* t = BN_new();
    BN_mod_mul(t, x, y, get_ed25519_prime(), ctx);
    
    Point4D result(point.x, point.y, "1", bn_to_hex(t));
    
    BN_free(x); BN_free(y); BN_free(t);
    BN_CTX_free(ctx);
    
    return result;
}

Point2D Ed25519::unexpand(const Point4D& point) {
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* p = get_ed25519_prime();
    
    BIGNUM* x = hex_to_bn(point.x);
    BIGNUM* y = hex_to_bn(point.y);
    BIGNUM* z = hex_to_bn(point.z);
    
    // Convert to affine coordinates: (X/Z, Y/Z)
    BIGNUM* z_inv = BN_new();
    BN_mod_inverse(z_inv, z, p, ctx);
    
    BIGNUM* affine_x = BN_new();
    BIGNUM* affine_y = BN_new();
    
    BN_mod_mul(affine_x, x, z_inv, p, ctx);
    BN_mod_mul(affine_y, y, z_inv, p, ctx);
    
    Point2D result(bn_to_hex(affine_x), bn_to_hex(affine_y));
    
    BN_free(x); BN_free(y); BN_free(z);
    BN_free(z_inv); BN_free(affine_x); BN_free(affine_y);
    BN_CTX_free(ctx);
    
    return result;
}

bool Ed25519::is_valid_point(const Point4D& point) {
    if (point.x.empty() || point.y.empty() || point.z.empty() || point.t.empty()) {
        return false;
    }
    
    // Check if point is the zero point (0, 1, 1, 0)
    if (point.x == "0" && point.y == "1" && point.z == "1" && point.t == "0") {
        return false;  // Zero point is not valid for our purposes
    }
    
    // Ed25519 point validation using cofactor clearing:
    // A valid point P should satisfy: 8*P is not the zero point
    Point4D eight_p = point_mul8(point);
    
    // Check if 8*P is the zero point
    return !(eight_p.x == "0" && eight_p.y == "1" && eight_p.z == "1" && eight_p.t == "0");
}

Point4D Ed25519::point_mul8(const Point4D& point) {
    // Multiply by 8 = 2^3, so we double 3 times
    Point4D result = point_add(point, point);          // 2P
    result = point_add(result, result);                // 4P
    result = point_add(result, result);                // 8P
    return result;
}

// Shamir Secret Sharing
std::vector<Share> ShamirSecretSharing::split_secret(const std::string& secret_hex, int threshold, int num_shares) {
    // Input validation
    if (secret_hex.empty()) {
        throw OpenADPError("Secret cannot be empty");
    }
    if (threshold < 1) {
        throw OpenADPError("Threshold must be at least 1");
    }
    if (num_shares < 1) {
        throw OpenADPError("Number of shares must be at least 1");
    }
    if (threshold > num_shares) {
        throw OpenADPError("Threshold cannot be greater than number of shares");
    }
    if (num_shares > 255) {
        throw OpenADPError("Number of shares cannot exceed 255");
    }
    
    BIGNUM* secret = hex_to_bn(secret_hex);
    BIGNUM* prime = hex_to_bn("1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED"); // Ed25519 group order Q
    
    // Validate that secret is less than the prime modulus
    if (BN_cmp(secret, prime) >= 0) {
        BN_free(secret);
        BN_free(prime);
        throw OpenADPError("Secret value must be less than the field prime Q (Ed25519 group order)");
    }
    
    // Generate random coefficients
    std::vector<BIGNUM*> coefficients;
    coefficients.push_back(BN_dup(secret)); // a0 = secret
    
    for (int i = 1; i < threshold; i++) {
        BIGNUM* coeff = BN_new();
        
        if (debug::is_debug_mode_enabled()) {
            // In debug mode, use deterministic coefficients: 1, 2, 3, ...
            std::stringstream ss;
            ss << std::hex << i;
            std::string coeff_hex = ss.str();
            BN_hex2bn(&coeff, coeff_hex.c_str());
            debug::debug_log("Using deterministic coefficient " + std::to_string(i) + ": " + coeff_hex);
        } else {
            BN_rand_range(coeff, prime);
        }
        
        coefficients.push_back(coeff);
    }
    
    // Generate shares
    std::vector<Share> shares;
    BN_CTX* ctx = BN_CTX_new();
    
    for (int x = 1; x <= num_shares; x++) {
        BIGNUM* y = BN_new();
        BN_zero(y);
        
        BIGNUM* x_power = BN_new();
        BN_one(x_power);
        
        // Evaluate polynomial: y = a0 + a1*x + a2*x^2 + ... + a(t-1)*x^(t-1)
        for (int i = 0; i < threshold; i++) {
            BIGNUM* term = BN_new();
            BN_mod_mul(term, coefficients[i], x_power, prime, ctx);
            BN_mod_add(y, y, term, prime, ctx);
            
            // Prepare x_power for next iteration: x_power *= x
            if (i < threshold - 1) {  // Don't multiply on last iteration
                BN_mul_word(x_power, x);
                BN_mod(x_power, x_power, prime, ctx);
            }
            BN_free(term);
        }
        
        shares.emplace_back(x, bn_to_hex(y));
        
        BN_free(y);
        BN_free(x_power);
    }
    
    BN_CTX_free(ctx);
    
    // Cleanup
    for (BIGNUM* coeff : coefficients) {
        BN_free(coeff);
    }
    BN_free(secret);
    BN_free(prime);
    
    return shares;
}

std::string ShamirSecretSharing::recover_secret(const std::vector<Share>& shares) {
    if (shares.empty()) {
        throw OpenADPError("No shares provided");
    }
    
    if (debug::is_debug_mode_enabled()) {
        debug::debug_log("📊 C++ SHAMIR RECOVERY: Starting secret recovery");
        debug::debug_log("   Number of shares: " + std::to_string(shares.size()));
        debug::debug_log("   Input shares:");
        for (size_t i = 0; i < shares.size(); i++) {
            debug::debug_log("     Share " + std::to_string(i + 1) + ": (x=" + std::to_string(shares[i].x) + ", y=" + shares[i].y + ")");
        }
    }
    
    // Check for duplicate indices
    std::set<int> seen_indices;
    for (const auto& share : shares) {
        if (seen_indices.count(share.x)) {
            throw OpenADPError("Duplicate share indices detected");
        }
        seen_indices.insert(share.x);
    }
    
    BIGNUM* prime = hex_to_bn("1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED"); // Ed25519 group order Q
    BIGNUM* result = BN_new();
    BN_zero(result);
    BN_CTX* ctx = BN_CTX_new();
    
    if (debug::is_debug_mode_enabled()) {
        debug::debug_log("   Using prime modulus Q: 1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED");
        debug::debug_log("   Starting Lagrange interpolation...");
    }
    
    // Lagrange interpolation - evaluate polynomial at x=0
    for (size_t i = 0; i < shares.size(); i++) {
        if (debug::is_debug_mode_enabled()) {
            debug::debug_log("   Processing share " + std::to_string(i + 1) + " (x=" + std::to_string(shares[i].x) + ", y=" + shares[i].y + ")");
        }
        
        BIGNUM* numerator = BN_new();
        BIGNUM* denominator = BN_new();
        BN_one(numerator);
        BN_one(denominator);
        
        for (size_t j = 0; j < shares.size(); j++) {
            if (i != j) {
                // Numerator: multiply by -shares[j].x (since we evaluate at x=0)
                // This is equivalent to multiplying by (0 - shares[j].x) = -shares[j].x
                BIGNUM* neg_xj = BN_new();
                BN_set_word(neg_xj, shares[j].x);
                BN_sub(neg_xj, prime, neg_xj); // neg_xj = prime - shares[j].x (mod prime)
                BN_mod_mul(numerator, numerator, neg_xj, prime, ctx);
                
                if (debug::is_debug_mode_enabled()) {
                    debug::debug_log("     Multiplying numerator by (-" + std::to_string(shares[j].x) + ") = " + bn_to_hex(neg_xj));
                }
                
                BN_free(neg_xj);
                
                // Denominator: multiply by (shares[i].x - shares[j].x)
                BIGNUM* xi = BN_new();
                BIGNUM* xj = BN_new();
                BIGNUM* diff = BN_new();
                BN_set_word(xi, shares[i].x);
                BN_set_word(xj, shares[j].x);
                
                // Compute xi - xj mod prime
                if (shares[i].x >= shares[j].x) {
                    BN_set_word(diff, shares[i].x - shares[j].x);
                } else {
                    // Handle negative difference: compute prime - (xj - xi)
                    BN_set_word(diff, shares[j].x - shares[i].x);
                    BN_sub(diff, prime, diff);
                }
                
                BN_mod_mul(denominator, denominator, diff, prime, ctx);
                
                if (debug::is_debug_mode_enabled()) {
                    debug::debug_log("     Multiplying denominator by (" + std::to_string(shares[i].x) + " - " + std::to_string(shares[j].x) + ") = " + bn_to_hex(diff));
                }
                
                BN_free(xi);
                BN_free(xj);
                BN_free(diff);
            }
        }
        
        // Compute Lagrange coefficient: numerator / denominator mod prime
        if (debug::is_debug_mode_enabled()) {
            debug::debug_log("     Final numerator: " + bn_to_hex(numerator));
            debug::debug_log("     Final denominator: " + bn_to_hex(denominator));
        }
        
        BIGNUM* inv = BN_new();
        if (BN_mod_inverse(inv, denominator, prime, ctx) == NULL) {
            // Denominator is zero, which shouldn't happen with distinct x values
            BN_free(numerator);
            BN_free(denominator);
            BN_free(inv);
            BN_free(result);
            BN_free(prime);
            BN_CTX_free(ctx);
            throw OpenADPError("Failed to compute modular inverse in Lagrange interpolation");
        }
        
        BIGNUM* lagrange = BN_new();
        BN_mod_mul(lagrange, numerator, inv, prime, ctx);
        
        if (debug::is_debug_mode_enabled()) {
            debug::debug_log("     Lagrange basis polynomial L" + std::to_string(i) + "(0): " + bn_to_hex(lagrange));
        }
        
        // Multiply by the y-value of this share
        BIGNUM* y = hex_to_bn(shares[i].y);
        BN_mod_mul(lagrange, lagrange, y, prime, ctx);
        
        if (debug::is_debug_mode_enabled()) {
            debug::debug_log("     Term " + std::to_string(i) + ": y" + std::to_string(i) + " * L" + std::to_string(i) + "(0) = " + bn_to_hex(lagrange));
        }
        
        // Add to result
        BN_mod_add(result, result, lagrange, prime, ctx);
        
        if (debug::is_debug_mode_enabled()) {
            debug::debug_log("     Running total: " + bn_to_hex(result));
        }
        
        BN_free(numerator);
        BN_free(denominator);
        BN_free(inv);
        BN_free(lagrange);
        BN_free(y);
    }
    
    std::string secret_hex = bn_to_hex(result);
    
    if (debug::is_debug_mode_enabled()) {
        debug::debug_log("📊 C++ SHAMIR RECOVERY: Completed secret recovery");
        debug::debug_log("   Final recovered secret: " + secret_hex);
    }
    
    BN_free(result);
    BN_free(prime);
    BN_CTX_free(ctx);
    
    return secret_hex;
}

// Point Secret Sharing (simplified)
std::vector<PointShare> PointSecretSharing::split_point(const Point2D& point, int threshold, int num_shares) {
    auto x_shares = ShamirSecretSharing::split_secret(point.x, threshold, num_shares);
    auto y_shares = ShamirSecretSharing::split_secret(point.y, threshold, num_shares);
    
    std::vector<PointShare> point_shares;
    for (int i = 0; i < num_shares; i++) {
        Point2D share_point(x_shares[i].y, y_shares[i].y);
        point_shares.emplace_back(x_shares[i].x, share_point);
    }
    
    return point_shares;
}

Point2D PointSecretSharing::recover_point(const std::vector<PointShare>& shares) {
    std::vector<Share> x_shares, y_shares;
    
    for (const auto& point_share : shares) {
        x_shares.emplace_back(point_share.x, point_share.point.x);
        y_shares.emplace_back(point_share.x, point_share.point.y);
    }
    
    std::string x = ShamirSecretSharing::recover_secret(x_shares);
    std::string y = ShamirSecretSharing::recover_secret(y_shares);
    
    return Point2D(x, y);
}

// Key derivation
Bytes derive_encryption_key(const Point4D& point) {
    // Use HKDF to derive 32-byte key (matches Python's derive_enc_key)
    Bytes point_bytes = Ed25519::compress(point);
    
    // Use same salt and info as Python
    Bytes salt = {0x4f, 0x70, 0x65, 0x6e, 0x41, 0x44, 0x50, 0x2d, 0x45, 0x6e, 0x63, 0x4b, 0x65, 0x79, 0x2d, 0x76, 0x31}; // "OpenADP-EncKey-v1"
    Bytes info = {0x41, 0x45, 0x53, 0x2d, 0x32, 0x35, 0x36, 0x2d, 0x47, 0x43, 0x4d}; // "AES-256-GCM"
    
    return hkdf_derive(point_bytes, salt, info, 32);
}

// AES-GCM encryption
AESGCMResult aes_gcm_encrypt(const Bytes& plaintext, const Bytes& key, const Bytes& associated_data) {
    if (key.empty()) {
        throw OpenADPError("AES key cannot be empty");
    }
    
    // Determine cipher and prepare key
    const EVP_CIPHER* cipher;
    Bytes actual_key = key;
    
    if (key.size() >= 32) {
        // Use AES-256 for keys >= 32 bytes (truncate if longer)
        cipher = EVP_aes_256_gcm();
        actual_key.resize(32);
    } else if (key.size() >= 16) {
        // Use AES-128 for keys >= 16 bytes  
        cipher = EVP_aes_128_gcm();
        actual_key.resize(16);
    } else {
        // Pad short keys to 16 bytes for AES-128
        cipher = EVP_aes_128_gcm();
        actual_key.resize(16, 0);
    }
    
    // Generate random nonce
    Bytes nonce = utils::random_bytes(12);
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw OpenADPError("Failed to create cipher context");
    }
    
    // Initialize encryption
    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw OpenADPError("Failed to initialize AES-GCM");
    }
    
    // Set nonce length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw OpenADPError("Failed to set nonce length");
    }
    
    // Set key and nonce
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, actual_key.data(), nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw OpenADPError("Failed to set key and nonce");
    }
    
    // Set associated data
    int len;
    if (!associated_data.empty()) {
        if (EVP_EncryptUpdate(ctx, nullptr, &len, associated_data.data(), associated_data.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw OpenADPError("Failed to set associated data");
        }
    }
    
    // Encrypt
    Bytes ciphertext(plaintext.size());
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw OpenADPError("Encryption failed");
    }
    ciphertext.resize(len);
    
    // Finalize
    Bytes final_block(16);
    if (EVP_EncryptFinal_ex(ctx, final_block.data(), &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw OpenADPError("Encryption finalization failed");
    }
    
    if (len > 0) {
        ciphertext.insert(ciphertext.end(), final_block.begin(), final_block.begin() + len);
    }
    
    // Get tag
    Bytes tag(16);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw OpenADPError("Failed to get authentication tag");
    }
    
    EVP_CIPHER_CTX_free(ctx);
    
    return AESGCMResult{ciphertext, tag, nonce};
}

AESGCMResult aes_gcm_encrypt(const Bytes& plaintext, const Bytes& key) {
    return aes_gcm_encrypt(plaintext, key, Bytes{});
}

// AES-GCM encryption with custom nonce
AESGCMResult aes_gcm_encrypt(const Bytes& plaintext, const Bytes& key, const Bytes& nonce, const Bytes& associated_data) {
    if (key.empty()) {
        throw OpenADPError("AES key cannot be empty");
    }
    
    if (nonce.size() != 12) {
        throw OpenADPError("AES-GCM nonce must be 12 bytes");
    }
    
    // Determine cipher and prepare key
    const EVP_CIPHER* cipher;
    Bytes actual_key = key;
    
    if (key.size() >= 32) {
        // Use AES-256 for keys >= 32 bytes (truncate if longer)
        cipher = EVP_aes_256_gcm();
        actual_key.resize(32);
    } else if (key.size() >= 16) {
        // Use AES-128 for keys >= 16 bytes  
        cipher = EVP_aes_128_gcm();
        actual_key.resize(16);
    } else {
        // Pad short keys to 16 bytes for AES-128
        cipher = EVP_aes_128_gcm();
        actual_key.resize(16, 0);
    }
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw OpenADPError("Failed to create cipher context");
    }
    
    // Initialize encryption
    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw OpenADPError("Failed to initialize AES-GCM");
    }
    
    // Set nonce length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw OpenADPError("Failed to set nonce length");
    }
    
    // Set key and nonce
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, actual_key.data(), nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw OpenADPError("Failed to set key and nonce");
    }
    
    // Set associated data
    int len;
    if (!associated_data.empty()) {
        if (EVP_EncryptUpdate(ctx, nullptr, &len, associated_data.data(), associated_data.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw OpenADPError("Failed to set associated data");
        }
    }
    
    // Encrypt
    Bytes ciphertext(plaintext.size());
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw OpenADPError("Encryption failed");
    }
    ciphertext.resize(len);
    
    // Finalize
    Bytes final_block(16);
    if (EVP_EncryptFinal_ex(ctx, final_block.data(), &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw OpenADPError("Encryption finalization failed");
    }
    
    if (len > 0) {
        ciphertext.insert(ciphertext.end(), final_block.begin(), final_block.begin() + len);
    }
    
    // Get tag
    Bytes tag(16);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw OpenADPError("Failed to get authentication tag");
    }
    
    EVP_CIPHER_CTX_free(ctx);
    
    return AESGCMResult{ciphertext, tag, nonce};
}

Bytes aes_gcm_decrypt(const Bytes& ciphertext, const Bytes& tag, const Bytes& nonce, 
                     const Bytes& key, const Bytes& associated_data) {
    if (key.empty()) {
        throw OpenADPError("AES key cannot be empty");
    }
    
    // Determine cipher and prepare key (same logic as encrypt)
    const EVP_CIPHER* cipher;
    Bytes actual_key = key;
    
    if (key.size() >= 32) {
        // Use AES-256 for keys >= 32 bytes (truncate if longer)
        cipher = EVP_aes_256_gcm();
        actual_key.resize(32);
    } else if (key.size() >= 16) {
        // Use AES-128 for keys >= 16 bytes  
        cipher = EVP_aes_128_gcm();
        actual_key.resize(16);
    } else {
        // Pad short keys to 16 bytes for AES-128
        cipher = EVP_aes_128_gcm();
        actual_key.resize(16, 0);
    }
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw OpenADPError("Failed to create cipher context");
    }
    
    // Initialize decryption
    if (EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw OpenADPError("Failed to initialize AES-GCM");
    }
    
    // Set nonce length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw OpenADPError("Failed to set nonce length");
    }
    
    // Set key and nonce
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, actual_key.data(), nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw OpenADPError("Failed to set key and nonce");
    }
    
    // Set associated data
    int len;
    if (!associated_data.empty()) {
        if (EVP_DecryptUpdate(ctx, nullptr, &len, associated_data.data(), associated_data.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw OpenADPError("Failed to set associated data");
        }
    }
    
    // Decrypt
    Bytes plaintext(ciphertext.size());
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw OpenADPError("Decryption failed");
    }
    plaintext.resize(len);
    
    // Set tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), const_cast<uint8_t*>(tag.data())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw OpenADPError("Failed to set authentication tag");
    }
    
    // Finalize
    Bytes final_block(16);
    int ret = EVP_DecryptFinal_ex(ctx, final_block.data(), &len);
    EVP_CIPHER_CTX_free(ctx);
    
    if (ret != 1) {
        throw OpenADPError("Authentication tag verification failed");
    }
    
    if (len > 0) {
        plaintext.insert(plaintext.end(), final_block.begin(), final_block.begin() + len);
    }
    
    return plaintext;
}

Bytes aes_gcm_decrypt(const Bytes& ciphertext, const Bytes& tag, const Bytes& nonce, 
                     const Bytes& key) {
    return aes_gcm_decrypt(ciphertext, tag, nonce, key, Bytes{});
}

// HKDF key derivation
Bytes hkdf_derive(const Bytes& input_key, const Bytes& salt, const Bytes& info, size_t output_length) {
    if (output_length == 0) {
        throw OpenADPError("HKDF output length must be greater than 0");
    }
    
    if (output_length > 8160) { // RFC 5869 limit: 255 * hash_length (255 * 32 for SHA-256)
        throw OpenADPError("HKDF output length exceeds maximum allowed");
    }
    
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!ctx) {
        throw OpenADPError("Failed to create HKDF context");
    }
    
    if (EVP_PKEY_derive_init(ctx) != 1) {
        EVP_PKEY_CTX_free(ctx);
        throw OpenADPError("Failed to initialize HKDF");
    }
    
    if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) != 1) {
        EVP_PKEY_CTX_free(ctx);
        throw OpenADPError("Failed to set HKDF hash function");
    }
    
    // Handle empty input key material - OpenSSL doesn't accept zero-length keys
    // Use single zero byte as workaround (standard approach for Noise Protocol implementations)
    Bytes effective_key = input_key.empty() ? Bytes(1, 0) : input_key;
    
    if (EVP_PKEY_CTX_set1_hkdf_key(ctx, effective_key.data(), effective_key.size()) != 1) {
        EVP_PKEY_CTX_free(ctx);
        throw OpenADPError("Failed to set HKDF input key");
    }
    
    if (!salt.empty()) {
        if (EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt.data(), salt.size()) != 1) {
            EVP_PKEY_CTX_free(ctx);
            throw OpenADPError("Failed to set HKDF salt");
        }
    }
    
    if (!info.empty()) {
        if (EVP_PKEY_CTX_add1_hkdf_info(ctx, info.data(), info.size()) != 1) {
            EVP_PKEY_CTX_free(ctx);
            throw OpenADPError("Failed to set HKDF info");
        }
    }
    
    Bytes output(output_length);
    size_t out_len = output_length;
    
    if (EVP_PKEY_derive(ctx, output.data(), &out_len) != 1) {
        EVP_PKEY_CTX_free(ctx);
        throw OpenADPError("HKDF derivation failed");
    }
    
    EVP_PKEY_CTX_free(ctx);
    output.resize(out_len);
    
    return output;
}

// HKDF-Expand-Only key derivation (for Noise Split operation)
Bytes hkdf_expand_only(const Bytes& prk, const Bytes& info, size_t output_length) {
    if (output_length == 0) {
        throw OpenADPError("HKDF output length must be greater than 0");
    }
    
    if (output_length > 8160) { // RFC 5869 limit: 255 * hash_length (255 * 32 for SHA-256)
        throw OpenADPError("HKDF output length exceeds maximum allowed");
    }
    
    if (prk.size() < 32) { // For SHA-256, PRK should be at least 32 bytes
        throw OpenADPError("PRK too short for HKDF-Expand");
    }
    
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!ctx) {
        throw OpenADPError("Failed to create HKDF context");
    }
    
    if (EVP_PKEY_derive_init(ctx) != 1) {
        EVP_PKEY_CTX_free(ctx);
        throw OpenADPError("Failed to initialize HKDF");
    }
    
    // Set HKDF mode to expand-only
    if (EVP_PKEY_CTX_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) != 1) {
        EVP_PKEY_CTX_free(ctx);
        throw OpenADPError("Failed to set HKDF expand-only mode");
    }
    
    if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) != 1) {
        EVP_PKEY_CTX_free(ctx);
        throw OpenADPError("Failed to set HKDF hash function");
    }
    
    // Set PRK as the key for expand-only mode
    if (EVP_PKEY_CTX_set1_hkdf_key(ctx, prk.data(), prk.size()) != 1) {
        EVP_PKEY_CTX_free(ctx);
        throw OpenADPError("Failed to set HKDF PRK");
    }
    
    if (!info.empty()) {
        if (EVP_PKEY_CTX_add1_hkdf_info(ctx, info.data(), info.size()) != 1) {
            EVP_PKEY_CTX_free(ctx);
            throw OpenADPError("Failed to set HKDF info");
        }
    }
    
    Bytes output(output_length);
    size_t out_len = output_length;
    
    if (EVP_PKEY_derive(ctx, output.data(), &out_len) != 1) {
        EVP_PKEY_CTX_free(ctx);
        throw OpenADPError("HKDF expand-only derivation failed");
    }
    
    EVP_PKEY_CTX_free(ctx);
    output.resize(out_len);
    
    return output;
}

// HMAC-SHA256 function (supports empty data)
Bytes hmac_sha256(const Bytes& key, const Bytes& data) {
    if (key.empty()) {
        throw OpenADPError("HMAC key cannot be empty");
    }
    
    unsigned char* result = nullptr;
    unsigned int result_len = 0;
    
    // Use HMAC with SHA256
    result = HMAC(EVP_sha256(), 
                  key.data(), static_cast<int>(key.size()),
                  data.empty() ? nullptr : data.data(), data.size(),
                  nullptr, &result_len);
    
    if (!result) {
        throw OpenADPError("HMAC-SHA256 computation failed");
    }
    
    // Copy result to Bytes vector
    Bytes output(result, result + result_len);
    
    return output;
}

// Global H function (matches Go H function exactly)
Point4D H(const Bytes& uid, const Bytes& did, const Bytes& bid, const Bytes& pin) {
    return Ed25519::hash_to_point(uid, did, bid, pin);
}

// Point validation (matches Go IsValidPoint)
bool is_valid_point(const Point4D& point) {
    return Ed25519::is_valid_point(point);
}

// Multiply point by 8 for cofactor clearing (matches Go pointMul8)
Point4D point_mul8(const Point4D& point) {
    return Ed25519::scalar_mult("8", point);
}

// Point scalar multiplication (matches Go PointMul)
Point4D point_mul(const std::string& scalar_hex, const Point4D& point) {
    return Ed25519::scalar_mult(scalar_hex, point);
}

// Point addition (matches Go point addition)
Point4D point_add(const Point4D& p1, const Point4D& p2) {
    return Ed25519::point_add(p1, p2);
}

// Point compression (matches Go PointCompress)
Bytes point_compress(const Point4D& point) {
    return Ed25519::compress(point);
}

// Point decompression (matches Go PointDecompress)
Point4D point_decompress(const Bytes& data) {
    return Ed25519::decompress(data);
}

// Convert Point4D to Point2D string representation (matches Go Unexpand)
std::string unexpand(const Point4D& point) {
    // Convert extended coordinates to affine coordinates
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* x = hex_to_bn(point.x);
    BIGNUM* y = hex_to_bn(point.y);
    BIGNUM* z = hex_to_bn(point.z);
    BIGNUM* z_inv = BN_new();
    BIGNUM* prime = get_ed25519_prime();
    
    // Compute z^-1
    BN_mod_inverse(z_inv, z, prime, ctx);
    
    // Compute affine coordinates: x_affine = x/z, y_affine = y/z
    BN_mod_mul(x, x, z_inv, prime, ctx);
    BN_mod_mul(y, y, z_inv, prime, ctx);
    
    std::string result = "(" + bn_to_hex(x) + "," + bn_to_hex(y) + ")";
    
    BN_free(x);
    BN_free(y);
    BN_free(z);
    BN_free(z_inv);
    BN_CTX_free(ctx);
    
    return result;
}

// Convert Point2D string representation to Point4D (matches Go Expand)
Point4D expand(const std::string& point_2d) {
    return Ed25519::expand_from_string(point_2d);
}

// Ed25519 static method implementations

Point4D Ed25519::H(const Bytes& uid, const Bytes& did, const Bytes& bid, const Bytes& pin) {
    return hash_to_point(uid, did, bid, pin);
}

Point4D Ed25519::expand_from_string(const std::string& point_2d) {
    // Parse "(x,y)" format
    if (point_2d.size() < 5 || point_2d[0] != '(' || point_2d.back() != ')') {
        throw OpenADPError("Invalid point format");
    }
    
    std::string inner = point_2d.substr(1, point_2d.size() - 2);
    size_t comma_pos = inner.find(',');
    if (comma_pos == std::string::npos) {
        throw OpenADPError("Invalid point format - missing comma");
    }
    
    std::string x_hex = inner.substr(0, comma_pos);
    std::string y_hex = inner.substr(comma_pos + 1);
    
    // Create extended coordinates: (x, y, 1, x*y)
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* x = hex_to_bn(x_hex);
    BIGNUM* y = hex_to_bn(y_hex);
    BIGNUM* t = BN_new();
    BIGNUM* prime = get_ed25519_prime();
    
    BN_mod_mul(t, x, y, prime, ctx);
    
    Point4D result(x_hex, y_hex, "1", bn_to_hex(t));
    
    BN_free(x);
    BN_free(y);
    BN_free(t);
    BN_CTX_free(ctx);
    
    return result;
}

std::string Ed25519::unexpand_to_string(const Point4D& point) {
    // Convert extended coordinates to affine coordinates
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* x = hex_to_bn(point.x);
    BIGNUM* y = hex_to_bn(point.y);
    BIGNUM* z = hex_to_bn(point.z);
    BIGNUM* z_inv = BN_new();
    BIGNUM* prime = get_ed25519_prime();
    
    // Compute z^-1
    BN_mod_inverse(z_inv, z, prime, ctx);
    
    // Compute affine coordinates: x_affine = x/z, y_affine = y/z
    BN_mod_mul(x, x, z_inv, prime, ctx);
    BN_mod_mul(y, y, z_inv, prime, ctx);
    
    std::string result = "(" + bn_to_hex(x) + "," + bn_to_hex(y) + ")";
    
    BN_free(x);
    BN_free(y);
    BN_free(z);
    BN_free(z_inv);
    BN_CTX_free(ctx);
    
    return result;
}

// Cryptographically secure random byte generation using OpenSSL
Bytes random_bytes(size_t length) {
    if (length == 0) {
        return Bytes();
    }
    
    if (length > 1048576) { // 1MB limit for sanity
        throw OpenADPError("Random bytes request too large");
    }
    
    Bytes result(length);
    
    if (RAND_bytes(result.data(), static_cast<int>(length)) != 1) {
        throw OpenADPError("Failed to generate random bytes");
    }
    
    return result;
}

} // namespace crypto
} // namespace openadp 
