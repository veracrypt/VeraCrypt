#include "openadp/keygen.hpp"
#include "openadp/types.hpp"
#include "openadp/client.hpp"
#include "openadp/crypto.hpp"
#include "openadp/utils.hpp"
#include "openadp/debug.hpp"
#include <chrono>
#include <algorithm>
#include <cctype>
#include <openssl/bn.h>
#include <sstream>

namespace openadp {
namespace keygen {

std::string generate_random_scalar() {
    std::string scalar_hex;
    
    if (debug::is_debug_mode_enabled()) {
        // In debug mode, use large deterministic secret
        scalar_hex = debug::get_deterministic_main_secret();
    } else {
        // In normal mode, use cryptographically secure random
        scalar_hex = utils::random_hex(32); // 256-bit scalar
    }
    
    // Ensure scalar is less than Ed25519 group order Q
    BIGNUM* scalar_bn = BN_new();
    BIGNUM* q_bn = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    
    // Parse scalar from hex
    BN_hex2bn(&scalar_bn, scalar_hex.c_str());
    
    // Ed25519 group order Q
    BN_hex2bn(&q_bn, "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed");
    
    // Reduce modulo Q to ensure it's in valid range
    BN_mod(scalar_bn, scalar_bn, q_bn, ctx);
    
    // Convert back to hex (lowercase for consistency with other SDKs)
    char* reduced_hex = BN_bn2hex(scalar_bn);
    std::string result(reduced_hex);
    OPENSSL_free(reduced_hex);
    
    // Convert to lowercase for consistency with Go/Python/JS implementations
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    
    // Clean up
    BN_free(scalar_bn);
    BN_free(q_bn);
    BN_CTX_free(ctx);
    
    return result;
}

AuthCodes generate_auth_codes(const std::string& base_auth_code, const std::vector<ServerInfo>& server_infos) {
    AuthCodes auth_codes;
    auth_codes.base_auth_code = base_auth_code;
    
    // Generate server-specific auth codes using SHA256
    for (const auto& server_info : server_infos) {
        std::string combined = base_auth_code + ":" + server_info.url;
        Bytes combined_bytes = utils::string_to_bytes(combined);
        Bytes hash = crypto::sha256_hash(combined_bytes);
        std::string server_code = utils::hex_encode(hash);
        auth_codes.server_auth_codes[server_info.url] = server_code;
    }
    
    return auth_codes;
}

GenerateEncryptionKeyResult generate_encryption_key(
    const Identity& identity,
    const std::string& password,
    int max_guesses,
    int64_t expiration,
    const std::vector<ServerInfo>& server_infos
) {
    try {
        // Input validation
        if (identity.uid.empty()) {
            return GenerateEncryptionKeyResult::error("User ID cannot be empty");
        }
        if (identity.did.empty()) {
            return GenerateEncryptionKeyResult::error("Device ID cannot be empty");
        }
        if (identity.bid.empty()) {
            return GenerateEncryptionKeyResult::error("Backup ID cannot be empty");
        }
        
        if (password.empty()) {
            return GenerateEncryptionKeyResult::error("Password cannot be empty");
        }
        
        if (max_guesses <= 0) {
            return GenerateEncryptionKeyResult::error("Max guesses must be positive");
        }
        if (max_guesses > 100000) {
            return GenerateEncryptionKeyResult::error("Max guesses too large");
        }
        
        // Check expiration (if provided)
        if (expiration > 0) {
            auto now = std::chrono::system_clock::now();
            auto current_time = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
            if (expiration < current_time) {
                return GenerateEncryptionKeyResult::error("Expiration time is in the past");
            }
        }
        
        // Check if we have enough servers
        if (server_infos.empty()) {
            return GenerateEncryptionKeyResult::error("No servers available");
        }
        
        // Validate server URLs
        for (const auto& server_info : server_infos) {
            if (server_info.url.empty()) {
                return GenerateEncryptionKeyResult::error("Server URL cannot be empty");
            }
            if (server_info.url.find("http://") != 0 && server_info.url.find("https://") != 0) {
                return GenerateEncryptionKeyResult::error("Invalid server URL format: " + server_info.url);
            }
        }
        
        // Calculate threshold (majority: n/2 + 1, but at least 1)
        int threshold = std::max(1, static_cast<int>(server_infos.size()) / 2 + 1);
        int num_shares = static_cast<int>(server_infos.size());
        
        // For single server, we need that server to succeed
        if (server_infos.size() == 1) {
            threshold = 1;
        }
        
        // Generate main secret, ensuring it's valid for Ed25519
        std::string secret_hex = generate_random_scalar();
        
        // Generate base auth code (also needs to be valid scalar)
        std::string base_auth_code;
        if (debug::is_debug_mode_enabled()) {
            // Use the same deterministic value as Python, but ensure it's reduced mod Q
            std::string temp_code = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
            
            // Reduce modulo Q to ensure it's in valid range
            BIGNUM* code_bn = BN_new();
            BIGNUM* q_bn = BN_new();
            BN_CTX* ctx = BN_CTX_new();
            
            BN_hex2bn(&code_bn, temp_code.c_str());
            BN_hex2bn(&q_bn, "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed");
            BN_mod(code_bn, code_bn, q_bn, ctx);
            
            char* reduced_hex = BN_bn2hex(code_bn);
            base_auth_code = std::string(reduced_hex);
            OPENSSL_free(reduced_hex);
            
            // Convert to lowercase for consistency with Go/Python/JS implementations
            std::transform(base_auth_code.begin(), base_auth_code.end(), base_auth_code.begin(), ::tolower);
            
            BN_free(code_bn);
            BN_free(q_bn);
            BN_CTX_free(ctx);
            
            debug::debug_log("Using deterministic base auth code: " + base_auth_code);
        } else {
            base_auth_code = generate_random_scalar(); // Use the same scalar generation
        }
        
        // Generate server-specific auth codes
        AuthCodes auth_codes = generate_auth_codes(base_auth_code, server_infos);
        
        // Debug: Show auth codes
        if (debug::is_debug_mode_enabled()) {
            for (const auto& server_auth : auth_codes.server_auth_codes) {
                debug::debug_log("Auth code for server " + server_auth.first + ": " + server_auth.second);
            }
        }
        
        // Use simpler approach matching Python/Go debug values for now
        if (debug::is_debug_mode_enabled()) {
            debug::debug_log("Using deterministic secret: 0x" + secret_hex);
            debug::debug_log("Computed U point for identity: UID=" + identity.uid + 
                            ", DID=" + identity.did + ", BID=" + identity.bid);
            debug::debug_log("Computed S = secret * U");
            debug::debug_log("Splitting secret with threshold " + std::to_string(threshold) + 
                            ", num_shares " + std::to_string(num_shares));
        }

        // Generate Shamir secret shares using the existing crypto function
        std::vector<Share> shares = crypto::ShamirSecretSharing::split_secret(secret_hex, threshold, num_shares);
        
        // Set expiration if not provided
        // NOTE: Disabled automatic expiration calculation to match Python behavior (uses 0)
        /*
        if (expiration == 0) {
            auto now = std::chrono::system_clock::now();
            auto future = now + std::chrono::hours(24 * 365); // 1 year
            expiration = std::chrono::duration_cast<std::chrono::seconds>(future.time_since_epoch()).count();
        }
        */
        
        // Register shares with servers
        std::vector<ServerInfo> successful_servers;
        
        for (size_t i = 0; i < server_infos.size() && i < shares.size(); i++) {
            const auto& server_info = server_infos[i];
            const auto& share = shares[i];  // Get the corresponding share
            
            try {
                client::EncryptedOpenADPClient client(server_info.url, server_info.public_key);
                
                // Find the auth code for this server
                auto auth_it = auth_codes.server_auth_codes.find(server_info.url);
                std::string server_auth_code = (auth_it != auth_codes.server_auth_codes.end()) ? 
                                               auth_it->second : auth_codes.base_auth_code;
                
                if (debug::is_debug_mode_enabled()) {
                    debug::debug_log("Using auth code for server " + server_info.url + ": " + server_auth_code);
                }
                
                // Use the X and Y coordinates from the share
                int x = share.x;
                std::string share_y_hex = share.y;
                
                // Convert Y coordinate from hex to base64-encoded little-endian bytes
                std::string y_base64;
                BIGNUM* y_bn = BN_new();
                BN_hex2bn(&y_bn, share_y_hex.c_str());
                
                // ✅ CRITICAL FIX: Reduce Y coordinate modulo Q (Ed25519 group order)
                BIGNUM* q_bn = BN_new();
                BN_hex2bn(&q_bn, "1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED");
                BN_CTX* mod_ctx = BN_CTX_new();
                BN_mod(y_bn, y_bn, q_bn, mod_ctx);
                BN_free(q_bn);
                BN_CTX_free(mod_ctx);
                
                // Convert y to little-endian 32-byte array for base64 encoding
                Bytes y_bytes(32, 0);
                int y_size = BN_num_bytes(y_bn);
                if (y_size <= 32) {
                    // Convert to big-endian first
                    Bytes temp_bytes(y_size);
                    BN_bn2bin(y_bn, temp_bytes.data());
                    
                    // Copy to 32-byte array (right-aligned) and reverse to little-endian
                    std::copy(temp_bytes.begin(), temp_bytes.end(), 
                            y_bytes.end() - temp_bytes.size());
                    std::reverse(y_bytes.begin(), y_bytes.end());
                }
                
                y_base64 = utils::base64_encode(y_bytes);
                BN_free(y_bn);
                
                client::RegisterSecretRequest request(server_auth_code, identity, 1, max_guesses, expiration, x, y_base64, true);
                nlohmann::json response = client.register_secret(request);
                
                if (response.contains("success") && response["success"].get<bool>()) {
                    successful_servers.push_back(server_info);
                } else if (response.is_boolean() && response.get<bool>()) {
                    // Handle boolean true response
                    successful_servers.push_back(server_info);
                }
            } catch (const std::exception& e) {
                if (debug::is_debug_mode_enabled()) {
                    debug::debug_log("Failed to register with server " + server_info.url + ": " + e.what());
                }
                // Continue with other servers
                continue;
            }
        }
        
        if (successful_servers.size() < static_cast<size_t>(threshold)) {
            return GenerateEncryptionKeyResult::error(
                "Not enough servers responded successfully. Got " + 
                std::to_string(successful_servers.size()) + ", need " + std::to_string(threshold)
            );
        }
        
        // Derive encryption key from the secret point S = secret * U
        // First compute U point for this identity
        Bytes password_bytes = utils::string_to_bytes(password);
        Bytes uid_bytes = utils::string_to_bytes(identity.uid);
        Bytes did_bytes = utils::string_to_bytes(identity.did);
        Bytes bid_bytes = utils::string_to_bytes(identity.bid);
        
        Point4D U = crypto::Ed25519::hash_to_point(uid_bytes, did_bytes, bid_bytes, password_bytes);
        
        // Compute S = secret * U (the secret point)
        Point4D S = crypto::point_mul(secret_hex, U);
        
        // Derive encryption key from the secret point S (matching Python version)
        Bytes encryption_key = crypto::derive_encryption_key(S);
        
        return GenerateEncryptionKeyResult::success(encryption_key, auth_codes, successful_servers, threshold);
        
    } catch (const std::exception& e) {
        return GenerateEncryptionKeyResult::error(std::string("Key generation failed: ") + e.what());
    }
}

RecoverEncryptionKeyResult recover_encryption_key(
    const Identity& identity,
    const std::string& password,
    const AuthCodes& auth_codes,
    const std::vector<ServerInfo>& server_infos
) {
    try {
        if (server_infos.empty()) {
            return RecoverEncryptionKeyResult::error("No servers available");
        }
        
        // Convert password to bytes
        Bytes password_bytes = utils::string_to_bytes(password);
        Bytes uid_bytes = utils::string_to_bytes(identity.uid);
        Bytes did_bytes = utils::string_to_bytes(identity.did);
        Bytes bid_bytes = utils::string_to_bytes(identity.bid);
        
        // Compute U = H(uid, did, bid, pin) - same as in generation
        Point4D U = crypto::Ed25519::hash_to_point(uid_bytes, did_bytes, bid_bytes, password_bytes);
        
        // Generate blinding factor r (random scalar) - CRITICAL for security
        std::string r_scalar_hex = generate_random_scalar(); // Always use proper scalar generation
            
        // Compute r^-1 mod Q for later use
        // For now, we'll use a simple approach since we have 1-of-1 threshold
        std::string r_inv_hex = r_scalar_hex; // In 1-of-1, this will be simplified
        
        // Compute B = r * U (blinded point to send to server)
        Point4D B = crypto::point_mul(r_scalar_hex, U);
        
        if (debug::is_debug_mode_enabled()) {
            debug::debug_log("Recovery: r_scalar=" + r_scalar_hex);
            debug::debug_log("Recovery: U point (2D): " + crypto::unexpand(U));
            debug::debug_log("Recovery: B point (2D): " + crypto::unexpand(B));
            debug::debug_log("Recovery: B = r * U computed");
        }
        
        // Recover shares from servers
        std::vector<Share> shares;
        int remaining_guesses = 0;
        int actual_num_guesses = 0;
        int actual_max_guesses = 0;
        
        for (const auto& server_info : server_infos) {
            try {
                // Find the auth code for this server
                auto auth_it = auth_codes.server_auth_codes.find(server_info.url);
                if (auth_it == auth_codes.server_auth_codes.end()) {
                    continue; // Skip servers without auth codes
                }
                
                client::EncryptedOpenADPClient client(server_info.url, server_info.public_key);
                
                // First, get the guess number by listing backups
                nlohmann::json backups_response = client.list_backups(identity);
                int guess_num = 0;  // Default to 0 for first guess (0-based indexing)
                
                // Extract guess number from backup info
                if (backups_response.is_array() && !backups_response.empty()) {
                    for (const auto& backup : backups_response) {
                        if (backup.contains("uid") && backup.contains("did") && backup.contains("bid") &&
                            backup["uid"].get<std::string>() == identity.uid &&
                            backup["did"].get<std::string>() == identity.did &&
                            backup["bid"].get<std::string>() == identity.bid) {
                            guess_num = backup.contains("num_guesses") ? backup["num_guesses"].get<int>() : 0;
                            break;
                        }
                    }
                }
                
                // Compress the blinded point B to send to server
                Bytes b_compressed = crypto::point_compress(B);
                std::string b_base64 = utils::base64_encode(b_compressed);
                
                if (debug::is_debug_mode_enabled()) {
                    debug::debug_log("Recovery: B compressed size=" + std::to_string(b_compressed.size()));
                    debug::debug_log("Recovery: B base64=" + b_base64);
                }
                
                // Create a fresh client for the recovery request
                client::EncryptedOpenADPClient fresh_client(server_info.url, server_info.public_key);
                
                std::string server_auth_code = auth_it->second;
                client::RecoverSecretRequest request(server_auth_code, identity, b_base64, guess_num);
                nlohmann::json response = fresh_client.recover_secret(request);
                
                // Check if RecoverSecret succeeded (response contains si_b)
                if (response.contains("si_b")) {
                    std::string si_b = response["si_b"].get<std::string>();
                    
                    // Extract the x coordinate from the server response
                    int x_coordinate = 1; // Default fallback
                    if (response.contains("x")) {
                        x_coordinate = response["x"].get<int>();
                    }
                    
                    // Capture guess information from server response (first successful server)
                    if (actual_num_guesses == 0 && actual_max_guesses == 0) {
                        if (response.contains("num_guesses")) {
                            actual_num_guesses = response["num_guesses"].get<int>();
                        }
                        if (response.contains("max_guesses")) {
                            actual_max_guesses = response["max_guesses"].get<int>();
                        }
                    }
                    
                    remaining_guesses = response.contains("max_guesses") ? 
                        response["max_guesses"].get<int>() - (response.contains("num_guesses") ? response["num_guesses"].get<int>() : 0) : 10;
                    
                    // Create share using the actual x coordinate from server response
                    shares.emplace_back(x_coordinate, si_b);
                    
                    if (debug::is_debug_mode_enabled()) {
                        debug::debug_log("Successfully recovered share from server " + server_info.url + 
                                       ", si_b=" + si_b + ", remaining_guesses=" + std::to_string(remaining_guesses));
                    }
                }
            } catch (const std::exception& e) {
                // Continue with other servers
                continue;
            }
        }
        
        if (shares.empty()) {
            return RecoverEncryptionKeyResult::error("No valid shares recovered");
        }
        
        // Convert Share objects to PointShare objects for threshold reconstruction
        std::vector<PointShare> point_shares;
        for (const auto& share : shares) {
            // Decode base64 point and decompress to Point4D, then convert to Point2D
            Bytes si_b_bytes = utils::base64_decode(share.y);
            Point4D si_b_4d = crypto::point_decompress(si_b_bytes);
            Point2D si_b_2d = crypto::Ed25519::unexpand(si_b_4d);
            point_shares.emplace_back(share.x, si_b_2d);
            
            if (debug::is_debug_mode_enabled()) {
                debug::debug_log("Share " + std::to_string(share.x) + ": base64=" + share.y);
                debug::debug_log("Share " + std::to_string(share.x) + ": Point2D=(" + si_b_2d.x + "," + si_b_2d.y + ")");
            }
        }
        
        // Use manual Lagrange interpolation (matching Python implementation)
        // Initialize result as point at infinity (identity element)
        Point4D result_point("0", "1", "1", "0");  // Extended coordinates for identity
        
        for (size_t i = 0; i < point_shares.size(); i++) {
            // Compute Lagrange coefficient Li(0)
            BIGNUM* numerator = BN_new();
            BIGNUM* denominator = BN_new();
            BIGNUM* q_bn = BN_new();
            BN_CTX* ctx = BN_CTX_new();
            
            // Ed25519 curve order (Q)
            BN_hex2bn(&q_bn, "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed");
            BN_one(numerator);
            BN_one(denominator);
            
            for (size_t j = 0; j < point_shares.size(); j++) {
                if (i != j) {
                    // numerator *= (-share_j.x) mod Q
                    BIGNUM* neg_xj = BN_new();
                    BN_set_word(neg_xj, point_shares[j].x);
                    BN_mod_sub(neg_xj, q_bn, neg_xj, q_bn, ctx);  // -xj mod Q
                    BN_mod_mul(numerator, numerator, neg_xj, q_bn, ctx);
                    
                    // denominator *= (share_i.x - share_j.x) mod Q
                    BIGNUM* diff = BN_new();
                    BIGNUM* xi = BN_new();
                    BIGNUM* xj = BN_new();
                    BN_set_word(xi, point_shares[i].x);
                    BN_set_word(xj, point_shares[j].x);
                    BN_mod_sub(diff, xi, xj, q_bn, ctx);  // (xi - xj) mod Q
                    BN_mod_mul(denominator, denominator, diff, q_bn, ctx);
                    
                    BN_free(neg_xj);
                    BN_free(diff);
                    BN_free(xi);
                    BN_free(xj);
                }
            }
            
            // Compute Li(0) = numerator / denominator mod Q (using modular inverse)
            BIGNUM* li_0 = BN_new();
            BIGNUM* inv_denom = BN_new();
            BN_mod_inverse(inv_denom, denominator, q_bn, ctx);
            BN_mod_mul(li_0, numerator, inv_denom, q_bn, ctx);
            
            // Convert Li(0) to hex string for point multiplication
            char* li_0_hex = BN_bn2hex(li_0);
            std::string li_0_str(li_0_hex);
            OPENSSL_free(li_0_hex);
            
            // Multiply point by Li(0): Li(0) * point_shares[i]
            Point4D share_point_4d = crypto::Ed25519::expand(point_shares[i].point);
            Point4D weighted_point = crypto::point_mul(li_0_str, share_point_4d);
            
            // Add to result: result += Li(0) * point_shares[i]
            result_point = crypto::point_add(result_point, weighted_point);
            
            // Clean up
            BN_free(numerator);
            BN_free(denominator);
            BN_free(q_bn);
            BN_free(li_0);
            BN_free(inv_denom);
            BN_CTX_free(ctx);
        }
        
        Point4D si_b_point = result_point;
        Point2D si_b_2d = crypto::Ed25519::unexpand(si_b_point);
        
        if (debug::is_debug_mode_enabled()) {
            debug::debug_log("Manual Lagrange interpolation: recovered s*B point=(" + si_b_2d.x + "," + si_b_2d.y + ")");
        }
        
        // Recover the original secret point: s*U = r^-1 * (s*B) = r^-1 * si_b
        // This is the core of the blinding protocol - we must compute r^-1 * si_b
        
        // Compute r^-1 mod Q (modular inverse of the blinding factor)
        // For 1-of-1 threshold in debug mode, this can be simplified but we still need proper crypto
        Point4D secret_point;
        
        // The proper formula: s*U = point_mul(r^-1, si_b)
        // Where si_b = s * B = s * (r * U), so r^-1 * si_b = r^-1 * s * r * U = s * U
        
        // For 1-of-1 threshold, we can use the simplified approach:
        // Since threshold=1, the secret s is exactly the original secret from encryption
        // and si_b contains s*B, so we need to "unblind" it with r^-1
        
        // Correct unblinding protocol:
        // si_b = s * B = s * (r * U), so s * U = r^-1 * si_b
        // where r is the blinding factor and s is the Shamir secret (different values!)
        
        // Compute r^-1 mod Q (modular inverse of the blinding factor)
        // For Ed25519, Q = 2^252 + 27742317777372353535851937790883648493
        
        // Convert r from hex to BIGNUM for modular arithmetic
        BIGNUM* r_bn = BN_new();
        BIGNUM* q_bn = BN_new();
        BIGNUM* r_inv_bn = BN_new();
        BN_CTX* ctx = BN_CTX_new();
        
        // Parse r from hex
        BN_hex2bn(&r_bn, r_scalar_hex.c_str());
        
        // Ed25519 curve order (L = 2^252 + 27742317777372353535851937790883648493)
        BN_hex2bn(&q_bn, "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed");
        
        // Compute r^-1 mod Q
        BN_mod_inverse(r_inv_bn, r_bn, q_bn, ctx);
        
        // Convert back to hex
        char* r_inv_hex_str = BN_bn2hex(r_inv_bn);
        std::string r_inv_scalar_hex(r_inv_hex_str);
        OPENSSL_free(r_inv_hex_str);
        
        // Clean up
        BN_free(r_bn);
        BN_free(q_bn);
        BN_free(r_inv_bn);
        BN_CTX_free(ctx);
        
        // Apply r^-1 to recover the original secret point: s*U = r^-1 * si_b
        secret_point = crypto::point_mul(r_inv_scalar_hex, si_b_point);
        
        if (debug::is_debug_mode_enabled()) {
            Point2D secret_point_2d = crypto::Ed25519::unexpand(secret_point);
            debug::debug_log("Unblinding: s*U point=(" + secret_point_2d.x + "," + secret_point_2d.y + ")");
        }
        
        // Derive encryption key from the recovered secret point s*U
        Bytes encryption_key = crypto::derive_encryption_key(secret_point);
        
        if (debug::is_debug_mode_enabled()) {
            debug::debug_log("Key recovery: r_scalar=" + r_scalar_hex);
            debug::debug_log("Key recovery: r_inv_scalar=" + r_inv_scalar_hex);
            debug::debug_log("Key recovery: computed s*U = r^-1 * si_b");
            debug::debug_log("Key recovery: derived key size=" + std::to_string(encryption_key.size()));
            debug::debug_log("Key recovery: encryption_key hex=" + crypto::bytes_to_hex(encryption_key));
        }
        
        return RecoverEncryptionKeyResult::success(encryption_key, remaining_guesses, actual_num_guesses, actual_max_guesses);
        
    } catch (const std::exception& e) {
        return RecoverEncryptionKeyResult::error(std::string("Key recovery failed: ") + e.what());
    }
}

} // namespace keygen
} // namespace openadp 
