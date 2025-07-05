#include "openadp/noise.hpp"
#include "openadp/types.hpp"
#include "openadp/utils.hpp"
#include "openadp/crypto.hpp"
#include "openadp/debug.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <cstring>

namespace openadp {
namespace noise {

// Forward declarations
Bytes perform_dh(const Bytes& private_key, const Bytes& public_key);
std::pair<Bytes, Bytes> hkdf_2(const Bytes& ck, const Bytes& input_key_material);
Bytes encrypt_and_hash(const Bytes& plaintext, Bytes& h, const Bytes& k, uint64_t& nonce);
Bytes decrypt_and_hash(const Bytes& ciphertext, Bytes& h, const Bytes& k, uint64_t& nonce);
Bytes generate_keypair_private();
Bytes derive_public_key(const Bytes& private_key);
void mix_hash(Bytes& h, const Bytes& data);
void mix_key(Bytes& ck, Bytes& k, const Bytes& input_key_material);

// Noise protocol constants
const size_t KEY_SIZE = 32;
const size_t HASH_SIZE = 32;
const size_t MAC_SIZE = 16;

struct NoiseState::Impl {
    // Noise state
    Bytes s;  // Local static private key
    Bytes e;  // Local ephemeral private key
    Bytes rs; // Remote static public key
    Bytes re; // Remote ephemeral public key
    
    // Symmetric state
    Bytes ck; // Chaining key
    Bytes h;  // Hash
    Bytes k;  // Encryption key
    
    // Transport keys
    Bytes send_key;
    Bytes recv_key;
    uint64_t send_nonce;
    uint64_t recv_nonce;
    
    bool handshake_finished;
    bool is_initiator;
    
    Impl() : send_nonce(0), recv_nonce(0), handshake_finished(false), is_initiator(false) {
        // Initialize with Noise_NK protocol name (matching JS/Python)
        std::string protocol_name = "Noise_NK_25519_AESGCM_SHA256";
        Bytes protocol_bytes = utils::string_to_bytes(protocol_name);
        
        if (protocol_bytes.size() <= 32) {
            h = protocol_bytes;
            h.resize(32, 0);
        } else {
            h = crypto::sha256_hash(protocol_bytes);
        }
        
        ck = h;
        k.clear(); // No key initially
    }
};

NoiseState::NoiseState() : pimpl_(std::make_unique<Impl>()) {}

NoiseState::~NoiseState() = default;

void NoiseState::initialize_handshake(const Bytes& remote_public_key) {
    // Initialize as initiator (client)
    pimpl_->is_initiator = true;
    pimpl_->rs = remote_public_key;
    
    // Mix prologue (empty) into hash - this is required by Noise protocol
    Bytes prologue; // Empty prologue
    mix_hash(pimpl_->h, prologue);
    
    // Mix remote static public key into hash (NK pattern)
    mix_hash(pimpl_->h, remote_public_key);
}

void NoiseState::initialize_responder(const Bytes& local_private_key) {
    // Initialize as responder (server)
    pimpl_->is_initiator = false;
    pimpl_->s = local_private_key;
    
    // Mix prologue (empty) into hash - this is required by Noise protocol
    Bytes prologue; // Empty prologue
    mix_hash(pimpl_->h, prologue);
    
    // Mix local static public key into hash (NK pattern)
    Bytes local_public = derive_public_key(local_private_key);
    mix_hash(pimpl_->h, local_public);
}

Bytes NoiseState::write_message(const Bytes& payload) {
    if (pimpl_->handshake_finished) {
        throw OpenADPError("Handshake already finished");
    }
    
    if (pimpl_->is_initiator) {
        // Initiator message: -> e, es
        
        // Generate ephemeral keypair
        pimpl_->e = generate_keypair_private();
        Bytes e_pub = derive_public_key(pimpl_->e);
        
        // Mix ephemeral public key
        mix_hash(pimpl_->h, e_pub);
        
        // Perform DH: es = DH(e, rs)
        Bytes dh = perform_dh(pimpl_->e, pimpl_->rs);
        mix_key(pimpl_->ck, pimpl_->k, dh);
        
        // Encrypt payload (always encrypt if we have a key, even for empty payload)
        uint64_t nonce = 0;
        Bytes ciphertext = encrypt_and_hash(payload, pimpl_->h, pimpl_->k, nonce);
        
        // Build message: e + encrypted_payload
        Bytes message = e_pub;
        message.insert(message.end(), ciphertext.begin(), ciphertext.end());
        
        return message;
        
    } else {
        // Responder message: <- e, ee
        
        // Generate ephemeral keypair
        pimpl_->e = generate_keypair_private();
        Bytes e_pub = derive_public_key(pimpl_->e);
        
        // Mix ephemeral public key
        mix_hash(pimpl_->h, e_pub);
        
        // Perform DH: ee = DH(e, re)
        Bytes dh = perform_dh(pimpl_->e, pimpl_->re);
        mix_key(pimpl_->ck, pimpl_->k, dh);
        
        // Encrypt payload (always encrypt if we have a key, even for empty payload)
        uint64_t nonce = 0;
        Bytes ciphertext = encrypt_and_hash(payload, pimpl_->h, pimpl_->k, nonce);
        
        // Split transport keys
        openadp::debug::debug_log("🔑 RESPONDER: About to call hkdf_2 for transport keys");
        openadp::debug::debug_log("  - chaining key: " + openadp::crypto::bytes_to_hex(pimpl_->ck));
        auto transport_keys = hkdf_2(pimpl_->ck, Bytes());
        pimpl_->recv_key = transport_keys.first;   // Responder receives with k1 (initiator->responder)
        pimpl_->send_key = transport_keys.second;  // Responder sends with k2 (responder->initiator)
        openadp::debug::debug_log("🔑 RESPONDER: Transport key assignment complete");
        openadp::debug::debug_log("  - recv_key: " + openadp::crypto::bytes_to_hex(pimpl_->recv_key));
        openadp::debug::debug_log("  - send_key: " + openadp::crypto::bytes_to_hex(pimpl_->send_key));
        pimpl_->handshake_finished = true;
        
        // Build message: e + encrypted_payload
        Bytes message = e_pub;
        message.insert(message.end(), ciphertext.begin(), ciphertext.end());
        
        return message;
    }
}

Bytes NoiseState::write_message() {
    return write_message(Bytes{});
}

Bytes NoiseState::read_message(const Bytes& message) {
    openadp::debug::debug_log("🔍 READ_MESSAGE CALLED - message size: " + std::to_string(message.size()));
    if (message.size() < 32) {
        throw OpenADPError("Message too short");
    }
    
    if (pimpl_->is_initiator) {
        // Initiator reading responder message: <- e, ee
        
        // Extract ephemeral public key
        pimpl_->re = Bytes(message.begin(), message.begin() + 32);
        
        // Mix ephemeral public key
        mix_hash(pimpl_->h, pimpl_->re);
        
        // Perform DH: ee = DH(e, re)
        Bytes dh = perform_dh(pimpl_->e, pimpl_->re);
        mix_key(pimpl_->ck, pimpl_->k, dh);
        
        // Decrypt payload
        Bytes payload;
        if (message.size() > 32) {
            Bytes ciphertext(message.begin() + 32, message.end());
            uint64_t nonce = 0;
            payload = decrypt_and_hash(ciphertext, pimpl_->h, pimpl_->k, nonce);
        } else {
            // No ciphertext, but we still need to process an empty payload
            uint64_t nonce = 0;
            payload = decrypt_and_hash(Bytes{}, pimpl_->h, pimpl_->k, nonce);
        }
        
        // Split transport keys
        openadp::debug::debug_log("🔑 INITIATOR: About to call hkdf_2 for transport keys");
        openadp::debug::debug_log("  - chaining key: " + openadp::crypto::bytes_to_hex(pimpl_->ck));
        auto transport_keys = hkdf_2(pimpl_->ck, Bytes());
        pimpl_->send_key = transport_keys.first;
        pimpl_->recv_key = transport_keys.second;
        openadp::debug::debug_log("🔑 INITIATOR: Transport key assignment complete");
        openadp::debug::debug_log("  - send_key: " + openadp::crypto::bytes_to_hex(pimpl_->send_key));
        openadp::debug::debug_log("  - recv_key: " + openadp::crypto::bytes_to_hex(pimpl_->recv_key));
        pimpl_->handshake_finished = true;
        
        return payload;
        
    } else {
        // Responder reading initiator message: -> e, es
        
        // Extract ephemeral public key
        pimpl_->re = Bytes(message.begin(), message.begin() + 32);
        
        // Mix ephemeral public key
        mix_hash(pimpl_->h, pimpl_->re);
        
        // Perform DH: es = DH(s, re)
        Bytes dh = perform_dh(pimpl_->s, pimpl_->re);
        mix_key(pimpl_->ck, pimpl_->k, dh);
        
        // Decrypt payload
        Bytes payload;
        if (message.size() > 32) {
            Bytes ciphertext(message.begin() + 32, message.end());
            uint64_t nonce = 0;
            payload = decrypt_and_hash(ciphertext, pimpl_->h, pimpl_->k, nonce);
        } else {
            // No ciphertext, but we still need to process an empty payload
            uint64_t nonce = 0;
            payload = decrypt_and_hash(Bytes{}, pimpl_->h, pimpl_->k, nonce);
        }
        
        return payload;
    }
}

bool NoiseState::handshake_finished() const {
    return pimpl_->handshake_finished;
}

Bytes NoiseState::encrypt(const Bytes& plaintext) {
    if (!pimpl_->handshake_finished) {
        throw OpenADPError("Handshake not finished");
    }
    
    openadp::debug::debug_log("🔐 TRANSPORT ENCRYPT");
    openadp::debug::debug_log("  - plaintext length: " + std::to_string(plaintext.size()));
    openadp::debug::debug_log("  - plaintext hex: " + openadp::crypto::bytes_to_hex(plaintext));
    openadp::debug::debug_log("  - send key: " + openadp::crypto::bytes_to_hex(pimpl_->send_key));
    openadp::debug::debug_log("  - send nonce: " + std::to_string(pimpl_->send_nonce));
    
    // Create nonce (12 bytes: 4 zeros + 8-byte counter big-endian)
    Bytes nonce(12, 0);
    nonce[4] = (pimpl_->send_nonce >> 56) & 0xFF;
    nonce[5] = (pimpl_->send_nonce >> 48) & 0xFF;
    nonce[6] = (pimpl_->send_nonce >> 40) & 0xFF;
    nonce[7] = (pimpl_->send_nonce >> 32) & 0xFF;
    nonce[8] = (pimpl_->send_nonce >> 24) & 0xFF;
    nonce[9] = (pimpl_->send_nonce >> 16) & 0xFF;
    nonce[10] = (pimpl_->send_nonce >> 8) & 0xFF;
    nonce[11] = pimpl_->send_nonce & 0xFF;
    
    openadp::debug::debug_log("  - nonce (12 bytes): " + openadp::crypto::bytes_to_hex(nonce));
    
    // Encrypt with NO AAD (matching Python/Go)
    Bytes empty_aad; // Empty AAD for transport encryption
    openadp::debug::debug_log("  - AAD length: " + std::to_string(empty_aad.size()));
    openadp::debug::debug_log("  - AAD: " + openadp::crypto::bytes_to_hex(empty_aad));
    
    auto result = openadp::crypto::aes_gcm_encrypt(plaintext, pimpl_->send_key, nonce, empty_aad);
    
    // Combine ciphertext and tag (AES-GCM format)
    Bytes ciphertext = result.ciphertext;
    ciphertext.insert(ciphertext.end(), result.tag.begin(), result.tag.end());
    
    openadp::debug::debug_log("  - ciphertext length: " + std::to_string(result.ciphertext.size()));
    openadp::debug::debug_log("  - ciphertext hex: " + openadp::crypto::bytes_to_hex(result.ciphertext));
    openadp::debug::debug_log("  - tag length: " + std::to_string(result.tag.size()));
    openadp::debug::debug_log("  - tag hex: " + openadp::crypto::bytes_to_hex(result.tag));
    openadp::debug::debug_log("  - combined length: " + std::to_string(ciphertext.size()));
    openadp::debug::debug_log("  - combined hex: " + openadp::crypto::bytes_to_hex(ciphertext));
    
    pimpl_->send_nonce++;
    openadp::debug::debug_log("  - incremented send nonce to: " + std::to_string(pimpl_->send_nonce));
    
    return ciphertext;
}

Bytes NoiseState::decrypt(const Bytes& ciphertext) {
    if (!pimpl_->handshake_finished) {
        throw OpenADPError("Handshake not finished");
    }
    
    openadp::debug::debug_log("🔓 TRANSPORT DECRYPT");
    openadp::debug::debug_log("  - ciphertext length: " + std::to_string(ciphertext.size()));
    openadp::debug::debug_log("  - ciphertext hex: " + openadp::crypto::bytes_to_hex(ciphertext));
    openadp::debug::debug_log("  - recv key: " + openadp::crypto::bytes_to_hex(pimpl_->recv_key));
    openadp::debug::debug_log("  - recv nonce: " + std::to_string(pimpl_->recv_nonce));
    
    // Create nonce (12 bytes: 4 zeros + 8-byte counter big-endian)
    Bytes nonce(12, 0);
    nonce[4] = (pimpl_->recv_nonce >> 56) & 0xFF;
    nonce[5] = (pimpl_->recv_nonce >> 48) & 0xFF;
    nonce[6] = (pimpl_->recv_nonce >> 40) & 0xFF;
    nonce[7] = (pimpl_->recv_nonce >> 32) & 0xFF;
    nonce[8] = (pimpl_->recv_nonce >> 24) & 0xFF;
    nonce[9] = (pimpl_->recv_nonce >> 16) & 0xFF;
    nonce[10] = (pimpl_->recv_nonce >> 8) & 0xFF;
    nonce[11] = pimpl_->recv_nonce & 0xFF;
    
    openadp::debug::debug_log("  - nonce (12 bytes): " + openadp::crypto::bytes_to_hex(nonce));
    
    if (ciphertext.size() < 16) {
        throw OpenADPError("Ciphertext too short for decryption");
    }
    
    // Extract components: last 16 bytes are the tag
    Bytes tag(ciphertext.end() - 16, ciphertext.end());
    Bytes data(ciphertext.begin(), ciphertext.end() - 16);
    
    openadp::debug::debug_log("  - data length: " + std::to_string(data.size()));
    openadp::debug::debug_log("  - data hex: " + openadp::crypto::bytes_to_hex(data));
    openadp::debug::debug_log("  - tag length: " + std::to_string(tag.size()));
    openadp::debug::debug_log("  - tag hex: " + openadp::crypto::bytes_to_hex(tag));
    
    // Decrypt with NO AAD (matching Python/Go)
    Bytes empty_aad; // Empty AAD for transport encryption
    openadp::debug::debug_log("  - AAD length: " + std::to_string(empty_aad.size()));
    openadp::debug::debug_log("  - AAD: " + openadp::crypto::bytes_to_hex(empty_aad));
    
    Bytes plaintext = openadp::crypto::aes_gcm_decrypt(data, tag, nonce, pimpl_->recv_key, empty_aad);
    
    openadp::debug::debug_log("  - plaintext length: " + std::to_string(plaintext.size()));
    openadp::debug::debug_log("  - plaintext hex: " + openadp::crypto::bytes_to_hex(plaintext));
    
    pimpl_->recv_nonce++;
    openadp::debug::debug_log("  - incremented recv nonce to: " + std::to_string(pimpl_->recv_nonce));
    
    return plaintext;
}

Bytes NoiseState::get_handshake_hash() const {
    return pimpl_->h;
}

std::pair<Bytes, Bytes> NoiseState::get_transport_keys() const {
    return std::make_pair(pimpl_->send_key, pimpl_->recv_key);
}

// Helper functions implementation

Bytes perform_dh(const Bytes& private_key, const Bytes& public_key) {
    if (debug::is_debug_mode_enabled()) {
        debug::debug_log("DH operation: private_key size=" + std::to_string(private_key.size()) + 
                        ", public_key size=" + std::to_string(public_key.size()));
    }
    
    if (private_key.size() != 32 || public_key.size() != 32) {
        throw OpenADPError("Invalid key size for DH");
    }
    
    // Create private key
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, private_key.data(), private_key.size());
    if (!pkey) {
        throw OpenADPError("Failed to create private key");
    }
    
    // Create public key
    EVP_PKEY* peer_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, public_key.data(), public_key.size());
    if (!peer_key) {
        EVP_PKEY_free(pkey);
        throw OpenADPError("Failed to create public key");
    }
    
    // Create EVP context for key derivation
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx) {
        EVP_PKEY_free(peer_key);
        EVP_PKEY_free(pkey);
        throw OpenADPError("Failed to create X25519 context");
    }
    
    // Initialize key derivation
    if (EVP_PKEY_derive_init(ctx) != 1) {
        EVP_PKEY_free(peer_key);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        throw OpenADPError("Failed to initialize key derivation");
    }
    
    // Set peer key
    if (EVP_PKEY_derive_set_peer(ctx, peer_key) != 1) {
        EVP_PKEY_free(peer_key);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        throw OpenADPError("Failed to set peer key");
    }
    
    // Get shared secret length
    size_t secret_len;
    if (EVP_PKEY_derive(ctx, nullptr, &secret_len) != 1) {
        EVP_PKEY_free(peer_key);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        throw OpenADPError("Failed to get secret length");
    }
    
    // Derive shared secret
    Bytes shared_secret(secret_len);
    if (EVP_PKEY_derive(ctx, shared_secret.data(), &secret_len) != 1) {
        EVP_PKEY_free(peer_key);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        throw OpenADPError("X25519 DH failed");
    }
    
    EVP_PKEY_free(peer_key);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    
    return shared_secret;
}

std::pair<Bytes, Bytes> hkdf_2(const Bytes& ck, const Bytes& input_key_material) {
    // Use HKDF to derive two 32-byte keys following Noise spec
    Bytes salt = ck.empty() ? Bytes(32, 0) : ck;
    
    // Debug logging
    openadp::debug::debug_log("🔑 HKDF_2 DEBUG:");
    openadp::debug::debug_log("  - chaining key (ck): " + openadp::crypto::bytes_to_hex(ck));
    openadp::debug::debug_log("  - input key material: " + openadp::crypto::bytes_to_hex(input_key_material));
    openadp::debug::debug_log("  - salt: " + openadp::crypto::bytes_to_hex(salt));
    
    Bytes output;
    if (input_key_material.empty()) {
        // For Noise Split() operation: use HKDF-Expand-Only with manually computed PRK
        // This is the correct workaround for OpenSSL's zero-length IKM limitation
        openadp::debug::debug_log("  - using HKDF-Expand-Only mode (Split operation)");
        
        // Step 1: Manually compute PRK = HMAC-SHA256(salt, empty_input)
        Bytes prk = crypto::hmac_sha256(salt, Bytes());  // HMAC with empty input
        openadp::debug::debug_log("  - computed PRK via HMAC: " + openadp::crypto::bytes_to_hex(prk));
        
        // Step 2: Use HKDF-Expand-Only with the computed PRK
        output = crypto::hkdf_expand_only(prk, Bytes(), 64);
    } else {
        // For normal operations: use full HKDF-Extract-then-Expand
        openadp::debug::debug_log("  - using full HKDF-Extract-then-Expand mode");
        output = crypto::hkdf_derive(input_key_material, salt, Bytes(), 64);
    }
    
    openadp::debug::debug_log("  - HKDF output (64 bytes): " + openadp::crypto::bytes_to_hex(output));
    
    // Split into two 32-byte keys
    Bytes output1(output.begin(), output.begin() + 32);
    Bytes output2(output.begin() + 32, output.end());
    
    openadp::debug::debug_log("  - k1 (initiator->responder): " + openadp::crypto::bytes_to_hex(output1));
    openadp::debug::debug_log("  - k2 (responder->initiator): " + openadp::crypto::bytes_to_hex(output2));
    
    return std::make_pair(output1, output2);
}

Bytes encrypt_and_hash(const Bytes& plaintext, Bytes& h, const Bytes& k, uint64_t& nonce) {
    if (k.empty()) {
        // No key yet - just mix plaintext into hash
        mix_hash(h, plaintext);
        return plaintext;
    }
    
    // Create nonce (12 bytes: 4 zeros + 8-byte counter big-endian)
    Bytes nonce_bytes(12, 0);
    nonce_bytes[4] = (nonce >> 56) & 0xFF;
    nonce_bytes[5] = (nonce >> 48) & 0xFF;
    nonce_bytes[6] = (nonce >> 40) & 0xFF;
    nonce_bytes[7] = (nonce >> 32) & 0xFF;
    nonce_bytes[8] = (nonce >> 24) & 0xFF;
    nonce_bytes[9] = (nonce >> 16) & 0xFF;
    nonce_bytes[10] = (nonce >> 8) & 0xFF;
    nonce_bytes[11] = nonce & 0xFF;
    
    // Encrypt with AES-GCM using current hash as AAD
    auto result = crypto::aes_gcm_encrypt(plaintext, k, nonce_bytes, h);
    
    // Combine ciphertext + tag
    Bytes ciphertext = result.ciphertext;
    ciphertext.insert(ciphertext.end(), result.tag.begin(), result.tag.end());
    
    // Mix ciphertext into hash
    mix_hash(h, ciphertext);
    
    nonce++;
    
    return ciphertext;
}

Bytes decrypt_and_hash(const Bytes& ciphertext, Bytes& h, const Bytes& k, uint64_t& nonce) {
    if (k.empty()) {
        // No key yet - just mix ciphertext into hash and return as plaintext
        mix_hash(h, ciphertext);
        return ciphertext;
    }
    
    if (ciphertext.size() < 16) {
        throw OpenADPError("Ciphertext too short for decryption");
    }
    
    // Create nonce (12 bytes: 4 zeros + 8-byte counter big-endian)
    Bytes nonce_bytes(12, 0);
    nonce_bytes[4] = (nonce >> 56) & 0xFF;
    nonce_bytes[5] = (nonce >> 48) & 0xFF;
    nonce_bytes[6] = (nonce >> 40) & 0xFF;
    nonce_bytes[7] = (nonce >> 32) & 0xFF;
    nonce_bytes[8] = (nonce >> 24) & 0xFF;
    nonce_bytes[9] = (nonce >> 16) & 0xFF;
    nonce_bytes[10] = (nonce >> 8) & 0xFF;
    nonce_bytes[11] = nonce & 0xFF;
    
    // Extract components
    Bytes tag(ciphertext.end() - 16, ciphertext.end());
    Bytes data(ciphertext.begin(), ciphertext.end() - 16);
    
    // Decrypt with AES-GCM using current hash as AAD
    Bytes plaintext = crypto::aes_gcm_decrypt(data, tag, nonce_bytes, k, h);
    
    // Mix ciphertext into hash AFTER successful decryption
    mix_hash(h, ciphertext);
    
    nonce++;
    
    return plaintext;
}

void mix_hash(Bytes& h, const Bytes& data) {
    // Debug hash mixing
    if (debug::is_debug_mode_enabled()) {
        debug::debug_log("🔑 C++ NOISE: mix_hash called");
        debug::debug_log("  - Input data length: " + std::to_string(data.size()) + " bytes");
        debug::debug_log("  - Input data hex: " + crypto::bytes_to_hex(data));
        debug::debug_log("  - Previous h: " + crypto::bytes_to_hex(h));
    }
    
    // Mix data into hash state: h = SHA256(h || data)
    Bytes combined = h;
    combined.insert(combined.end(), data.begin(), data.end());
    h = crypto::sha256_hash(combined);
    
    if (debug::is_debug_mode_enabled()) {
        debug::debug_log("  - Updated h: " + crypto::bytes_to_hex(h));
    }
}

void mix_key(Bytes& ck, Bytes& k, const Bytes& input_key_material) {
    // Debug key mixing
    if (debug::is_debug_mode_enabled()) {
        debug::debug_log("🔑 C++ NOISE: mix_key called");
        debug::debug_log("  - Input key material length: " + std::to_string(input_key_material.size()) + " bytes");
        debug::debug_log("  - Input key material hex: " + crypto::bytes_to_hex(input_key_material));
        debug::debug_log("  - Previous ck: " + crypto::bytes_to_hex(ck));
    }
    
    // Mix key material into chaining key and derive new symmetric key
    auto keys = hkdf_2(ck, input_key_material);
    ck = keys.first;
    k = keys.second;
    
    if (debug::is_debug_mode_enabled()) {
        debug::debug_log("  - Updated ck: " + crypto::bytes_to_hex(ck));
        debug::debug_log("  - Derived temp k: " + crypto::bytes_to_hex(k));
    }
}

Bytes generate_keypair_private() {
    if (debug::is_debug_mode_enabled()) {
        // In debug mode, use deterministic ephemeral secret
        std::string hex_secret = debug::get_deterministic_ephemeral_secret();
        Bytes key = utils::hex_decode(hex_secret);
        debug::debug_log("Generated ephemeral key size: " + std::to_string(key.size()) + " bytes");
        return key;
    }
    
    // In normal mode, use cryptographically secure random
    Bytes private_key(32);
    if (RAND_bytes(private_key.data(), 32) != 1) {
        throw OpenADPError("Failed to generate private key");
    }
    return private_key;
}

Bytes derive_public_key(const Bytes& private_key) {
    if (private_key.size() != 32) {
        throw OpenADPError("Private key must be 32 bytes");
    }
    
    // Create EVP_PKEY from private key
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, private_key.data(), private_key.size());
    if (!pkey) {
        throw OpenADPError("Failed to create private key");
    }
    
    // Extract public key
    size_t public_key_len = 32;
    Bytes public_key(public_key_len);
    
    if (EVP_PKEY_get_raw_public_key(pkey, public_key.data(), &public_key_len) <= 0) {
        EVP_PKEY_free(pkey);
        throw OpenADPError("Failed to extract public key");
    }
    
    EVP_PKEY_free(pkey);
    
    public_key.resize(public_key_len);
    return public_key;
}

} // namespace noise
} // namespace openadp 