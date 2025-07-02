#pragma once

#include "types.hpp"
#include <memory>

namespace openadp {
namespace noise {

// Noise protocol state
class NoiseState {
private:
    struct Impl;
    std::unique_ptr<Impl> pimpl_;
    
public:
    NoiseState();
    ~NoiseState();
    
    // Initialize handshake with remote public key (as initiator)
    void initialize_handshake(const Bytes& remote_public_key);
    
    // Initialize as responder with local private key
    void initialize_responder(const Bytes& local_private_key);
    
    // Write handshake message
    Bytes write_message(const Bytes& payload);
    Bytes write_message();
    
    // Read handshake message
    Bytes read_message(const Bytes& message);
    
    // Check if handshake is complete
    bool handshake_finished() const;
    
    // Get handshake hash
    Bytes get_handshake_hash() const;
    
    // Encrypt transport message (after handshake)
    Bytes encrypt(const Bytes& plaintext);
    
    // Decrypt transport message (after handshake)
    Bytes decrypt(const Bytes& ciphertext);
    
    // Get transport keys (for debugging)
    std::pair<Bytes, Bytes> get_transport_keys() const;
};

// Utility functions
Bytes generate_keypair_private();
Bytes derive_public_key(const Bytes& private_key);

} // namespace noise
} // namespace openadp 