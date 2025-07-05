#pragma once

// Main OpenADP C++ SDK Header
// This provides a complete C++ implementation of the OpenADP distributed cryptography protocol

#include "openadp/types.hpp"
#include "openadp/crypto.hpp"
#include "openadp/client.hpp"
#include "openadp/keygen.hpp"
#include "openadp/ocrypt.hpp"
#include "openadp/noise.hpp"
#include "openadp/utils.hpp"
#include "openadp/debug.hpp"
#include <nlohmann/json.hpp>

// Main namespace
namespace openadp {

// Version information
constexpr const char* VERSION = "0.1.3";

// Convenience functions for common operations

// Encrypt data using OpenADP
struct EncryptResult {
    Bytes ciphertext;
    Bytes metadata;
    
    EncryptResult(const Bytes& ciphertext, const Bytes& metadata)
        : ciphertext(ciphertext), metadata(metadata) {}
};

EncryptResult encrypt_data(
    const Bytes& plaintext,
    const Identity& identity,
    const std::string& password,
    int max_guesses = 10,
    int64_t expiration = 0,
    const std::string& servers_url = ""
);

// Encrypt data using OpenADP with specific servers
EncryptResult encrypt_data(
    const Bytes& plaintext,
    const Identity& identity,
    const std::string& password,
    int max_guesses,
    int64_t expiration,
    const std::vector<ServerInfo>& servers
);

// Decrypt data using OpenADP
Bytes decrypt_data(
    const Bytes& ciphertext,
    const Bytes& metadata,
    const Identity& identity,
    const std::string& password,
    const std::string& servers_url = ""
);

// File I/O utilities
Bytes read_file_bytes(const std::string& file_path);
void write_file_bytes(const std::string& file_path, const Bytes& data);
void write_metadata_file(const std::string& file_path, const nlohmann::json& metadata);

// Convenience functions for encryption/decryption
void encrypt_data(const std::string& input_file, const std::string& output_file, 
                 const std::string& metadata_file, const std::string& user_id, 
                 const std::string& password, int max_guesses, 
                 const std::vector<ServerInfo>& servers);

void decrypt_data(const std::string& input_file, const std::string& output_file, 
                 const std::string& metadata_file, const std::string& user_id, 
                 const std::string& password, const std::vector<ServerInfo>& servers);

} // namespace openadp 
