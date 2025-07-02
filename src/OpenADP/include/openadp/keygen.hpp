#pragma once

#include "types.hpp"

namespace openadp {
namespace keygen {

// Generate encryption key using OpenADP protocol
GenerateEncryptionKeyResult generate_encryption_key(
    const Identity& identity,
    const std::string& password,
    int max_guesses,
    int64_t expiration,
    const std::vector<ServerInfo>& server_infos
);

// Recover encryption key using OpenADP protocol
RecoverEncryptionKeyResult recover_encryption_key(
    const Identity& identity,
    const std::string& password,
    const AuthCodes& auth_codes,
    const std::vector<ServerInfo>& server_infos
);

// Helper functions for key generation
std::string generate_random_scalar();
AuthCodes generate_auth_codes(const std::string& base_auth_code, const std::vector<ServerInfo>& server_infos);

} // namespace keygen
} // namespace openadp 