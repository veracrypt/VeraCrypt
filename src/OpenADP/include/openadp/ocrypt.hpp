#pragma once

#include "types.hpp"

namespace openadp {
namespace ocrypt {

// Ocrypt result structure
struct OcryptRecoverResult {
    Bytes secret;
    int remaining_guesses;
    Bytes updated_metadata;
    
    OcryptRecoverResult(const Bytes& secret, int remaining, const Bytes& metadata)
        : secret(secret), remaining_guesses(remaining), updated_metadata(metadata) {}
};

// Ocrypt recover and reregister result structure
struct OcryptRecoverAndReregisterResult {
    Bytes secret;
    Bytes new_metadata;
    
    OcryptRecoverAndReregisterResult(const Bytes& secret, const Bytes& metadata)
        : secret(secret), new_metadata(metadata) {}
};

// Register a long-term secret protected by a PIN using OpenADP distributed cryptography
Bytes register_secret(
    const std::string& user_id,
    const std::string& app_id, 
    const Bytes& long_term_secret,
    const std::string& pin,
    int max_guesses = 10,
    const std::string& servers_url = ""
);

// Recover a long-term secret using the PIN and automatically refresh backup
OcryptRecoverResult recover(
    const Bytes& metadata,
    const std::string& pin,
    const std::string& servers_url = ""
);

// Internal functions for backup management
Bytes register_with_bid(
    const std::string& user_id,
    const std::string& app_id,
    const Bytes& long_term_secret, 
    const std::string& pin,
    int max_guesses,
    const std::string& backup_id,
    const std::string& servers_url = ""
);

OcryptRecoverResult recover_without_refresh(
    const Bytes& metadata,
    const std::string& pin,
    const std::string& servers_url = ""
);

std::string generate_next_backup_id(const std::string& current_backup_id);

// Recover a long-term secret and reregister with completely fresh metadata
OcryptRecoverAndReregisterResult recover_and_reregister(
    const Bytes& metadata,
    const std::string& pin,
    const std::string& servers_url = ""
);

} // namespace ocrypt
} // namespace openadp 