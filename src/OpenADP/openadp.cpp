#include <openadp.hpp>
#include "openadp/keygen.hpp"
#include "openadp/client.hpp"
#include "openadp/crypto.hpp"
#include "openadp/utils.hpp"
#include "openadp/debug.hpp"
#include <nlohmann/json.hpp>
#include <fstream>
#include <filesystem>

namespace openadp {

// File I/O utilities
Bytes read_file_bytes(const std::string& file_path) {
    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open()) {
        throw OpenADPError("Failed to open file for reading: " + file_path);
    }
    
    file.seekg(0, std::ios::end);
    size_t file_size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    Bytes data(file_size);
    file.read(reinterpret_cast<char*>(data.data()), file_size);
    
    if (!file) {
        throw OpenADPError("Failed to read file: " + file_path);
    }
    
    return data;
}

void write_file_bytes(const std::string& file_path, const Bytes& data) {
    std::ofstream file(file_path, std::ios::binary);
    if (!file.is_open()) {
        throw OpenADPError("Failed to open file for writing: " + file_path);
    }
    
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    
    if (!file) {
        throw OpenADPError("Failed to write file: " + file_path);
    }
}

void write_metadata_file(const std::string& file_path, const nlohmann::json& metadata) {
    std::ofstream file(file_path);
    if (!file.is_open()) {
        throw OpenADPError("Failed to open metadata file for writing: " + file_path);
    }
    
    file << metadata.dump(4); // Pretty print with 4-space indentation
    
    if (!file) {
        throw OpenADPError("Failed to write metadata file: " + file_path);
    }
}

EncryptResult encrypt_data(
    const Bytes& plaintext,
    const Identity& identity,
    const std::string& password,
    int max_guesses,
    int64_t expiration,
    const std::string& servers_url
) {
    // Get server list
    std::vector<ServerInfo> server_infos = client::get_servers(servers_url);
    
    if (server_infos.empty()) {
        throw OpenADPError("No servers available");
    }
    
    // Get server noise_nk_public_keys (only if not already provided by registry)
    for (auto& server_info : server_infos) {
        if (server_info.public_key.has_value()) {
            // Public key already available from registry
            if (debug::is_debug_mode_enabled()) {
                debug::debug_log("Using noise_nk_public_key from registry for server: " + server_info.url);
            }
            continue;
        }
        
        // Public key not available, need to fetch from server
        if (debug::is_debug_mode_enabled()) {
            debug::debug_log("Public key not in registry, calling GetServerInfo for: " + server_info.url);
        }
        
        try {
            client::BasicOpenADPClient client(server_info.url);
            nlohmann::json info = client.get_server_info();
            
            if (info.contains("noise_nk_public_key")) {
                std::string public_key_str = info["noise_nk_public_key"].get<std::string>();
                server_info.public_key = utils::base64_decode(public_key_str);
                
                if (debug::is_debug_mode_enabled()) {
                    debug::debug_log("Successfully fetched noise_nk_public_key via GetServerInfo for: " + server_info.url);
                }
            } else {
                if (debug::is_debug_mode_enabled()) {
                    debug::debug_log("GetServerInfo response missing public_key for: " + server_info.url);
                }
            }
        } catch (const std::exception& e) {
            if (debug::is_debug_mode_enabled()) {
                debug::debug_log("Failed to get noise_nk_public_key via GetServerInfo for " + server_info.url + ": " + e.what());
            }
            // Continue without noise_nk_public_key (will use unencrypted)
        }
    }
    
    // Generate encryption key using OpenADP
    auto result = keygen::generate_encryption_key(
        identity, password, max_guesses, expiration, server_infos
    );
    
    if (result.error_message.has_value()) {
        throw OpenADPError("Failed to generate encryption key: " + result.error_message.value());
    }
    
    // Create metadata for AAD (without crypto data)
    nlohmann::json metadata;
    metadata["user_id"] = identity.uid;
    metadata["device_id"] = identity.did;
    metadata["backup_id"] = identity.bid;
    metadata["auth_code"] = result.auth_codes.value().base_auth_code;
    metadata["threshold"] = result.threshold;
    metadata["version"] = "1.0";
    
    // Add server URLs
    nlohmann::json servers_array = nlohmann::json::array();
    for (const auto& server : result.server_infos) {
        servers_array.push_back(server.url);
    }
    metadata["servers"] = servers_array;
    
    std::string metadata_str = metadata.dump();
    Bytes metadata_aad = utils::string_to_bytes(metadata_str);
    
    // Encrypt the data using metadata as AAD
    if (debug::is_debug_mode_enabled()) {
        debug::debug_log("🔐 AES-GCM ENCRYPTION INPUTS:");
        debug::debug_log("  - Plaintext size: " + std::to_string(plaintext.size()) + " bytes");
        debug::debug_log("  - Plaintext hex: " + crypto::bytes_to_hex(plaintext));
        debug::debug_log("  - Key size: " + std::to_string(result.encryption_key.value().size()) + " bytes");
        debug::debug_log("  - Key hex: " + crypto::bytes_to_hex(result.encryption_key.value()));
        debug::debug_log("  - AAD size: " + std::to_string(metadata_aad.size()) + " bytes");
        debug::debug_log("  - AAD: " + metadata_str);
    }
    auto aes_result = crypto::aes_gcm_encrypt(plaintext, result.encryption_key.value(), metadata_aad);
    
    // Create full metadata with crypto data for return
    nlohmann::json full_metadata = metadata;
    full_metadata["ciphertext"] = utils::base64_encode(aes_result.ciphertext);
    full_metadata["tag"] = utils::base64_encode(aes_result.tag);
    full_metadata["nonce"] = utils::base64_encode(aes_result.nonce);
    
    std::string full_metadata_str = full_metadata.dump();
    Bytes metadata_bytes = utils::string_to_bytes(full_metadata_str);
    
    return EncryptResult(aes_result.ciphertext, metadata_bytes);
}

// Overload for encrypt_data that accepts a vector of servers
EncryptResult encrypt_data(
    const Bytes& plaintext,
    const Identity& identity,
    const std::string& password,
    int max_guesses,
    int64_t expiration,
    const std::vector<ServerInfo>& servers
) {
    if (servers.empty()) {
        throw OpenADPError("No servers available");
    }
    
    // Use the provided servers directly
    std::vector<ServerInfo> server_infos = servers;
    
    // Get server noise_nk_public_keys (only if not already provided by registry)
    for (auto& server_info : server_infos) {
        if (server_info.public_key.has_value()) {
            // Public key already available from registry
            if (debug::is_debug_mode_enabled()) {
                debug::debug_log("Using noise_nk_public_key from registry for server: " + server_info.url);
            }
            continue;
        }
        
        // Public key not available, need to fetch from server
        if (debug::is_debug_mode_enabled()) {
            debug::debug_log("Public key not in registry, calling GetServerInfo for: " + server_info.url);
        }
        
        try {
            client::BasicOpenADPClient client(server_info.url);
            nlohmann::json info = client.get_server_info();
            
            if (info.contains("noise_nk_public_key")) {
                std::string public_key_str = info["noise_nk_public_key"].get<std::string>();
                server_info.public_key = utils::base64_decode(public_key_str);
                
                if (debug::is_debug_mode_enabled()) {
                    debug::debug_log("Successfully fetched noise_nk_public_key via GetServerInfo for: " + server_info.url);
                }
            } else {
                if (debug::is_debug_mode_enabled()) {
                    debug::debug_log("GetServerInfo response missing public_key for: " + server_info.url);
                }
            }
        } catch (const std::exception& e) {
            if (debug::is_debug_mode_enabled()) {
                debug::debug_log("Failed to get noise_nk_public_key via GetServerInfo for " + server_info.url + ": " + e.what());
            }
            // Continue without noise_nk_public_key (will use unencrypted)
        }
    }
    
    // Generate encryption key using OpenADP
    auto result = keygen::generate_encryption_key(
        identity, password, max_guesses, expiration, server_infos
    );
    
    if (result.error_message.has_value()) {
        throw OpenADPError("Failed to generate encryption key: " + result.error_message.value());
    }
    
    // Create metadata for AAD (without crypto data)
    nlohmann::json metadata;
    metadata["user_id"] = identity.uid;
    metadata["device_id"] = identity.did;
    metadata["backup_id"] = identity.bid;
    metadata["auth_code"] = result.auth_codes.value().base_auth_code;
    metadata["threshold"] = result.threshold;
    metadata["version"] = "1.0";
    
    // Add server URLs
    nlohmann::json servers_array = nlohmann::json::array();
    for (const auto& server : result.server_infos) {
        servers_array.push_back(server.url);
    }
    metadata["servers"] = servers_array;
    
    std::string metadata_str = metadata.dump();
    Bytes metadata_aad = utils::string_to_bytes(metadata_str);
    
    // Encrypt the data using metadata as AAD
    if (debug::is_debug_mode_enabled()) {
        debug::debug_log("🔐 AES-GCM ENCRYPTION INPUTS:");
        debug::debug_log("  - Plaintext size: " + std::to_string(plaintext.size()) + " bytes");
        debug::debug_log("  - Plaintext hex: " + crypto::bytes_to_hex(plaintext));
        debug::debug_log("  - Key size: " + std::to_string(result.encryption_key.value().size()) + " bytes");
        debug::debug_log("  - Key hex: " + crypto::bytes_to_hex(result.encryption_key.value()));
        debug::debug_log("  - AAD size: " + std::to_string(metadata_aad.size()) + " bytes");
        debug::debug_log("  - AAD: " + metadata_str);
    }
    auto aes_result = crypto::aes_gcm_encrypt(plaintext, result.encryption_key.value(), metadata_aad);
    
    // Create full metadata with crypto data for return
    nlohmann::json full_metadata = metadata;
    full_metadata["ciphertext"] = utils::base64_encode(aes_result.ciphertext);
    full_metadata["tag"] = utils::base64_encode(aes_result.tag);
    full_metadata["nonce"] = utils::base64_encode(aes_result.nonce);
    
    std::string full_metadata_str = full_metadata.dump();
    Bytes metadata_bytes = utils::string_to_bytes(full_metadata_str);
    
    return EncryptResult(aes_result.ciphertext, metadata_bytes);
}

Bytes decrypt_data(
    const Bytes& ciphertext,
    const Bytes& metadata,
    const Identity& identity,
    const std::string& password,
    const std::string& servers_url
) {
    // Parse metadata
    std::string metadata_str = utils::bytes_to_string(metadata);
    nlohmann::json metadata_json = nlohmann::json::parse(metadata_str);
    
    std::string base_auth_code = metadata_json["auth_code"].get<std::string>();
    Bytes tag = utils::base64_decode(metadata_json["tag"].get<std::string>());
    Bytes nonce = utils::base64_decode(metadata_json["nonce"].get<std::string>());
    
    // Get server list
    std::vector<ServerInfo> server_infos;
    if (metadata_json.contains("servers")) {
        for (const auto& server_url : metadata_json["servers"]) {
            server_infos.emplace_back(server_url.get<std::string>());
        }
    } else {
        server_infos = client::get_servers(servers_url);
    }
    
    // Get server noise_nk_public_keys (only if not already provided by registry)
    for (auto& server_info : server_infos) {
        if (server_info.public_key.has_value()) {
            // Public key already available from registry
            if (debug::is_debug_mode_enabled()) {
                debug::debug_log("Using noise_nk_public_key from registry for server: " + server_info.url);
            }
            continue;
        }
        
        // Public key not available, need to fetch from server
        if (debug::is_debug_mode_enabled()) {
            debug::debug_log("Public key not in registry, calling GetServerInfo for: " + server_info.url);
        }
        
        try {
            client::BasicOpenADPClient client(server_info.url);
            nlohmann::json info = client.get_server_info();
            
            if (info.contains("noise_nk_public_key")) {
                std::string public_key_str = info["noise_nk_public_key"].get<std::string>();
                server_info.public_key = utils::base64_decode(public_key_str);
                
                if (debug::is_debug_mode_enabled()) {
                    debug::debug_log("Successfully fetched noise_nk_public_key via GetServerInfo for: " + server_info.url);
                }
            } else {
                if (debug::is_debug_mode_enabled()) {
                    debug::debug_log("GetServerInfo response missing public_key for: " + server_info.url);
                }
            }
        } catch (const std::exception& e) {
            if (debug::is_debug_mode_enabled()) {
                debug::debug_log("Failed to get noise_nk_public_key via GetServerInfo for " + server_info.url + ": " + e.what());
            }
            // Continue without noise_nk_public_key
        }
    }
    
    // Reconstruct auth codes
    AuthCodes auth_codes = keygen::generate_auth_codes(base_auth_code, server_infos);
    
    // Recover encryption key
    auto result = keygen::recover_encryption_key(identity, password, auth_codes, server_infos);
    
    if (result.error_message.has_value()) {
        throw OpenADPError("Failed to recover encryption key: " + result.error_message.value());
    }
    
    // Use the exact metadata bytes that were passed to us as AAD
    // (This is the metadata that was originally used during encryption)
    Bytes metadata_aad = metadata;
    
    // 🔍 DEBUG: AES-GCM decryption inputs
    if (debug::is_debug_mode_enabled()) {
        debug::debug_log("🔍 AES-GCM DECRYPTION INPUTS:");
        debug::debug_log("  - Ciphertext size: " + std::to_string(ciphertext.size()) + " bytes");
        debug::debug_log("  - Ciphertext hex: " + crypto::bytes_to_hex(ciphertext));
        debug::debug_log("  - Tag size: " + std::to_string(tag.size()) + " bytes");
        debug::debug_log("  - Tag hex: " + crypto::bytes_to_hex(tag));
        debug::debug_log("  - Nonce size: " + std::to_string(nonce.size()) + " bytes");
        debug::debug_log("  - Nonce hex: " + crypto::bytes_to_hex(nonce));
        debug::debug_log("  - Key size: " + std::to_string(result.encryption_key.value().size()) + " bytes");
        debug::debug_log("  - Key hex: " + crypto::bytes_to_hex(result.encryption_key.value()));
        debug::debug_log("  - AAD size: " + std::to_string(metadata_aad.size()) + " bytes");
        debug::debug_log("  - AAD: " + utils::bytes_to_string(metadata_aad));
    }
    
    // Decrypt the data using metadata as AAD (matching what was used during encryption)
    Bytes plaintext = crypto::aes_gcm_decrypt(ciphertext, tag, nonce, result.encryption_key.value(), metadata_aad);
    
    return plaintext;
}

// Convenience functions for encryption/decryption
void encrypt_data(const std::string& input_file, const std::string& output_file, 
                 const std::string& metadata_file, const std::string& user_id, 
                 const std::string& password, int max_guesses, 
                 const std::vector<ServerInfo>& servers) {
    // Validate parameters
    if (input_file.empty()) {
        throw OpenADPError("Input file path cannot be empty");
    }
    if (user_id.empty()) {
        throw OpenADPError("User ID cannot be empty");
    }
    if (servers.empty()) {
        throw OpenADPError("Server list cannot be empty");
    }
    
    // Check if input file exists
    if (!std::filesystem::exists(input_file)) {
        throw OpenADPError("Input file does not exist: " + input_file);
    }
    
    // Read input file
    Bytes plaintext = read_file_bytes(input_file);
    
    // Generate encryption key
    Identity identity(user_id, "default_device", "default_backup");
    auto result = keygen::generate_encryption_key(identity, password, max_guesses, 3600, servers);
    
    if (result.error_message.has_value()) {
        throw OpenADPError("Failed to generate encryption key: " + result.error_message.value());
    }
    
    // Encrypt data
    if (debug::is_debug_mode_enabled()) {
        debug::debug_log("🔐 AES-GCM ENCRYPTION INPUTS (file-based):");
        debug::debug_log("  - Plaintext size: " + std::to_string(plaintext.size()) + " bytes");
        debug::debug_log("  - Plaintext hex: " + crypto::bytes_to_hex(plaintext));
        debug::debug_log("  - Key size: " + std::to_string(result.encryption_key.value().size()) + " bytes");
        debug::debug_log("  - Key hex: " + crypto::bytes_to_hex(result.encryption_key.value()));
        debug::debug_log("  - AAD: None");
    }
    auto encrypted = crypto::aes_gcm_encrypt(plaintext, result.encryption_key.value());
    
    // Write encrypted file
    write_file_bytes(output_file, encrypted.ciphertext);
    
    // Create metadata
    nlohmann::json metadata;
    metadata["uid"] = identity.uid;
    metadata["did"] = identity.did;
    metadata["bid"] = identity.bid;
    // Do NOT store encryption key - it must be derived for security
    metadata["tag"] = utils::hex_encode(encrypted.tag);
    metadata["nonce"] = utils::hex_encode(encrypted.nonce);
    metadata["auth_codes"] = result.auth_codes.value().base_auth_code;
    
    nlohmann::json server_urls = nlohmann::json::array();
    for (const auto& server : result.server_infos) {
        server_urls.push_back(server.url);
    }
    metadata["server_urls"] = server_urls;
    metadata["threshold"] = result.threshold;
    
    write_metadata_file(metadata_file, metadata);
}

void decrypt_data(const std::string& input_file, const std::string& output_file, 
                 const std::string& metadata_file, const std::string& user_id, 
                 const std::string& password, const std::vector<ServerInfo>& servers) {
    // Validate parameters
    if (user_id.empty()) {
        throw OpenADPError("User ID cannot be empty");
    }
    
    // Check if files exist
    if (!std::filesystem::exists(input_file)) {
        throw OpenADPError("Input file does not exist: " + input_file);
    }
    if (!std::filesystem::exists(metadata_file)) {
        throw OpenADPError("Metadata file does not exist: " + metadata_file);
    }
    
    // Read metadata
    std::ifstream meta_file(metadata_file);
    nlohmann::json metadata;
    meta_file >> metadata;
    
    // Extract metadata fields
    std::string uid = metadata["uid"];
    std::string did = metadata["did"];
    std::string bid = metadata["bid"];
    std::string base_auth_code = metadata["auth_codes"];
    Bytes tag = utils::hex_decode(metadata["tag"]);
    Bytes nonce = utils::hex_decode(metadata["nonce"]);
    
    // Get server URLs from metadata
    std::vector<ServerInfo> server_infos;
    if (servers.empty() && metadata.contains("server_urls")) {
        // Use servers from metadata if not overridden
        for (const auto& url : metadata["server_urls"]) {
            server_infos.push_back(ServerInfo{url.get<std::string>(), {}});
        }
    } else {
        // Use provided servers
        server_infos = servers;
    }
    
    // Read encrypted file
    Bytes ciphertext = read_file_bytes(input_file);
    
    // Derive encryption key (DO NOT read from metadata for security)
    Identity identity(uid, did, bid);
    AuthCodes auth_codes = keygen::generate_auth_codes(base_auth_code, server_infos);
    auto result = keygen::recover_encryption_key(identity, password, auth_codes, server_infos);
    
    if (result.error_message.has_value()) {
        throw OpenADPError("Failed to recover encryption key: " + result.error_message.value());
    }
    
    // Debug logging AFTER key recovery
    if (debug::is_debug_mode_enabled()) {
        debug::debug_log("🔍 AES-GCM DECRYPTION INPUTS (file-based):");
        debug::debug_log("  - Ciphertext size: " + std::to_string(ciphertext.size()) + " bytes");
        debug::debug_log("  - Ciphertext hex: " + crypto::bytes_to_hex(ciphertext));
        debug::debug_log("  - Tag size: " + std::to_string(tag.size()) + " bytes");
        debug::debug_log("  - Tag hex: " + crypto::bytes_to_hex(tag));
        debug::debug_log("  - Nonce size: " + std::to_string(nonce.size()) + " bytes");
        debug::debug_log("  - Nonce hex: " + crypto::bytes_to_hex(nonce));
        debug::debug_log("  - Key size: " + std::to_string(result.encryption_key.value().size()) + " bytes");
        debug::debug_log("  - Key hex: " + crypto::bytes_to_hex(result.encryption_key.value()));
        debug::debug_log("  - AAD: None");
    }
    
    Bytes plaintext = crypto::aes_gcm_decrypt(ciphertext, tag, nonce, result.encryption_key.value());
    
    // Write decrypted file
    write_file_bytes(output_file, plaintext);
}

} // namespace openadp 
