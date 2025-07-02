#pragma once

#include "types.hpp"
#include "noise.hpp"
#include <nlohmann/json.hpp>
#include <memory>

namespace openadp {
namespace client {

// JSON-RPC request structure
struct JsonRpcRequest {
    std::string method;
    nlohmann::json params;
    std::string id;
    bool encrypted;
    
    JsonRpcRequest(const std::string& method, const nlohmann::json& params = nullptr)
        : method(method), params(params), id("1"), encrypted(false) {}
    
    nlohmann::json to_dict() const;
};

// JSON-RPC response structure
struct JsonRpcResponse {
    nlohmann::json result;
    nlohmann::json error;
    std::string id;
    
    static JsonRpcResponse from_json(const nlohmann::json& json);
    bool has_error() const { return !error.is_null(); }
};

// Register secret request
struct RegisterSecretRequest {
    std::string auth_code;
    Identity identity;
    int version;
    int max_guesses;
    int64_t expiration;
    int x;  // Shamir X coordinate 
    std::string y;  // Shamir Y coordinate, Base64 encoded, little-endian.
    bool encrypted;
    nlohmann::json auth_data;  // Auth data
    
    RegisterSecretRequest(const std::string& auth_code, const Identity& identity, 
                         int version, int max_guesses, int64_t expiration, 
                         int x, const std::string& y, bool encrypted = true)
        : auth_code(auth_code), identity(identity), version(version), 
          max_guesses(max_guesses), expiration(expiration), x(x), y(y), 
          encrypted(encrypted), auth_data(nlohmann::json::object()) {}
};

// Recover secret request  
struct RecoverSecretRequest {
    Identity identity;
    std::string password;
    int guess_num;
    bool encrypted;
    std::string auth_code;
    std::string b;  // Blinded B point = r*U, compressed, base64 encoded.
    
    RecoverSecretRequest(const std::string& auth_code, const Identity& identity, 
                        const std::string& b, int guess_num)
        : identity(identity), password(""), guess_num(guess_num), encrypted(false), 
          auth_code(auth_code), b(b) {}
};

// Basic HTTP client
class BasicOpenADPClient {
private:
    std::string url_;
    int timeout_seconds_;
    
public:
    BasicOpenADPClient(const std::string& url, int timeout_seconds = 30);
    
    // HTTP request methods
    nlohmann::json make_request(const std::string& method, const nlohmann::json& params = nullptr);
    
    // Server info
    nlohmann::json get_server_info();
    
    // Secret operations
    nlohmann::json register_secret_standardized(const RegisterSecretRequest& request);
    nlohmann::json recover_secret_standardized(const RecoverSecretRequest& request);
    
    // Getters
    const std::string& url() const { return url_; }
    int timeout() const { return timeout_seconds_; }
};

// Encrypted client using Noise-NK
class EncryptedOpenADPClient {
private:
    std::unique_ptr<BasicOpenADPClient> basic_client_;
    std::optional<Bytes> public_key_;
    std::unique_ptr<noise::NoiseState> noise_state_;
    bool handshake_complete_;
    std::string session_id_;  // Store session ID for encrypted requests
    
    // Helper methods
    std::string generate_session_id();
    
public:
    EncryptedOpenADPClient(const std::string& url, const std::optional<Bytes>& public_key, 
                          int timeout_seconds = 30);
    
    // Check if we have a public key for encryption
    bool has_public_key() const { return public_key_.has_value(); }
    
    // Make encrypted request
    nlohmann::json make_encrypted_request(const std::string& method, const nlohmann::json& params = nullptr);
    
    // Perform Noise-NK handshake
    void perform_handshake();
    
    // Secret operations
    nlohmann::json register_secret(const RegisterSecretRequest& request);
    nlohmann::json recover_secret(const RecoverSecretRequest& request);
    
    // List backups
    nlohmann::json list_backups(const Identity& identity);
    
    // Getters
    const std::string& url() const { return basic_client_->url(); }
};

// Server discovery functions
std::vector<ServerInfo> get_servers(const std::string& servers_url = "");
std::vector<ServerInfo> get_fallback_server_info();

// Helper functions
ServerInfo parse_server_info(const nlohmann::json& server_json);
std::vector<ServerInfo> parse_servers_response(const nlohmann::json& response);

} // namespace client
} // namespace openadp 
