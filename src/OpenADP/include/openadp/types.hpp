#pragma once

#include <string>
#include <vector>
#include <optional>
#include <map>
#include <cstdint>
#include <set>

namespace openadp {

// Basic types
using Bytes = std::vector<uint8_t>;

// Identity structure
struct Identity {
    std::string uid;
    std::string did; 
    std::string bid;
    
    // Default constructor
    Identity() = default;
    
    Identity(const std::string& uid, const std::string& did, const std::string& bid)
        : uid(uid), did(did), bid(bid) {}
        
    // Equality operator
    bool operator==(const Identity& other) const {
        return uid == other.uid && did == other.did && bid == other.bid;
    }
};

// Server info structure
struct ServerInfo {
    std::string url;
    std::optional<Bytes> public_key;
    
    // Default constructor
    ServerInfo() = default;
    
    ServerInfo(const std::string& url) : url(url) {}
    ServerInfo(const std::string& url, const Bytes& public_key) 
        : url(url), public_key(public_key) {}
        
    // Equality operator
    bool operator==(const ServerInfo& other) const {
        return url == other.url && public_key == other.public_key;
    }
};

// Auth codes structure
struct AuthCodes {
    std::string base_auth_code;
    std::map<std::string, std::string> server_auth_codes;
};

// Point structures for cryptography
struct Point2D {
    std::string x;
    std::string y;
    
    Point2D() = default;
    Point2D(const std::string& x, const std::string& y) : x(x), y(y) {}
};

struct Point4D {
    std::string x;
    std::string y; 
    std::string z;
    std::string t;
    
    Point4D() = default;
    Point4D(const std::string& x, const std::string& y, const std::string& z, const std::string& t)
        : x(x), y(y), z(z), t(t) {}
};

// Share structure for secret sharing
struct Share {
    int x;
    std::string y;
    
    Share(int x, const std::string& y) : x(x), y(y) {}
};

// Point share structure
struct PointShare {
    int x;
    Point2D point;
    
    PointShare(int x, const Point2D& point) : x(x), point(point) {}
};

// Result structures
struct GenerateEncryptionKeyResult {
    std::optional<Bytes> encryption_key;
    std::optional<AuthCodes> auth_codes;
    std::vector<ServerInfo> server_infos;
    int threshold;
    std::optional<std::string> error_message;
    
    static GenerateEncryptionKeyResult success(const Bytes& key, const AuthCodes& codes, 
                                             const std::vector<ServerInfo>& servers, int threshold) {
        GenerateEncryptionKeyResult result;
        result.encryption_key = key;
        result.auth_codes = codes;
        result.server_infos = servers;
        result.threshold = threshold;
        return result;
    }
    
    static GenerateEncryptionKeyResult error(const std::string& error_msg) {
        GenerateEncryptionKeyResult result;
        result.error_message = error_msg;
        return result;
    }
};

struct RecoverEncryptionKeyResult {
    std::optional<Bytes> encryption_key;
    int remaining_guesses;
    std::optional<std::string> error_message;
    int num_guesses;  // Actual number of guesses used (from server responses)
    int max_guesses;  // Maximum guesses allowed (from server responses)
    
    static RecoverEncryptionKeyResult success(const Bytes& key, int remaining, int num_guesses = 0, int max_guesses = 0) {
        RecoverEncryptionKeyResult result;
        result.encryption_key = key;
        result.remaining_guesses = remaining;
        result.num_guesses = num_guesses;
        result.max_guesses = max_guesses;
        return result;
    }
    
    static RecoverEncryptionKeyResult error(const std::string& error_msg) {
        RecoverEncryptionKeyResult result;
        result.error_message = error_msg;
        result.remaining_guesses = 0;
        result.num_guesses = 0;
        result.max_guesses = 0;
        return result;
    }
};

// Exception class
class OpenADPError : public std::exception {
private:
    std::string message_;
    int code_;

public:
    OpenADPError(const std::string& message, int code = 0) 
        : message_(message), code_(code) {}
    
    const char* what() const noexcept override {
        return message_.c_str();
    }
    
    int code() const { return code_; }
};

} // namespace openadp 