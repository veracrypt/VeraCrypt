#include "openadp/utils.hpp"
#include "openadp/types.hpp"
#include "openadp/debug.hpp"
#include <openssl/rand.h>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <cctype>
#include <nlohmann/json.hpp>

namespace openadp {
namespace utils {

std::string hex_encode(const Bytes& data) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t byte : data) {
        oss << std::setw(2) << static_cast<int>(byte);
    }
    return oss.str();
}

Bytes hex_decode(const std::string& hex) {
    if (hex.length() % 2 != 0) {
        throw OpenADPError("Hex string must have even length");
    }
    
    Bytes result;
    result.reserve(hex.length() / 2);
    
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byte_string = hex.substr(i, 2);
        try {
            uint8_t byte = static_cast<uint8_t>(std::stoi(byte_string, nullptr, 16));
            result.push_back(byte);
        } catch (const std::invalid_argument& e) {
            throw OpenADPError("Invalid hex character in string: " + hex);
        } catch (const std::out_of_range& e) {
            throw OpenADPError("Hex value out of range: " + hex);
        }
    }
    
    return result;
}

Bytes string_to_bytes(const std::string& str) {
    return Bytes(str.begin(), str.end());
}

std::string bytes_to_string(const Bytes& data) {
    return std::string(data.begin(), data.end());
}

Bytes random_bytes(size_t length) {
    if (debug::is_debug_mode_enabled()) {
        // In debug mode, use deterministic bytes
        return debug::get_deterministic_random_bytes(length);
    } else {
        // In normal mode, use cryptographically secure random
        Bytes result(length);
        if (RAND_bytes(result.data(), static_cast<int>(length)) != 1) {
            throw OpenADPError("Failed to generate random bytes");
        }
        return result;
    }
}

std::string random_hex(size_t byte_length) {
    if (debug::is_debug_mode_enabled()) {
        // In debug mode, use deterministic hex
        return debug::get_deterministic_random_hex(byte_length * 2); // 2 hex chars per byte
    } else {
        // In normal mode, use cryptographically secure random
        return hex_encode(random_bytes(byte_length));
    }
}

Bytes read_file(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        throw OpenADPError("Failed to open file: " + filename);
    }
    
    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    Bytes data(size);
    file.read(reinterpret_cast<char*>(data.data()), size);
    
    return data;
}

void write_file(const std::string& filename, const Bytes& data) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        throw OpenADPError("Failed to create file: " + filename);
    }
    
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}

nlohmann::json parse_json(const std::string& json_str) {
    try {
        return nlohmann::json::parse(json_str);
    } catch (const std::exception& e) {
        throw OpenADPError("JSON parse error: " + std::string(e.what()));
    }
}

std::string to_json_string(const nlohmann::json& json) {
    return json.dump();
}

} // namespace utils
} // namespace openadp 