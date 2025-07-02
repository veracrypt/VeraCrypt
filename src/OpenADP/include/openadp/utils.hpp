#pragma once

#include "types.hpp"
#include <nlohmann/json.hpp>

namespace openadp {
namespace utils {

// Base64 encoding/decoding
std::string base64_encode(const Bytes& data);
Bytes base64_decode(const std::string& encoded);

// Hex encoding/decoding  
std::string hex_encode(const Bytes& data);
Bytes hex_decode(const std::string& hex);

// String conversion utilities
Bytes string_to_bytes(const std::string& str);
std::string bytes_to_string(const Bytes& data);

// System utilities
std::string get_hostname();

// Random number generation
Bytes random_bytes(size_t length);
std::string random_hex(size_t byte_length);

// File I/O helpers
Bytes read_file(const std::string& filename);
void write_file(const std::string& filename, const Bytes& data);

// JSON helpers
nlohmann::json parse_json(const std::string& json_str);
std::string to_json_string(const nlohmann::json& json);

} // namespace utils
} // namespace openadp 