#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace openadp {
namespace debug {

// Global debug flag - when true, all operations become deterministic
extern bool g_debug_mode;

// Set debug mode (enables/disables deterministic testing)
void set_debug(bool enabled);

// Alias for set_debug (camelCase version)
void setDebug(bool enabled);

// Check if debug mode is enabled
bool is_debug_mode_enabled();

// Debug logging function
void debug_log(const std::string& message);

// Deterministic random functions for debug mode
std::string get_deterministic_main_secret();  // Large deterministic scalar for main secret r
std::string get_deterministic_random_scalar();
std::string get_deterministic_random_hex(size_t length);
std::vector<uint8_t> get_deterministic_random_bytes(size_t length);
std::string get_deterministic_ephemeral_secret();

} // namespace debug
} // namespace openadp 
