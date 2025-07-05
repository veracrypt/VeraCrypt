#include "openadp/debug.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstdlib>

namespace openadp {
namespace debug {

// Function to check environment variable
static bool check_debug_env() {
    const char* env_debug = std::getenv("OPENADP_DEBUG");
    return env_debug != nullptr && std::string(env_debug) == "1";
}

// Global debug flag - initialize from environment
bool g_debug_mode = check_debug_env();

void set_debug(bool enabled) {
    g_debug_mode = enabled;
    if (enabled) {
        debug_log("Debug mode enabled - all operations are now deterministic");
    } else {
        debug_log("Debug mode disabled - randomness restored");
    }
}

void setDebug(bool enabled) {
    set_debug(enabled);
}

bool is_debug_mode_enabled() {
    return g_debug_mode;
}

void debug_log(const std::string& message) {
    if (g_debug_mode) {
        std::cout << "[DEBUG] " << message << std::endl;
    }
}

// Deterministic counter for reproducible "random" values
static size_t deterministic_counter = 0;

std::string get_deterministic_main_secret() {
    if (!g_debug_mode) {
        throw std::runtime_error("get_deterministic_main_secret called outside debug mode");
    }
    
    // Use the same large deterministic constant as Python/Go/JavaScript implementations
    // This is the hex pattern reduced modulo Ed25519 group order q
    // 64 characters (even length) for consistent hex parsing across all SDKs
    std::string deterministic_secret = "023456789abcdef0fedcba987654320ffd555c99f7c5421aa6ca577e195e5e23";
    
    debug_log("Using deterministic main secret r = 0x" + deterministic_secret);
    return deterministic_secret;
}

std::string get_deterministic_random_scalar() {
    if (!g_debug_mode) {
        throw std::runtime_error("get_deterministic_random_scalar called outside debug mode");
    }
    
    // In debug mode, r should always be 1
    // This is used for the random scalar in key generation
    debug_log("Using deterministic scalar r = 1");
    return "0000000000000000000000000000000000000000000000000000000000000001";
}

std::string get_deterministic_random_hex(size_t length) {
    if (!g_debug_mode) {
        throw std::runtime_error("get_deterministic_random_hex called outside debug mode");
    }
    
    deterministic_counter++;
    std::stringstream ss;
    
    // Generate deterministic hex string with C++ prefix to avoid session ID conflicts
    // Use 'C' (0x43) as first byte to make C++ session IDs unique from Python/Go
    ss << "43"; // 'C' in hex - this is 2 characters
    
    // Generate the rest of the hex string, ensuring we always produce exactly 'length' characters
    for (size_t i = 2; i < length; i += 2) {
        // Generate a full byte (2 hex chars) at a time
        int byte_val = (deterministic_counter + i) % 256;
        ss << std::hex << std::setfill('0') << std::setw(2) << byte_val;
    }
    
    std::string result = ss.str();
    
    // Ensure we have exactly the requested length
    if (result.length() > length) {
        result = result.substr(0, length);
    } else if (result.length() < length) {
        // Pad with zeros if needed
        result += std::string(length - result.length(), '0');
    }
    
    debug_log("Generated deterministic hex (" + std::to_string(length) + " chars): " + result);
    return result;
}

std::vector<uint8_t> get_deterministic_random_bytes(size_t length) {
    if (!g_debug_mode) {
        throw std::runtime_error("get_deterministic_random_bytes called outside debug mode");
    }
    
    deterministic_counter++;
    std::vector<uint8_t> bytes(length);
    
    for (size_t i = 0; i < length; i++) {
        bytes[i] = static_cast<uint8_t>((deterministic_counter + i) % 256);
    }
    
    debug_log("Generated deterministic bytes (" + std::to_string(length) + " bytes)");
    return bytes;
}

std::string get_deterministic_ephemeral_secret() {
    if (!g_debug_mode) {
        throw std::runtime_error("get_deterministic_ephemeral_secret called outside debug mode");
    }
    
    // Fixed ephemeral secret for reproducible Noise handshakes
    // This should be 32 bytes (64 hex chars) for X25519
    // Match Python/Go implementation ending in 04
    debug_log("Using deterministic ephemeral secret");
    return "0000000000000000000000000000000000000000000000000000000000000004";
}

} // namespace debug
} // namespace openadp 
