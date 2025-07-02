#include "openadp/utils.hpp"
#include <unistd.h>

namespace openadp {
namespace utils {

// Get hostname
std::string get_hostname() {
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        hostname[sizeof(hostname) - 1] = '\0'; // Ensure null termination
        return std::string(hostname);
    }
    return "unknown"; // Fallback if gethostname fails
}

} // namespace utils
} // namespace openadp 