#include "openadp/utils.hpp"
#include "openadp/types.hpp"
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <memory>

namespace openadp {
namespace utils {

std::string base64_encode(const Bytes& data) {
    if (data.empty()) return "";
    
    BIO* bio_mem = BIO_new(BIO_s_mem());
    BIO* bio_b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(bio_b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(bio_b64, bio_mem);
    
    BIO_write(bio_b64, data.data(), static_cast<int>(data.size()));
    BIO_flush(bio_b64);
    
    BUF_MEM* buf_mem;
    BIO_get_mem_ptr(bio_b64, &buf_mem);
    
    std::string result(buf_mem->data, buf_mem->length);
    
    BIO_free_all(bio_b64);
    
    return result;
}

Bytes base64_decode(const std::string& encoded) {
    if (encoded.empty()) return {};
    
    // Validate base64 characters
    const std::string valid_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    for (char c : encoded) {
        if (valid_chars.find(c) == std::string::npos) {
            throw OpenADPError("Invalid base64 character: " + std::string(1, c));
        }
    }
    
    BIO* bio_mem = BIO_new_mem_buf(encoded.c_str(), static_cast<int>(encoded.length()));
    BIO* bio_b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(bio_b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(bio_b64, bio_mem);
    
    Bytes result(encoded.length());
    int decoded_length = BIO_read(bio_b64, result.data(), static_cast<int>(result.size()));
    
    BIO_free_all(bio_b64);
    
    if (decoded_length < 0) {
        throw OpenADPError("Base64 decode failed");
    }
    
    result.resize(decoded_length);
    return result;
}

} // namespace utils
} // namespace openadp 