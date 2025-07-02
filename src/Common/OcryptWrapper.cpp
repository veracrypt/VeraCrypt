/*
 * Simple C wrapper for OpenADP Ocrypt distributed password hashing
 * Copyright (c) 2025 OpenADP
 */

#include "OcryptWrapper.h"
#include "../OpenADP/include/openadp/ocrypt.hpp"
#include <cstring>
#include <memory>

extern "C" {

/* Register a secret protected by a password using distributed cryptography */
int ocrypt_register_secret(
    const char* user_id,
    const char* app_id, 
    const unsigned char* secret,
    int secret_len,
    const char* password,
    int max_guesses,
    unsigned char** metadata_out,
    int* metadata_len_out)
{
    try {
        // Convert C types to C++ types
        std::string cpp_user_id(user_id);
        std::string cpp_app_id(app_id);
        std::string cpp_password(password);
        openadp::Bytes cpp_secret(secret, secret + secret_len);
        
        // Call the simple Ocrypt API
        openadp::Bytes metadata = openadp::ocrypt::register_secret(
            cpp_user_id,
            cpp_app_id,
            cpp_secret,
            cpp_password,
            max_guesses
        );
        
        // Allocate memory for output
        *metadata_len_out = static_cast<int>(metadata.size());
        *metadata_out = static_cast<unsigned char*>(malloc(*metadata_len_out));
        if (*metadata_out == nullptr) {
            return -1; // Memory allocation failed
        }
        
        // Copy metadata to output buffer
        std::memcpy(*metadata_out, metadata.data(), *metadata_len_out);
        
        return 0; // Success
        
    } catch (...) {
        return -1; // Error occurred
    }
}

/* Recover a secret using password and metadata */
int ocrypt_recover_secret(
    const unsigned char* metadata,
    int metadata_len,
    const char* password,
    unsigned char** secret_out,
    int* secret_len_out,
    int* remaining_guesses_out,
    unsigned char** updated_metadata_out,
    int* updated_metadata_len_out)
{
    try {
        // Convert C types to C++ types
        openadp::Bytes cpp_metadata(metadata, metadata + metadata_len);
        std::string cpp_password(password);
        
        // Call the simple Ocrypt API
        openadp::ocrypt::OcryptRecoverResult result = openadp::ocrypt::recover(
            cpp_metadata,
            cpp_password
        );
        
        // Allocate memory for secret output
        *secret_len_out = static_cast<int>(result.secret.size());
        *secret_out = static_cast<unsigned char*>(malloc(*secret_len_out));
        if (*secret_out == nullptr) {
            return -1; // Memory allocation failed
        }
        
        // Allocate memory for updated metadata output
        *updated_metadata_len_out = static_cast<int>(result.updated_metadata.size());
        *updated_metadata_out = static_cast<unsigned char*>(malloc(*updated_metadata_len_out));
        if (*updated_metadata_out == nullptr) {
            free(*secret_out);
            return -1; // Memory allocation failed
        }
        
        // Copy results to output buffers
        std::memcpy(*secret_out, result.secret.data(), *secret_len_out);
        std::memcpy(*updated_metadata_out, result.updated_metadata.data(), *updated_metadata_len_out);
        *remaining_guesses_out = result.remaining_guesses;
        
        return 0; // Success
        
    } catch (...) {
        return -1; // Error occurred
    }
}

/* Free memory allocated by ocrypt functions */
void ocrypt_free_memory(unsigned char* ptr)
{
    if (ptr != nullptr) {
        free(ptr);
    }
}

} // extern "C"
