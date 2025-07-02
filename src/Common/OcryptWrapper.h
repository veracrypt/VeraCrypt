/*
 * Simple C wrapper for OpenADP Ocrypt distributed password hashing
 * Copyright (c) 2025 OpenADP
 */

#ifndef OCRYPT_WRAPPER_H
#define OCRYPT_WRAPPER_H

#include "Tcdefs.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Register a secret protected by a password using distributed cryptography */
int ocrypt_register_secret(
    const char* user_id,
    const char* app_id, 
    const unsigned char* secret,
    int secret_len,
    const char* password,
    int max_guesses,
    unsigned char** metadata_out,
    int* metadata_len_out
);

/* Recover a secret using password and metadata */
int ocrypt_recover_secret(
    const unsigned char* metadata,
    int metadata_len,
    const char* password,
    unsigned char** secret_out,
    int* secret_len_out,
    int* remaining_guesses_out,
    unsigned char** updated_metadata_out,
    int* updated_metadata_len_out
);

/* Free memory allocated by ocrypt functions */
void ocrypt_free_memory(unsigned char* ptr);

#ifdef __cplusplus
}
#endif

#endif /* OCRYPT_WRAPPER_H */
