/*
 * gcm.h
 *
 * Lightweight MACsec stack
 * Minimal AES-GCM interface for the embedded MACsec stack
 *
 * Copyright (c) 2026 Michal Sarnovský
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */
#ifndef MATH_GCM_H
#define MATH_GCM_H

#include "common.h"

#if (MACSEC_SELF_TEST != 0)
#define MATH_SELF_TEST
#endif

#include "aes.h"

#include <stddef.h>
#include <stdint.h>

#define MATH_GCM_ENCRYPT     1
#define MATH_GCM_DECRYPT     0

#define MATH_ERR_GCM_BAD_INPUT    -1
#define MATH_ERR_GCM_AUTH_FAILED  -2

#define GCM_BLOCK_SIZE          16u
#define GCM_NIBBLE_TABLE_SIZE   16u

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    math_aes_context aes_ctx;

    uint64_t HL[GCM_NIBBLE_TABLE_SIZE];
    uint64_t HH[GCM_NIBBLE_TABLE_SIZE];

    uint64_t len;
    uint64_t add_len;

    unsigned char base_ectr[GCM_BLOCK_SIZE];
    unsigned char y[GCM_BLOCK_SIZE];
    unsigned char buf[GCM_BLOCK_SIZE];

    int mode;
} math_gcm_context;


void math_gcm_init( math_gcm_context *ctx );
void math_gcm_free( math_gcm_context *ctx );

int math_gcm_setkey( math_gcm_context *ctx,
                     const unsigned char *key,
                     unsigned int keybits );

int math_gcm_crypt_and_tag( math_gcm_context *ctx,
                            int mode,
                            size_t length,
                            const unsigned char *iv,
                            size_t iv_len,
                            const unsigned char *add,
                            size_t add_len,
                            const unsigned char *input,
                            unsigned char *output,
                            size_t tag_len,
                            unsigned char *tag );

int math_gcm_auth_decrypt( math_gcm_context *ctx,
                           size_t length,
                           const unsigned char *iv,
                           size_t iv_len,
                           const unsigned char *add,
                           size_t add_len,
                           const unsigned char *tag,
                           size_t tag_len,
                           const unsigned char *input,
                           unsigned char *output );

#if defined(MATH_SELF_TEST)
int math_gcm_self_test( int verbose );
#endif

#ifdef __cplusplus
}
#endif

#endif /* MATH_GCM_H */
