/*
 * aes.h
 *
 * Lightweight MACsec stack
 * Minimal AES interface for the embedded MACsec stack
 *
 * Copyright (c) 2026 Michal Sarnovský
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */
#ifndef MATH_AES_H
#define MATH_AES_H

#include "common.h"

#if (MACSEC_SELF_TEST != 0)
#define MATH_SELF_TEST
#endif

#define MATH_AES_ROM_TABLES
// #define MBEDTLS_AES_FEWER_TABLES

#define MATH_AES_ENCRYPT     1
#define MATH_AES_DECRYPT     0

typedef struct
{
    uint32_t *round_keys;
    int number_of_rounds;
    uint32_t buf[68];   /* round-key buffer */
} math_aes_context;

#ifdef __cplusplus
extern "C" {
#endif

void math_aes_init( math_aes_context *ctx );
void math_aes_free( math_aes_context *ctx );

int math_aes_setkey_enc( math_aes_context *ctx,
                         const unsigned char *key,
                         unsigned int keybits );

int math_aes_setkey_dec( math_aes_context *ctx,
                         const unsigned char *key,
                         unsigned int keybits );

int math_aes_crypt_ecb( math_aes_context *ctx,
                        int mode,
                        const unsigned char input[16],
                        unsigned char output[16] );

#if defined(MATH_SELF_TEST)
int math_aes_self_test( math_aes_context *ctx, int verbose );
#endif

#ifdef __cplusplus
}
#endif

#endif /* MATH_AES_H */
