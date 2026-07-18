/*
 * aes.h
 *
 * Lightweight MACsec stack
 * Minimal AES interface for the embedded MACsec stack
 *
 * Copyright (c) 2026 Michal Sarnovsky
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */
#ifndef MATH_AES_H
#define MATH_AES_H

#include "macsec_common.h"

#if (MACSEC_SELF_TEST != 0) && !defined(MATH_SELF_TEST)
#define MATH_SELF_TEST
#endif

typedef struct
{
    uint32_t *round_keys;
    int number_of_rounds;
    uint32_t buf[68]; /* round-key buffer */
} math_aes_context;

#ifdef __cplusplus
extern "C"
{
#endif

void math_aes_init(math_aes_context *ctx);
void math_aes_free(math_aes_context *ctx);

int math_aes_setenckey(math_aes_context *ctx, const uint8_t *key, uint32_t keybits);

int math_aes_setdeckey(math_aes_context *ctx, const uint8_t *key, uint32_t keybits);

int math_aes_encrypt(math_aes_context *ctx, const uint8_t input[16], uint8_t output[16]);

int math_aes_decrypt(math_aes_context *ctx, const uint8_t input[16], uint8_t output[16]);

#if defined(MATH_SELF_TEST)
int math_aes_self_test(math_aes_context *ctx, int verbose);
#endif

#ifdef __cplusplus
}
#endif

#endif /* MATH_AES_H */
