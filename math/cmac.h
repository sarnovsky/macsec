/*
 * cmac.h
 *
 * Lightweight MACsec stack
 * Minimal AES-CMAC interface for the embedded MACsec stack
 *
 * Copyright (c) 2026 Michal Sarnovský
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */
#ifndef MATH_CMAC_H
#define MATH_CMAC_H

#include "common.h"

#if (MACSEC_SELF_TEST != 0)
#define MATH_SELF_TEST
#endif

#include "aes.h"

#define MATH_AES_BLOCK_SIZE 16

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    math_aes_context aes_ctx;
    unsigned char state[MATH_AES_BLOCK_SIZE];
    unsigned char unprocessed_block[MATH_AES_BLOCK_SIZE];
    size_t unprocessed_len;
} math_cmac_context_t;

void math_cmac_init( math_cmac_context_t *ctx );
void math_cmac_free( math_cmac_context_t *ctx );

int math_cmac_aes( math_cmac_context_t *ctx,
                   const unsigned char *key,
                   size_t keybits,
                   const unsigned char *input,
                   size_t ilen,
                   unsigned char output[16] );

#if defined(MATH_SELF_TEST)
int math_cmac_self_test( math_cmac_context_t *ctx, int verbose );
#endif

#ifdef __cplusplus
}
#endif

#endif /* MATH_CMAC_H */
