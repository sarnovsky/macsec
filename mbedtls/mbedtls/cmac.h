/**
 * \file cmac.h
 *
 * \brief Cipher-based Message Authentication Code (CMAC) Mode for
 *        Authentication
 *
 *  Copyright (C) 2015-2016, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 *
 *  Modified by Michal Sarnovský, 2026:
 *  - refactored almost the whole code do dump calloc and free dependecies and left support only for AES
 */
#ifndef MBEDTLS_CMAC_H
#define MBEDTLS_CMAC_H

#include <stddef.h>
#include <mbedtls/aes.h>

#define MBEDTLS_AES_BLOCK_SIZE 16

typedef struct mbedtls_cmac_context_t
{
    mbedtls_aes_context aes_ctx;
    unsigned char state[MBEDTLS_AES_BLOCK_SIZE];
    unsigned char unprocessed_block[MBEDTLS_AES_BLOCK_SIZE];
    size_t unprocessed_len;
} mbedtls_cmac_context_t;

void mbedtls_cmac_init(mbedtls_cmac_context_t *ctx);
void mbedtls_cmac_free(mbedtls_cmac_context_t *ctx);

int mbedtls_cmac_starts(mbedtls_cmac_context_t *ctx,
                        const unsigned char *key,
                        size_t keybits);

int mbedtls_cmac_update(mbedtls_cmac_context_t *ctx,
                        const unsigned char *input,
                        size_t ilen);

int mbedtls_cmac_finish(mbedtls_cmac_context_t *ctx,
                        unsigned char output[16]);

int mbedtls_cmac_aes(mbedtls_cmac_context_t *ctx,
                     const unsigned char *key,
                     size_t keybits,
                     const unsigned char *input,
                     size_t ilen,
                     unsigned char output[16]);

#if defined(MBEDTLS_SELF_TEST)
int mbedtls_cmac_self_test(int verbose);
#endif /* MBEDTLS_SELF_TEST */

#endif /* MBEDTLS_CMAC_H */
