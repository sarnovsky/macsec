/*
 *  NIST SP800-38D compliant GCM implementation
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
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

#include <mbedtls/cmac.h>

#include <string.h>

#define CMAC_BLOCK_SIZE 16u
#define CMAC_RB         0x87u

static void cmac_zeroize(void *v, size_t n)
{
    volatile unsigned char *p = (volatile unsigned char *)v;

    while (n-- != 0u)
    {
        *p++ = 0u;
    }
}

static void cmac_xor_block(unsigned char out[16],
                           const unsigned char a[16],
                           const unsigned char b[16])
{
    size_t i;

    for (i = 0u; i < 16u; i++)
    {
        out[i] = (unsigned char)(a[i] ^ b[i]);
    }
}

static void cmac_left_shift_one_bit(unsigned char out[16],
                                    const unsigned char in[16])
{
    int i;
    unsigned char overflow = 0u;

    for (i = 15; i >= 0; i--)
    {
        unsigned char current = in[i];
        out[i] = (unsigned char)((current << 1) | overflow);
        overflow = (unsigned char)((current & 0x80u) ? 1u : 0u);
    }
}

static void cmac_generate_subkeys(mbedtls_cmac_context_t *ctx,
                                  unsigned char k1[16],
                                  unsigned char k2[16])
{
    unsigned char zero[16];
    unsigned char l[16];

    memset(zero, 0, sizeof(zero));

    mbedtls_aes_crypt_ecb(&ctx->aes_ctx,
                          MBEDTLS_AES_ENCRYPT,
                          zero,
                          l);

    cmac_left_shift_one_bit(k1, l);

    if ((l[0] & 0x80u) != 0u)
    {
        k1[15] ^= CMAC_RB;
    }

    cmac_left_shift_one_bit(k2, k1);

    if ((k1[0] & 0x80u) != 0u)
    {
        k2[15] ^= CMAC_RB;
    }

    cmac_zeroize(zero, sizeof(zero));
    cmac_zeroize(l, sizeof(l));
}

void mbedtls_cmac_init(mbedtls_cmac_context_t *ctx)
{
    if (ctx == NULL)
    {
        return;
    }

    memset(ctx, 0, sizeof(*ctx));
    mbedtls_aes_init(&ctx->aes_ctx);
}

void mbedtls_cmac_free(mbedtls_cmac_context_t *ctx)
{
    if (ctx == NULL)
    {
        return;
    }

    mbedtls_aes_free(&ctx->aes_ctx);
    cmac_zeroize(ctx, sizeof(*ctx));
}

int mbedtls_cmac_starts(mbedtls_cmac_context_t *ctx,
                        const unsigned char *key,
                        size_t keybits)
{
    int ret;

    if ((ctx == NULL) || (key == NULL))
    {
        return -1;
    }

    if ((keybits != 128u) && (keybits != 192u) && (keybits != 256u))
    {
        return -1;
    }

    memset(ctx->state, 0, sizeof(ctx->state));
    memset(ctx->unprocessed_block, 0, sizeof(ctx->unprocessed_block));
    ctx->unprocessed_len = 0u;

    ret = mbedtls_aes_setkey_enc(&ctx->aes_ctx,
                                 key,
                                 (unsigned int)keybits);

    if (ret != 0)
    {
        return ret;
    }

    return 0;
}

int mbedtls_cmac_update(mbedtls_cmac_context_t *ctx,
                        const unsigned char *input,
                        size_t ilen)
{
    unsigned char temp[16];
    size_t use_len;
    int ret;

    if ((ctx == NULL) || ((input == NULL) && (ilen != 0u)))
    {
        return -1;
    }

    if (ilen == 0u)
    {
        return 0;
    }

    /*
     * If there is a partial block from previous update, fill it first.
     * Do not process the final complete block yet; CMAC needs to know
     * whether the last block is complete or padded.
     */
    if (ctx->unprocessed_len > 0u)
    {
        use_len = CMAC_BLOCK_SIZE - ctx->unprocessed_len;

        if (use_len > ilen)
        {
            use_len = ilen;
        }

        memcpy(ctx->unprocessed_block + ctx->unprocessed_len,
               input,
               use_len);

        ctx->unprocessed_len += use_len;
        input += use_len;
        ilen -= use_len;

        if (ctx->unprocessed_len < CMAC_BLOCK_SIZE)
        {
            return 0;
        }

        if (ilen == 0u)
        {
            return 0;
        }

        cmac_xor_block(temp, ctx->state, ctx->unprocessed_block);

        ret = mbedtls_aes_crypt_ecb(&ctx->aes_ctx,
                                    MBEDTLS_AES_ENCRYPT,
                                    temp,
                                    ctx->state);

        if (ret != 0)
        {
            cmac_zeroize(temp, sizeof(temp));
            return ret;
        }

        ctx->unprocessed_len = 0u;
        memset(ctx->unprocessed_block, 0, sizeof(ctx->unprocessed_block));
    }

    /*
     * Process all blocks except the final block.
     */
    while (ilen > CMAC_BLOCK_SIZE)
    {
        cmac_xor_block(temp, ctx->state, input);

        ret = mbedtls_aes_crypt_ecb(&ctx->aes_ctx,
                                    MBEDTLS_AES_ENCRYPT,
                                    temp,
                                    ctx->state);

        if (ret != 0)
        {
            cmac_zeroize(temp, sizeof(temp));
            return ret;
        }

        input += CMAC_BLOCK_SIZE;
        ilen -= CMAC_BLOCK_SIZE;
    }

    /*
     * Keep the last block, complete or incomplete, for finish().
     */
    if (ilen > 0u)
    {
        memcpy(ctx->unprocessed_block, input, ilen);
        ctx->unprocessed_len = ilen;
    }

    cmac_zeroize(temp, sizeof(temp));

    return 0;
}

int mbedtls_cmac_finish(mbedtls_cmac_context_t *ctx,
                        unsigned char output[16])
{
    unsigned char k1[16];
    unsigned char k2[16];
    unsigned char last_block[16];
    unsigned char temp[16];
    int ret;

    if ((ctx == NULL) || (output == NULL))
    {
        return -1;
    }

    cmac_generate_subkeys(ctx, k1, k2);

    if (ctx->unprocessed_len == CMAC_BLOCK_SIZE)
    {
        cmac_xor_block(last_block, ctx->unprocessed_block, k1);
    }
    else
    {
        memset(last_block, 0, sizeof(last_block));

        if (ctx->unprocessed_len > 0u)
        {
            memcpy(last_block,
                   ctx->unprocessed_block,
                   ctx->unprocessed_len);
        }

        last_block[ctx->unprocessed_len] = 0x80u;

        cmac_xor_block(last_block, last_block, k2);
    }

    cmac_xor_block(temp, ctx->state, last_block);

    ret = mbedtls_aes_crypt_ecb(&ctx->aes_ctx,
                                MBEDTLS_AES_ENCRYPT,
                                temp,
                                output);

    cmac_zeroize(k1, sizeof(k1));
    cmac_zeroize(k2, sizeof(k2));
    cmac_zeroize(last_block, sizeof(last_block));
    cmac_zeroize(temp, sizeof(temp));

    return ret;
}

int mbedtls_cmac_aes(mbedtls_cmac_context_t *ctx,
                     const unsigned char *key,
                     size_t keybits,
                     const unsigned char *input,
                     size_t ilen,
                     unsigned char output[16])
{
    int ret;

    if (ctx == NULL)
    {
        return -1;
    }

    ret = mbedtls_cmac_starts(ctx, key, keybits);
    if (ret != 0)
    {
        return ret;
    }

    ret = mbedtls_cmac_update(ctx, input, ilen);
    if (ret != 0)
    {
        return ret;
    }

    ret = mbedtls_cmac_finish(ctx, output);
    if (ret != 0)
    {
        return ret;
    }

    return 0;
}

#if defined(MBEDTLS_SELF_TEST)

int mbedtls_cmac_self_test(int verbose)
{
    static const unsigned char key[16] =
    {
        0x2Bu, 0x7Eu, 0x15u, 0x16u,
        0x28u, 0xAEu, 0xD2u, 0xA6u,
        0xABu, 0xF7u, 0x15u, 0x88u,
        0x09u, 0xCFu, 0x4Fu, 0x3Cu
    };

    static const unsigned char msg[64] =
    {
        0x6Bu, 0xC1u, 0xBEu, 0xE2u,
        0x2Eu, 0x40u, 0x9Fu, 0x96u,
        0xE9u, 0x3Du, 0x7Eu, 0x11u,
        0x73u, 0x93u, 0x17u, 0x2Au,
        0xAEu, 0x2Du, 0x8Au, 0x57u,
        0x1Eu, 0x03u, 0xACu, 0x9Cu,
        0x9Eu, 0xB7u, 0x6Fu, 0xACu,
        0x45u, 0xAFu, 0x8Eu, 0x51u,
        0x30u, 0xC8u, 0x1Cu, 0x46u,
        0xA3u, 0x5Cu, 0xE4u, 0x11u,
        0xE5u, 0xFBu, 0xC1u, 0x19u,
        0x1Au, 0x0Au, 0x52u, 0xEFu,
        0xF6u, 0x9Fu, 0x24u, 0x45u,
        0xDFu, 0x4Fu, 0x9Bu, 0x17u,
        0xADu, 0x2Bu, 0x41u, 0x7Bu,
        0xE6u, 0x6Cu, 0x37u, 0x10u
    };

    static const size_t msg_len[4] =
    {
        0u,
        16u,
        40u,
        64u
    };

    static const unsigned char expected[4][16] =
    {
        {
            0xBBu, 0x1Du, 0x69u, 0x29u,
            0xE9u, 0x59u, 0x37u, 0x28u,
            0x7Fu, 0xA3u, 0x7Du, 0x12u,
            0x9Bu, 0x75u, 0x67u, 0x46u
        },
        {
            0x07u, 0x0Au, 0x16u, 0xB4u,
            0x6Bu, 0x4Du, 0x41u, 0x44u,
            0xF7u, 0x9Bu, 0xDDu, 0x9Du,
            0xD0u, 0x4Au, 0x28u, 0x7Cu
        },
        {
            0xDFu, 0xA6u, 0x67u, 0x47u,
            0xDEu, 0x9Au, 0xE6u, 0x30u,
            0x30u, 0xCAu, 0x32u, 0x61u,
            0x14u, 0x97u, 0xC8u, 0x27u
        },
        {
            0x51u, 0xF0u, 0xBEu, 0xBFu,
            0x7Eu, 0x3Bu, 0x9Du, 0x92u,
            0xFCu, 0x49u, 0x74u, 0x17u,
            0x79u, 0x36u, 0x3Cu, 0xFEu
        }
    };

    mbedtls_cmac_context_t ctx;
    unsigned char out[16];
    int ret;
    size_t i;

    if (verbose != 0)
    {
        mbedtls_printf("  CMAC self-test: ");
    }

    /*
     * Test 1: one-shot API against RFC 4493 test vectors.
     */
    mbedtls_cmac_init(&ctx);

    for (i = 0u; i < 4u; i++)
    {
        memset(out, 0, sizeof(out));

        ret = mbedtls_cmac_aes(&ctx,
                                key,
                                128u,
                                msg,
                                msg_len[i],
                                out);
        if (ret != 0)
        {
            goto fail;
        }

        if (memcmp(out, expected[i], sizeof(out)) != 0)
        {
            ret = 1;
            goto fail;
        }
    }

    mbedtls_cmac_free(&ctx);

    /*
     * Test 2: streaming API, split update.
     * Uses RFC 4493 test vector #4, 64-byte message.
     */
    mbedtls_cmac_init(&ctx);

    ret = mbedtls_cmac_starts(&ctx, key, 128u);
    if (ret != 0)
    {
        goto fail;
    }

    ret = mbedtls_cmac_update(&ctx, msg, 1u);
    if (ret != 0)
    {
        goto fail;
    }

    ret = mbedtls_cmac_update(&ctx, msg + 1u, 15u);
    if (ret != 0)
    {
        goto fail;
    }

    ret = mbedtls_cmac_update(&ctx, msg + 16u, 17u);
    if (ret != 0)
    {
        goto fail;
    }

    ret = mbedtls_cmac_update(&ctx, msg + 33u, 31u);
    if (ret != 0)
    {
        goto fail;
    }

    memset(out, 0, sizeof(out));

    ret = mbedtls_cmac_finish(&ctx, out);
    if (ret != 0)
    {
        goto fail;
    }

    if (memcmp(out, expected[3], sizeof(out)) != 0)
    {
        ret = 1;
        goto fail;
    }

    mbedtls_cmac_free(&ctx);

    /*
     * Test 3: invalid parameter checks.
     */
    mbedtls_cmac_init(&ctx);

    ret = mbedtls_cmac_starts(NULL, key, 128u);
    if (ret == 0)
    {
        goto fail_param;
    }

    ret = mbedtls_cmac_starts(&ctx, NULL, 128u);
    if (ret == 0)
    {
        goto fail_param;
    }

    ret = mbedtls_cmac_starts(&ctx, key, 129u);
    if (ret == 0)
    {
        goto fail_param;
    }

    ret = mbedtls_cmac_update(NULL, msg, 1u);
    if (ret == 0)
    {
        goto fail_param;
    }

    ret = mbedtls_cmac_update(&ctx, NULL, 1u);
    if (ret == 0)
    {
        goto fail_param;
    }

    ret = mbedtls_cmac_finish(NULL, out);
    if (ret == 0)
    {
        goto fail_param;
    }

    ret = mbedtls_cmac_finish(&ctx, NULL);
    if (ret == 0)
    {
        goto fail_param;
    }

    mbedtls_cmac_free(&ctx);

    if (verbose != 0)
    {
        mbedtls_printf("passed\n");
    }

    cmac_zeroize(out, sizeof(out));

    return 0;

fail_param:
    ret = 1;

fail:
    mbedtls_cmac_free(&ctx);
    cmac_zeroize(out, sizeof(out));

    if (verbose != 0)
    {
        mbedtls_printf("failed\n");
    }

    return 1;
}

#endif /* MBEDTLS_SELF_TEST */

