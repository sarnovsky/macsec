/*
 * cmac.c
 *
 * Lightweight MACsec stack
 * Minimal AES-CMAC implementation for the embedded MACsec stack
 *
 * Copyright (c) 2026 Michal Sarnovský
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */
#include "cmac.h"

#define CMAC_BLOCK_SIZE 16u
#define CMAC_RB         0x87u

static void cmac_zeroize( void *v, size_t n )
{
    volatile unsigned char *p = (volatile unsigned char *) v;

    while( n-- != 0u )
        *p++ = 0u;
}

static void cmac_xor_block( unsigned char out[16],
                            const unsigned char a[16],
                            const unsigned char b[16] )
{
    size_t i;

    for( i = 0u; i < 16u; i++ )
        out[i] = (unsigned char) ( a[i] ^ b[i] );
}

static void cmac_left_shift_one_bit( unsigned char out[16],
                                     const unsigned char in[16] )
{
    int i;
    unsigned char overflow = 0u;

    for( i = 15; i >= 0; i-- )
    {
        unsigned char current = in[i];
        out[i] = (unsigned char) ( ( current << 1 ) | overflow );
        overflow = (unsigned char) ( ( current & 0x80u ) ? 1u : 0u );
    }
}

static void cmac_generate_subkeys( math_cmac_context_t *ctx,
                                   unsigned char k1[16],
                                   unsigned char k2[16] )
{
    unsigned char zero[16];
    unsigned char l[16];

    memset( zero, 0, sizeof( zero ) );

    (void) math_aes_crypt_ecb( &ctx->aes_ctx,
                                  MATH_AES_ENCRYPT,
                                  zero,
                                  l );

    cmac_left_shift_one_bit( k1, l );
    if( ( l[0] & 0x80u ) != 0u )
        k1[15] ^= CMAC_RB;

    cmac_left_shift_one_bit( k2, k1 );
    if( ( k1[0] & 0x80u ) != 0u )
        k2[15] ^= CMAC_RB;

    cmac_zeroize( zero, sizeof( zero ) );
    cmac_zeroize( l, sizeof( l ) );
}

void math_cmac_init( math_cmac_context_t *ctx )
{
    if( ctx == NULL )
        return;

    memset( ctx, 0, sizeof( *ctx ) );
    math_aes_init( &ctx->aes_ctx );
}

void math_cmac_free( math_cmac_context_t *ctx )
{
    if( ctx == NULL )
        return;

    math_aes_free( &ctx->aes_ctx );
    cmac_zeroize( ctx, sizeof( *ctx ) );
}

static int cmac_starts( math_cmac_context_t *ctx,
                        const unsigned char *key,
                        size_t keybits )
{
    int ret;

    if( ctx == NULL || key == NULL )
        return -1;

    if( keybits != 128u && keybits != 192u && keybits != 256u )
        return -1;

    memset( ctx->state, 0, sizeof( ctx->state ) );
    memset( ctx->unprocessed_block, 0, sizeof( ctx->unprocessed_block ) );
    ctx->unprocessed_len = 0u;

    ret = math_aes_setkey_enc( &ctx->aes_ctx,
                                  key,
                                  (unsigned int) keybits );
    if( ret != 0 )
        return ret;

    return 0;
}

static int cmac_update( math_cmac_context_t *ctx,
                        const unsigned char *input,
                        size_t ilen )
{
    unsigned char temp[16];
    size_t use_len;
    int ret;

    if( ctx == NULL || ( input == NULL && ilen != 0u ) )
        return -1;

    if( ilen == 0u )
        return 0;

    if( ctx->unprocessed_len > 0u )
    {
        use_len = CMAC_BLOCK_SIZE - ctx->unprocessed_len;
        if( use_len > ilen )
            use_len = ilen;

        memcpy( ctx->unprocessed_block + ctx->unprocessed_len,
                input,
                use_len );

        ctx->unprocessed_len += use_len;
        input += use_len;
        ilen -= use_len;

        if( ctx->unprocessed_len < CMAC_BLOCK_SIZE )
            return 0;

        /* Keep a complete final block unprocessed until finish(). */
        if( ilen == 0u )
            return 0;

        cmac_xor_block( temp, ctx->state, ctx->unprocessed_block );

        ret = math_aes_crypt_ecb( &ctx->aes_ctx,
                                     MATH_AES_ENCRYPT,
                                     temp,
                                     ctx->state );
        if( ret != 0 )
        {
            cmac_zeroize( temp, sizeof( temp ) );
            return ret;
        }

        ctx->unprocessed_len = 0u;
        memset( ctx->unprocessed_block, 0, sizeof( ctx->unprocessed_block ) );
    }

    while( ilen > CMAC_BLOCK_SIZE )
    {
        cmac_xor_block( temp, ctx->state, input );

        ret = math_aes_crypt_ecb( &ctx->aes_ctx,
                                     MATH_AES_ENCRYPT,
                                     temp,
                                     ctx->state );
        if( ret != 0 )
        {
            cmac_zeroize( temp, sizeof( temp ) );
            return ret;
        }

        input += CMAC_BLOCK_SIZE;
        ilen -= CMAC_BLOCK_SIZE;
    }

    if( ilen > 0u )
    {
        memcpy( ctx->unprocessed_block, input, ilen );
        ctx->unprocessed_len = ilen;
    }

    cmac_zeroize( temp, sizeof( temp ) );

    return 0;
}

static int cmac_finish( math_cmac_context_t *ctx,
                        unsigned char output[16] )
{
    unsigned char k1[16];
    unsigned char k2[16];
    unsigned char last_block[16];
    unsigned char temp[16];
    int ret;

    if( ctx == NULL || output == NULL )
        return -1;

    cmac_generate_subkeys( ctx, k1, k2 );

    if( ctx->unprocessed_len == CMAC_BLOCK_SIZE )
    {
        cmac_xor_block( last_block, ctx->unprocessed_block, k1 );
    }
    else
    {
        memset( last_block, 0, sizeof( last_block ) );

        if( ctx->unprocessed_len > 0u )
        {
            memcpy( last_block,
                    ctx->unprocessed_block,
                    ctx->unprocessed_len );
        }

        last_block[ctx->unprocessed_len] = 0x80u;
        cmac_xor_block( last_block, last_block, k2 );
    }

    cmac_xor_block( temp, ctx->state, last_block );

    ret = math_aes_crypt_ecb( &ctx->aes_ctx,
                                 MATH_AES_ENCRYPT,
                                 temp,
                                 output );

    cmac_zeroize( k1, sizeof( k1 ) );
    cmac_zeroize( k2, sizeof( k2 ) );
    cmac_zeroize( last_block, sizeof( last_block ) );
    cmac_zeroize( temp, sizeof( temp ) );

    return ret;
}

int math_cmac_aes( math_cmac_context_t *ctx,
                      const unsigned char *key,
                      size_t keybits,
                      const unsigned char *input,
                      size_t ilen,
                      unsigned char output[16] )
{
    int ret;

    ret = cmac_starts( ctx, key, keybits );
    if( ret != 0 )
        return ret;

    ret = cmac_update( ctx, input, ilen );
    if( ret != 0 )
        return ret;

    return cmac_finish( ctx, output );
}

#if defined(MATH_SELF_TEST)

typedef struct
{
    const unsigned char *key;
    size_t keybits;
    const unsigned char (*expected)[16];
    const char *name;
} cmac_test_suite_t;

static int cmac_run_vector_suite(math_cmac_context_t *ctx,
                                 const cmac_test_suite_t *suite,
                                 const unsigned char *msg,
                                 const size_t msg_len[4],
                                 unsigned char out[16],
                                 int verbose)
{
    size_t i;
    int ret;

    if ((ctx == NULL) ||
        (suite == NULL) ||
        (suite->key == NULL) ||
        (suite->expected == NULL) ||
        (msg == NULL) ||
        (msg_len == NULL) ||
        (out == NULL))
    {
        return 1;
    }

    if (verbose != 0)
    {
        macsec_printf("    %s: ", suite->name);
    }

    for (i = 0u; i < 4u; i++)
    {
        memset(out, 0, 16u);

        ret = math_cmac_aes(ctx,
                            suite->key,
                            suite->keybits,
                            msg,
                            msg_len[i],
                            out);
        if (ret != 0)
        {
            if (verbose != 0)
            {
                macsec_printf("crypto error %d\n", ret);
            }

            return 1;
        }

        if (memcmp(out, suite->expected[i], 16u) != 0)
        {
            if (verbose != 0)
            {
                macsec_printf("vector %u failed\n", (unsigned)i + 1u);
                MACSEC_PRINT_HEX(("Calculated CMAC", out, 16));
                MACSEC_PRINT_HEX(("Expected CMAC",
                                  suite->expected[i],
                                  16));
            }

            return 1;
        }
    }

    if (verbose != 0)
    {
        macsec_printf("passed\n");
    }

    return 0;
}

static int cmac_run_streaming_test(math_cmac_context_t *ctx,
                                   const unsigned char *key,
                                   size_t keybits,
                                   const unsigned char *msg,
                                   const unsigned char expected[16],
                                   unsigned char out[16],
                                   int verbose)
{
    int ret;

    if (verbose != 0)
    {
        macsec_printf("    AES-%u streaming: ",
                      (unsigned)keybits);
    }

    ret = cmac_starts(ctx, key, keybits);
    if (ret != 0)
    {
        goto fail;
    }

    /*
     * Exercise boundaries around complete and partial blocks:
     *
     *   1 + 15 + 17 + 31 = 64 bytes
     */
    ret = cmac_update(ctx, msg, 1u);
    if (ret != 0)
    {
        goto fail;
    }

    ret = cmac_update(ctx, msg + 1u, 15u);
    if (ret != 0)
    {
        goto fail;
    }

    ret = cmac_update(ctx, msg + 16u, 17u);
    if (ret != 0)
    {
        goto fail;
    }

    ret = cmac_update(ctx, msg + 33u, 31u);
    if (ret != 0)
    {
        goto fail;
    }

    memset(out, 0, 16u);

    ret = cmac_finish(ctx, out);
    if (ret != 0)
    {
        goto fail;
    }

    if (memcmp(out, expected, 16u) != 0)
    {
        if (verbose != 0)
        {
            macsec_printf("failed\n");
            MACSEC_PRINT_HEX(("Calculated CMAC", out, 16));
            MACSEC_PRINT_HEX(("Expected CMAC", expected, 16));
        }

        return 1;
    }

    if (verbose != 0)
    {
        macsec_printf("passed\n");
    }

    return 0;

fail:
    if (verbose != 0)
    {
        macsec_printf("crypto error %d\n", ret);
    }

    return 1;
}

int math_cmac_self_test( math_cmac_context_t *ctx, int verbose )
{
    /*
     * NIST SP 800-38B CMAC-AES examples.
     *
     * The message is shared by AES-128, AES-192 and AES-256 suites.
     */
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
        20u,
        64u
    };

    static const unsigned char key_128[16] =
    {
        0x2Bu, 0x7Eu, 0x15u, 0x16u,
        0x28u, 0xAEu, 0xD2u, 0xA6u,
        0xABu, 0xF7u, 0x15u, 0x88u,
        0x09u, 0xCFu, 0x4Fu, 0x3Cu
    };

    static const unsigned char expected_128[4][16] =
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
            0x7Du, 0x85u, 0x44u, 0x9Eu,
            0xA6u, 0xEAu, 0x19u, 0xC8u,
            0x23u, 0xA7u, 0xBFu, 0x78u,
            0x83u, 0x7Du, 0xFAu, 0xDEu
        },
        {
            0x51u, 0xF0u, 0xBEu, 0xBFu,
            0x7Eu, 0x3Bu, 0x9Du, 0x92u,
            0xFCu, 0x49u, 0x74u, 0x17u,
            0x79u, 0x36u, 0x3Cu, 0xFEu
        }
    };

    static const unsigned char key_192[24] =
    {
        0x8Eu, 0x73u, 0xB0u, 0xF7u,
        0xDAu, 0x0Eu, 0x64u, 0x52u,
        0xC8u, 0x10u, 0xF3u, 0x2Bu,
        0x80u, 0x90u, 0x79u, 0xE5u,
        0x62u, 0xF8u, 0xEAu, 0xD2u,
        0x52u, 0x2Cu, 0x6Bu, 0x7Bu
    };

    static const unsigned char expected_192[4][16] =
    {
        {
            0xD1u, 0x7Du, 0xDFu, 0x46u,
            0xADu, 0xAAu, 0xCDu, 0xE5u,
            0x31u, 0xCAu, 0xC4u, 0x83u,
            0xDEu, 0x7Au, 0x93u, 0x67u
        },
        {
            0x9Eu, 0x99u, 0xA7u, 0xBFu,
            0x31u, 0xE7u, 0x10u, 0x90u,
            0x06u, 0x62u, 0xF6u, 0x5Eu,
            0x61u, 0x7Cu, 0x51u, 0x84u
        },
        {
            0x3Du, 0x75u, 0xC1u, 0x94u,
            0xEDu, 0x96u, 0x07u, 0x04u,
            0x44u, 0xA9u, 0xFAu, 0x7Eu,
            0xC7u, 0x40u, 0xECu, 0xF8u
        },
        {
            0xA1u, 0xD5u, 0xDFu, 0x0Eu,
            0xEDu, 0x79u, 0x0Fu, 0x79u,
            0x4Du, 0x77u, 0x58u, 0x96u,
            0x59u, 0xF3u, 0x9Au, 0x11u
        }
    };

    static const unsigned char key_256[32] =
    {
        0x60u, 0x3Du, 0xEBu, 0x10u,
        0x15u, 0xCAu, 0x71u, 0xBEu,
        0x2Bu, 0x73u, 0xAEu, 0xF0u,
        0x85u, 0x7Du, 0x77u, 0x81u,

        0x1Fu, 0x35u, 0x2Cu, 0x07u,
        0x3Bu, 0x61u, 0x08u, 0xD7u,
        0x2Du, 0x98u, 0x10u, 0xA3u,
        0x09u, 0x14u, 0xDFu, 0xF4u
    };

    static const unsigned char expected_256[4][16] =
    {
        {
            0x02u, 0x89u, 0x62u, 0xF6u,
            0x1Bu, 0x7Bu, 0xF8u, 0x9Eu,
            0xFCu, 0x6Bu, 0x55u, 0x1Fu,
            0x46u, 0x67u, 0xD9u, 0x83u
        },
        {
            0x28u, 0xA7u, 0x02u, 0x3Fu,
            0x45u, 0x2Eu, 0x8Fu, 0x82u,
            0xBDu, 0x4Bu, 0xF2u, 0x8Du,
            0x8Cu, 0x37u, 0xC3u, 0x5Cu
        },
        {
            0x15u, 0x67u, 0x27u, 0xDCu,
            0x08u, 0x78u, 0x94u, 0x4Au,
            0x02u, 0x3Cu, 0x1Fu, 0xE0u,
            0x3Bu, 0xADu, 0x6Du, 0x93u
        },
        {
            0xE1u, 0x99u, 0x21u, 0x90u,
            0x54u, 0x9Fu, 0x6Eu, 0xD5u,
            0x69u, 0x6Au, 0x2Cu, 0x05u,
            0x6Cu, 0x31u, 0x54u, 0x10u
        }
    };

    static const cmac_test_suite_t suites[] =
    {
        {
            key_128,
            128u,
            expected_128,
            "AES-128-CMAC"
        },
        {
            key_192,
            192u,
            expected_192,
            "AES-192-CMAC"
        },
        {
            key_256,
            256u,
            expected_256,
            "AES-256-CMAC"
        }
    };

    unsigned char out[16];
    size_t i;
    int ret;

    if (verbose != 0)
    {
        macsec_printf("  AES-CMAC self-test:\n");
    }

    math_cmac_init(ctx);
    memset(out, 0, sizeof(out));

    /*
     * Known-answer tests for all AES key lengths.
     */
    for (i = 0u; i < (sizeof(suites) / sizeof(suites[0])); i++)
    {
        ret = cmac_run_vector_suite(ctx,
                                    &suites[i],
                                    msg,
                                    msg_len,
                                    out,
                                    verbose);
        if (ret != 0)
        {
            goto fail;
        }
    }

    /*
     * Exercise the streaming path independently for AES-128
     * and AES-256. The CMAC result must match the 64-byte
     * one-shot NIST vector.
     */
    ret = cmac_run_streaming_test(ctx,
                                  key_128,
                                  128u,
                                  msg,
                                  expected_128[3],
                                  out,
                                  verbose);
    if (ret != 0)
    {
        goto fail;
    }

    ret = cmac_run_streaming_test(ctx,
                                  key_256,
                                  256u,
                                  msg,
                                  expected_256[3],
                                  out,
                                  verbose);
    if (ret != 0)
    {
        goto fail;
    }

    /*
     * Invalid-argument tests.
     */
    if ((cmac_starts(NULL, key_128, 128u) == 0) ||
        (cmac_starts(ctx, NULL, 128u) == 0) ||
        (cmac_starts(ctx, key_128, 129u) == 0) ||
        (cmac_update(NULL, msg, 1u) == 0) ||
        (cmac_update(ctx, NULL, 1u) == 0) ||
        (cmac_finish(NULL, out) == 0) ||
        (cmac_finish(ctx, NULL) == 0) ||
        (math_cmac_aes(NULL,
                       key_128,
                       128u,
                       msg,
                       1u,
                       out) == 0))
    {
        goto fail;
    }

    math_cmac_free(ctx);
    cmac_zeroize(out, sizeof(out));

    if (verbose != 0)
    {
        macsec_printf("  AES-CMAC self-test passed\n");
    }

    return 0;

fail:
    math_cmac_free(ctx);
    cmac_zeroize(out, sizeof(out));

    if (verbose != 0)
    {
        macsec_printf("  AES-CMAC self-test failed\n");
    }

    return 1;
}

#endif /* MATH_SELF_TEST */
