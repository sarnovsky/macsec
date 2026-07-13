/*
 * mka_crypto.c
 *
 * Lightweight MACsec stack
 * Cryptographic helper functions for the MKA protocol.
 * This file contains MKA-specific cryptographic operations such as key
 * derivation, integrity calculation and other helpers built on top of the
 * selected cryptographic backend.
 *
 * Copyright (c) 2026 Michal Sarnovský
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */

#include "mka_crypto.h"

#define MACSEC_MKA_AES_BLOCK_LEN        16u
#define MACSEC_MKA_AES_KW_IV_BYTE       0xA6u

static macsec_bool_t macsec_mka_key_len_valid(size_t key_len)
{
    return (key_len == 16u) || (key_len == 32u);
}

static int macsec_mka_cmac(macsec_mka_crypto_ctx_t *ctx,
                           const uint8_t *key,
                           size_t key_len,
                           const uint8_t *input,
                           size_t input_len,
                           uint8_t out[16])
{
    int ret;

    macsec_assert(ctx != NULL);
    macsec_assert(key != NULL);
    macsec_assert(input != NULL);
    macsec_assert(out != NULL);
    macsec_check(macsec_mka_key_len_valid(key_len), MACSEC_ERR_PARAM);

    ret = math_cmac_aes(&ctx->cmac_ctx,
                           key,
                           (unsigned int)(key_len * 8u),
                           input,
                           input_len,
                           out);

    if (ret != 0)
        return MACSEC_ERR_CRYPTO;

    MACSEC_INFO_HEX(("MKA CMAC output", out, 16));

    return MACSEC_ERR_OK;
}

static int macsec_mka_kdf(macsec_mka_crypto_ctx_t *ctx,
                          const uint8_t *key,
                          size_t key_len,
                          const char *label,
                          const uint8_t *context,
                          size_t context_len,
                          uint16_t out_bits,
                          uint8_t *out,
                          size_t out_len)
{
    uint8_t buf[1u + 12u + 1u + MACSEC_MKA_CKN_MAX_LEN + 2u];
    uint8_t cmac_out[16];
    size_t label_len;
    size_t buf_len;
    size_t produced;
    uint8_t counter;
    int ret;

    macsec_assert(ctx != NULL);
    macsec_assert(key != NULL);
    macsec_assert(label != NULL);
    macsec_assert(context != NULL);
    macsec_assert(out != NULL);
    macsec_check(macsec_mka_key_len_valid(key_len), MACSEC_ERR_PARAM);

    label_len = strlen(label);

    macsec_check(label_len <= 12u, MACSEC_ERR_PARAM);
    macsec_check(context_len <= MACSEC_MKA_CKN_MAX_LEN, MACSEC_ERR_PARAM);
    macsec_check(out_len == ((out_bits + 7u) / 8u), MACSEC_ERR_PARAM);

    MACSEC_MEDIUM(("MKA KDF: label='%s' key_len=%lu context_len=%lu out_bits=%u out_len=%lu\n",
                   label,
                   (unsigned long)key_len,
                   (unsigned long)context_len,
                   out_bits,
                   (unsigned long)out_len));

    MACSEC_INFO_HEX(("MKA KDF context", context, (int)context_len));

    memset(out, 0, out_len);

    produced = 0u;
    counter = 1u;

    while (produced < out_len)
    {
        size_t copy_len;

        buf_len = 0u;

        buf[buf_len++] = counter;

        memcpy(&buf[buf_len], label, label_len);
        buf_len += label_len;

        buf[buf_len++] = 0x00u;

        memcpy(&buf[buf_len], context, context_len);
        buf_len += context_len;

        macsec_wr_be16(&buf[buf_len], out_bits);
        buf_len += 2u;

        MACSEC_INFO_HEX(("MKA KDF CMAC input", buf, (int)buf_len));

        ret = macsec_mka_cmac(ctx,
                              key,
                              key_len,
                              buf,
                              buf_len,
                              cmac_out);

        if (ret != MACSEC_ERR_OK)
        {
            MACSEC_ERROR(("MKA KDF CMAC failed ret=%d\n", ret));
            macsec_zeroize(buf, sizeof(buf));
            macsec_zeroize(cmac_out, sizeof(cmac_out));
            return ret;
        }

        copy_len = out_len - produced;

        if (copy_len > sizeof(cmac_out))
        {
            copy_len = sizeof(cmac_out);
        }

        memcpy(&out[produced], cmac_out, copy_len);
        produced += copy_len;
        counter++;
    }

    MACSEC_MEDIUM_HEX(("MKA KDF output", out, (int)out_len));

    macsec_zeroize(buf, sizeof(buf));
    macsec_zeroize(cmac_out, sizeof(cmac_out));

    return MACSEC_ERR_OK;
}

static int macsec_mka_derive_one(macsec_mka_crypto_ctx_t *ctx,
                                 const char *label,
                                 uint8_t *out,
                                 size_t out_len)
{
    uint8_t keyid[16];
    uint16_t out_bits;
    int ret;

    macsec_assert(ctx != NULL);
    macsec_assert(label != NULL);
    macsec_assert(out != NULL);
    macsec_check(ctx->psk.valid, MACSEC_ERR_STATE);

    macsec_check((out_len == 16u) || (out_len == 32u),
                 MACSEC_ERR_PARAM);

    memset(keyid, 0, sizeof(keyid));

    memcpy(keyid,
           ctx->psk.ckn,
           (ctx->psk.ckn_len < sizeof(keyid)) ?
               ctx->psk.ckn_len :
               sizeof(keyid));

    out_bits = (uint16_t)(out_len * 8u);

    MACSEC_MEDIUM((
        "MKA derive one: label='%s' cak_len=%u "
        "ckn_len=%u out_len=%lu\n",
        label,
        ctx->psk.cak_len,
        ctx->psk.ckn_len,
        (unsigned long)out_len));

    MACSEC_INFO_HEX(("MKA derive KeyID",
                     keyid,
                     sizeof(keyid)));

    ret = macsec_mka_kdf(ctx,
                         ctx->psk.cak,
                         ctx->psk.cak_len,
                         label,
                         keyid,
                         sizeof(keyid),
                         out_bits,
                         out,
                         out_len);

    if (ret == MACSEC_ERR_OK)
    {
        MACSEC_MEDIUM_HEX(("MKA derived key",
                           out,
                           (int)out_len));
    }

    macsec_zeroize(keyid, sizeof(keyid));

    return ret;
}

/*
 * RFC 3394 AES Key Wrap.
 */
static int macsec_mka_aes_kw_wrap(macsec_mka_crypto_ctx_t *ctx,
                                  const uint8_t *kek,
                                  size_t kek_len,
                                  const uint8_t *plain,
                                  size_t plain_len,
                                  uint8_t *wrapped,
                                  size_t *wrapped_len,
                                  size_t wrapped_max_len)
{
    uint8_t a[8];
    uint8_t block[16];
    uint8_t b[16];
    size_t n;
    size_t i;
    size_t j;
    uint64_t t;
    int ret;

    macsec_assert(ctx != NULL);
    macsec_assert(kek != NULL);
    macsec_assert(plain != NULL);
    macsec_assert(wrapped != NULL);
    macsec_assert(wrapped_len != NULL);

    macsec_check((kek_len == 16u) || (kek_len == 32u),
                 MACSEC_ERR_PARAM);
    macsec_check((plain_len >= 16u) && ((plain_len % 8u) == 0u),
                 MACSEC_ERR_PARAM);
    macsec_check((plain_len + 8u) <= wrapped_max_len, MACSEC_ERR_BUFFER);

    MACSEC_MEDIUM(("MKA AES-KW wrap: plain_len=%lu wrapped_max_len=%lu\n",
                   (unsigned long)plain_len,
                   (unsigned long)wrapped_max_len));

    MACSEC_INFO_HEX(("MKA AES-KW wrap plain", plain, (int)plain_len));

    if (!ctx->aes_initialized)
    {
        math_aes_init(&ctx->aes_ctx);
        ctx->aes_initialized = MACSEC_TRUE;
    }

    ret = math_aes_setkey_enc(&ctx->aes_ctx, kek, (unsigned int)(kek_len * 8u));
    if (ret != 0)
    {
        MACSEC_ERROR(("MKA AES-KW setkey enc failed ret=%d\n", ret));
        return MACSEC_ERR_CRYPTO;
    }

    memset(a, MACSEC_MKA_AES_KW_IV_BYTE, sizeof(a));

    n = plain_len / 8u;

    for (i = 0u; i < n; i++)
    {
        memcpy(&wrapped[8u + (i * 8u)], &plain[i * 8u], 8u);
    }

    for (j = 0u; j < 6u; j++)
    {
        for (i = 0u; i < n; i++)
        {
            memcpy(&block[0], a, 8u);
            memcpy(&block[8], &wrapped[8u + (i * 8u)], 8u);

            ret = math_aes_crypt_ecb(&ctx->aes_ctx,
                                     MATH_AES_ENCRYPT,
                                     block,
                                     b);
            if (ret != 0)
            {
                MACSEC_ERROR(("MKA AES-KW encrypt failed ret=%d\n", ret));
                macsec_zeroize(block, sizeof(block));
                macsec_zeroize(b, sizeof(b));
                macsec_zeroize(a, sizeof(a));
                return MACSEC_ERR_CRYPTO;
            }

            t = (uint64_t)((j * n) + i + 1u);

            a[0] = (uint8_t)(b[0] ^ (uint8_t)(t >> 56));
            a[1] = (uint8_t)(b[1] ^ (uint8_t)(t >> 48));
            a[2] = (uint8_t)(b[2] ^ (uint8_t)(t >> 40));
            a[3] = (uint8_t)(b[3] ^ (uint8_t)(t >> 32));
            a[4] = (uint8_t)(b[4] ^ (uint8_t)(t >> 24));
            a[5] = (uint8_t)(b[5] ^ (uint8_t)(t >> 16));
            a[6] = (uint8_t)(b[6] ^ (uint8_t)(t >> 8));
            a[7] = (uint8_t)(b[7] ^ (uint8_t)(t));

            memcpy(&wrapped[8u + (i * 8u)], &b[8], 8u);
        }
    }

    memcpy(&wrapped[0], a, 8u);
    *wrapped_len = plain_len + 8u;

    MACSEC_MEDIUM(("MKA AES-KW wrap done: wrapped_len=%lu\n",
                   (unsigned long)*wrapped_len));

    MACSEC_INFO_HEX(("MKA AES-KW wrapped", wrapped, (int)*wrapped_len));

    macsec_zeroize(block, sizeof(block));
    macsec_zeroize(b, sizeof(b));
    macsec_zeroize(a, sizeof(a));

    return MACSEC_ERR_OK;
}

static int macsec_mka_aes_kw_unwrap(macsec_mka_crypto_ctx_t *ctx,
                                    const uint8_t *kek,
                                    size_t kek_len,
                                    const uint8_t *wrapped,
                                    size_t wrapped_len,
                                    uint8_t *plain,
                                    size_t *plain_len,
                                    size_t plain_max_len)
{
    uint8_t a[8];
    uint8_t block[16];
    uint8_t b[16];
    uint8_t expected_a[8];
    size_t n;
    size_t i;
    size_t j_rev;
    uint64_t t;
    int ret;

    macsec_assert(ctx != NULL);
    macsec_assert(kek != NULL);
    macsec_assert(wrapped != NULL);
    macsec_assert(plain != NULL);
    macsec_assert(plain_len != NULL);

    macsec_check((kek_len == 16u) || (kek_len == 32u),
                 MACSEC_ERR_PARAM);

    macsec_check((wrapped_len >= 24u) &&
                 ((wrapped_len % 8u) == 0u),
                 MACSEC_ERR_PARAM);

    n = (wrapped_len / 8u) - 1u;

    macsec_check((n * 8u) <= plain_max_len, MACSEC_ERR_BUFFER);

    MACSEC_MEDIUM(("MKA AES-KW unwrap: wrapped_len=%lu plain_max_len=%lu\n",
                   (unsigned long)wrapped_len,
                   (unsigned long)plain_max_len));

    MACSEC_INFO_HEX(("MKA AES-KW wrapped input", wrapped, (int)wrapped_len));

    if (!ctx->aes_initialized)
    {
        math_aes_init(&ctx->aes_ctx);
        ctx->aes_initialized = MACSEC_TRUE;
    }

    ret = math_aes_setkey_dec(&ctx->aes_ctx, kek, (unsigned int)(kek_len * 8u));
    if (ret != 0)
    {
        MACSEC_ERROR(("MKA AES-KW setkey dec failed ret=%d\n", ret));
        return MACSEC_ERR_CRYPTO;
    }

    memcpy(a, &wrapped[0], 8u);

    for (i = 0u; i < n; i++)
    {
        memcpy(&plain[i * 8u], &wrapped[8u + (i * 8u)], 8u);
    }

    for (j_rev = 6u; j_rev > 0u; j_rev--)
    {
        size_t j = j_rev - 1u;

        for (i = n; i > 0u; i--)
        {
            size_t idx = i - 1u;

            t = (uint64_t)((j * n) + idx + 1u);

            block[0] = (uint8_t)(a[0] ^ (uint8_t)(t >> 56));
            block[1] = (uint8_t)(a[1] ^ (uint8_t)(t >> 48));
            block[2] = (uint8_t)(a[2] ^ (uint8_t)(t >> 40));
            block[3] = (uint8_t)(a[3] ^ (uint8_t)(t >> 32));
            block[4] = (uint8_t)(a[4] ^ (uint8_t)(t >> 24));
            block[5] = (uint8_t)(a[5] ^ (uint8_t)(t >> 16));
            block[6] = (uint8_t)(a[6] ^ (uint8_t)(t >> 8));
            block[7] = (uint8_t)(a[7] ^ (uint8_t)(t));

            memcpy(&block[8], &plain[idx * 8u], 8u);

            ret = math_aes_crypt_ecb(&ctx->aes_ctx,
                                     MATH_AES_DECRYPT,
                                     block,
                                     b);
            if (ret != 0)
            {
                MACSEC_ERROR(("MKA AES-KW decrypt failed ret=%d\n", ret));
                macsec_zeroize(block, sizeof(block));
                macsec_zeroize(b, sizeof(b));
                macsec_zeroize(a, sizeof(a));
                return MACSEC_ERR_CRYPTO;
            }

            memcpy(a, &b[0], 8u);
            memcpy(&plain[idx * 8u], &b[8], 8u);
        }
    }

    memset(expected_a, MACSEC_MKA_AES_KW_IV_BYTE, sizeof(expected_a));

    if (memcmp(a, expected_a, sizeof(a)) != 0)
    {
        MACSEC_ERROR(("MKA AES-KW unwrap authentication failed\n"));
        MACSEC_ERROR_HEX(("MKA AES-KW unwrap A", a, sizeof(a)));

        macsec_zeroize(block, sizeof(block));
        macsec_zeroize(b, sizeof(b));
        macsec_zeroize(a, sizeof(a));
        return MACSEC_ERR_AUTH;
    }

    *plain_len = n * 8u;

    MACSEC_MEDIUM(("MKA AES-KW unwrap done: plain_len=%lu\n",
                   (unsigned long)*plain_len));

    MACSEC_INFO_HEX(("MKA AES-KW unwrapped plain", plain, (int)*plain_len));

    macsec_zeroize(block, sizeof(block));
    macsec_zeroize(b, sizeof(b));
    macsec_zeroize(a, sizeof(a));

    return MACSEC_ERR_OK;
}

int macsec_mka_crypto_init(macsec_mka_crypto_ctx_t *ctx)
{
    macsec_assert(ctx != NULL);

    memset(ctx, 0, sizeof(*ctx));

    math_cmac_init(&ctx->cmac_ctx);
    ctx->cmac_initialized = MACSEC_TRUE;

    math_aes_init(&ctx->aes_ctx);
    ctx->aes_initialized = MACSEC_TRUE;

    MACSEC_MEDIUM(("MKA crypto init done\n"));

    return MACSEC_ERR_OK;
}

void macsec_mka_crypto_clear(macsec_mka_crypto_ctx_t *ctx)
{
    macsec_assert(ctx != NULL);

    MACSEC_MEDIUM(("MKA crypto clear\n"));

    if (ctx->cmac_initialized)
    {
        math_cmac_free(&ctx->cmac_ctx);
        ctx->cmac_initialized = MACSEC_FALSE;
    }

    if (ctx->aes_initialized)
    {
        math_aes_free(&ctx->aes_ctx);
        ctx->aes_initialized = MACSEC_FALSE;
    }

    macsec_zeroize(ctx, sizeof(*ctx));
}

int macsec_mka_crypto_set_psk(macsec_mka_crypto_ctx_t *ctx,
                              const uint8_t *cak,
                              size_t cak_len,
                              const uint8_t *ckn,
                              size_t ckn_len)
{
    macsec_assert(ctx != NULL);
    macsec_assert(cak != NULL);
    macsec_assert(ckn != NULL);
    macsec_check(macsec_mka_key_len_valid(cak_len), MACSEC_ERR_PARAM);
    macsec_check((ckn_len > 0u) && (ckn_len <= MACSEC_MKA_CKN_MAX_LEN),
                 MACSEC_ERR_PARAM);

    memset(&ctx->psk, 0, sizeof(ctx->psk));
    memset(&ctx->keys, 0, sizeof(ctx->keys));

    memcpy(ctx->psk.cak, cak, cak_len);
    ctx->psk.cak_len = (uint8_t)cak_len;

    memcpy(ctx->psk.ckn, ckn, ckn_len);
    ctx->psk.ckn_len = (uint8_t)ckn_len;

    ctx->psk.valid = MACSEC_TRUE;

    MACSEC_MEDIUM(("MKA PSK set: cak_len=%lu ckn_len=%lu\n",
                   (unsigned long)cak_len,
                   (unsigned long)ckn_len));

    MACSEC_INFO_HEX(("MKA CAK", ctx->psk.cak, ctx->psk.cak_len));
    MACSEC_INFO_HEX(("MKA CKN", ctx->psk.ckn, ctx->psk.ckn_len));

    return MACSEC_ERR_OK;
}

int macsec_mka_crypto_derive_ick_kek(macsec_mka_crypto_ctx_t *ctx)
{
    size_t derived_len;
    int ret;

    macsec_assert(ctx != NULL);
    macsec_check(ctx->psk.valid, MACSEC_ERR_STATE);

    derived_len = ctx->psk.cak_len;

    macsec_check((derived_len == 16u) || (derived_len == 32u),
                 MACSEC_ERR_PARAM);

    memset(&ctx->keys, 0, sizeof(ctx->keys));

    ret = macsec_mka_derive_one(ctx,
                                "IEEE8021 ICK",
                                ctx->keys.ick,
                                derived_len);
    if (ret != MACSEC_ERR_OK)
    {
        return ret;
    }

    ctx->keys.ick_len = (uint8_t)derived_len;

    ret = macsec_mka_derive_one(ctx,
                                "IEEE8021 KEK",
                                ctx->keys.kek,
                                derived_len);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_zeroize(&ctx->keys, sizeof(ctx->keys));
        return ret;
    }

    ctx->keys.kek_len = (uint8_t)derived_len;
    ctx->keys.valid = MACSEC_TRUE;

    MACSEC_MEDIUM_HEX(("MKA ICK",
                       ctx->keys.ick,
                       ctx->keys.ick_len));

    MACSEC_MEDIUM_HEX(("MKA KEK",
                       ctx->keys.kek,
                       ctx->keys.kek_len));

    return MACSEC_ERR_OK;
}

int macsec_mka_crypto_calc_mic(macsec_mka_crypto_ctx_t *ctx,
                               const uint8_t *pdu,
                               size_t pdu_len,
                               uint8_t mic[MACSEC_MKA_MIC_LEN])
{
    macsec_assert(ctx != NULL);
    macsec_assert(pdu != NULL);
    macsec_assert(mic != NULL);
    macsec_check(ctx->keys.valid, MACSEC_ERR_STATE);

    MACSEC_INFO(("MKA calc MIC: pdu_len=%lu\n", (unsigned long)pdu_len));

    return macsec_mka_cmac(ctx,
                           ctx->keys.ick,
                           ctx->keys.ick_len,
                           pdu,
                           pdu_len,
                           mic);
}

int macsec_mka_crypto_verify_mic(macsec_mka_crypto_ctx_t *ctx,
                                 const uint8_t *pdu,
                                 size_t pdu_len,
                                 const uint8_t mic[MACSEC_MKA_MIC_LEN])
{
    uint8_t calc_mic[MACSEC_MKA_MIC_LEN];
    int ret;

    macsec_assert(ctx != NULL);
    macsec_assert(pdu != NULL);
    macsec_assert(mic != NULL);

    MACSEC_INFO(("MKA verify MIC: pdu_len=%lu\n", (unsigned long)pdu_len));

    ret = macsec_mka_crypto_calc_mic(ctx, pdu, pdu_len, calc_mic);
    if (ret != MACSEC_ERR_OK)
    {
        MACSEC_ERROR(("MKA verify MIC calc failed ret=%d\n", ret));
        macsec_zeroize(calc_mic, sizeof(calc_mic));
        return ret;
    }

    if (memcmp(calc_mic, mic, MACSEC_MKA_MIC_LEN) != 0)
    {
        MACSEC_ERROR(("MKA verify MIC failed\n"));
        MACSEC_ERROR_HEX(("MKA calculated MIC", calc_mic, MACSEC_MKA_MIC_LEN));
        MACSEC_ERROR_HEX(("MKA expected MIC", mic, MACSEC_MKA_MIC_LEN));

        macsec_zeroize(calc_mic, sizeof(calc_mic));
        return MACSEC_ERR_AUTH;
    }

    MACSEC_INFO(("MKA verify MIC OK\n"));

    macsec_zeroize(calc_mic, sizeof(calc_mic));

    return MACSEC_ERR_OK;
}

int macsec_mka_crypto_wrap_sak(macsec_mka_crypto_ctx_t *ctx,
                               const uint8_t *sak,
                               size_t sak_len,
                               uint8_t *wrapped_sak,
                               size_t *wrapped_sak_len,
                               size_t wrapped_sak_max_len)
{
    macsec_assert(ctx != NULL);
    macsec_assert(sak != NULL);
    macsec_assert(wrapped_sak != NULL);
    macsec_assert(wrapped_sak_len != NULL);
    macsec_check(ctx->keys.valid, MACSEC_ERR_STATE);

    macsec_check((sak_len == 16u) || (sak_len == 32u), MACSEC_ERR_PARAM);

    MACSEC_MEDIUM(("MKA wrap SAK: sak_len=%lu\n", (unsigned long)sak_len));
    MACSEC_INFO_HEX(("MKA SAK plain", sak, (int)sak_len));

    return macsec_mka_aes_kw_wrap(ctx,
                                  ctx->keys.kek,
                                  ctx->keys.kek_len,
                                  sak,
                                  sak_len,
                                  wrapped_sak,
                                  wrapped_sak_len,
                                  wrapped_sak_max_len);
}

int macsec_mka_crypto_unwrap_sak(macsec_mka_crypto_ctx_t *ctx,
                                 const uint8_t *wrapped_sak,
                                 size_t wrapped_sak_len,
                                 uint8_t *sak,
                                 size_t *sak_len,
                                 size_t sak_max_len)
{
    int ret;

    macsec_assert(ctx != NULL);
    macsec_assert(wrapped_sak != NULL);
    macsec_assert(sak != NULL);
    macsec_assert(sak_len != NULL);
    macsec_check(ctx->keys.valid, MACSEC_ERR_STATE);

    MACSEC_MEDIUM(("MKA unwrap SAK: wrapped_len=%lu\n",
                   (unsigned long)wrapped_sak_len));

    MACSEC_INFO_HEX(("MKA wrapped SAK", wrapped_sak, (int)wrapped_sak_len));

    ret = macsec_mka_aes_kw_unwrap(ctx,
                                   ctx->keys.kek,
                                   ctx->keys.kek_len,
                                   wrapped_sak,
                                   wrapped_sak_len,
                                   sak,
                                   sak_len,
                                   sak_max_len);

    if (ret != MACSEC_ERR_OK)
    {
        MACSEC_ERROR(("MKA unwrap SAK failed ret=%d\n", ret));
        return ret;
    }

    MACSEC_MEDIUM(("MKA unwrap SAK OK: sak_len=%lu\n",
                   (unsigned long)*sak_len));

    MACSEC_INFO_HEX(("MKA unwrapped SAK", sak, (int)*sak_len));

    return MACSEC_ERR_OK;
}

static void macsec_mka_selftest_fill(uint8_t *buf, size_t len, uint8_t seed)
{
    size_t i;

    macsec_assert(buf != NULL);

    for (i = 0u; i < len; i++)
    {
        buf[i] = (uint8_t)(seed + (uint8_t)(i * 13u));
    }
}

int macsec_mka_crypto_self_test(macsec_mka_crypto_self_test_ctx_t *test_ctx,
                                int verbose)
{
    static const uint8_t cak[16] =
    {
        0x00u, 0x11u, 0x22u, 0x33u,
        0x44u, 0x55u, 0x66u, 0x77u,
        0x88u, 0x99u, 0xAAu, 0xBBu,
        0xCCu, 0xDDu, 0xEEu, 0xFFu
    };

    static const uint8_t ckn[16] =
    {
        0x10u, 0x11u, 0x12u, 0x13u,
        0x14u, 0x15u, 0x16u, 0x17u,
        0x18u, 0x19u, 0x1Au, 0x1Bu,
        0x1Cu, 0x1Du, 0x1Eu, 0x1Fu
    };

    size_t wrapped_len;
    size_t unwrapped_len;
    int ret;

    macsec_check(test_ctx != NULL, 1);

    memset(test_ctx, 0, sizeof(*test_ctx));

    if (verbose != 0)
    {
        MACSEC_PRINT(("  MACsec MKA crypto self-test: "));
    }

    MACSEC_MEDIUM(("MKA crypto self-test start\n"));

    ret = macsec_mka_crypto_init(&test_ctx->ctx);
    if (ret != MACSEC_ERR_OK)
    {
        goto fail;
    }

    ret = macsec_mka_crypto_set_psk(&test_ctx->ctx,
                                    cak,
                                    sizeof(cak),
                                    ckn,
                                    sizeof(ckn));
    if (ret != MACSEC_ERR_OK)
    {
        goto fail;
    }

    ret = macsec_mka_crypto_derive_ick_kek(&test_ctx->ctx);
    if (ret != MACSEC_ERR_OK)
    {
        goto fail;
    }

    macsec_mka_selftest_fill(test_ctx->pdu, 96u, 0x31u);

    ret = macsec_mka_crypto_calc_mic(&test_ctx->ctx,
                                     test_ctx->pdu,
                                     96u,
                                     test_ctx->mic);
    if (ret != MACSEC_ERR_OK)
    {
        goto fail;
    }

    ret = macsec_mka_crypto_verify_mic(&test_ctx->ctx,
                                       test_ctx->pdu,
                                       96u,
                                       test_ctx->mic);
    if (ret != MACSEC_ERR_OK)
    {
        goto fail;
    }

    memcpy(test_ctx->mic_check, test_ctx->mic, MACSEC_MKA_MIC_LEN);
    test_ctx->mic_check[0] ^= 0x01u;

    ret = macsec_mka_crypto_verify_mic(&test_ctx->ctx,
                                       test_ctx->pdu,
                                       96u,
                                       test_ctx->mic_check);
    if (ret == MACSEC_ERR_OK)
    {
        ret = MACSEC_ERR_AUTH;
        goto fail;
    }

    macsec_mka_selftest_fill(test_ctx->sak, 16u, 0x80u);

    wrapped_len = 0u;
    unwrapped_len = 0u;

    ret = macsec_mka_crypto_wrap_sak(&test_ctx->ctx,
                                     test_ctx->sak,
                                     16u,
                                     test_ctx->wrapped,
                                     &wrapped_len,
                                     sizeof(test_ctx->wrapped));
    if (ret != MACSEC_ERR_OK)
    {
        goto fail;
    }

    ret = macsec_mka_crypto_unwrap_sak(&test_ctx->ctx,
                                       test_ctx->wrapped,
                                       wrapped_len,
                                       test_ctx->unwrapped,
                                       &unwrapped_len,
                                       sizeof(test_ctx->unwrapped));
    if (ret != MACSEC_ERR_OK)
    {
        goto fail;
    }

    if (unwrapped_len != 16u)
    {
        ret = MACSEC_ERR_AUTH;
        goto fail;
    }

    if (memcmp(test_ctx->sak, test_ctx->unwrapped, 16u) != 0)
    {
        ret = MACSEC_ERR_AUTH;
        goto fail;
    }

    macsec_mka_crypto_clear(&test_ctx->ctx);
    macsec_zeroize(test_ctx, sizeof(*test_ctx));

    MACSEC_MEDIUM(("MKA crypto self-test passed\n"));

    if (verbose != 0)
    {
        MACSEC_PRINT(("passed\n"));
    }

    return 0;

fail:
    MACSEC_ERROR(("MKA crypto self-test failed ret=%d\n", ret));

    if (verbose != 0)
    {
        MACSEC_PRINT(("failed (%d)\n", ret));
    }

    macsec_mka_crypto_clear(&test_ctx->ctx);
    macsec_zeroize(test_ctx, sizeof(*test_ctx));

    return 1;
}
