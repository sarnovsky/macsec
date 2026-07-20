/*
 * test_mka_crypto.c
 *
 * Lightweight MACsec stack
 * Unit tests for MKA cryptographic functions.
 * This file validates MKA-specific cryptographic operations, including key
 * derivation, integrity calculation, SAK wrapping and error handling.
 *
 * Copyright (c) 2026 Michal Sarnovsky
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */

#include <tests/test_mka_crypto.h>
#include <tests/unit_tests.h>

#include <string.h>

#if (MACSEC_SELF_TEST != 0)

static const uint8_t test_cak_16[16] = {0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u,
                                        0x88u, 0x99u, 0xAAu, 0xBBu, 0xCCu, 0xDDu, 0xEEu, 0xFFu};

static const uint8_t test_cak_32[32] = {0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u,
                                        0x88u, 0x99u, 0xAAu, 0xBBu, 0xCCu, 0xDDu, 0xEEu, 0xFFu,
                                        0x10u, 0x21u, 0x32u, 0x43u, 0x54u, 0x65u, 0x76u, 0x87u,
                                        0x98u, 0xA9u, 0xBAu, 0xCBu, 0xDCu, 0xEDu, 0xFEu, 0x0Fu};

static const uint8_t test_cak_32_second_half_changed[32] = {
    0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u, 0x88u, 0x99u, 0xAAu,
    0xBBu, 0xCCu, 0xDDu, 0xEEu, 0xFFu, 0x10u, 0x21u, 0x32u, 0x43u, 0x54u, 0x65u,
    0x76u, 0x87u, 0x98u, 0xA9u, 0xBAu, 0xCBu, 0xDCu, 0xEDu, 0xFEu, 0x0Eu};

static const uint8_t test_ckn_16[16] = {0x10u, 0x11u, 0x12u, 0x13u, 0x14u, 0x15u, 0x16u, 0x17u,
                                        0x18u, 0x19u, 0x1Au, 0x1Bu, 0x1Cu, 0x1Du, 0x1Eu, 0x1Fu};

static const uint8_t test_ckn_24[24] = {0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u,
                                        0x88u, 0x99u, 0xAAu, 0xBBu, 0xCCu, 0xDDu, 0xEEu, 0xFFu,
                                        0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u};

static void macsec_test_mka_crypto_fill(uint8_t *buf, size_t len, uint8_t seed)
{
    size_t i;

    macsec_assert(buf != NULL);

    for (i = 0u; i < len; i++)
    {
        buf[i] = (uint8_t) (seed + (uint8_t) (i * 11u));
    }
}

static int macsec_test_mka_crypto_prepare(macsec_mka_crypto_ctx_t *ctx, const uint8_t *cak,
                                          size_t cak_len)
{
    int ret;

    ret = macsec_mka_crypto_init(ctx);
    if (ret != MACSEC_ERR_OK)
    {
        return ret;
    }

    ret = macsec_mka_crypto_set_psk(ctx, cak, cak_len, test_ckn_16, sizeof(test_ckn_16));
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_crypto_clear(ctx);
        return ret;
    }

    ret = macsec_mka_crypto_derive_ick_kek(ctx);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_crypto_clear(ctx);
        return ret;
    }

    return MACSEC_ERR_OK;
}

static int macsec_test_mka_crypto_selftest_api(macsec_test_mka_crypto_selftest_api_data_t *data,
                                               int verbose)
{
    int ret;

    ret = macsec_mka_crypto_self_test(&data->test_ctx, verbose ? 1 : 0);
    TEST_OK(ret);

    return 0;
}

static int macsec_test_mka_crypto_psk_derive(macsec_test_mka_crypto_psk_derive_data_t *data,
                                             const uint8_t *cak, size_t cak_len, int verbose)
{
    int ret;

    macsec_assert(cak != NULL);
    macsec_assert((cak_len == 16u) || (cak_len == 32u));

    if (verbose)
    {
        MACSEC_PRINT(("  MKA crypto PSK derive test, %u-byte CAK\n", (unsigned int) cak_len));
    }

    TEST_OK(macsec_mka_crypto_init(&data->ctx));

    ret = macsec_mka_crypto_set_psk(&data->ctx, cak, cak_len, test_ckn_24, sizeof(test_ckn_24));
    TEST_OK(ret);

    TEST_TRUE(data->ctx.psk.valid);
    TEST_EQ_U32(data->ctx.psk.cak_len, cak_len);
    TEST_EQ_U32(data->ctx.psk.ckn_len, sizeof(test_ckn_24));
    TEST_MEM_EQ(data->ctx.psk.cak, cak, cak_len);
    TEST_MEM_EQ(data->ctx.psk.ckn, test_ckn_24, sizeof(test_ckn_24));
    TEST_TRUE(!data->ctx.keys.valid);

    TEST_OK(macsec_mka_crypto_derive_ick_kek(&data->ctx));

    TEST_TRUE(data->ctx.keys.valid);
    TEST_EQ_U32(data->ctx.keys.ick_len, cak_len);
    TEST_EQ_U32(data->ctx.keys.kek_len, cak_len);

    macsec_mka_crypto_clear(&data->ctx);
    return 0;
}

static int macsec_test_mka_crypto_invalid_psk(macsec_test_mka_crypto_psk_derive_data_t *data,
                                              int verbose)
{
    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  MKA crypto invalid PSK parameter test\n"));
    }

    TEST_OK(macsec_mka_crypto_init(&data->ctx));

    ret = macsec_mka_crypto_set_psk(&data->ctx, test_cak_16, 15u, test_ckn_16, sizeof(test_ckn_16));
    TEST_TRUE(ret == MACSEC_ERR_PARAM);

    ret = macsec_mka_crypto_set_psk(&data->ctx, test_cak_16, sizeof(test_cak_16), test_ckn_16, 0u);
    TEST_TRUE(ret == MACSEC_ERR_PARAM);

    ret = macsec_mka_crypto_derive_ick_kek(&data->ctx);
    TEST_TRUE(ret == MACSEC_ERR_STATE);

    macsec_mka_crypto_clear(&data->ctx);
    return 0;
}

static int macsec_test_mka_crypto_mic_positive_negative(macsec_test_mka_crypto_mic_data_t *data,
                                                        const uint8_t *cak, size_t cak_len,
                                                        int verbose)
{
    int ret;

    if (verbose)
    {
        MACSEC_PRINT(
            ("  MKA crypto MIC positive/negative test, %u-byte CAK\n", (unsigned int) cak_len));
    }

    macsec_test_mka_crypto_fill(data->pdu, sizeof(data->pdu), 0x31u);
    TEST_OK(macsec_test_mka_crypto_prepare(&data->ctx, cak, cak_len));

    TEST_OK(macsec_mka_crypto_calc_mic(&data->ctx, data->pdu, sizeof(data->pdu), data->mic));

    TEST_OK(macsec_mka_crypto_verify_mic(&data->ctx, data->pdu, sizeof(data->pdu), data->mic));

    memcpy(data->bad_mic, data->mic, sizeof(data->bad_mic));
    data->bad_mic[0] ^= 0x01u;

    ret = macsec_mka_crypto_verify_mic(&data->ctx, data->pdu, sizeof(data->pdu), data->bad_mic);
    TEST_TRUE(ret == MACSEC_ERR_AUTH);

    data->pdu[sizeof(data->pdu) - 1u] ^= 0x80u;
    ret = macsec_mka_crypto_verify_mic(&data->ctx, data->pdu, sizeof(data->pdu), data->mic);
    TEST_TRUE(ret == MACSEC_ERR_AUTH);

    macsec_mka_crypto_clear(&data->ctx);
    return 0;
}

static int macsec_test_mka_crypto_mic_requires_keys(macsec_test_mka_crypto_mic_data_t *data,
                                                    int verbose)
{
    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  MKA crypto MIC readiness test\n"));
    }

    macsec_test_mka_crypto_fill(data->pdu, sizeof(data->pdu), 0x42u);
    memset(data->mic, 0xA5, sizeof(data->mic));

    TEST_OK(macsec_mka_crypto_init(&data->ctx));

    ret = macsec_mka_crypto_calc_mic(&data->ctx, data->pdu, sizeof(data->pdu), data->mic);
    TEST_TRUE(ret == MACSEC_ERR_STATE);

    TEST_OK(macsec_mka_crypto_set_psk(&data->ctx, test_cak_16, sizeof(test_cak_16), test_ckn_16,
                                      sizeof(test_ckn_16)));

    ret = macsec_mka_crypto_calc_mic(&data->ctx, data->pdu, sizeof(data->pdu), data->mic);
    TEST_TRUE(ret == MACSEC_ERR_STATE);

    macsec_mka_crypto_clear(&data->ctx);
    return 0;
}

static int macsec_test_mka_crypto_cak_32_second_half_used(macsec_test_mka_crypto_mic_data_t *data,
                                                          int verbose)
{
    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  MKA crypto 32-byte CAK second-half usage test\n"));
    }

    macsec_test_mka_crypto_fill(data->pdu, sizeof(data->pdu), 0x53u);

    TEST_OK(macsec_test_mka_crypto_prepare(&data->ctx, test_cak_32, sizeof(test_cak_32)));

    TEST_OK(macsec_mka_crypto_calc_mic(&data->ctx, data->pdu, sizeof(data->pdu), data->mic));

    macsec_mka_crypto_clear(&data->ctx);

    TEST_OK(macsec_test_mka_crypto_prepare(&data->ctx, test_cak_32_second_half_changed,
                                           sizeof(test_cak_32_second_half_changed)));

    ret = macsec_mka_crypto_verify_mic(&data->ctx, data->pdu, sizeof(data->pdu), data->mic);
    TEST_TRUE(ret == MACSEC_ERR_AUTH);

    macsec_mka_crypto_clear(&data->ctx);
    return 0;
}

static int macsec_test_mka_crypto_wrap_unwrap_sak(macsec_test_mka_crypto_wrap_data_t *data,
                                                  const uint8_t *cak, size_t cak_len,
                                                  size_t sak_len, int verbose)
{
    size_t wrapped_len = 0u;
    size_t unwrapped_len = 0u;
    size_t expected_wrapped_len;

    if (verbose)
    {
        MACSEC_PRINT(("  MKA crypto SAK wrap/unwrap test, %u-byte CAK, %u-byte SAK\n",
                      (unsigned int) cak_len, (unsigned int) sak_len));
    }

    macsec_assert((sak_len == 16u) || (sak_len == 32u));

    expected_wrapped_len = sak_len + 8u;
    macsec_test_mka_crypto_fill(data->sak, sak_len, 0x80u);

    TEST_OK(macsec_test_mka_crypto_prepare(&data->ctx, cak, cak_len));

    TEST_OK(macsec_mka_crypto_wrap_sak(&data->ctx, data->sak, sak_len, data->wrapped, &wrapped_len,
                                       sizeof(data->wrapped)));

    TEST_EQ_U32(wrapped_len, expected_wrapped_len);

    TEST_OK(macsec_mka_crypto_unwrap_sak(&data->ctx, data->wrapped, wrapped_len, data->unwrapped,
                                         &unwrapped_len, sizeof(data->unwrapped)));

    TEST_EQ_U32(unwrapped_len, sak_len);
    TEST_MEM_EQ(data->sak, data->unwrapped, sak_len);

    macsec_mka_crypto_clear(&data->ctx);
    return 0;
}

static int macsec_test_mka_crypto_wrap_buffer_limits(macsec_test_mka_crypto_wrap_data_t *data,
                                                     int verbose)
{
    size_t wrapped_len = 123u;
    size_t unwrapped_len = 123u;
    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  MKA crypto SAK buffer-limit test\n"));
    }

    macsec_test_mka_crypto_fill(data->sak, 32u, 0x91u);
    TEST_OK(macsec_test_mka_crypto_prepare(&data->ctx, test_cak_32, sizeof(test_cak_32)));

    memset(data->wrapped, 0xA5, sizeof(data->wrapped));

    ret = macsec_mka_crypto_wrap_sak(&data->ctx, data->sak, 32u, data->wrapped, &wrapped_len,
                                     MACSEC_MKA_WRAPPED_SAK_256_LEN - 1u);
    TEST_TRUE(ret == MACSEC_ERR_BUFFER);
    TEST_EQ_U32(wrapped_len, 0u);

    TEST_OK(macsec_mka_crypto_wrap_sak(&data->ctx, data->sak, 32u, data->wrapped, &wrapped_len,
                                       sizeof(data->wrapped)));

    memset(data->unwrapped, 0xA5, sizeof(data->unwrapped));

    ret = macsec_mka_crypto_unwrap_sak(&data->ctx, data->wrapped, wrapped_len, data->unwrapped,
                                       &unwrapped_len, 31u);
    TEST_TRUE(ret == MACSEC_ERR_BUFFER);
    TEST_EQ_U32(unwrapped_len, 0u);

    macsec_mka_crypto_clear(&data->ctx);
    return 0;
}

static int macsec_test_mka_crypto_wrap_auth_failure(macsec_test_mka_crypto_wrap_data_t *data,
                                                    size_t sak_len, int verbose)
{
    size_t wrapped_len = 0u;
    size_t unwrapped_len = 123u;
    size_t i;
    int ret;

    if (verbose)
    {
        MACSEC_PRINT(
            ("  MKA crypto SAK unwrap authentication test, %u-byte SAK\n", (unsigned int) sak_len));
    }

    macsec_test_mka_crypto_fill(data->sak, sak_len, 0xA0u);
    TEST_OK(macsec_test_mka_crypto_prepare(&data->ctx, test_cak_32, sizeof(test_cak_32)));

    TEST_OK(macsec_mka_crypto_wrap_sak(&data->ctx, data->sak, sak_len, data->wrapped, &wrapped_len,
                                       sizeof(data->wrapped)));

    memcpy(data->wrapped_copy, data->wrapped, wrapped_len);
    data->wrapped_copy[wrapped_len - 1u] ^= 0x01u;

    memset(data->unwrapped, 0xA5, sizeof(data->unwrapped));

    ret = macsec_mka_crypto_unwrap_sak(&data->ctx, data->wrapped_copy, wrapped_len, data->unwrapped,
                                       &unwrapped_len, sizeof(data->unwrapped));

    TEST_TRUE(ret == MACSEC_ERR_AUTH);
    TEST_EQ_U32(unwrapped_len, 0u);

    for (i = 0u; i < sizeof(data->unwrapped); i++)
    {
        TEST_EQ_U32(data->unwrapped[i], 0u);
    }

    macsec_mka_crypto_clear(&data->ctx);
    return 0;
}

static int macsec_test_mka_crypto_wrap_invalid_lengths(macsec_test_mka_crypto_wrap_data_t *data,
                                                       int verbose)
{
    size_t wrapped_len = 123u;
    size_t unwrapped_len = 123u;
    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  MKA crypto SAK invalid-length test\n"));
    }

    macsec_test_mka_crypto_fill(data->sak, sizeof(data->sak), 0xB0u);
    TEST_OK(macsec_test_mka_crypto_prepare(&data->ctx, test_cak_16, sizeof(test_cak_16)));

    ret = macsec_mka_crypto_wrap_sak(&data->ctx, data->sak, 24u, data->wrapped, &wrapped_len,
                                     sizeof(data->wrapped));
    TEST_TRUE(ret == MACSEC_ERR_PARAM);
    TEST_EQ_U32(wrapped_len, 0u);

    ret = macsec_mka_crypto_unwrap_sak(&data->ctx, data->wrapped, 32u, data->unwrapped,
                                       &unwrapped_len, sizeof(data->unwrapped));
    TEST_TRUE(ret == MACSEC_ERR_PARAM);
    TEST_EQ_U32(unwrapped_len, 0u);

    macsec_mka_crypto_clear(&data->ctx);
    return 0;
}

static int macsec_test_mka_crypto_wrap_requires_keys(macsec_test_mka_crypto_wrap_data_t *data,
                                                     int verbose)
{
    size_t wrapped_len = 123u;
    size_t unwrapped_len = 123u;
    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  MKA crypto SAK readiness test\n"));
    }

    macsec_test_mka_crypto_fill(data->sak, 16u, 0xC0u);
    TEST_OK(macsec_mka_crypto_init(&data->ctx));

    ret = macsec_mka_crypto_wrap_sak(&data->ctx, data->sak, 16u, data->wrapped, &wrapped_len,
                                     sizeof(data->wrapped));
    TEST_TRUE(ret == MACSEC_ERR_STATE);

    ret = macsec_mka_crypto_unwrap_sak(&data->ctx, data->wrapped, MACSEC_MKA_WRAPPED_SAK_128_LEN,
                                       data->unwrapped, &unwrapped_len, sizeof(data->unwrapped));
    TEST_TRUE(ret == MACSEC_ERR_STATE);

    macsec_mka_crypto_clear(&data->ctx);
    return 0;
}

int macsec_test_mka_crypto(macsec_test_mka_crypto_data_t *data, int verbose)
{
    if (verbose)
    {
        MACSEC_PRINT(("MACsec MKA crypto tests\n"));
    }

    TEST_OK(macsec_test_mka_crypto_selftest_api(&data->test_mka_crypto_selftest_api_data, verbose));

    TEST_OK(macsec_test_mka_crypto_psk_derive(&data->test_mka_crypto_psk_derive_data, test_cak_16,
                                              sizeof(test_cak_16), verbose));

    TEST_OK(macsec_test_mka_crypto_psk_derive(&data->test_mka_crypto_psk_derive_data, test_cak_32,
                                              sizeof(test_cak_32), verbose));

    TEST_OK(macsec_test_mka_crypto_invalid_psk(&data->test_mka_crypto_psk_derive_data, verbose));

    TEST_OK(macsec_test_mka_crypto_mic_positive_negative(
        &data->test_mka_crypto_mic_data, test_cak_16, sizeof(test_cak_16), verbose));

    TEST_OK(macsec_test_mka_crypto_mic_positive_negative(
        &data->test_mka_crypto_mic_data, test_cak_32, sizeof(test_cak_32), verbose));

    TEST_OK(macsec_test_mka_crypto_mic_requires_keys(&data->test_mka_crypto_mic_data, verbose));

    TEST_OK(
        macsec_test_mka_crypto_cak_32_second_half_used(&data->test_mka_crypto_mic_data, verbose));

    TEST_OK(macsec_test_mka_crypto_wrap_unwrap_sak(&data->test_mka_crypto_wrap_data, test_cak_16,
                                                   sizeof(test_cak_16), 16u, verbose));

    TEST_OK(macsec_test_mka_crypto_wrap_unwrap_sak(&data->test_mka_crypto_wrap_data, test_cak_16,
                                                   sizeof(test_cak_16), 32u, verbose));

    TEST_OK(macsec_test_mka_crypto_wrap_unwrap_sak(&data->test_mka_crypto_wrap_data, test_cak_32,
                                                   sizeof(test_cak_32), 16u, verbose));

    TEST_OK(macsec_test_mka_crypto_wrap_unwrap_sak(&data->test_mka_crypto_wrap_data, test_cak_32,
                                                   sizeof(test_cak_32), 32u, verbose));

    TEST_OK(macsec_test_mka_crypto_wrap_buffer_limits(&data->test_mka_crypto_wrap_data, verbose));

    TEST_OK(
        macsec_test_mka_crypto_wrap_auth_failure(&data->test_mka_crypto_wrap_data, 16u, verbose));

    TEST_OK(
        macsec_test_mka_crypto_wrap_auth_failure(&data->test_mka_crypto_wrap_data, 32u, verbose));

    TEST_OK(macsec_test_mka_crypto_wrap_invalid_lengths(&data->test_mka_crypto_wrap_data, verbose));

    TEST_OK(macsec_test_mka_crypto_wrap_requires_keys(&data->test_mka_crypto_wrap_data, verbose));

    if (verbose)
    {
        MACSEC_PRINT(("MACsec MKA crypto tests PASSED\n"));
    }

    return 0;
}

#endif /* MACSEC_SELF_TEST */
