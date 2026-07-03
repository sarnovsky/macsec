/*
 * test_mka_crypto.c
 *
 * Lightweight MACsec stack
 * Unit tests for MKA cryptographic functions.
 * This file validates MKA-specific cryptographic operations, including key
 * derivation, integrity calculation and related helper functions.
 *
 * Copyright (c) 2026 Michal Sarnovský
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */

#include <tests/test_mka_crypto.h>
#include <tests/unit_tests.h>

#if (MACSEC_SELF_TEST != 0)

static int macsec_test_mka_crypto_selftest_api(macsec_test_mka_crypto_selftest_api_data_t *data, int verbose)
{
    int ret;

    ret = macsec_mka_crypto_self_test(&data->test_ctx, verbose ? 1 : 0);
    TEST_OK(ret);

    return 0;
}

static int macsec_test_mka_crypto_psk_derive(macsec_test_mka_crypto_psk_derive_data_t *data, int verbose)
{
    static const uint8_t cak[16] =
    {
        0x00u, 0x11u, 0x22u, 0x33u,
        0x44u, 0x55u, 0x66u, 0x77u,
        0x88u, 0x99u, 0xAAu, 0xBBu,
        0xCCu, 0xDDu, 0xEEu, 0xFFu
    };

    static const uint8_t ckn[24] =
    {
        0x00u, 0x11u, 0x22u, 0x33u,
        0x44u, 0x55u, 0x66u, 0x77u,
        0x88u, 0x99u, 0xAAu, 0xBBu,
        0xCCu, 0xDDu, 0xEEu, 0xFFu,
        0x00u, 0x11u, 0x22u, 0x33u,
        0x44u, 0x55u, 0x66u, 0x77u
    };

    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  MKA crypto PSK derive test\n"));
    }

    ret = macsec_mka_crypto_init(&data->ctx);
    TEST_OK(ret);

    ret = macsec_mka_crypto_set_psk(&data->ctx, cak, sizeof(cak), ckn, sizeof(ckn));
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_crypto_clear(&data->ctx);
        return ret;
    }

    ret = macsec_mka_crypto_derive_ick_kek(&data->ctx);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_crypto_clear(&data->ctx);
        return ret;
    }

    TEST_TRUE(data->ctx.psk.valid);
    TEST_TRUE(data->ctx.keys.valid);

    macsec_mka_crypto_clear(&data->ctx);

    return 0;
}

static int macsec_test_mka_crypto_mic_positive_negative(macsec_test_mka_crypto_mic_positive_negative_data_t *data, int verbose)
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

    size_t i;
    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  MKA crypto MIC positive/negative test\n"));
    }

    for (i = 0u; i < sizeof(data->pdu); i++)
    {
        data->pdu[i] = (uint8_t)(0x31u + (uint8_t)(i * 7u));
    }

    ret = macsec_mka_crypto_init(&data->ctx);
    TEST_OK(ret);

    ret = macsec_mka_crypto_set_psk(&data->ctx, cak, sizeof(cak), ckn, sizeof(ckn));
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_crypto_clear(&data->ctx);
        return ret;
    }

    ret = macsec_mka_crypto_derive_ick_kek(&data->ctx);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_crypto_clear(&data->ctx);
        return ret;
    }

    ret = macsec_mka_crypto_calc_mic(&data->ctx, data->pdu, sizeof(data->pdu), data->mic);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_crypto_clear(&data->ctx);
        return ret;
    }

    ret = macsec_mka_crypto_verify_mic(&data->ctx, data->pdu, sizeof(data->pdu), data->mic);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_crypto_clear(&data->ctx);
        return ret;
    }

    memcpy(data->bad_mic, data->mic, sizeof(data->bad_mic));
    data->bad_mic[0] ^= 0x01u;

    ret = macsec_mka_crypto_verify_mic(&data->ctx, data->pdu, sizeof(data->pdu), data->bad_mic);
    if (ret != MACSEC_ERR_AUTH)
    {
        macsec_mka_crypto_clear(&data->ctx);
        return -1;
    }

    macsec_mka_crypto_clear(&data->ctx);

    return 0;
}

static int macsec_test_mka_crypto_wrap_unwrap_sak(macsec_test_mka_crypto_wrap_unwrap_sak_data_t *data, int verbose)
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

    size_t wrapped_len = 0u;
    size_t unwrapped_len = 0u;
    size_t i;
    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  MKA crypto SAK wrap/unwrap test\n"));
    }

    for (i = 0u; i < sizeof(data->sak); i++)
    {
        data->sak[i] = (uint8_t)(0x80u + (uint8_t)(i * 11u));
    }

    ret = macsec_mka_crypto_init(&data->ctx);
    TEST_OK(ret);

    ret = macsec_mka_crypto_set_psk(&data->ctx, cak, sizeof(cak), ckn, sizeof(ckn));
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_crypto_clear(&data->ctx);
        return ret;
    }

    ret = macsec_mka_crypto_derive_ick_kek(&data->ctx);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_crypto_clear(&data->ctx);
        return ret;
    }

    ret = macsec_mka_crypto_wrap_sak(&data->ctx,
                                     data->sak,
                                     sizeof(data->sak),
                                     data->wrapped,
                                     &wrapped_len,
                                     sizeof(data->wrapped));
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_crypto_clear(&data->ctx);
        return ret;
    }

    ret = macsec_mka_crypto_unwrap_sak(&data->ctx,
                                       data->wrapped,
                                       wrapped_len,
                                       data->unwrapped,
                                       &unwrapped_len,
                                       sizeof(data->unwrapped));
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_crypto_clear(&data->ctx);
        return ret;
    }

    TEST_EQ_U32(unwrapped_len, sizeof(data->sak));
    TEST_MEM_EQ(data->sak, data->unwrapped, sizeof(data->sak));

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
    TEST_OK(macsec_test_mka_crypto_psk_derive(&data->test_mka_crypto_psk_derive_data, verbose));
    TEST_OK(macsec_test_mka_crypto_mic_positive_negative(&data->test_mka_crypto_mic_positive_negative_data, verbose));
    TEST_OK(macsec_test_mka_crypto_wrap_unwrap_sak(&data->test_mka_crypto_wrap_unwrap_sak_data, verbose));

    if (verbose)
    {
        MACSEC_PRINT(("MACsec MKA crypto tests PASSED\n"));
    }

    return 0;
}

#endif /* MACSEC_SELF_TEST */
