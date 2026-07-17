/*
 * test_mka_crypto.h
 *
 * Lightweight MACsec stack
 * Unit tests for MKA cryptographic functions.
 * This file validates MKA-specific cryptographic operations, including key
 * derivation, integrity calculation and related helper functions.
 *
 * Copyright (c) 2026 Michal Sarnovsky
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */

#ifndef TESTS_TEST_MKA_CRYPTO_H
#define TESTS_TEST_MKA_CRYPTO_H

#include "macsec_common.h"
#include "mka_crypto.h"

#ifdef __cplusplus
extern "C"
{
#endif

#if (MACSEC_SELF_TEST != 0)

typedef struct
{
    macsec_mka_crypto_self_test_ctx_t test_ctx;
} macsec_test_mka_crypto_selftest_api_data_t;

typedef struct
{
    macsec_mka_crypto_ctx_t ctx;
} macsec_test_mka_crypto_psk_derive_data_t;

typedef struct
{
    uint8_t pdu[96];
    uint8_t mic[MACSEC_MKA_MIC_LEN];
    uint8_t bad_mic[MACSEC_MKA_MIC_LEN];

    macsec_mka_crypto_ctx_t ctx;
} macsec_test_mka_crypto_mic_positive_negative_data_t;

typedef struct
{
    uint8_t sak[16];
    uint8_t wrapped[40];
    uint8_t unwrapped[32];

    macsec_mka_crypto_ctx_t ctx;
} macsec_test_mka_crypto_wrap_unwrap_sak_data_t;

typedef union
{
    macsec_test_mka_crypto_selftest_api_data_t test_mka_crypto_selftest_api_data;

    macsec_test_mka_crypto_psk_derive_data_t test_mka_crypto_psk_derive_data;

    macsec_test_mka_crypto_mic_positive_negative_data_t test_mka_crypto_mic_positive_negative_data;

    macsec_test_mka_crypto_wrap_unwrap_sak_data_t test_mka_crypto_wrap_unwrap_sak_data;
} macsec_test_mka_crypto_data_t;

int macsec_test_mka_crypto(macsec_test_mka_crypto_data_t *data, int verbose);

#endif /* MACSEC_SELF_TEST */

#ifdef __cplusplus
}
#endif

#endif /* TESTS_TEST_MKA_CRYPTO_H */
