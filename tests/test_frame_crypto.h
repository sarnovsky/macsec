/*
 * test_frame_crypto.h
 *
 * Lightweight MACsec stack
 * Unit tests for MACsec frame protection.
 * This file validates Ethernet frame encryption, decryption, authentication
 * and MACsec frame processing using predefined test vectors.
 *
 * Copyright (c) 2026 Michal Sarnovsky
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */

#ifndef TEST_FRAME_CRYPTO_H
#define TEST_FRAME_CRYPTO_H

#include "frame_crypto.h"
#include "macsec_common.h"

#ifdef __cplusplus
extern "C"
{
#endif

#if (MACSEC_SELF_TEST != 0)

typedef struct
{
    macsec_frame_crypto_self_test_ctx_t test_ctx;
} macsec_test_frame_crypto_selftest_wrapper_data_t;

typedef struct
{
    uint8_t plain[MACSEC_FRAME_MAX_PLAIN_SIZE];
    uint8_t secure[MACSEC_FRAME_MAX_SECURE_SIZE];
    uint8_t decrypted[MACSEC_FRAME_MAX_PLAIN_SIZE];

    macsec_frame_sci_t sci;
    macsec_frame_sak_t sak;
    macsec_frame_crypto_ctx_t tx_ctx;
    macsec_frame_crypto_ctx_t rx_ctx;
} macsec_test_frame_crypto_encrypt_decrypt_one_data_t;

typedef union
{
    macsec_test_frame_crypto_selftest_wrapper_data_t test_frame_crypto_selftest_wrapper_data;

    macsec_test_frame_crypto_encrypt_decrypt_one_data_t test_frame_crypto_encrypt_decrypt_one_data;
} macsec_test_frame_crypto_data_t;

int macsec_test_frame_crypto(macsec_test_frame_crypto_data_t *data, int verbose);

#endif /* MACSEC_SELF_TEST */

#ifdef __cplusplus
}
#endif

#endif /* TEST_FRAME_CRYPTO_H */