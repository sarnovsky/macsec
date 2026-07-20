/*
 * test_rekey.h
 *
 * Lightweight MACsec stack
 * Rekeying and key update tests.
 * This file validates Secure Association Key (SAK) replacement, packet
 * number continuity and key transition procedures during MACsec operation.
 *
 * Copyright (c) 2026 Michal Sarnovsky
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */

#ifndef TEST_REKEY_H
#define TEST_REKEY_H

#include "frame_crypto.h"
#include "macsec_common.h"

#ifdef __cplusplus
extern "C"
{
#endif

#if (MACSEC_SELF_TEST != 0)

#define MACSEC_TEST_REKEY_PLAIN_MAX_LEN 128u
#define MACSEC_TEST_REKEY_SECURE_MAX_LEN 256u
#define MACSEC_TEST_REKEY_PLAIN_LEN 96u

typedef struct
{
    uint8_t plain[MACSEC_TEST_REKEY_PLAIN_MAX_LEN];
    uint8_t secure[MACSEC_TEST_REKEY_SECURE_MAX_LEN];
    uint8_t decrypted[MACSEC_TEST_REKEY_PLAIN_MAX_LEN];

    macsec_frame_sci_t sci;

    macsec_frame_crypto_ctx_t tx_ctx;
    macsec_frame_crypto_ctx_t rx_ctx;

    macsec_frame_sak_t sak;
} macsec_test_rekey_an_rotation_decrypts_all_data_t;

typedef struct
{
    uint8_t plain0[MACSEC_TEST_REKEY_PLAIN_MAX_LEN];
    uint8_t plain1[MACSEC_TEST_REKEY_PLAIN_MAX_LEN];

    uint8_t secure0[MACSEC_TEST_REKEY_SECURE_MAX_LEN];
    uint8_t secure1[MACSEC_TEST_REKEY_SECURE_MAX_LEN];

    uint8_t decrypted[MACSEC_TEST_REKEY_PLAIN_MAX_LEN];

    macsec_frame_sci_t sci;

    macsec_frame_crypto_ctx_t tx_ctx;
    macsec_frame_crypto_ctx_t rx_ctx;

    macsec_frame_sak_t sak0;
    macsec_frame_sak_t sak1;
} macsec_test_rekey_old_rx_sak_still_accepted_data_t;

typedef struct
{
    uint8_t plain[MACSEC_TEST_REKEY_PLAIN_MAX_LEN];
    uint8_t secure[MACSEC_TEST_REKEY_SECURE_MAX_LEN];
    uint8_t decrypted[MACSEC_TEST_REKEY_PLAIN_MAX_LEN];

    macsec_frame_sci_t sci;

    macsec_frame_crypto_ctx_t tx_ctx;
    macsec_frame_crypto_ctx_t rx_ctx;

    macsec_frame_sak_t tx_sak;
    macsec_frame_sak_t wrong_rx_sak;
} macsec_test_rekey_wrong_key_same_an_fails_data_t;

typedef union
{
    macsec_test_rekey_an_rotation_decrypts_all_data_t rekey_an_rotation_decrypts_all_data;

    macsec_test_rekey_old_rx_sak_still_accepted_data_t rekey_old_rx_sak_still_accepted_data;

    macsec_test_rekey_wrong_key_same_an_fails_data_t rekey_wrong_key_same_an_fails_data;
} macsec_test_rekey_data_t;

int macsec_test_rekey(macsec_test_rekey_data_t *data, int verbose);

#endif /* MACSEC_SELF_TEST */

#ifdef __cplusplus
}
#endif

#endif /* TEST_REKEY_H */
