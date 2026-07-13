/*
 * test_mka_negative.h
 *
 * Lightweight MACsec stack
 * Negative and robustness tests for the MKA protocol.
 * This file verifies correct handling of malformed, invalid and unexpected
 * MKA messages, ensuring proper error detection and protocol robustness.
 *
 * Copyright (c) 2026 Michal Sarnovský
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */

#ifndef TEST_MKA_NEGATIVE_H
#define TEST_MKA_NEGATIVE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "common.h"
#include "mka.h"

#if (MACSEC_SELF_TEST != 0)

typedef struct
{
    uint8_t frame[MACSEC_MKA_MAX_FRAME_LEN];
    macsec_mka_ctx_t mka;
} macsec_test_mka_negative_bad_ethertype_data_t;

typedef struct
{
    uint8_t frame[MACSEC_MKA_MAX_FRAME_LEN];
    macsec_mka_ctx_t mka;
} macsec_test_mka_negative_bad_eapol_type_data_t;

typedef struct
{
    uint8_t frame[32];
    macsec_mka_ctx_t mka;
} macsec_test_mka_negative_short_frame_data_t;

typedef struct
{
    uint8_t frame[MACSEC_MKA_MAX_FRAME_LEN];

    macsec_mka_ctx_t tx;
    macsec_mka_ctx_t rx;
} macsec_test_mka_negative_bad_icv_data_t;

typedef struct
{
    uint8_t frame[MACSEC_MKA_MAX_FRAME_LEN];

    macsec_mka_ctx_t tx;
    macsec_mka_ctx_t rx;
} macsec_test_mka_negative_wrong_cak_fails_icv_data_t;

typedef struct
{
    uint8_t frame[MACSEC_MKA_MAX_FRAME_LEN];
    macsec_mka_ctx_t mka;
} macsec_test_mka_negative_reflected_own_frame_ignored_data_t;

typedef union
{
    macsec_test_mka_negative_bad_ethertype_data_t
        test_mka_negative_bad_ethertype_data;

    macsec_test_mka_negative_bad_eapol_type_data_t
        test_mka_negative_bad_eapol_type_data;

    macsec_test_mka_negative_short_frame_data_t
        test_mka_negative_short_frame_data_data;

    macsec_test_mka_negative_bad_icv_data_t
        test_mka_negative_bad_icv_data_data;

    macsec_test_mka_negative_wrong_cak_fails_icv_data_t
        test_mka_negative_wrong_cak_fails_icv_data;

    macsec_test_mka_negative_reflected_own_frame_ignored_data_t
        test_mka_negative_reflected_own_frame_ignored_data;
} macsec_test_mka_negative_data_t;

int macsec_test_mka_negative(macsec_test_mka_negative_data_t *data,
                             int verbose);

#endif /* MACSEC_SELF_TEST */

#ifdef __cplusplus
}
#endif

#endif /* TEST_MKA_NEGATIVE_H */
