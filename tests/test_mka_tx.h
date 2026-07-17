/*
 * test_mka_tx.h
 *
 * Lightweight MACsec stack
 * Unit tests for the explicit MKA transmit lifecycle.
 * This file verifies separation of MKPDU building from transmission commit,
 * successful and failed transmission notification and TX reason handling.
 *
 * Copyright (c) 2026 Michal Sarnovský
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */

#ifndef TESTS_TEST_MKA_TX_H
#define TESTS_TEST_MKA_TX_H

#include "macsec_common.h"
#include "mka.h"

#ifdef __cplusplus
extern "C" {
#endif

#if (MACSEC_SELF_TEST != 0)

typedef struct
{
    macsec_mka_ctx_t mka;
    macsec_mka_tx_meta_t tx_meta;
    macsec_mka_basic_t basic_a;
    macsec_mka_basic_t basic_b;
    uint8_t frame_a[MACSEC_MKA_MAX_FRAME_LEN];
    uint8_t frame_b[MACSEC_MKA_MAX_FRAME_LEN];
} macsec_test_mka_tx_case_data_t;

typedef union
{
    macsec_test_mka_tx_case_data_t build_without_commit_data;
    macsec_test_mka_tx_case_data_t success_commit_data;
    macsec_test_mka_tx_case_data_t failure_retry_data;
    macsec_test_mka_tx_case_data_t preserve_new_reason_data;
    macsec_test_mka_tx_case_data_t periodic_after_success_data;
} macsec_test_mka_tx_data_t;

int macsec_test_mka_tx(macsec_test_mka_tx_data_t *data,
                       int verbose);

#endif /* MACSEC_SELF_TEST */

#ifdef __cplusplus
}
#endif

#endif /* TESTS_TEST_MKA_TX_H */
