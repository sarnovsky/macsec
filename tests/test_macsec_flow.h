/*
 * test_macsec_flow.h
 *
 * Lightweight MACsec stack
 * MACsec communication flow tests.
 * This file validates complete MACsec communication scenarios, including
 * secure frame transmission, reception and protocol state transitions.
 *
 * Copyright (c) 2026 Michal Sarnovský
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */

#ifndef TEST_MACSEC_FLOW_H
#define TEST_MACSEC_FLOW_H

#ifdef __cplusplus
extern "C" {
#endif

#include <macsec/common.h>

#include <macsec/macsec.h>
#include <macsec/mka.h>

#if (MACSEC_SELF_TEST != 0)

typedef struct
{
    macsec_ctx_t a;
    macsec_ctx_t b;

    macsec_config_t cfg_a;
    macsec_config_t cfg_b;

    uint8_t plain_a[128];
    uint8_t plain_b[128];
    uint8_t secure[256];
    uint8_t decrypted[128];
} macsec_test_macsec_flow_static_bidirectional_data_t;

typedef struct
{
    macsec_ctx_t macsec;
    macsec_mka_ctx_t mka_tx;

    macsec_config_t cfg;

    uint8_t eapol[MACSEC_MKA_MAX_FRAME_LEN];
    uint8_t plain[MACSEC_MKA_MAX_FRAME_LEN];
} macsec_test_macsec_flow_eapol_consumed_data_t;

typedef struct
{
    macsec_ctx_t ctx;
    macsec_config_t cfg;

    uint8_t plain[128];
    uint8_t secure[256];
} macsec_test_macsec_flow_mka_wait_drops_data_tx_data_t;

typedef struct
{
    macsec_ctx_t a;
    macsec_ctx_t b;

    macsec_config_t cfg_a;
    macsec_config_t cfg_b;

    uint8_t plain[128];
    uint8_t secure[256];
    uint8_t decrypted[128];
} macsec_test_macsec_flow_static_bad_key_rejected_data_t;

typedef union
{
    macsec_test_macsec_flow_static_bidirectional_data_t test_macsec_flow_static_bidirectional_data;
    macsec_test_macsec_flow_eapol_consumed_data_t test_macsec_flow_eapol_consumed_data;
    macsec_test_macsec_flow_mka_wait_drops_data_tx_data_t test_macsec_flow_mka_wait_drops_data_tx_data;
    macsec_test_macsec_flow_static_bad_key_rejected_data_t test_macsec_flow_static_bad_key_rejected_data;
} macsec_test_macsec_flow_data_t;


int macsec_test_macsec_flow(macsec_test_macsec_flow_data_t *data, int verbose);

#endif

#ifdef __cplusplus
}
#endif

#endif /* TEST_MACSEC_FLOW_H */
