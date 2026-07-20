/*
 * test_macsec_flow.h
 *
 * Lightweight MACsec stack
 * MACsec communication flow tests.
 * This file validates complete MACsec communication scenarios, including
 * secure frame transmission, reception and protocol state transitions.
 *
 * Copyright (c) 2026 Michal Sarnovsky
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */

#ifndef TEST_MACSEC_FLOW_H
#define TEST_MACSEC_FLOW_H

#include "macsec.h"
#include "macsec_common.h"

#ifdef __cplusplus
extern "C"
{
#endif

#if (MACSEC_SELF_TEST != 0)

#define MACSEC_TEST_MACSEC_FLOW_PLAIN_MAX_LEN 128u
#define MACSEC_TEST_MACSEC_FLOW_SECURE_MAX_LEN 256u
#define MACSEC_TEST_MACSEC_FLOW_CONTROL_MAX_LEN 256u
#define MACSEC_TEST_MACSEC_FLOW_PLAIN_LEN 96u
#define MACSEC_TEST_MACSEC_FLOW_SHORT_FRAME_MAX_LEN 13u

typedef struct
{
    macsec_ctx_t a;
    macsec_ctx_t b;

    macsec_config_t cfg_a;
    macsec_config_t cfg_b;

    uint8_t plain_a[MACSEC_TEST_MACSEC_FLOW_PLAIN_MAX_LEN];
    uint8_t plain_b[MACSEC_TEST_MACSEC_FLOW_PLAIN_MAX_LEN];
    uint8_t secure[MACSEC_TEST_MACSEC_FLOW_SECURE_MAX_LEN];
    uint8_t decrypted[MACSEC_TEST_MACSEC_FLOW_PLAIN_MAX_LEN];
} macsec_test_macsec_flow_static_bidirectional_data_t;

typedef struct
{
    macsec_ctx_t ctx;
    macsec_config_t cfg;

    uint8_t plain[MACSEC_TEST_MACSEC_FLOW_PLAIN_MAX_LEN];
    uint8_t output[MACSEC_TEST_MACSEC_FLOW_SECURE_MAX_LEN];
} macsec_test_macsec_flow_disabled_passthrough_data_t;

typedef struct
{
    macsec_ctx_t tx;
    macsec_ctx_t rx;

    macsec_config_t cfg_tx;
    macsec_config_t cfg_rx;

    uint8_t control[MACSEC_TEST_MACSEC_FLOW_CONTROL_MAX_LEN];
    uint8_t plain[MACSEC_TEST_MACSEC_FLOW_PLAIN_MAX_LEN];
} macsec_test_macsec_flow_eapol_consumed_data_t;

typedef struct
{
    macsec_ctx_t tx;
    macsec_ctx_t rx;

    macsec_config_t cfg_tx;
    macsec_config_t cfg_rx;

    uint8_t control[MACSEC_TEST_MACSEC_FLOW_CONTROL_MAX_LEN];
    uint8_t plain[MACSEC_TEST_MACSEC_FLOW_PLAIN_MAX_LEN];
} macsec_test_macsec_flow_bad_eapol_icv_data_t;

typedef struct
{
    macsec_ctx_t ctx;
    macsec_config_t cfg;

    uint8_t plain[MACSEC_TEST_MACSEC_FLOW_PLAIN_MAX_LEN];
    uint8_t secure[MACSEC_TEST_MACSEC_FLOW_SECURE_MAX_LEN];
} macsec_test_macsec_flow_mka_wait_drops_data_tx_data_t;

typedef struct
{
    macsec_ctx_t ctx;
    macsec_config_t cfg;

    uint8_t plain[MACSEC_TEST_MACSEC_FLOW_PLAIN_MAX_LEN];
    uint8_t decrypted[MACSEC_TEST_MACSEC_FLOW_PLAIN_MAX_LEN];
} macsec_test_macsec_flow_mka_wait_drops_data_rx_data_t;

typedef struct
{
    macsec_ctx_t a;
    macsec_ctx_t b;

    macsec_config_t cfg_a;
    macsec_config_t cfg_b;

    uint8_t plain[MACSEC_TEST_MACSEC_FLOW_PLAIN_MAX_LEN];
    uint8_t secure[MACSEC_TEST_MACSEC_FLOW_SECURE_MAX_LEN];
    uint8_t decrypted[MACSEC_TEST_MACSEC_FLOW_PLAIN_MAX_LEN];
} macsec_test_macsec_flow_static_bad_key_rejected_data_t;

typedef struct
{
    macsec_ctx_t a;
    macsec_ctx_t b;

    macsec_config_t cfg_a;
    macsec_config_t cfg_b;

    uint8_t plain[MACSEC_TEST_MACSEC_FLOW_PLAIN_MAX_LEN];
    uint8_t secure[MACSEC_TEST_MACSEC_FLOW_SECURE_MAX_LEN];
    uint8_t decrypted[MACSEC_TEST_MACSEC_FLOW_PLAIN_MAX_LEN];
} macsec_test_macsec_flow_tampered_secure_frame_data_t;

typedef struct
{
    macsec_ctx_t ctx;
    macsec_config_t cfg;

    uint8_t plain[MACSEC_TEST_MACSEC_FLOW_PLAIN_MAX_LEN];
    uint8_t secure[MACSEC_TEST_MACSEC_FLOW_SECURE_MAX_LEN];
    uint8_t decrypted[MACSEC_TEST_MACSEC_FLOW_PLAIN_MAX_LEN];
} macsec_test_macsec_flow_small_buffer_data_t;

typedef struct
{
    macsec_ctx_t ctx;
    macsec_config_t cfg;

    uint8_t short_frame[MACSEC_TEST_MACSEC_FLOW_SHORT_FRAME_MAX_LEN];
    uint8_t plain[MACSEC_TEST_MACSEC_FLOW_PLAIN_MAX_LEN];
} macsec_test_macsec_flow_short_frame_data_t;

typedef struct
{
    macsec_ctx_t a;
    macsec_ctx_t b;

    macsec_config_t cfg_a;
    macsec_config_t cfg_b;

    uint8_t control_a[MACSEC_TEST_MACSEC_FLOW_CONTROL_MAX_LEN];
    uint8_t control_b[MACSEC_TEST_MACSEC_FLOW_CONTROL_MAX_LEN];

    uint8_t plain_a[MACSEC_TEST_MACSEC_FLOW_PLAIN_MAX_LEN];
    uint8_t plain_b[MACSEC_TEST_MACSEC_FLOW_PLAIN_MAX_LEN];
    uint8_t secure[MACSEC_TEST_MACSEC_FLOW_SECURE_MAX_LEN];
    uint8_t decrypted[MACSEC_TEST_MACSEC_FLOW_PLAIN_MAX_LEN];
} macsec_test_macsec_flow_mka_secure_bidirectional_data_t;

typedef union
{
    macsec_test_macsec_flow_static_bidirectional_data_t test_static_bidirectional_data;

    macsec_test_macsec_flow_disabled_passthrough_data_t test_disabled_passthrough_data;

    macsec_test_macsec_flow_eapol_consumed_data_t test_eapol_consumed_data;

    macsec_test_macsec_flow_bad_eapol_icv_data_t test_bad_eapol_icv_data;

    macsec_test_macsec_flow_mka_wait_drops_data_tx_data_t test_mka_wait_drops_data_tx_data;

    macsec_test_macsec_flow_mka_wait_drops_data_rx_data_t test_mka_wait_drops_data_rx_data;

    macsec_test_macsec_flow_static_bad_key_rejected_data_t test_static_bad_key_rejected_data;

    macsec_test_macsec_flow_tampered_secure_frame_data_t test_tampered_secure_frame_data;

    macsec_test_macsec_flow_small_buffer_data_t test_small_buffer_data;

    macsec_test_macsec_flow_short_frame_data_t test_short_frame_data;

    macsec_test_macsec_flow_mka_secure_bidirectional_data_t test_mka_secure_bidirectional_data;
} macsec_test_macsec_flow_data_t;

int macsec_test_macsec_flow(macsec_test_macsec_flow_data_t *data, int verbose);

#endif /* MACSEC_SELF_TEST */

#ifdef __cplusplus
}
#endif

#endif /* TEST_MACSEC_FLOW_H */