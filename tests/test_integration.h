/*
 * test_integration.h
 *
 * Lightweight MACsec stack
 * End-to-end integration tests.
 * This file verifies correct interaction between the MACsec, MKA and
 * cryptographic modules under realistic operating conditions.
 *
 * Copyright (c) 2026 Michal Sarnovský
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */

#ifndef TEST_INTEGRATION_H
#define TEST_INTEGRATION_H

#ifdef __cplusplus
extern "C" {
#endif

#include "common.h"

#include "macsec.h"

#if (MACSEC_SELF_TEST != 0)

typedef struct
{
    macsec_ctx_t ctx;
    macsec_config_t cfg;

    uint8_t plain_tx[96];
    uint8_t tx_frame[128];
    uint8_t rx_frame[128];
} macsec_test_integration_disabled_passthrough_data_t;

typedef struct
{
    macsec_ctx_t a;
    macsec_ctx_t b;

    macsec_config_t cfg_a;
    macsec_config_t cfg_b;

    uint8_t plain_tx[128];
    uint8_t secure_frame[256];
    uint8_t plain_rx[128];
} macsec_test_integration_static_sak_ping_like_data_t;

typedef struct
{
    macsec_ctx_t ctx;
    macsec_config_t cfg;

    uint8_t plain[96];
    uint8_t out[128];
} macsec_test_integration_protected_drops_plain_data_t;

typedef struct
{
    macsec_ctx_t ctx;
    macsec_config_t cfg;

    uint8_t plain[96];
    uint8_t secure[160];
} macsec_test_integration_output_not_ready_mka_data_t;

typedef union
{
    macsec_test_integration_disabled_passthrough_data_t test_integration_disabled_passthrough_data;
    macsec_test_integration_static_sak_ping_like_data_t test_integration_static_sak_ping_like_data;
    macsec_test_integration_protected_drops_plain_data_t test_integration_protected_drops_plain_data;
    macsec_test_integration_output_not_ready_mka_data_t test_integration_output_not_ready_mka_data;
} macsec_test_integration_data_t;

int macsec_test_integration(macsec_test_integration_data_t *data, int verbose);

#endif

#ifdef __cplusplus
}
#endif

#endif /* TEST_INTEGRATION_H */
