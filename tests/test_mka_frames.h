/*
 * test_mka_frames.h
 *
 * Lightweight MACsec stack
 * Unit tests for MKA frame encoding and decoding.
 * This file verifies generation, parsing and validation of MKA protocol
 * frames and their individual parameter sets.
 *
 * Copyright (c) 2026 Michal Sarnovský
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */

#ifndef TESTS_TEST_MKA_FRAMES_H
#define TESTS_TEST_MKA_FRAMES_H

#include <macsec/common.h>
#include <macsec/mka.h>

#ifdef __cplusplus
extern "C" {
#endif

#if (MACSEC_SELF_TEST != 0)

typedef struct
{
    macsec_mka_ctx_t mka;
    uint8_t frame[MACSEC_MKA_MAX_FRAME_LEN];
} macsec_test_mka_frames_linux_basic_icv_data_t;

typedef struct
{
    macsec_mka_ctx_t mka;
    macsec_mka_basic_t basic;
    uint8_t frame[MACSEC_MKA_MAX_FRAME_LEN];
} macsec_test_mka_frames_build_parse_basic_data_t;

typedef struct
{
    macsec_mka_ctx_t tx;
    macsec_mka_ctx_t rx;
    uint8_t frame[MACSEC_MKA_MAX_FRAME_LEN];
} macsec_test_mka_frames_generated_icv_ok_data_t;

typedef struct
{
    macsec_mka_ctx_t tx;
    macsec_mka_ctx_t rx;
    uint8_t frame[MACSEC_MKA_MAX_FRAME_LEN];
} macsec_test_mka_frames_generated_icv_bad_data_t;

typedef struct
{
    uint8_t cak[32];
    uint8_t ckn[32];
    uint8_t frame[MACSEC_MKA_MAX_FRAME_LEN];
    macsec_mka_ctx_t a;
    macsec_mka_ctx_t b;
} macsec_test_mka_frames_two_peer_exchange_data_t;

typedef struct
{
    macsec_mka_ctx_t mka;
    uint8_t frame[MACSEC_MKA_MAX_FRAME_LEN];
} macsec_test_mka_frames_tx_pending_timing_data_t;

typedef struct
{
} macsec_test_mka_frames_distributed_sak_layout_data_t;

typedef struct
{
    macsec_mka_ctx_t a;
    macsec_mka_ctx_t b;
    uint8_t frame_a[MACSEC_MKA_MAX_FRAME_LEN];
    uint8_t frame_b[MACSEC_MKA_MAX_FRAME_LEN];
} macsec_test_mka_frames_stm32_key_server_distributes_sak_data_t;

typedef struct
{
    macsec_mka_ctx_t a;
    macsec_mka_ctx_t b;
    uint8_t frame_a[MACSEC_MKA_MAX_FRAME_LEN];
    uint8_t frame_b[MACSEC_MKA_MAX_FRAME_LEN];
} macsec_test_mka_frames_sak_use_key_server_mi_data_t;

typedef struct
{
    macsec_mka_ctx_t a;
    macsec_mka_ctx_t b;
    uint8_t frame_a[MACSEC_MKA_MAX_FRAME_LEN];
    uint8_t frame_b[MACSEC_MKA_MAX_FRAME_LEN];
} macsec_test_mka_frames_sak_use_tx_rx_flags_data_t;

typedef union
{
    macsec_test_mka_frames_linux_basic_icv_data_t test_mka_frames_linux_basic_icv_data;
    macsec_test_mka_frames_build_parse_basic_data_t test_mka_frames_build_parse_basic_data;
    macsec_test_mka_frames_generated_icv_ok_data_t test_mka_frames_generated_icv_ok_data;
    macsec_test_mka_frames_generated_icv_bad_data_t test_mka_frames_generated_icv_bad_data;
    macsec_test_mka_frames_two_peer_exchange_data_t test_mka_frames_two_peer_exchange_data;
    macsec_test_mka_frames_tx_pending_timing_data_t test_mka_frames_tx_pending_timing_data;
    macsec_test_mka_frames_distributed_sak_layout_data_t test_mka_frames_distributed_sak_layout_data;
    macsec_test_mka_frames_stm32_key_server_distributes_sak_data_t test_mka_frames_stm32_key_server_distributes_sak_data;
    macsec_test_mka_frames_sak_use_key_server_mi_data_t test_mka_frames_sak_use_key_server_mi_data;
    macsec_test_mka_frames_sak_use_tx_rx_flags_data_t test_mka_frames_sak_use_tx_rx_flags_data;
} macsec_test_mka_frames_data_t;

int macsec_test_mka_frames(macsec_test_mka_frames_data_t *data, int verbose);

#endif

#ifdef __cplusplus
}
#endif

#endif /* TESTS_TEST_MKA_FRAMES_H */
