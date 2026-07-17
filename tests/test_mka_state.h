/*
 * test_mka_state.h
 *
 * Lightweight MACsec stack
 * Unit tests for MKA participant state, event handling and SAK lifecycle.
 * This file verifies event consumption, SAK installation handoff,
 * data-plane installation confirmation and SAK retirement.
 *
 * Copyright (c) 2026 Michal Sarnovský
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */

#ifndef TESTS_TEST_MKA_STATE_H
#define TESTS_TEST_MKA_STATE_H

#include "macsec_common.h"
#include "mka.h"

#ifdef __cplusplus
extern "C" {
#endif

#if (MACSEC_SELF_TEST != 0)

/*
 * Event handling tests.
 */
typedef struct
{
    macsec_mka_ctx_t mka;
} macsec_test_mka_state_events_data_t;


/*
 * SAK handoff tests.
 */
typedef struct
{
    macsec_mka_ctx_t mka;
    macsec_mka_sak_t sak;
    macsec_mka_sak_t second_sak;
} macsec_test_mka_state_sak_take_data_t;


/*
 * SAK installation notification tests.
 */
typedef struct
{
    macsec_mka_ctx_t mka;
    macsec_mka_sak_t sak;
} macsec_test_mka_state_sak_install_data_t;


/*
 * SAK retirement tests.
 */
typedef struct
{
    macsec_mka_ctx_t mka;
} macsec_test_mka_state_sak_retire_data_t;


/*
 * The individual test groups are executed sequentially, therefore their
 * storage can be shared.
 */
typedef union
{
    macsec_test_mka_state_events_data_t
        test_mka_state_events_data;

    macsec_test_mka_state_sak_take_data_t
        test_mka_state_sak_take_data;

    macsec_test_mka_state_sak_install_data_t
        test_mka_state_sak_install_data;

    macsec_test_mka_state_sak_retire_data_t
        test_mka_state_sak_retire_data;
} macsec_test_mka_state_data_t;


/*
 * Execute all MKA state and SAK lifecycle unit tests.
 */
int macsec_test_mka_state(macsec_test_mka_state_data_t *data,
                          int verbose);

#endif /* MACSEC_SELF_TEST */

#ifdef __cplusplus
}
#endif

#endif /* TESTS_TEST_MKA_STATE_H */