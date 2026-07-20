/*
 * unit_tests.h
 *
 * Lightweight MACsec stack
 * Test framework and unit test entry points.
 * This file provides the common infrastructure for executing and organizing
 * the unit tests included with the lightweight MACsec stack.
 *
 * Copyright (c) 2026 Michal Sarnovsky
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */

#ifndef MACSEC_UNIT_TESTS_H
#define MACSEC_UNIT_TESTS_H

#include "macsec_common.h"

#include <tests/test_common.h>
#include <tests/test_frame_crypto.h>
#include <tests/test_integration.h>
#include <tests/test_macsec_flow.h>
#include <tests/test_math_selftest.h>
#include <tests/test_mka_crypto.h>
#include <tests/test_mka_frames.h>
#include <tests/test_mka_negative.h>
#include <tests/test_mka_state.h>
#include <tests/test_mka_tx.h>
#include <tests/test_rekey.h>

#ifdef __cplusplus
extern "C"
{
#endif

#if (MACSEC_SELF_TEST != 0)

#define TEST_OK(expr)                                                                              \
    do                                                                                             \
    {                                                                                              \
        int _test_ret = (expr);                                                                    \
        if (_test_ret != 0)                                                                        \
        {                                                                                          \
            return _test_ret;                                                                      \
        }                                                                                          \
    } while (0)

#define TEST_TRUE(expr)                                                                            \
    do                                                                                             \
    {                                                                                              \
        if (!(expr))                                                                               \
        {                                                                                          \
            return -1;                                                                             \
        }                                                                                          \
    } while (0)

#define TEST_EQ_U32(a, b)                                                                          \
    do                                                                                             \
    {                                                                                              \
        uint32_t _test_a = (uint32_t) (a);                                                         \
        uint32_t _test_b = (uint32_t) (b);                                                         \
        if (_test_a != _test_b)                                                                    \
        {                                                                                          \
            return -1;                                                                             \
        }                                                                                          \
    } while (0)

#define TEST_MEM_EQ(a, b, len)                                                                     \
    do                                                                                             \
    {                                                                                              \
        if (macsec_compare((a), (b), (len)) != 0)                                                  \
        {                                                                                          \
            return -1;                                                                             \
        }                                                                                          \
    } while (0)

typedef union
{
    macsec_test_math_selftest_data_t test_math_selftest_data;
    macsec_test_mka_crypto_data_t test_mka_crypto_data;
    macsec_test_mka_frames_data_t test_mka_frames_data;
    macsec_test_frame_crypto_data_t test_frame_crypto_data;
    macsec_test_integration_data_t test_integration_data;
    macsec_test_mka_negative_data_t test_mka_negative_data;
    macsec_test_rekey_data_t test_rekey_data;
    macsec_test_macsec_flow_data_t test_macsec_flow_data;
    macsec_test_mka_state_data_t test_mka_state_data;
    macsec_test_mka_tx_data_t test_mka_tx_data;
} macsec_test_data_t;

int macsec_test_all(macsec_test_data_t *data, int verbose);

#endif

#ifdef __cplusplus
}
#endif

#endif
