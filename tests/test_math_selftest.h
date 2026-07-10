/*
 * test_math_selftest.h
 *
 * Lightweight MACsec stack
 * Cryptographic backend self-test wrapper.
 * This file executes the built-in math self-tests to verify that the
 * underlying cryptographic library operates correctly on the target platform.
 *
 * Copyright (c) 2026 Michal Sarnovský
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */

#ifndef TESTS_TEST_MATH_SELFTEST_H
#define TESTS_TEST_MATH_SELFTEST_H

#include "common.h"
#include "mka_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

#if (MACSEC_SELF_TEST != 0)

typedef struct
{
    math_aes_context ctx;
} macsec_test_math_aes_selftest_data_t;

typedef struct
{
} macsec_test_math_gcm_selftest_data_t;

typedef struct
{
} macsec_test_math_cmac_selftest_data_t;

typedef union
{
    macsec_test_math_aes_selftest_data_t test_math_aes_selftest_data_t;
    macsec_test_math_gcm_selftest_data_t test_math_gcm_selftest_data_t;
    macsec_test_math_cmac_selftest_data_t test_math_cmac_selftest_data_t;
} macsec_test_math_selftest_data_t;


int macsec_test_math_selftests(macsec_test_math_selftest_data_t *data, int verbose);

#endif

#ifdef __cplusplus
}
#endif

#endif /* TESTS_TEST_MATH_SELFTEST_H */
