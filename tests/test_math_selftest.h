/*
 * test_math_selftest.h
 *
 * Lightweight MACsec stack
 * Cryptographic backend self-test wrapper.
 * This file executes the built-in math self-tests to verify that the
 * underlying cryptographic library operates correctly on the target platform.
 *
 * Copyright (c) 2026 Michal Sarnovsky
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */

#ifndef TESTS_TEST_MATH_SELFTEST_H
#define TESTS_TEST_MATH_SELFTEST_H

#include "macsec_common.h"
#include "math/aes.h"
#include "math/cmac.h"
#include "math/gcm.h"

#ifdef __cplusplus
extern "C"
{
#endif

#if (MACSEC_SELF_TEST != 0)

typedef struct
{
    math_aes_context ctx;
} macsec_test_math_aes_selftest_data_t;

typedef struct
{
    math_gcm_context ctx;
    unsigned char buf[GCM_BUF_SIZE];
} macsec_test_math_gcm_selftest_data_t;

typedef struct
{
    math_cmac_context_t ctx;
} macsec_test_math_cmac_selftest_data_t;

typedef union
{
    macsec_test_math_aes_selftest_data_t test_math_aes_selftest_data;
    macsec_test_math_gcm_selftest_data_t test_math_gcm_selftest_data;
    macsec_test_math_cmac_selftest_data_t test_math_cmac_selftest_data;
} macsec_test_math_selftest_data_t;

int macsec_test_math_selftests(macsec_test_math_selftest_data_t *data, int verbose);

#endif

#ifdef __cplusplus
}
#endif

#endif /* TESTS_TEST_MATH_SELFTEST_H */
