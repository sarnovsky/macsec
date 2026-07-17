/*
 * test_math_selftest.c
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

#include <tests/test_mka_crypto.h>
#include <tests/unit_tests.h>

#if (MACSEC_SELF_TEST != 0)

int macsec_test_math_selftests(macsec_test_math_selftest_data_t *data, int verbose)
{
    if (verbose)
    {
        MACSEC_PRINT(("MACsec math self-tests\n"));
    }

    TEST_OK(math_aes_self_test(&data->test_math_aes_selftest_data.ctx, verbose ? 1 : 0));
    TEST_OK(math_gcm_self_test(&data->test_math_gcm_selftest_data.ctx,
                               data->test_math_gcm_selftest_data.buf, verbose ? 1 : 0));
    TEST_OK(math_cmac_self_test(&data->test_math_cmac_selftest_data.ctx, verbose ? 1 : 0));

    if (verbose)
    {
        MACSEC_PRINT(("MACsec math self-tests PASSED\n"));
    }

    return 0;
}

#endif /* MACSEC_SELF_TEST */
