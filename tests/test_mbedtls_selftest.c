/*
 * test_mbedtls_selftest.c
 *
 * Lightweight MACsec stack
 * Cryptographic backend self-test wrapper.
 * This file executes the built-in mbedTLS self-tests to verify that the
 * underlying cryptographic library operates correctly on the target platform.
 *
 * Copyright (c) 2026 Michal Sarnovský
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */

#include <tests/test_mka_crypto.h>
#include <tests/unit_tests.h>

#if (MACSEC_SELF_TEST != 0)

int macsec_test_mbedtls_selftests(macsec_test_mbedtls_selftest_data_t *data, int verbose)
{
    if (verbose)
    {
        MACSEC_PRINT(("MACsec MbedTLS self-tests\n"));
    }

    TEST_OK(mbedtls_aes_self_test(verbose ? 1 : 0));
    TEST_OK(mbedtls_gcm_self_test(verbose ? 1 : 0));
    TEST_OK(mbedtls_cmac_self_test(verbose ? 1 : 0));

    if (verbose)
    {
        MACSEC_PRINT(("MACsec MbedTLS self-tests PASSED\n"));
    }

    return 0;
}

#endif /* MACSEC_SELF_TEST */
