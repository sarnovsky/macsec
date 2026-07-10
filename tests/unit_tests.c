/*
 * unit_tests.c
 *
 * Lightweight MACsec stack
 * Test framework and unit test entry points.
 * This file provides the common infrastructure for executing and organizing
 * the unit tests included with the lightweight MACsec stack.
 *
 * Copyright (c) 2026 Michal Sarnovský
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */

#include <tests/unit_tests.h>

#if (MACSEC_SELF_TEST != 0)

int macsec_test_all(macsec_test_data_t *data, int verbose)
{
    if (verbose)
    {
        MACSEC_PRINT(("========================================\n"));
        MACSEC_PRINT(("MACsec self-tests\n"));
        MACSEC_PRINT(("========================================\n"));
    }

    TEST_OK(macsec_test_common(verbose));
    TEST_OK(macsec_test_math_selftests(&data->test_math_selftest_data, verbose));
    TEST_OK(macsec_test_mka_crypto(&data->test_mka_crypto_data, verbose));
    TEST_OK(macsec_test_mka_frames(&data->test_mka_frames_data, verbose));
    TEST_OK(macsec_test_frame_crypto(&data->test_frame_crypto_data, verbose));
    TEST_OK(macsec_test_integration(&data->test_integration_data, verbose));
    TEST_OK(macsec_test_mka_negative(&data->test_mka_negative_data, verbose));
    TEST_OK(macsec_test_rekey(&data->test_rekey_data, verbose));
    TEST_OK(macsec_test_macsec_flow(&data->test_macsec_flow_data, verbose));

    if (verbose)
    {
        MACSEC_PRINT(("========================================\n"));
        MACSEC_PRINT(("MACsec self-tests PASSED\n"));
        MACSEC_PRINT(("========================================\n"));
    }

    return 0;
}

#endif
