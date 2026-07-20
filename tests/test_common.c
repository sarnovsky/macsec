/*
 * test_common.c
 *
 * Lightweight MACsec stack
 * Unit tests for common utility functions.
 * This file verifies the behavior of shared helper routines, including
 * byte-order conversion, buffer manipulation and other common utilities.
 *
 * Copyright (c) 2026 Michal Sarnovsky
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */

#include <tests/test_common.h>
#include <tests/unit_tests.h>

#include <string.h>

#if (MACSEC_SELF_TEST != 0)

static int macsec_test_common_be16(int verbose)
{
    uint8_t buf[2];
    uint16_t v;

    (void) verbose;

    memset(buf, 0, sizeof(buf));

    macsec_wr_be16(buf, 0x1234u);
    TEST_EQ_U32(buf[0], 0x12u);
    TEST_EQ_U32(buf[1], 0x34u);

    v = macsec_rd_be16(buf);
    TEST_EQ_U32(v, 0x1234u);

    return 0;
}

static int macsec_test_common_be32(int verbose)
{
    uint8_t buf[4];
    uint32_t v;

    (void) verbose;

    memset(buf, 0, sizeof(buf));

    macsec_wr_be32(buf, 0x12345678ul);
    TEST_EQ_U32(buf[0], 0x12u);
    TEST_EQ_U32(buf[1], 0x34u);
    TEST_EQ_U32(buf[2], 0x56u);
    TEST_EQ_U32(buf[3], 0x78u);

    v = macsec_rd_be32(buf);
    TEST_EQ_U32(v, 0x12345678ul);

    return 0;
}

static int macsec_test_common_be64(int verbose)
{
    uint8_t buf[8];
    uint64_t v;

    (void) verbose;

    memset(buf, 0, sizeof(buf));

    macsec_wr_be64(buf, 0x0102030405060708ull);

    TEST_EQ_U32(buf[0], 0x01u);
    TEST_EQ_U32(buf[1], 0x02u);
    TEST_EQ_U32(buf[2], 0x03u);
    TEST_EQ_U32(buf[3], 0x04u);
    TEST_EQ_U32(buf[4], 0x05u);
    TEST_EQ_U32(buf[5], 0x06u);
    TEST_EQ_U32(buf[6], 0x07u);
    TEST_EQ_U32(buf[7], 0x08u);

    v = macsec_rd_be64(buf);

    TEST_TRUE(v == 0x0102030405060708ull);

    return 0;
}

static int macsec_test_common_zeroize(int verbose)
{
    uint8_t buf[16];
    size_t i;

    (void) verbose;

    memset(buf, 0xA5, sizeof(buf));
    macsec_zeroize(buf, sizeof(buf));

    for (i = 0u; i < sizeof(buf); i++)
    {
        TEST_EQ_U32(buf[i], 0u);
    }

    return 0;
}

static int macsec_test_common_zeroize_region(int verbose)
{
    uint8_t buf[16];
    size_t i;

    (void) verbose;

    memset(buf, 0xA5, sizeof(buf));

    macsec_zeroize(&buf[4], 8u);

    for (i = 0u; i < 4u; i++)
    {
        TEST_EQ_U32(buf[i], 0xA5u);
    }

    for (i = 4u; i < 12u; i++)
    {
        TEST_EQ_U32(buf[i], 0u);
    }

    for (i = 12u; i < sizeof(buf); i++)
    {
        TEST_EQ_U32(buf[i], 0xA5u);
    }

    return 0;
}

static int macsec_test_common_zeroize_zero_length(int verbose)
{
    uint8_t buf[8];
    size_t i;

    (void) verbose;

    memset(buf, 0x5Au, sizeof(buf));

    macsec_zeroize(buf, 0u);

    for (i = 0u; i < sizeof(buf); i++)
    {
        TEST_EQ_U32(buf[i], 0x5Au);
    }

    return 0;
}

static int macsec_test_common_compare_equal(int verbose)
{
    static const uint8_t buf1[] = {0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u,
                                   0x88u, 0x99u, 0xAAu, 0xBBu, 0xCCu, 0xDDu, 0xEEu, 0xFFu};

    static const uint8_t buf2[] = {0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u,
                                   0x88u, 0x99u, 0xAAu, 0xBBu, 0xCCu, 0xDDu, 0xEEu, 0xFFu};

    (void) verbose;

    TEST_TRUE(macsec_compare(buf1, buf2, sizeof(buf1)) == 0);

    return 0;
}

static int macsec_test_common_compare_different_first(int verbose)
{
    static const uint8_t buf1[] = {0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u};

    static const uint8_t buf2[] = {0xFFu, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u};

    (void) verbose;

    TEST_TRUE(macsec_compare(buf1, buf2, sizeof(buf1)) != 0);

    return 0;
}

static int macsec_test_common_compare_different_middle(int verbose)
{
    static const uint8_t buf1[] = {0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u};

    static const uint8_t buf2[] = {0x00u, 0x11u, 0x22u, 0x33u, 0x45u, 0x55u, 0x66u, 0x77u};

    (void) verbose;

    TEST_TRUE(macsec_compare(buf1, buf2, sizeof(buf1)) != 0);

    return 0;
}

static int macsec_test_common_compare_different_last(int verbose)
{
    static const uint8_t buf1[] = {0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u};

    static const uint8_t buf2[] = {0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x76u};

    (void) verbose;

    TEST_TRUE(macsec_compare(buf1, buf2, sizeof(buf1)) != 0);

    return 0;
}

static int macsec_test_common_compare_multiple_differences(int verbose)
{
    static const uint8_t buf1[] = {0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u};

    static const uint8_t buf2[] = {0xFFu, 0x11u, 0xDDu, 0x33u, 0x44u, 0xAAu, 0x66u, 0x88u};

    (void) verbose;

    TEST_TRUE(macsec_compare(buf1, buf2, sizeof(buf1)) != 0);

    return 0;
}

static int macsec_test_common_compare_zero_length(int verbose)
{
    static const uint8_t buf1[] = {0x00u};
    static const uint8_t buf2[] = {0xFFu};

    (void) verbose;

    /*
     * With a zero length, no bytes are compared and the buffers are
     * therefore considered equal.
     */
    TEST_TRUE(macsec_compare(buf1, buf2, 0u) == 0);

    return 0;
}

static int macsec_test_common_compare_prefix(int verbose)
{
    static const uint8_t buf1[] = {0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u};

    static const uint8_t buf2[] = {0x00u, 0x11u, 0x22u, 0x33u, 0xFFu, 0xFFu, 0xFFu, 0xFFu};

    (void) verbose;

    /*
     * Only the requested prefix is compared. Differences after len bytes
     * must not affect the result.
     */
    TEST_TRUE(macsec_compare(buf1, buf2, 4u) == 0);
    TEST_TRUE(macsec_compare(buf1, buf2, sizeof(buf1)) != 0);

    return 0;
}

static int macsec_test_common_hex_to_bin_basic(int verbose)
{
    static const char hex[] = "00112233AABBccdd";
    static const uint8_t expected[] = {0x00u, 0x11u, 0x22u, 0x33u, 0xAAu, 0xBBu, 0xCCu, 0xDDu};

    uint8_t out[16];
    size_t out_len;
    int ret;

    (void) verbose;

    memset(out, 0, sizeof(out));
    out_len = 0u;

    ret = macsec_hex_to_bin(hex, out, &out_len, sizeof(out));
    TEST_OK(ret);

    TEST_EQ_U32(out_len, sizeof(expected));
    TEST_MEM_EQ(out, expected, sizeof(expected));

    return 0;
}

static int macsec_test_common_hex_to_bin_too_small(int verbose)
{
    static const char hex[] = "00112233";

    uint8_t out[2];
    size_t out_len;
    int ret;

    (void) verbose;

    memset(out, 0, sizeof(out));
    out_len = 0u;

    ret = macsec_hex_to_bin(hex, out, &out_len, sizeof(out));

    TEST_TRUE(ret != MACSEC_ERR_OK);

    return 0;
}

static int macsec_test_common_hex_to_bin_invalid(int verbose)
{
    static const char hex[] = "0011223Z";

    uint8_t out[8];
    size_t out_len;
    int ret;

    (void) verbose;

    memset(out, 0, sizeof(out));
    out_len = 0u;

    ret = macsec_hex_to_bin(hex, out, &out_len, sizeof(out));

    TEST_TRUE(ret != MACSEC_ERR_OK);

    return 0;
}

int macsec_test_common(int verbose)
{
    if (verbose)
    {
        MACSEC_PRINT(("MACsec common tests\n"));
    }

    TEST_OK(macsec_test_common_be16(verbose));
    TEST_OK(macsec_test_common_be32(verbose));
    TEST_OK(macsec_test_common_be64(verbose));

    TEST_OK(macsec_test_common_zeroize(verbose));
    TEST_OK(macsec_test_common_zeroize_region(verbose));
    TEST_OK(macsec_test_common_zeroize_zero_length(verbose));

    TEST_OK(macsec_test_common_compare_equal(verbose));
    TEST_OK(macsec_test_common_compare_different_first(verbose));
    TEST_OK(macsec_test_common_compare_different_middle(verbose));
    TEST_OK(macsec_test_common_compare_different_last(verbose));
    TEST_OK(macsec_test_common_compare_multiple_differences(verbose));
    TEST_OK(macsec_test_common_compare_zero_length(verbose));
    TEST_OK(macsec_test_common_compare_prefix(verbose));

    TEST_OK(macsec_test_common_hex_to_bin_basic(verbose));
    TEST_OK(macsec_test_common_hex_to_bin_too_small(verbose));
    TEST_OK(macsec_test_common_hex_to_bin_invalid(verbose));

    if (verbose)
    {
        MACSEC_PRINT(("MACsec common tests PASSED\n"));
    }

    return 0;
}

#endif /* MACSEC_SELF_TEST */
