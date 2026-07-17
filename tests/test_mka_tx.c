/*
 * test_mka_tx.c
 *
 * Lightweight MACsec stack
 * Unit tests for the explicit MKA transmit lifecycle.
 * This file verifies separation of MKPDU building from transmission commit,
 * successful and failed transmission notification and TX reason handling.
 *
 * Copyright (c) 2026 Michal Sarnovský
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */

#include <tests/test_mka_tx.h>
#include <tests/unit_tests.h>

#include <string.h>

#if (MACSEC_SELF_TEST != 0)

#define MACSEC_TEST_MKA_TX_INTERVAL_MS  2000u
#define MACSEC_TEST_MKA_TX_TIME_MS      1000u

static const uint8_t s_macsec_test_mka_tx_cak[16] =
{
    0x00u, 0x11u, 0x22u, 0x33u,
    0x44u, 0x55u, 0x66u, 0x77u,
    0x88u, 0x99u, 0xAAu, 0xBBu,
    0xCCu, 0xDDu, 0xEEu, 0xFFu
};

static const uint8_t s_macsec_test_mka_tx_ckn[24] =
{
    0x00u, 0x11u, 0x22u, 0x33u,
    0x44u, 0x55u, 0x66u, 0x77u,
    0x88u, 0x99u, 0xAAu, 0xBBu,
    0xCCu, 0xDDu, 0xEEu, 0xFFu,
    0x00u, 0x11u, 0x22u, 0x33u,
    0x44u, 0x55u, 0x66u, 0x77u
};

static const uint8_t s_macsec_test_mka_tx_mac[6] =
{
    0x02u, 0x00u, 0x00u, 0x00u, 0x00u, 0x01u
};

static int macsec_test_mka_tx_init(
    macsec_test_mka_tx_case_data_t *data)
{
    macsec_assert(data != NULL);

    memset(data, 0, sizeof(*data));

    return macsec_mka_init(
        &data->mka,
        s_macsec_test_mka_tx_cak,
        sizeof(s_macsec_test_mka_tx_cak),
        s_macsec_test_mka_tx_ckn,
        sizeof(s_macsec_test_mka_tx_ckn),
        s_macsec_test_mka_tx_mac,
        1u,
        255u,
        MACSEC_TEST_MKA_TX_INTERVAL_MS);
}

static int macsec_test_mka_tx_build(
    macsec_test_mka_tx_case_data_t *data,
    uint8_t *frame,
    size_t *frame_len,
    macsec_mka_basic_t *basic)
{
    int ret;

    macsec_assert(data != NULL);
    macsec_assert(frame != NULL);
    macsec_assert(frame_len != NULL);
    macsec_assert(basic != NULL);

    *frame_len = 0u;

    memset(&data->tx_meta, 0, sizeof(data->tx_meta));
    memset(basic, 0, sizeof(*basic));

    ret = macsec_mka_build_tx_frame(
        &data->mka,
        frame,
        frame_len,
        MACSEC_MKA_MAX_FRAME_LEN,
        &data->tx_meta);
    if (ret != MACSEC_ERR_OK)
    {
        return ret;
    }

    return macsec_mka_parse_basic(frame,
                                  *frame_len,
                                  basic);
}

static int macsec_test_mka_tx_build_without_commit(
    macsec_test_mka_tx_case_data_t *data,
    int verbose)
{
    macsec_mka_tx_reason_flags_t reasons_before;
    uint32_t last_tx_before;
    size_t frame_a_len;
    size_t frame_b_len;

    macsec_assert(data != NULL);

    if (verbose)
    {
        MACSEC_PRINT(("  MKA TX build without commit test\n"));
    }

    TEST_OK(macsec_test_mka_tx_init(data));

    reasons_before = data->mka.tx_reasons;
    last_tx_before = data->mka.last_tx_ms;

    TEST_TRUE(reasons_before != MACSEC_MKA_TX_REASON_NONE);

    TEST_OK(macsec_test_mka_tx_build(
        data,
        data->frame_a,
        &frame_a_len,
        &data->basic_a));

    TEST_EQ_U32(data->mka.tx_reasons, reasons_before);
    TEST_EQ_U32(data->mka.last_tx_ms, last_tx_before);

    TEST_OK(macsec_test_mka_tx_build(
        data,
        data->frame_b,
        &frame_b_len,
        &data->basic_b));

    TEST_EQ_U32(data->basic_b.actor_mn,
                data->basic_a.actor_mn);
    TEST_EQ_U32(data->mka.tx_reasons, reasons_before);
    TEST_EQ_U32(data->mka.last_tx_ms, last_tx_before);

    macsec_mka_clear(&data->mka);

    return 0;
}

static int macsec_test_mka_tx_success_commit(
    macsec_test_mka_tx_case_data_t *data,
    int verbose)
{
    uint32_t first_mn;
    size_t frame_a_len;
    size_t frame_b_len;
    int ret;

    macsec_assert(data != NULL);

    if (verbose)
    {
        MACSEC_PRINT(("  MKA TX successful commit test\n"));
    }

    TEST_OK(macsec_test_mka_tx_init(data));

    TEST_OK(macsec_test_mka_tx_build(
        data,
        data->frame_a,
        &frame_a_len,
        &data->basic_a));

    first_mn = data->basic_a.actor_mn;

    ret = macsec_mka_notify_tx_success(
        &data->mka,
        &data->tx_meta,
        MACSEC_TEST_MKA_TX_TIME_MS);

    TEST_TRUE(ret == MACSEC_ERR_OK);
    TEST_EQ_U32(data->mka.last_tx_ms,
                MACSEC_TEST_MKA_TX_TIME_MS);
    TEST_EQ_U32(data->mka.tx_reasons,
                MACSEC_MKA_TX_REASON_NONE);

    data->mka.tx_reasons = MACSEC_MKA_TX_REASON_PERIODIC;

    TEST_OK(macsec_test_mka_tx_build(
        data,
        data->frame_b,
        &frame_b_len,
        &data->basic_b));

    TEST_EQ_U32(data->basic_b.actor_mn,
                first_mn + 1u);

    macsec_mka_clear(&data->mka);

    return 0;
}

static int macsec_test_mka_tx_failure_retry(
    macsec_test_mka_tx_case_data_t *data,
    int verbose)
{
    macsec_mka_tx_reason_flags_t reasons_before;
    uint32_t last_tx_before;
    size_t frame_a_len;
    size_t frame_b_len;

    macsec_assert(data != NULL);

    if (verbose)
    {
        MACSEC_PRINT(("  MKA TX failure retry test\n"));
    }

    TEST_OK(macsec_test_mka_tx_init(data));

    reasons_before = data->mka.tx_reasons;
    last_tx_before = data->mka.last_tx_ms;

    TEST_OK(macsec_test_mka_tx_build(
        data,
        data->frame_a,
        &frame_a_len,
        &data->basic_a));

    macsec_mka_notify_tx_failure(
        &data->mka,
        &data->tx_meta);

    TEST_EQ_U32(data->mka.tx_reasons, reasons_before);
    TEST_EQ_U32(data->mka.last_tx_ms, last_tx_before);

    TEST_OK(macsec_test_mka_tx_build(
        data,
        data->frame_b,
        &frame_b_len,
        &data->basic_b));

    TEST_EQ_U32(data->basic_b.actor_mn,
                data->basic_a.actor_mn);

    macsec_mka_clear(&data->mka);

    return 0;
}

static int macsec_test_mka_tx_success_preserves_new_reason(
    macsec_test_mka_tx_case_data_t *data,
    int verbose)
{
    macsec_mka_tx_reason_flags_t built_reasons;
    size_t frame_len;
    int ret;

    macsec_assert(data != NULL);

    if (verbose)
    {
        MACSEC_PRINT((
            "  MKA TX success preserves newly scheduled reason test\n"));
    }

    TEST_OK(macsec_test_mka_tx_init(data));

    built_reasons = data->mka.tx_reasons;

    TEST_TRUE(
        (built_reasons & MACSEC_MKA_TX_REASON_INITIAL) != 0u);
    TEST_TRUE(
        (built_reasons & MACSEC_MKA_TX_REASON_SAK_USE) == 0u);

    TEST_OK(macsec_test_mka_tx_build(
        data,
        data->frame_a,
        &frame_len,
        &data->basic_a));

    data->mka.tx_reasons |= MACSEC_MKA_TX_REASON_SAK_USE;

    ret = macsec_mka_notify_tx_success(
        &data->mka,
        &data->tx_meta,
        MACSEC_TEST_MKA_TX_TIME_MS);

    TEST_TRUE(ret == MACSEC_ERR_OK);

    TEST_TRUE((data->mka.tx_reasons & built_reasons) == 0u);
    TEST_TRUE(
        (data->mka.tx_reasons &
         MACSEC_MKA_TX_REASON_SAK_USE) != 0u);

    macsec_mka_clear(&data->mka);

    return 0;
}

static int macsec_test_mka_tx_periodic_after_success(
    macsec_test_mka_tx_case_data_t *data,
    int verbose)
{
    size_t frame_len;
    int ret;

    macsec_assert(data != NULL);

    if (verbose)
    {
        MACSEC_PRINT((
            "  MKA TX periodic scheduling after success test\n"));
    }

    TEST_OK(macsec_test_mka_tx_init(data));

    TEST_OK(macsec_test_mka_tx_build(
        data,
        data->frame_a,
        &frame_len,
        &data->basic_a));

    ret = macsec_mka_notify_tx_success(
        &data->mka,
        &data->tx_meta,
        MACSEC_TEST_MKA_TX_TIME_MS);

    TEST_TRUE(ret == MACSEC_ERR_OK);
    TEST_EQ_U32(data->mka.tx_reasons,
                MACSEC_MKA_TX_REASON_NONE);

    TEST_OK(macsec_mka_tick(
        &data->mka,
        MACSEC_TEST_MKA_TX_TIME_MS +
        MACSEC_TEST_MKA_TX_INTERVAL_MS - 1u));

    TEST_EQ_U32(data->mka.tx_reasons,
                MACSEC_MKA_TX_REASON_NONE);

    TEST_OK(macsec_mka_tick(
        &data->mka,
        MACSEC_TEST_MKA_TX_TIME_MS +
        MACSEC_TEST_MKA_TX_INTERVAL_MS));

    TEST_TRUE(
        (data->mka.tx_reasons &
         MACSEC_MKA_TX_REASON_PERIODIC) != 0u);

    macsec_mka_clear(&data->mka);

    return 0;
}

int macsec_test_mka_tx(macsec_test_mka_tx_data_t *data,
                       int verbose)
{
    macsec_assert(data != NULL);

    if (verbose)
    {
        MACSEC_PRINT(("MACsec MKA TX lifecycle tests\n"));
    }

    TEST_OK(macsec_test_mka_tx_build_without_commit(
        &data->build_without_commit_data,
        verbose));

    TEST_OK(macsec_test_mka_tx_success_commit(
        &data->success_commit_data,
        verbose));

    TEST_OK(macsec_test_mka_tx_failure_retry(
        &data->failure_retry_data,
        verbose));

    TEST_OK(macsec_test_mka_tx_success_preserves_new_reason(
        &data->preserve_new_reason_data,
        verbose));

    TEST_OK(macsec_test_mka_tx_periodic_after_success(
        &data->periodic_after_success_data,
        verbose));

    if (verbose)
    {
        MACSEC_PRINT((
            "MACsec MKA TX lifecycle tests PASSED\n"));
    }

    return 0;
}

#endif /* MACSEC_SELF_TEST */
