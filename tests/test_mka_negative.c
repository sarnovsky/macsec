/*
 * test_mka_negative.c
 *
 * Lightweight MACsec stack
 * Negative and robustness tests for the MKA protocol.
 * This file verifies correct handling of malformed, invalid and unexpected
 * MKA messages, ensuring proper error detection and protocol robustness.
 *
 * Copyright (c) 2026 Michal Sarnovsky
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */

#include <tests/test_mka_negative.h>
#include <tests/unit_tests.h>

#include <string.h>

#if (MACSEC_SELF_TEST != 0)

static const uint8_t test_cak_16[16] = {0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u,
                                        0x88u, 0x99u, 0xAAu, 0xBBu, 0xCCu, 0xDDu, 0xEEu, 0xFFu};

static const uint8_t test_cak_32[32] = {0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u,
                                        0x88u, 0x99u, 0xAAu, 0xBBu, 0xCCu, 0xDDu, 0xEEu, 0xFFu,

                                        0x10u, 0x21u, 0x32u, 0x43u, 0x54u, 0x65u, 0x76u, 0x87u,
                                        0x98u, 0xA9u, 0xBAu, 0xCBu, 0xDCu, 0xEDu, 0xFEu, 0x0Fu};

/*
 * Differs from test_cak_32 only in the last byte.
 * This verifies that the second half of a 32-byte CAK is used.
 */
static const uint8_t wrong_cak_32[32] = {0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u,
                                         0x88u, 0x99u, 0xAAu, 0xBBu, 0xCCu, 0xDDu, 0xEEu, 0xFFu,

                                         0x10u, 0x21u, 0x32u, 0x43u, 0x54u, 0x65u, 0x76u, 0x87u,
                                         0x98u, 0xA9u, 0xBAu, 0xCBu, 0xDCu, 0xEDu, 0xFEu, 0x0Eu};

static const uint8_t wrong_cak_16[16] = {0xFFu, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u,
                                         0x88u, 0x99u, 0xAAu, 0xBBu, 0xCCu, 0xDDu, 0xEEu, 0xFFu};

static const uint8_t test_ckn[24] = {0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u,
                                     0x88u, 0x99u, 0xAAu, 0xBBu, 0xCCu, 0xDDu, 0xEEu, 0xFFu,
                                     0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u};

static const uint8_t test_mac_a[6] = {0x02u, 0x00u, 0x00u, 0x00u, 0x00u, 0x01u};

static const uint8_t test_mac_b[6] = {0x02u, 0x00u, 0x00u, 0x00u, 0x00u, 0x02u};

static int macsec_test_mka_negative_init(macsec_mka_ctx_t *ctx, const uint8_t *cak, size_t cak_len,
                                         const uint8_t mac[6], uint8_t priority)
{
    macsec_assert(ctx != NULL);
    macsec_assert(cak != NULL);
    macsec_assert(mac != NULL);
    macsec_assert((cak_len == 16u) || (cak_len == 32u));

    return macsec_mka_init(ctx, cak, cak_len, test_ckn, sizeof(test_ckn), mac, 1u, priority, 2000u);
}

/*
 * Build an MKPDU and simulate successful transmission.
 *
 * Negative tests subsequently inspect, modify or deliver the generated
 * frame. The success notification commits the message number, transmission
 * time and transmitted scheduling reasons.
 */
static int macsec_test_mka_build_and_commit_tx(macsec_mka_ctx_t *ctx, uint8_t *frame,
                                               size_t *frame_len, size_t frame_max_len,
                                               uint32_t now_ms)
{
    macsec_mka_tx_meta_t tx_meta;
    int ret;

    macsec_assert(ctx != NULL);
    macsec_assert(frame != NULL);
    macsec_assert(frame_len != NULL);

    memset(&tx_meta, 0, sizeof(tx_meta));

    ret = macsec_mka_build_tx_frame(ctx, frame, frame_len, frame_max_len, &tx_meta);
    if (ret != MACSEC_ERR_OK)
    {
        return ret;
    }

    ret = macsec_mka_notify_tx_success(ctx, &tx_meta, now_ms);

    macsec_zeroize(&tx_meta, sizeof(tx_meta));

    return ret;
}

static int
macsec_test_mka_negative_bad_ethertype(macsec_test_mka_negative_bad_ethertype_data_t *data,
                                       const uint8_t *cak, size_t cak_len, int verbose)
{
    size_t frame_len = 0u;
    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  MKA negative bad EtherType test, %u-byte CAK\n", (unsigned int) cak_len));
    }

    ret = macsec_test_mka_negative_init(&data->mka, cak, cak_len, test_mac_a, 255u);
    TEST_OK(ret);

    ret = macsec_test_mka_build_and_commit_tx(&data->mka, data->frame, &frame_len,
                                              sizeof(data->frame), 100u);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_clear(&data->mka);
        return ret;
    }

    macsec_wr_be16(&data->frame[12], 0x0800u);

    ret = macsec_mka_input(&data->mka, data->frame, frame_len, 100u);

    macsec_mka_clear(&data->mka);

    TEST_TRUE(ret != MACSEC_ERR_OK);

    return 0;
}

static int
macsec_test_mka_negative_bad_eapol_type(macsec_test_mka_negative_bad_eapol_type_data_t *data,
                                        const uint8_t *cak, size_t cak_len, int verbose)
{
    size_t frame_len = 0u;
    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  MKA negative bad EAPOL type test, %u-byte CAK\n", (unsigned int) cak_len));
    }

    ret = macsec_test_mka_negative_init(&data->mka, cak, cak_len, test_mac_a, 255u);
    TEST_OK(ret);

    ret = macsec_test_mka_build_and_commit_tx(&data->mka, data->frame, &frame_len,
                                              sizeof(data->frame), 100u);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_clear(&data->mka);
        return ret;
    }

    data->frame[15] = 0x01u;

    ret = macsec_mka_input(&data->mka, data->frame, frame_len, 100u);

    macsec_mka_clear(&data->mka);

    TEST_TRUE(ret != MACSEC_ERR_OK);

    return 0;
}

static int macsec_test_mka_negative_short_frame(macsec_test_mka_negative_short_frame_data_t *data,
                                                const uint8_t *cak, size_t cak_len, int verbose)
{
    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  MKA negative short frame test, %u-byte CAK\n", (unsigned int) cak_len));
    }

    ret = macsec_test_mka_negative_init(&data->mka, cak, cak_len, test_mac_a, 255u);
    TEST_OK(ret);

    memset(data->frame, 0, sizeof(data->frame));

    macsec_wr_be16(&data->frame[12], MACSEC_MKA_ETHERTYPE_EAPOL);

    data->frame[15] = MACSEC_MKA_EAPOL_TYPE_MKA;

    ret = macsec_mka_input(&data->mka, data->frame, sizeof(data->frame), 100u);

    macsec_mka_clear(&data->mka);

    TEST_TRUE(ret != MACSEC_ERR_OK);

    return 0;
}

static int macsec_test_mka_negative_bad_icv(macsec_test_mka_negative_bad_icv_data_t *data,
                                            const uint8_t *cak, size_t cak_len, int verbose)
{
    size_t frame_len = 0u;
    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  MKA negative bad ICV test, %u-byte CAK\n", (unsigned int) cak_len));
    }

    ret = macsec_test_mka_negative_init(&data->tx, cak, cak_len, test_mac_a, 255u);
    TEST_OK(ret);

    ret = macsec_test_mka_negative_init(&data->rx, cak, cak_len, test_mac_b, 100u);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_clear(&data->tx);
        return ret;
    }

    ret = macsec_test_mka_build_and_commit_tx(&data->tx, data->frame, &frame_len,
                                              sizeof(data->frame), 100u);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_clear(&data->tx);
        macsec_mka_clear(&data->rx);
        return ret;
    }

    data->frame[frame_len - 1u] ^= 0x01u;

    ret = macsec_mka_input(&data->rx, data->frame, frame_len, 100u);

    TEST_TRUE(ret == MACSEC_ERR_AUTH);
    TEST_TRUE(!data->rx.last_icv_valid);
    TEST_TRUE(!data->rx.peer.valid);

    macsec_mka_clear(&data->tx);
    macsec_mka_clear(&data->rx);

    return 0;
}

static int macsec_test_mka_negative_reflected_own_frame_ignored(
    macsec_test_mka_negative_reflected_own_frame_ignored_data_t *data, const uint8_t *cak,
    size_t cak_len, int verbose)
{
    size_t frame_len = 0u;
    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  MKA negative reflected own frame ignored test, "
                      "%u-byte CAK\n",
                      (unsigned int) cak_len));
    }

    ret = macsec_test_mka_negative_init(&data->mka, cak, cak_len, test_mac_a, 255u);
    TEST_OK(ret);

    ret = macsec_test_mka_build_and_commit_tx(&data->mka, data->frame, &frame_len,
                                              sizeof(data->frame), 100u);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_clear(&data->mka);
        return ret;
    }

    ret = macsec_mka_input(&data->mka, data->frame, frame_len, 100u);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_clear(&data->mka);
        return ret;
    }

    TEST_TRUE(!data->mka.peer.valid);
    TEST_TRUE(data->mka.state == MACSEC_MKA_STATE_WAIT_PEER);

    macsec_mka_clear(&data->mka);

    return 0;
}

static int macsec_test_mka_negative_wrong_cak_fails_icv(
    macsec_test_mka_negative_wrong_cak_fails_icv_data_t *data, const uint8_t *tx_cak,
    const uint8_t *rx_cak, size_t cak_len, int verbose)
{
    size_t frame_len = 0u;
    int ret;

    macsec_assert(tx_cak != NULL);
    macsec_assert(rx_cak != NULL);
    macsec_assert((cak_len == 16u) || (cak_len == 32u));

    if (verbose)
    {
        MACSEC_PRINT(("  MKA negative wrong CAK fails ICV test, "
                      "%u-byte CAK\n",
                      (unsigned int) cak_len));
    }

    ret = macsec_test_mka_negative_init(&data->tx, tx_cak, cak_len, test_mac_a, 255u);
    TEST_OK(ret);

    ret = macsec_test_mka_negative_init(&data->rx, rx_cak, cak_len, test_mac_b, 100u);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_clear(&data->tx);
        return ret;
    }

    ret = macsec_test_mka_build_and_commit_tx(&data->tx, data->frame, &frame_len,
                                              sizeof(data->frame), 100u);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_clear(&data->tx);
        macsec_mka_clear(&data->rx);
        return ret;
    }

    ret = macsec_mka_input(&data->rx, data->frame, frame_len, 100u);

    TEST_TRUE(ret == MACSEC_ERR_AUTH);
    TEST_TRUE(!data->rx.last_icv_valid);
    TEST_TRUE(!data->rx.peer.valid);

    macsec_mka_clear(&data->tx);
    macsec_mka_clear(&data->rx);

    return 0;
}

int macsec_test_mka_negative(macsec_test_mka_negative_data_t *data, int verbose)
{
    if (verbose)
    {
        MACSEC_PRINT(("MACsec MKA negative tests\n"));
    }

    TEST_OK(macsec_test_mka_negative_bad_ethertype(&data->test_mka_negative_bad_ethertype_data,
                                                   test_cak_16, sizeof(test_cak_16), verbose));

    TEST_OK(macsec_test_mka_negative_bad_ethertype(&data->test_mka_negative_bad_ethertype_data,
                                                   test_cak_32, sizeof(test_cak_32), verbose));

    TEST_OK(macsec_test_mka_negative_bad_eapol_type(&data->test_mka_negative_bad_eapol_type_data,
                                                    test_cak_16, sizeof(test_cak_16), verbose));

    TEST_OK(macsec_test_mka_negative_bad_eapol_type(&data->test_mka_negative_bad_eapol_type_data,
                                                    test_cak_32, sizeof(test_cak_32), verbose));

    TEST_OK(macsec_test_mka_negative_short_frame(&data->test_mka_negative_short_frame_data_data,
                                                 test_cak_16, sizeof(test_cak_16), verbose));

    TEST_OK(macsec_test_mka_negative_short_frame(&data->test_mka_negative_short_frame_data_data,
                                                 test_cak_32, sizeof(test_cak_32), verbose));

    TEST_OK(macsec_test_mka_negative_bad_icv(&data->test_mka_negative_bad_icv_data_data,
                                             test_cak_16, sizeof(test_cak_16), verbose));

    TEST_OK(macsec_test_mka_negative_bad_icv(&data->test_mka_negative_bad_icv_data_data,
                                             test_cak_32, sizeof(test_cak_32), verbose));

    TEST_OK(macsec_test_mka_negative_wrong_cak_fails_icv(
        &data->test_mka_negative_wrong_cak_fails_icv_data, test_cak_16, wrong_cak_16,
        sizeof(test_cak_16), verbose));

    TEST_OK(macsec_test_mka_negative_wrong_cak_fails_icv(
        &data->test_mka_negative_wrong_cak_fails_icv_data, test_cak_32, wrong_cak_32,
        sizeof(test_cak_32), verbose));

    TEST_OK(macsec_test_mka_negative_reflected_own_frame_ignored(
        &data->test_mka_negative_reflected_own_frame_ignored_data, test_cak_16, sizeof(test_cak_16),
        verbose));

    TEST_OK(macsec_test_mka_negative_reflected_own_frame_ignored(
        &data->test_mka_negative_reflected_own_frame_ignored_data, test_cak_32, sizeof(test_cak_32),
        verbose));

    return 0;
}

#endif /* MACSEC_SELF_TEST */
