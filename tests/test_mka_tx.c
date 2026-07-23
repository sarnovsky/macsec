/*
 * test_mka_tx.c
 *
 * Lightweight MACsec stack
 * Unit tests for the explicit MKA transmit lifecycle.
 * This file verifies separation of MKPDU building from transmission commit,
 * successful and failed transmission notification, TX reason handling and
 * Distributed SAK retransmission after a peer identity change.
 *
 * Copyright (c) 2026 Michal Sarnovsky
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

/******************************************************************************
 * Test constants
 *****************************************************************************/

#define MACSEC_TEST_MKA_TX_INTERVAL_MS 2000u
#define MACSEC_TEST_MKA_TX_TIME_MS 1000u

#define MACSEC_TEST_MKA_TX_KEY_NUMBER 1u
#define MACSEC_TEST_MKA_TX_AN 0u

#define MACSEC_TEST_MKA_TX_LOCAL_PRIORITY 10u
#define MACSEC_TEST_MKA_TX_PEER_PRIORITY 20u

/*
 * IEEE 802.1X MKA parameter-set type for Distributed SAK.
 */
#define MACSEC_TEST_MKA_TX_PARAM_DISTRIBUTED_SAK 4u

/*
 * Ethernet header followed by the four-byte EAPOL header.
 */
#define MACSEC_TEST_MKA_TX_EAPOL_BODY_OFFSET 18u
#define MACSEC_TEST_MKA_TX_EAPOL_LENGTH_OFFSET 16u
#define MACSEC_TEST_MKA_TX_PARAMETER_HEADER_LEN 4u

static const uint8_t s_macsec_test_mka_tx_cak[16] = {0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u,
                                                     0x66u, 0x77u, 0x88u, 0x99u, 0xAAu, 0xBBu,
                                                     0xCCu, 0xDDu, 0xEEu, 0xFFu};

static const uint8_t s_macsec_test_mka_tx_ckn[24] = {
    0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u, 0x88u, 0x99u, 0xAAu, 0xBBu,
    0xCCu, 0xDDu, 0xEEu, 0xFFu, 0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u};

static const uint8_t s_macsec_test_mka_tx_mac[6] = {0x02u, 0x00u, 0x00u, 0x00u, 0x00u, 0x01u};

static const uint8_t s_macsec_test_mka_tx_peer_mac[6] = {0x02u, 0x00u, 0x00u, 0x00u, 0x00u, 0x02u};

static const uint8_t s_macsec_test_mka_tx_sak[16] = {0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u,
                                                     0x06u, 0x07u, 0x08u, 0x09u, 0x0Au, 0x0Bu,
                                                     0x0Cu, 0x0Du, 0x0Eu, 0x0Fu};

/******************************************************************************
 * Test helpers
 *****************************************************************************/

static int macsec_test_mka_tx_init(macsec_test_mka_tx_case_data_t *data)
{
    macsec_assert(data != NULL);

    memset(data, 0, sizeof(*data));

    return macsec_mka_init(&data->mka, s_macsec_test_mka_tx_cak, sizeof(s_macsec_test_mka_tx_cak),
                           s_macsec_test_mka_tx_ckn, sizeof(s_macsec_test_mka_tx_ckn),
                           s_macsec_test_mka_tx_mac, 1u, MACSEC_TEST_MKA_TX_LOCAL_PRIORITY,
                           MACSEC_TEST_MKA_TX_INTERVAL_MS);
}

static int macsec_test_mka_tx_build(macsec_test_mka_tx_case_data_t *data, uint8_t *frame,
                                    size_t *frame_len, macsec_mka_basic_t *basic)
{
    int ret;

    macsec_assert(data != NULL);
    macsec_assert(frame != NULL);
    macsec_assert(frame_len != NULL);
    macsec_assert(basic != NULL);

    *frame_len = 0u;

    memset(&data->tx_meta, 0, sizeof(data->tx_meta));
    memset(basic, 0, sizeof(*basic));

    ret = macsec_mka_build_tx_frame(&data->mka, frame, frame_len, MACSEC_MKA_MAX_FRAME_LEN,
                                    &data->tx_meta);
    if (ret != MACSEC_ERR_OK)
    {
        return ret;
    }

    return macsec_mka_parse_basic(frame, *frame_len, basic);
}

static macsec_bool_t macsec_test_mka_tx_frame_has_parameter(const uint8_t *frame, size_t frame_len,
                                                            uint8_t expected_type)
{
    uint16_t eapol_len;
    uint16_t body_len;
    size_t pos;
    size_t end;
    size_t next_pos;

    macsec_assert(frame != NULL);

    if (frame_len < MACSEC_TEST_MKA_TX_EAPOL_BODY_OFFSET)
    {
        return MACSEC_FALSE;
    }

    eapol_len = (uint16_t) (((uint16_t) frame[MACSEC_TEST_MKA_TX_EAPOL_LENGTH_OFFSET] << 8u) |
                            (uint16_t) frame[MACSEC_TEST_MKA_TX_EAPOL_LENGTH_OFFSET + 1u]);

    if (eapol_len < MACSEC_MKA_ICV_LEN)
    {
        return MACSEC_FALSE;
    }

    end = MACSEC_TEST_MKA_TX_EAPOL_BODY_OFFSET + (size_t) eapol_len - MACSEC_MKA_ICV_LEN;

    if (end > frame_len)
    {
        return MACSEC_FALSE;
    }

    pos = MACSEC_TEST_MKA_TX_EAPOL_BODY_OFFSET;

    while ((pos + MACSEC_TEST_MKA_TX_PARAMETER_HEADER_LEN) <= end)
    {
        body_len =
            (uint16_t) (((uint16_t) (frame[pos + 2u] & 0x0Fu) << 8u) | (uint16_t) frame[pos + 3u]);

        next_pos = pos + MACSEC_TEST_MKA_TX_PARAMETER_HEADER_LEN + (size_t) body_len;

        if (next_pos > end)
        {
            return MACSEC_FALSE;
        }

        if (frame[pos] == expected_type)
        {
            return MACSEC_TRUE;
        }

        pos = next_pos;
    }

    return MACSEC_FALSE;
}

static int macsec_test_mka_tx_prepare_redistribution(macsec_test_mka_tx_case_data_t *data)
{
    macsec_assert(data != NULL);

    TEST_OK(macsec_test_mka_tx_init(data));

    /*
     * Prepare one live peer. The local participant has the lower priority and
     * therefore acts as the Key Server.
     */
    data->mka.local_key_server = MACSEC_TRUE;

    data->mka.peer.valid = MACSEC_TRUE;
    data->mka.peer.live = MACSEC_TRUE;
    data->mka.peer.seen_in_peer_list = MACSEC_TRUE;

    memcpy(data->mka.peer.mac, s_macsec_test_mka_tx_peer_mac, sizeof(data->mka.peer.mac));

    data->mka.peer.key_server_priority = MACSEC_TEST_MKA_TX_PEER_PRIORITY;

    /*
     * Prepare the already installed locally generated SAK which existed before
     * the peer changed its MI. Local data-plane installation remains valid,
     * but confirmation belonging to the current peer identity is cleared.
     */
    memset(&data->mka.latest_sak, 0, sizeof(data->mka.latest_sak));

    memcpy(data->mka.latest_sak.sak, s_macsec_test_mka_tx_sak, sizeof(s_macsec_test_mka_tx_sak));

    data->mka.latest_sak.sak_len = sizeof(s_macsec_test_mka_tx_sak);
    data->mka.latest_sak.an = MACSEC_TEST_MKA_TX_AN;
    data->mka.latest_sak.key_number = MACSEC_TEST_MKA_TX_KEY_NUMBER;
    data->mka.latest_sak.lowest_pn = 1u;
    data->mka.latest_sak.origin = MACSEC_MKA_SAK_ORIGIN_LOCAL_KEY_SERVER;
    data->mka.latest_sak.lifecycle_state = MACSEC_MKA_SAK_STATE_ACTIVE;
    data->mka.latest_sak.valid = MACSEC_TRUE;
    data->mka.latest_sak.rx_installed = MACSEC_TRUE;
    data->mka.latest_sak.tx_installed = MACSEC_TRUE;
    data->mka.latest_sak.peer_rx_confirmed = MACSEC_FALSE;
    data->mka.latest_sak.peer_tx_confirmed = MACSEC_FALSE;

    data->mka.latest_key_rx = MACSEC_TRUE;
    data->mka.latest_key_tx = MACSEC_TRUE;
    data->mka.latest_lowest_pn = 1u;

    data->mka.state = MACSEC_MKA_STATE_OPERATIONAL;

    /*
     * A peer identity change normally schedules an immediate redistribution.
     */
    data->mka.tx_reasons = MACSEC_MKA_TX_REASON_DISTRIBUTE_SAK;

    return 0;
}

/******************************************************************************
 * Existing explicit TX lifecycle tests
 *****************************************************************************/

static int macsec_test_mka_tx_build_without_commit(macsec_test_mka_tx_case_data_t *data,
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

    TEST_OK(macsec_test_mka_tx_build(data, data->frame_a, &frame_a_len, &data->basic_a));

    TEST_EQ_U32(data->mka.tx_reasons, reasons_before);
    TEST_EQ_U32(data->mka.last_tx_ms, last_tx_before);

    TEST_OK(macsec_test_mka_tx_build(data, data->frame_b, &frame_b_len, &data->basic_b));

    TEST_EQ_U32(data->basic_b.actor_mn, data->basic_a.actor_mn);
    TEST_EQ_U32(data->mka.tx_reasons, reasons_before);
    TEST_EQ_U32(data->mka.last_tx_ms, last_tx_before);

    macsec_mka_clear(&data->mka);

    return 0;
}

static int macsec_test_mka_tx_success_commit(macsec_test_mka_tx_case_data_t *data, int verbose)
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

    TEST_OK(macsec_test_mka_tx_build(data, data->frame_a, &frame_a_len, &data->basic_a));

    first_mn = data->basic_a.actor_mn;

    ret = macsec_mka_notify_tx_success(&data->mka, &data->tx_meta, MACSEC_TEST_MKA_TX_TIME_MS);

    TEST_TRUE(ret == MACSEC_ERR_OK);
    TEST_EQ_U32(data->mka.last_tx_ms, MACSEC_TEST_MKA_TX_TIME_MS);
    TEST_EQ_U32(data->mka.tx_reasons, MACSEC_MKA_TX_REASON_NONE);

    data->mka.tx_reasons = MACSEC_MKA_TX_REASON_PERIODIC;

    TEST_OK(macsec_test_mka_tx_build(data, data->frame_b, &frame_b_len, &data->basic_b));

    TEST_EQ_U32(data->basic_b.actor_mn, first_mn + 1u);

    macsec_mka_clear(&data->mka);

    return 0;
}

static int macsec_test_mka_tx_failure_retry(macsec_test_mka_tx_case_data_t *data, int verbose)
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

    TEST_OK(macsec_test_mka_tx_build(data, data->frame_a, &frame_a_len, &data->basic_a));

    macsec_mka_notify_tx_failure(&data->mka, &data->tx_meta);

    TEST_EQ_U32(data->mka.tx_reasons, reasons_before);
    TEST_EQ_U32(data->mka.last_tx_ms, last_tx_before);

    TEST_OK(macsec_test_mka_tx_build(data, data->frame_b, &frame_b_len, &data->basic_b));

    TEST_EQ_U32(data->basic_b.actor_mn, data->basic_a.actor_mn);

    macsec_mka_clear(&data->mka);

    return 0;
}

static int macsec_test_mka_tx_success_preserves_new_reason(macsec_test_mka_tx_case_data_t *data,
                                                           int verbose)
{
    macsec_mka_tx_reason_flags_t built_reasons;
    size_t frame_len;
    int ret;

    macsec_assert(data != NULL);

    if (verbose)
    {
        MACSEC_PRINT(("  MKA TX success preserves newly scheduled reason test\n"));
    }

    TEST_OK(macsec_test_mka_tx_init(data));

    built_reasons = data->mka.tx_reasons;

    TEST_TRUE((built_reasons & MACSEC_MKA_TX_REASON_INITIAL) != 0u);
    TEST_TRUE((built_reasons & MACSEC_MKA_TX_REASON_SAK_USE) == 0u);

    TEST_OK(macsec_test_mka_tx_build(data, data->frame_a, &frame_len, &data->basic_a));

    data->mka.tx_reasons |= MACSEC_MKA_TX_REASON_SAK_USE;

    ret = macsec_mka_notify_tx_success(&data->mka, &data->tx_meta, MACSEC_TEST_MKA_TX_TIME_MS);

    TEST_TRUE(ret == MACSEC_ERR_OK);

    TEST_TRUE((data->mka.tx_reasons & built_reasons) == 0u);
    TEST_TRUE((data->mka.tx_reasons & MACSEC_MKA_TX_REASON_SAK_USE) != 0u);

    macsec_mka_clear(&data->mka);

    return 0;
}

static int macsec_test_mka_tx_periodic_after_success(macsec_test_mka_tx_case_data_t *data,
                                                     int verbose)
{
    size_t frame_len;
    int ret;

    macsec_assert(data != NULL);

    if (verbose)
    {
        MACSEC_PRINT(("  MKA TX periodic scheduling after success test\n"));
    }

    TEST_OK(macsec_test_mka_tx_init(data));

    TEST_OK(macsec_test_mka_tx_build(data, data->frame_a, &frame_len, &data->basic_a));

    ret = macsec_mka_notify_tx_success(&data->mka, &data->tx_meta, MACSEC_TEST_MKA_TX_TIME_MS);

    TEST_TRUE(ret == MACSEC_ERR_OK);
    TEST_EQ_U32(data->mka.tx_reasons, MACSEC_MKA_TX_REASON_NONE);

    TEST_OK(macsec_mka_tick(&data->mka,
                            MACSEC_TEST_MKA_TX_TIME_MS + MACSEC_TEST_MKA_TX_INTERVAL_MS - 1u));

    TEST_EQ_U32(data->mka.tx_reasons, MACSEC_MKA_TX_REASON_NONE);

    TEST_OK(
        macsec_mka_tick(&data->mka, MACSEC_TEST_MKA_TX_TIME_MS + MACSEC_TEST_MKA_TX_INTERVAL_MS));

    TEST_TRUE((data->mka.tx_reasons & MACSEC_MKA_TX_REASON_PERIODIC) != 0u);

    macsec_mka_clear(&data->mka);

    return 0;
}

/******************************************************************************
 * Distributed SAK retransmission tests
 *****************************************************************************/

static int macsec_test_mka_tx_peer_restart_redistributes_sak(macsec_test_mka_tx_case_data_t *data,
                                                             int verbose)
{
    size_t frame_len;

    macsec_assert(data != NULL);

    if (verbose)
    {
        MACSEC_PRINT(("  MKA TX peer restart redistributes SAK test\n"));
    }

    TEST_OK(macsec_test_mka_tx_prepare_redistribution(data));

    TEST_OK(macsec_test_mka_tx_build(data, data->frame_a, &frame_len, &data->basic_a));

    TEST_TRUE(macsec_test_mka_tx_frame_has_parameter(data->frame_a, frame_len,
                                                     MACSEC_TEST_MKA_TX_PARAM_DISTRIBUTED_SAK) ==
              MACSEC_TRUE);

    TEST_EQ_U32(data->mka.latest_sak.lifecycle_state, MACSEC_MKA_SAK_STATE_ACTIVE);
    TEST_TRUE(data->mka.latest_sak.peer_rx_confirmed == MACSEC_FALSE);
    TEST_TRUE(data->mka.latest_sak.peer_tx_confirmed == MACSEC_FALSE);

    /*
     * Building the retransmission must not allocate a new key identity.
     */
    TEST_EQ_U32(data->mka.latest_sak.key_number, MACSEC_TEST_MKA_TX_KEY_NUMBER);
    TEST_EQ_U32(data->mka.latest_sak.an, MACSEC_TEST_MKA_TX_AN);

    macsec_mka_clear(&data->mka);

    return 0;
}

static int
macsec_test_mka_tx_redistribution_repeats_until_confirmation(macsec_test_mka_tx_case_data_t *data,
                                                             int verbose)
{
    size_t frame_a_len;
    size_t frame_b_len;
    int ret;

    macsec_assert(data != NULL);

    if (verbose)
    {
        MACSEC_PRINT(("  MKA TX SAK redistribution repeats until confirmation test\n"));
    }

    TEST_OK(macsec_test_mka_tx_prepare_redistribution(data));

    TEST_OK(macsec_test_mka_tx_build(data, data->frame_a, &frame_a_len, &data->basic_a));

    TEST_TRUE(macsec_test_mka_tx_frame_has_parameter(data->frame_a, frame_a_len,
                                                     MACSEC_TEST_MKA_TX_PARAM_DISTRIBUTED_SAK) ==
              MACSEC_TRUE);

    ret = macsec_mka_notify_tx_success(&data->mka, &data->tx_meta, MACSEC_TEST_MKA_TX_TIME_MS);

    TEST_TRUE(ret == MACSEC_ERR_OK);

    /*
     * Successful local transmission is not peer confirmation.
     */
    TEST_TRUE(data->mka.latest_sak.peer_rx_confirmed == MACSEC_FALSE);
    TEST_TRUE(data->mka.latest_sak.peer_tx_confirmed == MACSEC_FALSE);
    TEST_EQ_U32(data->mka.latest_sak.lifecycle_state, MACSEC_MKA_SAK_STATE_ACTIVE);

    TEST_OK(
        macsec_mka_tick(&data->mka, MACSEC_TEST_MKA_TX_TIME_MS + MACSEC_TEST_MKA_TX_INTERVAL_MS));

    TEST_TRUE((data->mka.tx_reasons & MACSEC_MKA_TX_REASON_PERIODIC) != 0u);

    TEST_OK(macsec_test_mka_tx_build(data, data->frame_b, &frame_b_len, &data->basic_b));

    TEST_TRUE(macsec_test_mka_tx_frame_has_parameter(data->frame_b, frame_b_len,
                                                     MACSEC_TEST_MKA_TX_PARAM_DISTRIBUTED_SAK) ==
              MACSEC_TRUE);

    TEST_EQ_U32(data->mka.latest_sak.key_number, MACSEC_TEST_MKA_TX_KEY_NUMBER);
    TEST_EQ_U32(data->mka.latest_sak.an, MACSEC_TEST_MKA_TX_AN);

    macsec_mka_clear(&data->mka);

    return 0;
}

static int
macsec_test_mka_tx_redistribution_stops_after_confirmation(macsec_test_mka_tx_case_data_t *data,
                                                           int verbose)
{
    size_t frame_a_len;
    size_t frame_b_len;
    int ret;

    macsec_assert(data != NULL);

    if (verbose)
    {
        MACSEC_PRINT(("  MKA TX SAK redistribution stops after confirmation test\n"));
    }

    TEST_OK(macsec_test_mka_tx_prepare_redistribution(data));

    TEST_OK(macsec_test_mka_tx_build(data, data->frame_a, &frame_a_len, &data->basic_a));

    TEST_TRUE(macsec_test_mka_tx_frame_has_parameter(data->frame_a, frame_a_len,
                                                     MACSEC_TEST_MKA_TX_PARAM_DISTRIBUTED_SAK) ==
              MACSEC_TRUE);

    ret = macsec_mka_notify_tx_success(&data->mka, &data->tx_meta, MACSEC_TEST_MKA_TX_TIME_MS);

    TEST_TRUE(ret == MACSEC_ERR_OK);

    /*
     * The MKA state tests verify that a matching received SAK Use produces
     * this confirmed state. This TX test verifies its effect on the builder.
     */
    data->mka.latest_sak.peer_rx_confirmed = MACSEC_TRUE;
    data->mka.latest_sak.peer_tx_confirmed = MACSEC_TRUE;
    data->mka.latest_sak.lifecycle_state = MACSEC_MKA_SAK_STATE_CONFIRMED;

    TEST_OK(
        macsec_mka_tick(&data->mka, MACSEC_TEST_MKA_TX_TIME_MS + MACSEC_TEST_MKA_TX_INTERVAL_MS));

    TEST_TRUE((data->mka.tx_reasons & MACSEC_MKA_TX_REASON_PERIODIC) != 0u);

    TEST_OK(macsec_test_mka_tx_build(data, data->frame_b, &frame_b_len, &data->basic_b));

    TEST_TRUE(macsec_test_mka_tx_frame_has_parameter(data->frame_b, frame_b_len,
                                                     MACSEC_TEST_MKA_TX_PARAM_DISTRIBUTED_SAK) ==
              MACSEC_FALSE);

    TEST_EQ_U32(data->mka.latest_sak.lifecycle_state, MACSEC_MKA_SAK_STATE_CONFIRMED);
    TEST_EQ_U32(data->mka.latest_sak.key_number, MACSEC_TEST_MKA_TX_KEY_NUMBER);
    TEST_EQ_U32(data->mka.latest_sak.an, MACSEC_TEST_MKA_TX_AN);

    macsec_mka_clear(&data->mka);

    return 0;
}

/******************************************************************************
 * Public test entry point
 *****************************************************************************/

int macsec_test_mka_tx(macsec_test_mka_tx_data_t *data, int verbose)
{
    macsec_assert(data != NULL);

    if (verbose)
    {
        MACSEC_PRINT(("MACsec MKA TX lifecycle tests\n"));
    }

    TEST_OK(macsec_test_mka_tx_build_without_commit(&data->build_without_commit_data, verbose));

    TEST_OK(macsec_test_mka_tx_success_commit(&data->success_commit_data, verbose));

    TEST_OK(macsec_test_mka_tx_failure_retry(&data->failure_retry_data, verbose));

    TEST_OK(
        macsec_test_mka_tx_success_preserves_new_reason(&data->preserve_new_reason_data, verbose));

    TEST_OK(macsec_test_mka_tx_periodic_after_success(&data->periodic_after_success_data, verbose));

    TEST_OK(macsec_test_mka_tx_peer_restart_redistributes_sak(
        &data->peer_restart_redistribution_data, verbose));

    TEST_OK(macsec_test_mka_tx_redistribution_repeats_until_confirmation(
        &data->redistribution_repeat_data, verbose));

    TEST_OK(macsec_test_mka_tx_redistribution_stops_after_confirmation(
        &data->redistribution_stop_data, verbose));

    if (verbose)
    {
        MACSEC_PRINT(("MACsec MKA TX lifecycle tests PASSED\n"));
    }

    return 0;
}

#endif /* MACSEC_SELF_TEST */
