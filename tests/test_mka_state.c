/*
 * test_mka_state.c
 *
 * Lightweight MACsec stack
 * Unit tests for MKA participant state, event handling and SAK lifecycle.
 * This file verifies event consumption, SAK installation handoff,
 * data-plane installation confirmation and SAK retirement.
 *
 * Copyright (c) 2026 Michal Sarnovsky
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */

#include <tests/test_mka_state.h>
#include <tests/unit_tests.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if (MACSEC_SELF_TEST != 0)

/******************************************************************************
 * Test constants
 *****************************************************************************/

#define MACSEC_TEST_MKA_KEY_NUMBER 1u
#define MACSEC_TEST_MKA_OTHER_KEY_NUMBER 2u

#define MACSEC_TEST_MKA_AN 0u
#define MACSEC_TEST_MKA_OTHER_AN 1u

#define MACSEC_TEST_MKA_LOWEST_PN 123u

#define MACSEC_TEST_MKA_LOCAL_PRIORITY 10u
#define MACSEC_TEST_MKA_PEER_PRIORITY 20u

#define MACSEC_TEST_MKA_TX_INTERVAL_MS 1000u
#define MACSEC_TEST_MKA_RX_TIME_MS 1000u

static const uint8_t s_macsec_test_mka_cak[16] = {0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u,
                                                  0x66u, 0x77u, 0x88u, 0x99u, 0xAAu, 0xBBu,
                                                  0xCCu, 0xDDu, 0xEEu, 0xFFu};

static const uint8_t s_macsec_test_mka_ckn[16] = {0x10u, 0x11u, 0x12u, 0x13u, 0x14u, 0x15u,
                                                  0x16u, 0x17u, 0x18u, 0x19u, 0x1Au, 0x1Bu,
                                                  0x1Cu, 0x1Du, 0x1Eu, 0x1Fu};

static const uint8_t s_macsec_test_mka_local_mac[MACSEC_MKA_SRC_LEN] = {0x02u, 0x00u, 0x00u,
                                                                        0x00u, 0x00u, 0x01u};

static const uint8_t s_macsec_test_mka_peer_mac[MACSEC_MKA_SRC_LEN] = {0x02u, 0x00u, 0x00u,
                                                                       0x00u, 0x00u, 0x02u};

static const uint8_t s_macsec_test_mka_sak[16] = {0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u,
                                                  0x06u, 0x07u, 0x08u, 0x09u, 0x0Au, 0x0Bu,
                                                  0x0Cu, 0x0Du, 0x0Eu, 0x0Fu};

/******************************************************************************
 * Test helpers
 *****************************************************************************/

static void macsec_test_mka_state_clear_context(macsec_mka_ctx_t *mka)
{
    macsec_assert(mka != NULL);

    memset(mka, 0, sizeof(*mka));

    mka->state = MACSEC_MKA_STATE_INIT;

    mka->latest_sak.lifecycle_state = MACSEC_MKA_SAK_STATE_NONE;

    mka->latest_sak.origin = MACSEC_MKA_SAK_ORIGIN_NONE;
}

static void macsec_test_mka_state_prepare_sak(macsec_mka_ctx_t *mka, macsec_mka_sak_origin_t origin,
                                              macsec_mka_sak_state_t lifecycle_state)
{
    macsec_assert(mka != NULL);

    memset(&mka->latest_sak, 0, sizeof(mka->latest_sak));

    memcpy(mka->latest_sak.sak, s_macsec_test_mka_sak, sizeof(s_macsec_test_mka_sak));

    mka->latest_sak.sak_len = sizeof(s_macsec_test_mka_sak);

    mka->latest_sak.an = MACSEC_TEST_MKA_AN;

    mka->latest_sak.key_number = MACSEC_TEST_MKA_KEY_NUMBER;

    mka->latest_sak.lowest_pn = 1u;

    mka->latest_sak.origin = origin;

    mka->latest_sak.lifecycle_state = lifecycle_state;

    mka->latest_sak.rx_installed = MACSEC_FALSE;

    mka->latest_sak.tx_installed = MACSEC_FALSE;

    mka->latest_sak.peer_rx_confirmed = MACSEC_FALSE;

    mka->latest_sak.peer_tx_confirmed = MACSEC_FALSE;
}

static void macsec_test_mka_state_prepare_remote_candidate(macsec_mka_ctx_t *mka)
{
    macsec_assert(mka != NULL);

    macsec_test_mka_state_clear_context(mka);

    macsec_test_mka_state_prepare_sak(mka, MACSEC_MKA_SAK_ORIGIN_REMOTE_KEY_SERVER,
                                      MACSEC_MKA_SAK_STATE_CANDIDATE);
}

static int macsec_test_mka_state_prepare_install_pending(macsec_mka_ctx_t *mka,
                                                         macsec_mka_sak_t *sak)
{
    macsec_assert(mka != NULL);
    macsec_assert(sak != NULL);

    macsec_test_mka_state_prepare_remote_candidate(mka);

    memset(sak, 0, sizeof(*sak));

    return macsec_mka_take_sak_for_install(mka, sak);
}

static macsec_bool_t macsec_test_mka_state_buffer_is_zero(const uint8_t *buffer, size_t buffer_len)
{
    size_t i;

    macsec_assert(buffer != NULL);

    for (i = 0u; i < buffer_len; i++)
    {
        if (buffer[i] != 0u)
        {
            return MACSEC_FALSE;
        }
    }

    return MACSEC_TRUE;
}

static int macsec_test_mka_state_prepare_peer_confirmation(
    macsec_test_mka_state_peer_confirmation_data_t *data)
{
    macsec_assert(data != NULL);

    memset(data, 0, sizeof(*data));

    TEST_OK(macsec_mka_init(&data->local, s_macsec_test_mka_cak, sizeof(s_macsec_test_mka_cak),
                            s_macsec_test_mka_ckn, sizeof(s_macsec_test_mka_ckn),
                            s_macsec_test_mka_local_mac, 1u, MACSEC_TEST_MKA_LOCAL_PRIORITY,
                            MACSEC_TEST_MKA_TX_INTERVAL_MS));

    TEST_OK(macsec_mka_init(&data->peer, s_macsec_test_mka_cak, sizeof(s_macsec_test_mka_cak),
                            s_macsec_test_mka_ckn, sizeof(s_macsec_test_mka_ckn),
                            s_macsec_test_mka_peer_mac, 1u, MACSEC_TEST_MKA_PEER_PRIORITY,
                            MACSEC_TEST_MKA_TX_INTERVAL_MS));

    /*
     * The local participant is the Key Server and already has one active
     * locally generated SAK.
     */
    data->local.local_key_server = MACSEC_TRUE;
    data->local.state = MACSEC_MKA_STATE_OPERATIONAL;

    macsec_test_mka_state_prepare_sak(&data->local, MACSEC_MKA_SAK_ORIGIN_LOCAL_KEY_SERVER,
                                      MACSEC_MKA_SAK_STATE_ACTIVE);

    data->local.latest_sak.rx_installed = MACSEC_TRUE;
    data->local.latest_sak.tx_installed = MACSEC_TRUE;
    data->local.latest_sak.lowest_pn = 1u;

    /*
     * Pretend that an older participant identity was previously live. The
     * newly initialized peer uses a different random MI, so the next frame
     * represents a participant restart.
     */
    data->local.peer.valid = MACSEC_TRUE;
    data->local.peer.live = MACSEC_TRUE;
    data->local.peer.seen_in_peer_list = MACSEC_TRUE;
    memcpy(data->local.peer.mac, s_macsec_test_mka_peer_mac, sizeof(data->local.peer.mac));
    memcpy(data->local.peer.sci, data->peer.local_sci, sizeof(data->local.peer.sci));
    memcpy(data->local.peer.mi, data->peer.local_mi, sizeof(data->local.peer.mi));
    data->local.peer.mi[0] ^= 0x80u;
    data->local.peer.mn = 1u;
    data->local.peer.key_server_priority = MACSEC_TEST_MKA_PEER_PRIORITY;

    /*
     * Let the peer list the local participant so the received frame makes
     * the replacement peer live immediately.
     */
    data->peer.local_key_server = MACSEC_FALSE;
    data->peer.peer.valid = MACSEC_TRUE;
    data->peer.peer.live = MACSEC_TRUE;
    data->peer.peer.seen_in_peer_list = MACSEC_TRUE;
    memcpy(data->peer.peer.mac, data->local.local_mac, sizeof(data->peer.peer.mac));
    memcpy(data->peer.peer.sci, data->local.local_sci, sizeof(data->peer.peer.sci));
    memcpy(data->peer.peer.mi, data->local.local_mi, sizeof(data->peer.peer.mi));
    data->peer.peer.mn = data->local.local_mn;
    data->peer.peer.key_server_priority = MACSEC_TEST_MKA_LOCAL_PRIORITY;

    data->peer.tx_reasons = MACSEC_MKA_TX_REASON_PEER_CHANGE;

    return 0;
}

static void
macsec_test_mka_state_clear_peer_confirmation(macsec_test_mka_state_peer_confirmation_data_t *data)
{
    macsec_assert(data != NULL);

    macsec_mka_clear(&data->local);
    macsec_mka_clear(&data->peer);
}

static int
macsec_test_mka_state_build_peer_frame(macsec_test_mka_state_peer_confirmation_data_t *data)
{
    macsec_assert(data != NULL);

    data->frame_len = 0u;
    memset(&data->tx_meta, 0, sizeof(data->tx_meta));

    return macsec_mka_build_tx_frame(&data->peer, data->frame, &data->frame_len,
                                     sizeof(data->frame), &data->tx_meta);
}

/******************************************************************************
 * Event tests
 *****************************************************************************/

static int macsec_test_mka_state_events_take(macsec_test_mka_state_events_data_t *data, int verbose)
{
    macsec_mka_event_flags_t events;

    macsec_assert(data != NULL);

    if (verbose)
    {
        MACSEC_PRINT(("  MKA event take test\n"));
    }

    macsec_test_mka_state_clear_context(&data->mka);

    data->mka.pending_events = MACSEC_MKA_EVENT_PEER_LIVE | MACSEC_MKA_EVENT_SAK_AVAILABLE;

    events = macsec_mka_take_events(&data->mka);

    TEST_TRUE((events & MACSEC_MKA_EVENT_PEER_LIVE) != 0u);

    TEST_TRUE((events & MACSEC_MKA_EVENT_SAK_AVAILABLE) != 0u);

    TEST_EQ_U32(data->mka.pending_events, MACSEC_MKA_EVENT_NONE);

    return 0;
}

static int macsec_test_mka_state_events_second_take_empty(macsec_test_mka_state_events_data_t *data,
                                                          int verbose)
{
    macsec_mka_event_flags_t events;

    macsec_assert(data != NULL);

    if (verbose)
    {
        MACSEC_PRINT(("  MKA second event take empty test\n"));
    }

    macsec_test_mka_state_clear_context(&data->mka);

    data->mka.pending_events = MACSEC_MKA_EVENT_SAK_AVAILABLE;

    events = macsec_mka_take_events(&data->mka);

    TEST_EQ_U32(events, MACSEC_MKA_EVENT_SAK_AVAILABLE);

    events = macsec_mka_take_events(&data->mka);

    TEST_EQ_U32(events, MACSEC_MKA_EVENT_NONE);

    return 0;
}

static int macsec_test_mka_state_events_preserve_tx(macsec_test_mka_state_events_data_t *data,
                                                    int verbose)
{
    macsec_mka_tx_reason_flags_t reasons_before;

    macsec_assert(data != NULL);

    if (verbose)
    {
        MACSEC_PRINT(("  MKA event take preserves TX state test\n"));
    }

    macsec_test_mka_state_clear_context(&data->mka);

    data->mka.pending_events = MACSEC_MKA_EVENT_PEER_LIVE;

    data->mka.tx_reasons = MACSEC_MKA_TX_REASON_INITIAL | MACSEC_MKA_TX_REASON_PERIODIC;

    reasons_before = data->mka.tx_reasons;

    (void) macsec_mka_take_events(&data->mka);

    TEST_EQ_U32(data->mka.pending_events, MACSEC_MKA_EVENT_NONE);

    TEST_EQ_U32(data->mka.tx_reasons, reasons_before);

    return 0;
}

/******************************************************************************
 * SAK handoff tests
 *****************************************************************************/

static int macsec_test_mka_state_sak_take_no_sak(macsec_test_mka_state_sak_take_data_t *data,
                                                 int verbose)
{
    int ret;

    macsec_assert(data != NULL);

    if (verbose)
    {
        MACSEC_PRINT(("  MKA SAK take without available SAK test\n"));
    }

    macsec_test_mka_state_clear_context(&data->mka);

    memset(&data->sak, 0xA5, sizeof(data->sak));

    ret = macsec_mka_take_sak_for_install(&data->mka, &data->sak);

    TEST_TRUE(ret == MACSEC_ERR_NOT_READY);

    TEST_TRUE(macsec_test_mka_state_buffer_is_zero((const uint8_t *) &data->sak,
                                                   sizeof(data->sak)) == MACSEC_TRUE);

    return 0;
}

static int
macsec_test_mka_state_sak_take_remote_candidate(macsec_test_mka_state_sak_take_data_t *data,
                                                int verbose)
{
    int ret;

    macsec_assert(data != NULL);

    if (verbose)
    {
        MACSEC_PRINT(("  MKA remote candidate SAK take test\n"));
    }

    macsec_test_mka_state_prepare_remote_candidate(&data->mka);

    memset(&data->sak, 0, sizeof(data->sak));

    ret = macsec_mka_take_sak_for_install(&data->mka, &data->sak);

    TEST_TRUE(ret == MACSEC_ERR_OK);

    TEST_EQ_U32(data->mka.latest_sak.lifecycle_state, MACSEC_MKA_SAK_STATE_INSTALL_PENDING);

    TEST_EQ_U32(data->sak.lifecycle_state, MACSEC_MKA_SAK_STATE_INSTALL_PENDING);

    TEST_TRUE(data->sak.lifecycle_state != MACSEC_MKA_SAK_STATE_NONE);

    TEST_EQ_U32(data->sak.origin, MACSEC_MKA_SAK_ORIGIN_REMOTE_KEY_SERVER);

    TEST_EQ_U32(data->sak.sak_len, sizeof(s_macsec_test_mka_sak));

    TEST_EQ_U32(data->sak.an, MACSEC_TEST_MKA_AN);

    TEST_EQ_U32(data->sak.key_number, MACSEC_TEST_MKA_KEY_NUMBER);

    TEST_MEM_EQ(data->sak.sak, s_macsec_test_mka_sak, sizeof(s_macsec_test_mka_sak));

    return 0;
}

static int
macsec_test_mka_state_sak_take_install_pending_retry(macsec_test_mka_state_sak_take_data_t *data,
                                                     int verbose)
{
    macsec_assert(data != NULL);

    if (verbose)
    {
        MACSEC_PRINT(("  MKA INSTALL_PENDING SAK retry test\n"));
    }

    macsec_test_mka_state_prepare_remote_candidate(&data->mka);

    memset(&data->sak, 0, sizeof(data->sak));

    memset(&data->second_sak, 0, sizeof(data->second_sak));

    /*
     * First handoff moves the SAK to INSTALL_PENDING.
     */
    TEST_OK(macsec_mka_take_sak_for_install(&data->mka, &data->sak));

    TEST_EQ_U32(data->mka.latest_sak.lifecycle_state, MACSEC_MKA_SAK_STATE_INSTALL_PENDING);

    TEST_EQ_U32(data->sak.lifecycle_state, MACSEC_MKA_SAK_STATE_INSTALL_PENDING);

    TEST_TRUE(data->sak.rx_installed == MACSEC_FALSE);

    TEST_TRUE(data->sak.tx_installed == MACSEC_FALSE);

    /*
     * Confirm only RX installation.
     */
    TEST_OK(macsec_mka_notify_sak_installed(&data->mka, MACSEC_TEST_MKA_KEY_NUMBER,
                                            MACSEC_TEST_MKA_AN, MACSEC_MKA_INSTALL_RX,
                                            MACSEC_TEST_MKA_LOWEST_PN));

    TEST_TRUE(data->mka.latest_sak.rx_installed == MACSEC_TRUE);

    TEST_TRUE(data->mka.latest_sak.tx_installed == MACSEC_FALSE);

    TEST_EQ_U32(data->mka.latest_sak.lifecycle_state, MACSEC_MKA_SAK_STATE_INSTALL_PENDING);

    /*
     * The pending SAK must be returned again for the missing TX direction.
     */
    TEST_OK(macsec_mka_take_sak_for_install(&data->mka, &data->second_sak));

    TEST_EQ_U32(data->second_sak.lifecycle_state, MACSEC_MKA_SAK_STATE_INSTALL_PENDING);

    TEST_TRUE(data->second_sak.rx_installed == MACSEC_TRUE);

    TEST_TRUE(data->second_sak.tx_installed == MACSEC_FALSE);

    TEST_EQ_U32(data->second_sak.key_number, MACSEC_TEST_MKA_KEY_NUMBER);

    TEST_EQ_U32(data->second_sak.an, MACSEC_TEST_MKA_AN);

    TEST_MEM_EQ(data->second_sak.sak, s_macsec_test_mka_sak, sizeof(s_macsec_test_mka_sak));

    /*
     * Confirm TX and complete the lifecycle.
     */
    TEST_OK(macsec_mka_notify_sak_installed(&data->mka, MACSEC_TEST_MKA_KEY_NUMBER,
                                            MACSEC_TEST_MKA_AN, MACSEC_MKA_INSTALL_TX,
                                            MACSEC_TEST_MKA_LOWEST_PN));

    TEST_TRUE(data->mka.latest_sak.rx_installed == MACSEC_TRUE);

    TEST_TRUE(data->mka.latest_sak.tx_installed == MACSEC_TRUE);

    TEST_EQ_U32(data->mka.latest_sak.lifecycle_state, MACSEC_MKA_SAK_STATE_ACTIVE);

    return 0;
}

static int
macsec_test_mka_state_sak_take_local_candidate_rejected(macsec_test_mka_state_sak_take_data_t *data,
                                                        int verbose)
{
    int ret;

    macsec_assert(data != NULL);

    if (verbose)
    {
        MACSEC_PRINT(("  MKA local candidate SAK rejection test\n"));
    }

    macsec_test_mka_state_clear_context(&data->mka);

    macsec_test_mka_state_prepare_sak(&data->mka, MACSEC_MKA_SAK_ORIGIN_LOCAL_KEY_SERVER,
                                      MACSEC_MKA_SAK_STATE_CANDIDATE);

    ret = macsec_mka_take_sak_for_install(&data->mka, &data->sak);

    TEST_TRUE(ret == MACSEC_ERR_NOT_READY);

    TEST_EQ_U32(data->mka.latest_sak.lifecycle_state, MACSEC_MKA_SAK_STATE_CANDIDATE);

    return 0;
}

static int macsec_test_mka_state_sak_take_distribution_pending_rejected(
    macsec_test_mka_state_sak_take_data_t *data, int verbose)
{
    int ret;

    macsec_assert(data != NULL);

    if (verbose)
    {
        MACSEC_PRINT(("  MKA local distribution-pending SAK rejection test\n"));
    }

    macsec_test_mka_state_clear_context(&data->mka);

    macsec_test_mka_state_prepare_sak(&data->mka, MACSEC_MKA_SAK_ORIGIN_LOCAL_KEY_SERVER,
                                      MACSEC_MKA_SAK_STATE_DISTRIBUTION_PENDING);

    ret = macsec_mka_take_sak_for_install(&data->mka, &data->sak);

    TEST_TRUE(ret == MACSEC_ERR_NOT_READY);

    TEST_EQ_U32(data->mka.latest_sak.lifecycle_state, MACSEC_MKA_SAK_STATE_DISTRIBUTION_PENDING);

    return 0;
}

static int
macsec_test_mka_state_sak_take_local_distributed(macsec_test_mka_state_sak_take_data_t *data,
                                                 int verbose)
{
    int ret;

    macsec_assert(data != NULL);

    if (verbose)
    {
        MACSEC_PRINT(("  MKA local distributed SAK take test\n"));
    }

    macsec_test_mka_state_clear_context(&data->mka);

    macsec_test_mka_state_prepare_sak(&data->mka, MACSEC_MKA_SAK_ORIGIN_LOCAL_KEY_SERVER,
                                      MACSEC_MKA_SAK_STATE_DISTRIBUTED);

    ret = macsec_mka_take_sak_for_install(&data->mka, &data->sak);

    TEST_TRUE(ret == MACSEC_ERR_OK);

    TEST_EQ_U32(data->mka.latest_sak.lifecycle_state, MACSEC_MKA_SAK_STATE_INSTALL_PENDING);

    TEST_EQ_U32(data->sak.lifecycle_state, MACSEC_MKA_SAK_STATE_INSTALL_PENDING);

    TEST_EQ_U32(data->sak.origin, MACSEC_MKA_SAK_ORIGIN_LOCAL_KEY_SERVER);

    return 0;
}

static int
macsec_test_mka_state_sak_take_invalid_length(macsec_test_mka_state_sak_take_data_t *data,
                                              int verbose)
{
    int ret;

    macsec_assert(data != NULL);

    if (verbose)
    {
        MACSEC_PRINT(("  MKA invalid SAK length test\n"));
    }

    macsec_test_mka_state_prepare_remote_candidate(&data->mka);

    data->mka.latest_sak.sak_len = 24u;

    ret = macsec_mka_take_sak_for_install(&data->mka, &data->sak);

    TEST_TRUE(ret == MACSEC_ERR_STATE);

    TEST_EQ_U32(data->mka.latest_sak.lifecycle_state, MACSEC_MKA_SAK_STATE_CANDIDATE);

    return 0;
}

static int macsec_test_mka_state_sak_take_invalid_an(macsec_test_mka_state_sak_take_data_t *data,
                                                     int verbose)
{
    int ret;

    macsec_assert(data != NULL);

    if (verbose)
    {
        MACSEC_PRINT(("  MKA invalid SAK AN test\n"));
    }

    macsec_test_mka_state_prepare_remote_candidate(&data->mka);

    data->mka.latest_sak.an = 4u;

    ret = macsec_mka_take_sak_for_install(&data->mka, &data->sak);

    TEST_TRUE(ret == MACSEC_ERR_STATE);

    TEST_EQ_U32(data->mka.latest_sak.lifecycle_state, MACSEC_MKA_SAK_STATE_CANDIDATE);

    return 0;
}

static int
macsec_test_mka_state_sak_take_invalid_key_number(macsec_test_mka_state_sak_take_data_t *data,
                                                  int verbose)
{
    int ret;

    macsec_assert(data != NULL);

    if (verbose)
    {
        MACSEC_PRINT(("  MKA invalid SAK key number test\n"));
    }

    macsec_test_mka_state_prepare_remote_candidate(&data->mka);

    data->mka.latest_sak.key_number = 0u;

    ret = macsec_mka_take_sak_for_install(&data->mka, &data->sak);

    TEST_TRUE(ret == MACSEC_ERR_STATE);

    TEST_EQ_U32(data->mka.latest_sak.lifecycle_state, MACSEC_MKA_SAK_STATE_CANDIDATE);

    return 0;
}

/******************************************************************************
 * SAK installation tests
 *****************************************************************************/

static int
macsec_test_mka_state_sak_install_wrong_key_number(macsec_test_mka_state_sak_install_data_t *data,
                                                   int verbose)
{
    int ret;

    macsec_assert(data != NULL);

    if (verbose)
    {
        MACSEC_PRINT(("  MKA SAK install wrong key number test\n"));
    }

    TEST_OK(macsec_test_mka_state_prepare_install_pending(&data->mka, &data->sak));

    ret = macsec_mka_notify_sak_installed(&data->mka, MACSEC_TEST_MKA_OTHER_KEY_NUMBER,
                                          MACSEC_TEST_MKA_AN, MACSEC_MKA_INSTALL_RX, 1u);

    TEST_TRUE(ret == MACSEC_ERR_PARAM);

    TEST_EQ_U32(data->mka.latest_sak.lifecycle_state, MACSEC_MKA_SAK_STATE_INSTALL_PENDING);

    TEST_TRUE(data->mka.latest_sak.rx_installed == MACSEC_FALSE);

    TEST_TRUE(data->mka.latest_sak.tx_installed == MACSEC_FALSE);

    return 0;
}

static int
macsec_test_mka_state_sak_install_wrong_an(macsec_test_mka_state_sak_install_data_t *data,
                                           int verbose)
{
    int ret;

    macsec_assert(data != NULL);

    if (verbose)
    {
        MACSEC_PRINT(("  MKA SAK install wrong AN test\n"));
    }

    TEST_OK(macsec_test_mka_state_prepare_install_pending(&data->mka, &data->sak));

    ret = macsec_mka_notify_sak_installed(&data->mka, MACSEC_TEST_MKA_KEY_NUMBER,
                                          MACSEC_TEST_MKA_OTHER_AN, MACSEC_MKA_INSTALL_RX, 1u);

    TEST_TRUE(ret == MACSEC_ERR_PARAM);

    TEST_TRUE(data->mka.latest_sak.rx_installed == MACSEC_FALSE);

    TEST_TRUE(data->mka.latest_sak.tx_installed == MACSEC_FALSE);

    return 0;
}

static int
macsec_test_mka_state_sak_install_invalid_direction(macsec_test_mka_state_sak_install_data_t *data,
                                                    int verbose)
{
    int ret;

    macsec_assert(data != NULL);

    if (verbose)
    {
        MACSEC_PRINT(("  MKA SAK install invalid direction test\n"));
    }

    TEST_OK(macsec_test_mka_state_prepare_install_pending(&data->mka, &data->sak));

    ret = macsec_mka_notify_sak_installed(&data->mka, MACSEC_TEST_MKA_KEY_NUMBER,
                                          MACSEC_TEST_MKA_AN, MACSEC_MKA_INSTALL_NONE, 1u);

    TEST_TRUE(ret == MACSEC_ERR_PARAM);

    ret =
        macsec_mka_notify_sak_installed(&data->mka, MACSEC_TEST_MKA_KEY_NUMBER, MACSEC_TEST_MKA_AN,
                                        (macsec_mka_install_directions_t) 0x80u, 1u);

    TEST_TRUE(ret == MACSEC_ERR_PARAM);

    TEST_TRUE(data->mka.latest_sak.rx_installed == MACSEC_FALSE);

    TEST_TRUE(data->mka.latest_sak.tx_installed == MACSEC_FALSE);

    return 0;
}

static int macsec_test_mka_state_sak_install_rx_only(macsec_test_mka_state_sak_install_data_t *data,
                                                     int verbose)
{
    int ret;

    macsec_assert(data != NULL);

    if (verbose)
    {
        MACSEC_PRINT(("  MKA SAK RX-only install test\n"));
    }

    TEST_OK(macsec_test_mka_state_prepare_install_pending(&data->mka, &data->sak));

    ret =
        macsec_mka_notify_sak_installed(&data->mka, MACSEC_TEST_MKA_KEY_NUMBER, MACSEC_TEST_MKA_AN,
                                        MACSEC_MKA_INSTALL_RX, MACSEC_TEST_MKA_LOWEST_PN);

    TEST_TRUE(ret == MACSEC_ERR_OK);

    TEST_TRUE(data->mka.latest_sak.rx_installed == MACSEC_TRUE);

    TEST_TRUE(data->mka.latest_sak.tx_installed == MACSEC_FALSE);

    TEST_EQ_U32(data->mka.latest_sak.lifecycle_state, MACSEC_MKA_SAK_STATE_INSTALL_PENDING);

    TEST_EQ_U32(data->mka.latest_sak.lowest_pn, MACSEC_TEST_MKA_LOWEST_PN);

    return 0;
}

static int macsec_test_mka_state_sak_install_tx_only(macsec_test_mka_state_sak_install_data_t *data,
                                                     int verbose)
{
    int ret;

    macsec_assert(data != NULL);

    if (verbose)
    {
        MACSEC_PRINT(("  MKA SAK TX-only install test\n"));
    }

    TEST_OK(macsec_test_mka_state_prepare_install_pending(&data->mka, &data->sak));

    ret =
        macsec_mka_notify_sak_installed(&data->mka, MACSEC_TEST_MKA_KEY_NUMBER, MACSEC_TEST_MKA_AN,
                                        MACSEC_MKA_INSTALL_TX, MACSEC_TEST_MKA_LOWEST_PN);

    TEST_TRUE(ret == MACSEC_ERR_OK);

    TEST_TRUE(data->mka.latest_sak.rx_installed == MACSEC_FALSE);

    TEST_TRUE(data->mka.latest_sak.tx_installed == MACSEC_TRUE);

    TEST_EQ_U32(data->mka.latest_sak.lifecycle_state, MACSEC_MKA_SAK_STATE_INSTALL_PENDING);

    return 0;
}

static int
macsec_test_mka_state_sak_install_rx_then_tx(macsec_test_mka_state_sak_install_data_t *data,
                                             int verbose)
{
    macsec_mka_event_flags_t events;

    macsec_assert(data != NULL);

    if (verbose)
    {
        MACSEC_PRINT(("  MKA SAK RX-then-TX install test\n"));
    }

    TEST_OK(macsec_test_mka_state_prepare_install_pending(&data->mka, &data->sak));

    TEST_OK(macsec_mka_notify_sak_installed(&data->mka, MACSEC_TEST_MKA_KEY_NUMBER,
                                            MACSEC_TEST_MKA_AN, MACSEC_MKA_INSTALL_RX,
                                            MACSEC_TEST_MKA_LOWEST_PN));

    TEST_EQ_U32(data->mka.latest_sak.lifecycle_state, MACSEC_MKA_SAK_STATE_INSTALL_PENDING);

    TEST_OK(macsec_mka_notify_sak_installed(&data->mka, MACSEC_TEST_MKA_KEY_NUMBER,
                                            MACSEC_TEST_MKA_AN, MACSEC_MKA_INSTALL_TX,
                                            MACSEC_TEST_MKA_LOWEST_PN));

    TEST_TRUE(data->mka.latest_sak.rx_installed == MACSEC_TRUE);

    TEST_TRUE(data->mka.latest_sak.tx_installed == MACSEC_TRUE);

    TEST_EQ_U32(data->mka.latest_sak.lifecycle_state, MACSEC_MKA_SAK_STATE_ACTIVE);

    TEST_TRUE((data->mka.tx_reasons & MACSEC_MKA_TX_REASON_SAK_USE) != 0u);

    events = macsec_mka_take_events(&data->mka);

    TEST_TRUE((events & MACSEC_MKA_EVENT_SAK_ACTIVE) != 0u);

    TEST_TRUE((events & MACSEC_MKA_EVENT_TX_SAK_USE) != 0u);

    return 0;
}

static int macsec_test_mka_state_sak_install_both(macsec_test_mka_state_sak_install_data_t *data,
                                                  int verbose)
{
    macsec_mka_install_directions_t directions;

    macsec_assert(data != NULL);

    if (verbose)
    {
        MACSEC_PRINT(("  MKA combined RX/TX SAK install test\n"));
    }

    TEST_OK(macsec_test_mka_state_prepare_install_pending(&data->mka, &data->sak));

    directions = (macsec_mka_install_directions_t) (MACSEC_MKA_INSTALL_RX | MACSEC_MKA_INSTALL_TX);

    TEST_OK(macsec_mka_notify_sak_installed(&data->mka, MACSEC_TEST_MKA_KEY_NUMBER,
                                            MACSEC_TEST_MKA_AN, directions,
                                            MACSEC_TEST_MKA_LOWEST_PN));

    TEST_TRUE(data->mka.latest_sak.rx_installed == MACSEC_TRUE);

    TEST_TRUE(data->mka.latest_sak.tx_installed == MACSEC_TRUE);

    TEST_EQ_U32(data->mka.latest_sak.lifecycle_state, MACSEC_MKA_SAK_STATE_ACTIVE);

    return 0;
}

static int
macsec_test_mka_state_sak_install_lowest_pn(macsec_test_mka_state_sak_install_data_t *data,
                                            int verbose)
{
    int ret;

    macsec_assert(data != NULL);

    if (verbose)
    {
        MACSEC_PRINT(("  MKA SAK lowest PN handling test\n"));
    }

    TEST_OK(macsec_test_mka_state_prepare_install_pending(&data->mka, &data->sak));

    ret = macsec_mka_notify_sak_installed(&data->mka, MACSEC_TEST_MKA_KEY_NUMBER,
                                          MACSEC_TEST_MKA_AN, MACSEC_MKA_INSTALL_RX, 0u);

    TEST_TRUE(ret == MACSEC_ERR_OK);

    TEST_EQ_U32(data->mka.latest_sak.lowest_pn, 1u);

    TEST_OK(macsec_test_mka_state_prepare_install_pending(&data->mka, &data->sak));

    ret =
        macsec_mka_notify_sak_installed(&data->mka, MACSEC_TEST_MKA_KEY_NUMBER, MACSEC_TEST_MKA_AN,
                                        MACSEC_MKA_INSTALL_RX, MACSEC_TEST_MKA_LOWEST_PN);

    TEST_TRUE(ret == MACSEC_ERR_OK);

    TEST_EQ_U32(data->mka.latest_sak.lowest_pn, MACSEC_TEST_MKA_LOWEST_PN);

    return 0;
}

static int
macsec_test_mka_state_sak_install_active_rejected(macsec_test_mka_state_sak_install_data_t *data,
                                                  int verbose)
{
    macsec_mka_install_directions_t directions;
    macsec_mka_event_flags_t events;
    int ret;

    macsec_assert(data != NULL);

    if (verbose)
    {
        MACSEC_PRINT(("  MKA active SAK reinstall rejection test\n"));
    }

    TEST_OK(macsec_test_mka_state_prepare_install_pending(&data->mka, &data->sak));

    directions = (macsec_mka_install_directions_t) (MACSEC_MKA_INSTALL_RX | MACSEC_MKA_INSTALL_TX);

    TEST_OK(macsec_mka_notify_sak_installed(&data->mka, MACSEC_TEST_MKA_KEY_NUMBER,
                                            MACSEC_TEST_MKA_AN, directions, 1u));

    events = macsec_mka_take_events(&data->mka);

    TEST_TRUE((events & MACSEC_MKA_EVENT_SAK_ACTIVE) != 0u);

    ret = macsec_mka_notify_sak_installed(&data->mka, MACSEC_TEST_MKA_KEY_NUMBER,
                                          MACSEC_TEST_MKA_AN, directions, 1u);

    TEST_TRUE(ret == MACSEC_ERR_STATE);

    events = macsec_mka_take_events(&data->mka);

    TEST_EQ_U32(events, MACSEC_MKA_EVENT_NONE);

    return 0;
}

static int
macsec_test_mka_state_sak_install_operational(macsec_test_mka_state_sak_install_data_t *data,
                                              int verbose)
{
    macsec_mka_install_directions_t directions;

    macsec_assert(data != NULL);

    if (verbose)
    {
        MACSEC_PRINT(("  MKA SAK operational transition test\n"));
    }

    TEST_OK(macsec_test_mka_state_prepare_install_pending(&data->mka, &data->sak));

    data->mka.peer.valid = MACSEC_TRUE;

    data->mka.peer.live = MACSEC_TRUE;

    data->mka.state = MACSEC_MKA_STATE_PEER_LIVE;

    directions = (macsec_mka_install_directions_t) (MACSEC_MKA_INSTALL_RX | MACSEC_MKA_INSTALL_TX);

    TEST_OK(macsec_mka_notify_sak_installed(&data->mka, MACSEC_TEST_MKA_KEY_NUMBER,
                                            MACSEC_TEST_MKA_AN, directions, 1u));

    TEST_EQ_U32(data->mka.latest_sak.lifecycle_state, MACSEC_MKA_SAK_STATE_ACTIVE);

    TEST_EQ_U32(data->mka.state, MACSEC_MKA_STATE_OPERATIONAL);

    return 0;
}

static int
macsec_test_mka_state_sak_install_without_live_peer(macsec_test_mka_state_sak_install_data_t *data,
                                                    int verbose)
{
    macsec_mka_install_directions_t directions;

    macsec_assert(data != NULL);

    if (verbose)
    {
        MACSEC_PRINT(("  MKA SAK install without live peer test\n"));
    }

    TEST_OK(macsec_test_mka_state_prepare_install_pending(&data->mka, &data->sak));

    data->mka.peer.valid = MACSEC_TRUE;

    data->mka.peer.live = MACSEC_FALSE;

    data->mka.state = MACSEC_MKA_STATE_PEER_DISCOVERED;

    directions = (macsec_mka_install_directions_t) (MACSEC_MKA_INSTALL_RX | MACSEC_MKA_INSTALL_TX);

    TEST_OK(macsec_mka_notify_sak_installed(&data->mka, MACSEC_TEST_MKA_KEY_NUMBER,
                                            MACSEC_TEST_MKA_AN, directions, 1u));

    TEST_EQ_U32(data->mka.latest_sak.lifecycle_state, MACSEC_MKA_SAK_STATE_ACTIVE);

    TEST_EQ_U32(data->mka.state, MACSEC_MKA_STATE_PEER_DISCOVERED);

    return 0;
}

/******************************************************************************
 * Peer SAK confirmation tests
 *****************************************************************************/

static int macsec_test_mka_state_peer_restart_resets_confirmation(
    macsec_test_mka_state_peer_confirmation_data_t *data, int verbose)
{
    macsec_mka_event_flags_t events;

    macsec_assert(data != NULL);

    if (verbose)
    {
        MACSEC_PRINT(("  MKA peer restart resets SAK confirmation test\n"));
    }

    TEST_OK(macsec_test_mka_state_prepare_peer_confirmation(data));

    data->local.latest_sak.lifecycle_state = MACSEC_MKA_SAK_STATE_CONFIRMED;
    data->local.latest_sak.peer_rx_confirmed = MACSEC_TRUE;
    data->local.latest_sak.peer_tx_confirmed = MACSEC_TRUE;

    /*
     * The replacement peer has not installed the SAK yet, therefore its
     * MKPDU contains no SAK Use Parameter Set.
     */
    TEST_OK(macsec_test_mka_state_build_peer_frame(data));
    TEST_TRUE(data->tx_meta.contains_sak_use == MACSEC_FALSE);

    TEST_OK(
        macsec_mka_input(&data->local, data->frame, data->frame_len, MACSEC_TEST_MKA_RX_TIME_MS));

    TEST_EQ_U32(data->local.latest_sak.lifecycle_state, MACSEC_MKA_SAK_STATE_ACTIVE);
    TEST_TRUE(data->local.latest_sak.peer_rx_confirmed == MACSEC_FALSE);
    TEST_TRUE(data->local.latest_sak.peer_tx_confirmed == MACSEC_FALSE);

    TEST_TRUE((data->local.tx_reasons & MACSEC_MKA_TX_REASON_DISTRIBUTE_SAK) != 0u);

    events = macsec_mka_take_events(&data->local);

    TEST_TRUE((events & MACSEC_MKA_EVENT_PEER_DISCOVERED) != 0u);
    TEST_TRUE((events & MACSEC_MKA_EVENT_TX_DISTRIBUTE_SAK) != 0u);

    macsec_test_mka_state_clear_peer_confirmation(data);

    return 0;
}

static int macsec_test_mka_state_matching_sak_use_confirms_current_sak(
    macsec_test_mka_state_peer_confirmation_data_t *data, int verbose)
{
    macsec_mka_event_flags_t events;

    macsec_assert(data != NULL);

    if (verbose)
    {
        MACSEC_PRINT(("  MKA matching SAK Use confirms current SAK test\n"));
    }

    TEST_OK(macsec_test_mka_state_prepare_peer_confirmation(data));

    data->local.latest_sak.lifecycle_state = MACSEC_MKA_SAK_STATE_ACTIVE;
    data->local.latest_sak.peer_rx_confirmed = MACSEC_FALSE;
    data->local.latest_sak.peer_tx_confirmed = MACSEC_FALSE;

    /*
     * Represent the same SAK as installed by the non-Key-Server peer. Its
     * SAK Use therefore references the local Key Server MI, Key Number and
     * AN and advertises both latest RX and latest TX.
     */
    data->peer.latest_sak = data->local.latest_sak;
    data->peer.latest_sak.origin = MACSEC_MKA_SAK_ORIGIN_REMOTE_KEY_SERVER;
    data->peer.latest_sak.lifecycle_state = MACSEC_MKA_SAK_STATE_ACTIVE;
    data->peer.latest_sak.peer_rx_confirmed = MACSEC_FALSE;
    data->peer.latest_sak.peer_tx_confirmed = MACSEC_FALSE;
    data->peer.latest_sak.rx_installed = MACSEC_TRUE;
    data->peer.latest_sak.tx_installed = MACSEC_TRUE;
    data->peer.latest_sak.lowest_pn = 1u;

    TEST_OK(macsec_test_mka_state_build_peer_frame(data));
    TEST_TRUE(data->tx_meta.contains_sak_use == MACSEC_TRUE);

    TEST_OK(
        macsec_mka_input(&data->local, data->frame, data->frame_len, MACSEC_TEST_MKA_RX_TIME_MS));

    TEST_TRUE(data->local.latest_sak.peer_rx_confirmed == MACSEC_TRUE);
    TEST_TRUE(data->local.latest_sak.peer_tx_confirmed == MACSEC_TRUE);
    TEST_EQ_U32(data->local.latest_sak.lifecycle_state, MACSEC_MKA_SAK_STATE_CONFIRMED);

    events = macsec_mka_take_events(&data->local);
    TEST_TRUE((events & MACSEC_MKA_EVENT_SAK_CONFIRMED) != 0u);

    macsec_test_mka_state_clear_peer_confirmation(data);

    return 0;
}

static int macsec_test_mka_state_mismatching_sak_use_not_confirmed(
    macsec_test_mka_state_peer_confirmation_data_t *data, int verbose)
{
    macsec_mka_event_flags_t events;

    macsec_assert(data != NULL);

    if (verbose)
    {
        MACSEC_PRINT(("  MKA mismatching SAK Use remains unconfirmed test\n"));
    }

    TEST_OK(macsec_test_mka_state_prepare_peer_confirmation(data));

    data->local.latest_sak.lifecycle_state = MACSEC_MKA_SAK_STATE_ACTIVE;
    data->local.latest_sak.peer_rx_confirmed = MACSEC_FALSE;
    data->local.latest_sak.peer_tx_confirmed = MACSEC_FALSE;

    data->peer.latest_sak = data->local.latest_sak;
    data->peer.latest_sak.origin = MACSEC_MKA_SAK_ORIGIN_REMOTE_KEY_SERVER;
    data->peer.latest_sak.lifecycle_state = MACSEC_MKA_SAK_STATE_ACTIVE;

    /*
     * SAK Use is otherwise well formed and authenticated, but references a
     * different Key Number.
     */
    data->peer.latest_sak.key_number = MACSEC_TEST_MKA_OTHER_KEY_NUMBER;
    data->peer.latest_sak.rx_installed = MACSEC_TRUE;
    data->peer.latest_sak.tx_installed = MACSEC_TRUE;
    data->peer.latest_sak.lowest_pn = 1u;

    TEST_OK(macsec_test_mka_state_build_peer_frame(data));
    TEST_TRUE(data->tx_meta.contains_sak_use == MACSEC_TRUE);

    TEST_OK(
        macsec_mka_input(&data->local, data->frame, data->frame_len, MACSEC_TEST_MKA_RX_TIME_MS));

    TEST_TRUE(data->local.latest_sak.peer_rx_confirmed == MACSEC_FALSE);
    TEST_TRUE(data->local.latest_sak.peer_tx_confirmed == MACSEC_FALSE);
    TEST_EQ_U32(data->local.latest_sak.lifecycle_state, MACSEC_MKA_SAK_STATE_ACTIVE);

    TEST_TRUE((data->local.tx_reasons & MACSEC_MKA_TX_REASON_DISTRIBUTE_SAK) != 0u);

    events = macsec_mka_take_events(&data->local);
    TEST_TRUE((events & MACSEC_MKA_EVENT_SAK_CONFIRMED) == 0u);
    TEST_TRUE((events & MACSEC_MKA_EVENT_TX_DISTRIBUTE_SAK) != 0u);

    macsec_test_mka_state_clear_peer_confirmation(data);

    return 0;
}

/******************************************************************************
 * SAK retirement tests
 *****************************************************************************/

static int macsec_test_mka_state_sak_retire_no_sak(macsec_test_mka_state_sak_retire_data_t *data,
                                                   int verbose)
{
    int ret;

    macsec_assert(data != NULL);

    if (verbose)
    {
        MACSEC_PRINT(("  MKA SAK retirement without SAK test\n"));
    }

    macsec_test_mka_state_clear_context(&data->mka);

    ret = macsec_mka_notify_sak_retired(&data->mka, MACSEC_TEST_MKA_KEY_NUMBER, MACSEC_TEST_MKA_AN);

    TEST_TRUE(ret == MACSEC_ERR_NOT_READY);

    return 0;
}

static int
macsec_test_mka_state_sak_retire_invalid_identity(macsec_test_mka_state_sak_retire_data_t *data,
                                                  int verbose)
{
    int ret;

    macsec_assert(data != NULL);

    if (verbose)
    {
        MACSEC_PRINT(("  MKA SAK retirement invalid identity test\n"));
    }

    macsec_test_mka_state_clear_context(&data->mka);

    macsec_test_mka_state_prepare_sak(&data->mka, MACSEC_MKA_SAK_ORIGIN_REMOTE_KEY_SERVER,
                                      MACSEC_MKA_SAK_STATE_RETIRING);

    ret = macsec_mka_notify_sak_retired(&data->mka, MACSEC_TEST_MKA_OTHER_KEY_NUMBER,
                                        MACSEC_TEST_MKA_AN);

    TEST_TRUE(ret == MACSEC_ERR_PARAM);

    TEST_TRUE(data->mka.latest_sak.lifecycle_state != MACSEC_MKA_SAK_STATE_NONE);

    ret = macsec_mka_notify_sak_retired(&data->mka, MACSEC_TEST_MKA_KEY_NUMBER,
                                        MACSEC_TEST_MKA_OTHER_AN);

    TEST_TRUE(ret == MACSEC_ERR_PARAM);

    TEST_TRUE(data->mka.latest_sak.lifecycle_state != MACSEC_MKA_SAK_STATE_NONE);

    TEST_EQ_U32(data->mka.latest_sak.lifecycle_state, MACSEC_MKA_SAK_STATE_RETIRING);

    return 0;
}

static int
macsec_test_mka_state_sak_retire_invalid_state(macsec_test_mka_state_sak_retire_data_t *data,
                                               int verbose)
{
    int ret;

    macsec_assert(data != NULL);

    if (verbose)
    {
        MACSEC_PRINT(("  MKA SAK retirement invalid state test\n"));
    }

    macsec_test_mka_state_clear_context(&data->mka);

    macsec_test_mka_state_prepare_sak(&data->mka, MACSEC_MKA_SAK_ORIGIN_REMOTE_KEY_SERVER,
                                      MACSEC_MKA_SAK_STATE_ACTIVE);

    ret = macsec_mka_notify_sak_retired(&data->mka, MACSEC_TEST_MKA_KEY_NUMBER, MACSEC_TEST_MKA_AN);

    TEST_TRUE(ret == MACSEC_ERR_STATE);

    TEST_TRUE(data->mka.latest_sak.lifecycle_state != MACSEC_MKA_SAK_STATE_NONE);

    TEST_EQ_U32(data->mka.latest_sak.lifecycle_state, MACSEC_MKA_SAK_STATE_ACTIVE);

    return 0;
}

static int
macsec_test_mka_state_sak_retire_clears_key(macsec_test_mka_state_sak_retire_data_t *data,
                                            int verbose)
{
    macsec_mka_event_flags_t events;

    macsec_assert(data != NULL);

    if (verbose)
    {
        MACSEC_PRINT(("  MKA SAK retirement key clearing test\n"));
    }

    macsec_test_mka_state_clear_context(&data->mka);

    macsec_test_mka_state_prepare_sak(&data->mka, MACSEC_MKA_SAK_ORIGIN_REMOTE_KEY_SERVER,
                                      MACSEC_MKA_SAK_STATE_RETIRING);

    data->mka.latest_sak.rx_installed = MACSEC_TRUE;

    data->mka.latest_sak.tx_installed = MACSEC_TRUE;

    data->mka.latest_sak.lowest_pn = MACSEC_TEST_MKA_LOWEST_PN;

    TEST_OK(
        macsec_mka_notify_sak_retired(&data->mka, MACSEC_TEST_MKA_KEY_NUMBER, MACSEC_TEST_MKA_AN));

    TEST_TRUE(data->mka.latest_sak.lifecycle_state == MACSEC_MKA_SAK_STATE_NONE);

    TEST_EQ_U32(data->mka.latest_sak.lifecycle_state, MACSEC_MKA_SAK_STATE_NONE);

    TEST_EQ_U32(data->mka.latest_sak.origin, MACSEC_MKA_SAK_ORIGIN_NONE);

    TEST_EQ_U32(data->mka.latest_sak.sak_len, 0u);

    TEST_EQ_U32(data->mka.latest_sak.key_number, 0u);

    TEST_EQ_U32(data->mka.latest_sak.an, 0u);

    TEST_EQ_U32(data->mka.latest_sak.lowest_pn, 0u);

    TEST_TRUE(data->mka.latest_sak.rx_installed == MACSEC_FALSE);

    TEST_TRUE(data->mka.latest_sak.tx_installed == MACSEC_FALSE);

    TEST_TRUE(macsec_test_mka_state_buffer_is_zero(
                  data->mka.latest_sak.sak, sizeof(data->mka.latest_sak.sak)) == MACSEC_TRUE);

    events = macsec_mka_take_events(&data->mka);

    TEST_TRUE((events & MACSEC_MKA_EVENT_SAK_RETIRED) != 0u);

    return 0;
}

static int
macsec_test_mka_state_sak_retire_to_peer_live(macsec_test_mka_state_sak_retire_data_t *data,
                                              int verbose)
{
    macsec_assert(data != NULL);

    if (verbose)
    {
        MACSEC_PRINT(("  MKA SAK retirement to peer-live test\n"));
    }

    macsec_test_mka_state_clear_context(&data->mka);

    macsec_test_mka_state_prepare_sak(&data->mka, MACSEC_MKA_SAK_ORIGIN_REMOTE_KEY_SERVER,
                                      MACSEC_MKA_SAK_STATE_RETIRING);

    data->mka.peer.valid = MACSEC_TRUE;

    data->mka.peer.live = MACSEC_TRUE;

    data->mka.state = MACSEC_MKA_STATE_OPERATIONAL;

    TEST_OK(
        macsec_mka_notify_sak_retired(&data->mka, MACSEC_TEST_MKA_KEY_NUMBER, MACSEC_TEST_MKA_AN));

    TEST_EQ_U32(data->mka.state, MACSEC_MKA_STATE_PEER_LIVE);

    return 0;
}

static int
macsec_test_mka_state_sak_retire_to_wait_peer(macsec_test_mka_state_sak_retire_data_t *data,
                                              int verbose)
{
    macsec_assert(data != NULL);

    if (verbose)
    {
        MACSEC_PRINT(("  MKA SAK retirement to wait-peer test\n"));
    }

    macsec_test_mka_state_clear_context(&data->mka);

    macsec_test_mka_state_prepare_sak(&data->mka, MACSEC_MKA_SAK_ORIGIN_REMOTE_KEY_SERVER,
                                      MACSEC_MKA_SAK_STATE_RETIRING);

    data->mka.peer.valid = MACSEC_FALSE;

    data->mka.peer.live = MACSEC_FALSE;

    data->mka.state = MACSEC_MKA_STATE_OPERATIONAL;

    TEST_OK(
        macsec_mka_notify_sak_retired(&data->mka, MACSEC_TEST_MKA_KEY_NUMBER, MACSEC_TEST_MKA_AN));

    TEST_EQ_U32(data->mka.state, MACSEC_MKA_STATE_WAIT_PEER);

    return 0;
}

/******************************************************************************
 * Public test entry point
 *****************************************************************************/

int macsec_test_mka_state(macsec_test_mka_state_data_t *data, int verbose)
{
    macsec_assert(data != NULL);

    if (verbose)
    {
        MACSEC_PRINT(("MACsec MKA state and SAK lifecycle tests\n"));
    }

    TEST_OK(macsec_test_mka_state_events_take(&data->test_mka_state_events_data, verbose));

    TEST_OK(
        macsec_test_mka_state_events_second_take_empty(&data->test_mka_state_events_data, verbose));

    TEST_OK(macsec_test_mka_state_events_preserve_tx(&data->test_mka_state_events_data, verbose));

    TEST_OK(macsec_test_mka_state_sak_take_no_sak(&data->test_mka_state_sak_take_data, verbose));

    TEST_OK(macsec_test_mka_state_sak_take_remote_candidate(&data->test_mka_state_sak_take_data,
                                                            verbose));

    TEST_OK(macsec_test_mka_state_sak_take_install_pending_retry(
        &data->test_mka_state_sak_take_data, verbose));

    TEST_OK(macsec_test_mka_state_sak_take_local_candidate_rejected(
        &data->test_mka_state_sak_take_data, verbose));

    TEST_OK(macsec_test_mka_state_sak_take_distribution_pending_rejected(
        &data->test_mka_state_sak_take_data, verbose));

    TEST_OK(macsec_test_mka_state_sak_take_local_distributed(&data->test_mka_state_sak_take_data,
                                                             verbose));

    TEST_OK(macsec_test_mka_state_sak_take_invalid_length(&data->test_mka_state_sak_take_data,
                                                          verbose));

    TEST_OK(
        macsec_test_mka_state_sak_take_invalid_an(&data->test_mka_state_sak_take_data, verbose));

    TEST_OK(macsec_test_mka_state_sak_take_invalid_key_number(&data->test_mka_state_sak_take_data,
                                                              verbose));

    TEST_OK(macsec_test_mka_state_sak_install_wrong_key_number(
        &data->test_mka_state_sak_install_data, verbose));

    TEST_OK(macsec_test_mka_state_sak_install_wrong_an(&data->test_mka_state_sak_install_data,
                                                       verbose));

    TEST_OK(macsec_test_mka_state_sak_install_invalid_direction(
        &data->test_mka_state_sak_install_data, verbose));

    TEST_OK(
        macsec_test_mka_state_sak_install_rx_only(&data->test_mka_state_sak_install_data, verbose));

    TEST_OK(
        macsec_test_mka_state_sak_install_tx_only(&data->test_mka_state_sak_install_data, verbose));

    TEST_OK(macsec_test_mka_state_sak_install_rx_then_tx(&data->test_mka_state_sak_install_data,
                                                         verbose));

    TEST_OK(
        macsec_test_mka_state_sak_install_both(&data->test_mka_state_sak_install_data, verbose));

    TEST_OK(macsec_test_mka_state_sak_install_lowest_pn(&data->test_mka_state_sak_install_data,
                                                        verbose));

    TEST_OK(macsec_test_mka_state_sak_install_active_rejected(
        &data->test_mka_state_sak_install_data, verbose));

    TEST_OK(macsec_test_mka_state_sak_install_operational(&data->test_mka_state_sak_install_data,
                                                          verbose));

    TEST_OK(macsec_test_mka_state_sak_install_without_live_peer(
        &data->test_mka_state_sak_install_data, verbose));

    TEST_OK(macsec_test_mka_state_peer_restart_resets_confirmation(
        &data->test_mka_state_peer_confirmation_data, verbose));

    TEST_OK(macsec_test_mka_state_matching_sak_use_confirms_current_sak(
        &data->test_mka_state_peer_confirmation_data, verbose));

    TEST_OK(macsec_test_mka_state_mismatching_sak_use_not_confirmed(
        &data->test_mka_state_peer_confirmation_data, verbose));

    TEST_OK(
        macsec_test_mka_state_sak_retire_no_sak(&data->test_mka_state_sak_retire_data, verbose));

    TEST_OK(macsec_test_mka_state_sak_retire_invalid_identity(&data->test_mka_state_sak_retire_data,
                                                              verbose));

    TEST_OK(macsec_test_mka_state_sak_retire_invalid_state(&data->test_mka_state_sak_retire_data,
                                                           verbose));

    TEST_OK(macsec_test_mka_state_sak_retire_clears_key(&data->test_mka_state_sak_retire_data,
                                                        verbose));

    TEST_OK(macsec_test_mka_state_sak_retire_to_peer_live(&data->test_mka_state_sak_retire_data,
                                                          verbose));

    TEST_OK(macsec_test_mka_state_sak_retire_to_wait_peer(&data->test_mka_state_sak_retire_data,
                                                          verbose));

    if (verbose)
    {
        MACSEC_PRINT(("MACsec MKA state and SAK lifecycle tests PASSED\n"));
    }

    return 0;
}

#endif /* MACSEC_SELF_TEST */