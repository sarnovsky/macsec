/*
 * test_macsec_flow.c
 *
 * Lightweight MACsec stack
 * MACsec communication flow tests.
 * This file validates complete MACsec communication scenarios, including
 * secure frame transmission, reception and protocol state transitions.
 *
 * Copyright (c) 2026 Michal Sarnovsky
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */

#include <tests/test_macsec_flow.h>
#include <tests/unit_tests.h>

#include <string.h>

#if (MACSEC_SELF_TEST != 0)

#define MACSEC_TEST_MACSEC_FLOW_ETHERNET_HEADER_LEN 14u
#define MACSEC_TEST_MACSEC_FLOW_IPV4_ETHERTYPE 0x0800u

#define MACSEC_TEST_MACSEC_FLOW_PORT_ID 1u
#define MACSEC_TEST_MACSEC_FLOW_STATIC_AN 0u

#define MACSEC_TEST_MACSEC_FLOW_MKA_TX_TIME_MS 1000u
#define MACSEC_TEST_MACSEC_FLOW_TX_INTERVAL_MS 2000u
#define MACSEC_TEST_MACSEC_FLOW_KEY_SERVER_PRIORITY 10u
#define MACSEC_TEST_MACSEC_FLOW_PEER_PRIORITY 20u

#define MACSEC_TEST_MACSEC_FLOW_TAMPER_MASK 0x01u

static const uint8_t test_cak_16[16] = {0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u,
                                        0x88u, 0x99u, 0xAAu, 0xBBu, 0xCCu, 0xDDu, 0xEEu, 0xFFu};

static const uint8_t test_cak_32[32] = {0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u,
                                        0x88u, 0x99u, 0xAAu, 0xBBu, 0xCCu, 0xDDu, 0xEEu, 0xFFu,
                                        0x10u, 0x21u, 0x32u, 0x43u, 0x54u, 0x65u, 0x76u, 0x87u,
                                        0x98u, 0xA9u, 0xBAu, 0xCBu, 0xDCu, 0xEDu, 0xFEu, 0x0Fu};

static const uint8_t test_ckn[24] = {0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u,
                                     0x88u, 0x99u, 0xAAu, 0xBBu, 0xCCu, 0xDDu, 0xEEu, 0xFFu,
                                     0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u};

static const uint8_t test_static_sak[16] = {0x10u, 0x11u, 0x12u, 0x13u, 0x14u, 0x15u, 0x16u, 0x17u,
                                            0x18u, 0x19u, 0x1Au, 0x1Bu, 0x1Cu, 0x1Du, 0x1Eu, 0x1Fu};

static const uint8_t test_mac_a[6] = {0x02u, 0x00u, 0x00u, 0x00u, 0x00u, 0x01u};

static const uint8_t test_mac_b[6] = {0x02u, 0x00u, 0x00u, 0x00u, 0x00u, 0x02u};

static void macsec_test_fill_plain_frame(uint8_t *frame, size_t len, const uint8_t dst_mac[6],
                                         const uint8_t src_mac[6], uint16_t ethertype, uint8_t seed)
{
    size_t i;

    macsec_assert(frame != NULL);
    macsec_assert(dst_mac != NULL);
    macsec_assert(src_mac != NULL);
    macsec_assert(len >= MACSEC_TEST_MACSEC_FLOW_ETHERNET_HEADER_LEN);

    memcpy(&frame[0], dst_mac, sizeof(test_mac_a));
    memcpy(&frame[6], src_mac, sizeof(test_mac_a));
    macsec_wr_be16(&frame[12], ethertype);

    for (i = MACSEC_TEST_MACSEC_FLOW_ETHERNET_HEADER_LEN; i < len; i++)
    {
        frame[i] = (uint8_t) (seed + (uint8_t) i);
    }
}

static void macsec_test_static_config(macsec_config_t *cfg, const uint8_t local_mac[6], uint8_t an)
{
    macsec_assert(cfg != NULL);
    macsec_assert(local_mac != NULL);

    memset(cfg, 0, sizeof(*cfg));

    cfg->mode = MACSEC_MODE_STATIC_SAK;

    memcpy(cfg->local_mac.addr, local_mac, sizeof(cfg->local_mac.addr));
    cfg->port_id = MACSEC_TEST_MACSEC_FLOW_PORT_ID;

    memcpy(cfg->static_sak, test_static_sak, sizeof(test_static_sak));
    cfg->static_sak_len = sizeof(test_static_sak);
    cfg->static_an = an & 0x03u;

    cfg->replay_protect = MACSEC_FALSE;
    cfg->replay_window = 0u;
}

static void macsec_test_disabled_config(macsec_config_t *cfg, const uint8_t local_mac[6])
{
    macsec_assert(cfg != NULL);
    macsec_assert(local_mac != NULL);

    memset(cfg, 0, sizeof(*cfg));

    cfg->mode = MACSEC_MODE_DISABLED;

    memcpy(cfg->local_mac.addr, local_mac, sizeof(cfg->local_mac.addr));
    cfg->port_id = MACSEC_TEST_MACSEC_FLOW_PORT_ID;
}

static void macsec_test_mka_config(macsec_config_t *cfg, const uint8_t local_mac[6],
                                   const uint8_t *cak, size_t cak_len, uint8_t priority)
{
    macsec_assert(cfg != NULL);
    macsec_assert(local_mac != NULL);
    macsec_assert(cak != NULL);
    macsec_assert((cak_len == sizeof(test_cak_16)) || (cak_len == sizeof(test_cak_32)));
    macsec_assert(cak_len <= sizeof(cfg->cak));

    memset(cfg, 0, sizeof(*cfg));

    cfg->mode = MACSEC_MODE_MKA_PSK;

    memcpy(cfg->local_mac.addr, local_mac, sizeof(cfg->local_mac.addr));
    cfg->port_id = MACSEC_TEST_MACSEC_FLOW_PORT_ID;

    memcpy(cfg->cak, cak, cak_len);
    cfg->cak_len = cak_len;

    memcpy(cfg->ckn, test_ckn, sizeof(test_ckn));
    cfg->ckn_len = sizeof(test_ckn);

    cfg->key_server_priority = priority;
    cfg->mka_tx_interval_ms = MACSEC_TEST_MACSEC_FLOW_TX_INTERVAL_MS;

    cfg->replay_protect = MACSEC_FALSE;
    cfg->replay_window = 0u;
}

static int macsec_test_macsec_flow_static_bidirectional(
    macsec_test_macsec_flow_static_bidirectional_data_t *data, int verbose)
{
    const size_t plain_len = MACSEC_TEST_MACSEC_FLOW_PLAIN_LEN;

    size_t secure_len = 0u;
    size_t decrypted_len = 0u;

    macsec_bool_t pass_to_stack = MACSEC_FALSE;

    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  MACsec flow static bidirectional test\n"));
    }

    macsec_test_static_config(&data->cfg_a, test_mac_a, MACSEC_TEST_MACSEC_FLOW_STATIC_AN);
    macsec_test_static_config(&data->cfg_b, test_mac_b, MACSEC_TEST_MACSEC_FLOW_STATIC_AN);

    ret = macsec_init(&data->a, &data->cfg_a);
    TEST_OK(ret);

    ret = macsec_init(&data->b, &data->cfg_b);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_clear(&data->a);
        return ret;
    }

    TEST_TRUE(macsec_get_state(&data->a) == MACSEC_STATE_SECURED);
    TEST_TRUE(macsec_get_state(&data->b) == MACSEC_STATE_SECURED);

    macsec_test_fill_plain_frame(data->plain_a, plain_len, test_mac_b, test_mac_a,
                                 MACSEC_TEST_MACSEC_FLOW_IPV4_ETHERTYPE, 0x10u);

    ret = macsec_output(&data->a, data->plain_a, plain_len, data->secure, &secure_len,
                        sizeof(data->secure));
    if (ret != MACSEC_ERR_OK)
    {
        macsec_clear(&data->a);
        macsec_clear(&data->b);
        return ret;
    }

    TEST_TRUE(secure_len > plain_len);

    ret = macsec_input(&data->b, data->secure, secure_len, data->decrypted, &decrypted_len,
                       sizeof(data->decrypted), &pass_to_stack);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_clear(&data->a);
        macsec_clear(&data->b);
        return ret;
    }

    TEST_TRUE(pass_to_stack);
    TEST_EQ_U32(decrypted_len, plain_len);
    TEST_MEM_EQ(data->plain_a, data->decrypted, plain_len);

    macsec_test_fill_plain_frame(data->plain_b, plain_len, test_mac_a, test_mac_b,
                                 MACSEC_TEST_MACSEC_FLOW_IPV4_ETHERTYPE, 0x30u);

    secure_len = 0u;
    decrypted_len = 0u;
    pass_to_stack = MACSEC_FALSE;

    ret = macsec_output(&data->b, data->plain_b, plain_len, data->secure, &secure_len,
                        sizeof(data->secure));
    if (ret != MACSEC_ERR_OK)
    {
        macsec_clear(&data->a);
        macsec_clear(&data->b);
        return ret;
    }

    TEST_TRUE(secure_len > plain_len);

    ret = macsec_input(&data->a, data->secure, secure_len, data->decrypted, &decrypted_len,
                       sizeof(data->decrypted), &pass_to_stack);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_clear(&data->a);
        macsec_clear(&data->b);
        return ret;
    }

    TEST_TRUE(pass_to_stack);
    TEST_EQ_U32(decrypted_len, plain_len);
    TEST_MEM_EQ(data->plain_b, data->decrypted, plain_len);

    TEST_TRUE(macsec_get_state(&data->a) == MACSEC_STATE_SECURED);
    TEST_TRUE(macsec_get_state(&data->b) == MACSEC_STATE_SECURED);

    macsec_clear(&data->a);
    macsec_clear(&data->b);

    return 0;
}

static int macsec_test_macsec_flow_disabled_passthrough(
    macsec_test_macsec_flow_disabled_passthrough_data_t *data, int verbose)
{
    const size_t plain_len = MACSEC_TEST_MACSEC_FLOW_PLAIN_LEN;

    size_t output_len = 0u;

    macsec_bool_t pass_to_stack = MACSEC_FALSE;

    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  MACsec flow disabled passthrough test\n"));
    }

    macsec_test_disabled_config(&data->cfg, test_mac_a);

    ret = macsec_init(&data->ctx, &data->cfg);
    TEST_OK(ret);

    TEST_TRUE(macsec_get_state(&data->ctx) == MACSEC_STATE_SECURED);

    macsec_test_fill_plain_frame(data->plain, plain_len, test_mac_b, test_mac_a,
                                 MACSEC_TEST_MACSEC_FLOW_IPV4_ETHERTYPE, 0x50u);

    ret = macsec_output(&data->ctx, data->plain, plain_len, data->output, &output_len,
                        sizeof(data->output));
    if (ret != MACSEC_ERR_OK)
    {
        macsec_clear(&data->ctx);
        return ret;
    }

    TEST_EQ_U32(output_len, plain_len);
    TEST_MEM_EQ(data->plain, data->output, plain_len);

    output_len = 0u;
    pass_to_stack = MACSEC_FALSE;

    ret = macsec_input(&data->ctx, data->plain, plain_len, data->output, &output_len,
                       sizeof(data->output), &pass_to_stack);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_clear(&data->ctx);
        return ret;
    }

    TEST_TRUE(pass_to_stack);
    TEST_EQ_U32(output_len, plain_len);
    TEST_MEM_EQ(data->plain, data->output, plain_len);

    macsec_clear(&data->ctx);

    return 0;
}

static int macsec_test_macsec_flow_static_bad_key_rejected(
    macsec_test_macsec_flow_static_bad_key_rejected_data_t *data, int verbose)
{
    const size_t plain_len = MACSEC_TEST_MACSEC_FLOW_PLAIN_LEN;

    size_t secure_len = 0u;
    size_t decrypted_len = sizeof(data->decrypted);

    macsec_bool_t pass_to_stack = MACSEC_TRUE;

    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  MACsec flow static bad key rejected test\n"));
    }

    macsec_test_static_config(&data->cfg_a, test_mac_a, MACSEC_TEST_MACSEC_FLOW_STATIC_AN);
    macsec_test_static_config(&data->cfg_b, test_mac_b, MACSEC_TEST_MACSEC_FLOW_STATIC_AN);

    data->cfg_b.static_sak[0] ^= MACSEC_TEST_MACSEC_FLOW_TAMPER_MASK;

    ret = macsec_init(&data->a, &data->cfg_a);
    TEST_OK(ret);

    ret = macsec_init(&data->b, &data->cfg_b);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_clear(&data->a);
        return ret;
    }

    macsec_test_fill_plain_frame(data->plain, plain_len, test_mac_b, test_mac_a,
                                 MACSEC_TEST_MACSEC_FLOW_IPV4_ETHERTYPE, 0x88u);

    ret = macsec_output(&data->a, data->plain, plain_len, data->secure, &secure_len,
                        sizeof(data->secure));
    if (ret != MACSEC_ERR_OK)
    {
        macsec_clear(&data->a);
        macsec_clear(&data->b);
        return ret;
    }

    ret = macsec_input(&data->b, data->secure, secure_len, data->decrypted, &decrypted_len,
                       sizeof(data->decrypted), &pass_to_stack);

    macsec_clear(&data->a);
    macsec_clear(&data->b);

    TEST_TRUE(ret != MACSEC_ERR_OK);
    TEST_EQ_U32(decrypted_len, 0u);
    TEST_TRUE(!pass_to_stack);

    return 0;
}

/*
 * Generate one MKA control frame through the public MACsec API and report
 * successful transmission to the stack.
 */
static int macsec_test_macsec_flow_build_control_frame(macsec_ctx_t *ctx, uint8_t *control,
                                                       size_t *control_len, size_t control_max_len,
                                                       uint32_t now_ms)
{
    int ret;

    macsec_assert(ctx != NULL);
    macsec_assert(control != NULL);
    macsec_assert(control_len != NULL);

    *control_len = 0u;

    ret = macsec_tick(ctx, now_ms);
    if (ret != MACSEC_ERR_OK)
    {
        return ret;
    }

    ret = macsec_get_control_frame(ctx, control, control_len, control_max_len);
    if (ret != MACSEC_ERR_OK)
    {
        *control_len = 0u;
        return ret;
    }

    ret = macsec_notify_control_tx_success(ctx, now_ms);
    if (ret != MACSEC_ERR_OK)
    {
        *control_len = 0u;
        return ret;
    }

    return MACSEC_ERR_OK;
}

static int
macsec_test_macsec_flow_eapol_consumed(macsec_test_macsec_flow_eapol_consumed_data_t *data,
                                       int verbose)
{
    size_t control_len = 0u;
    size_t plain_len = sizeof(data->plain);

    macsec_bool_t pass_to_stack = MACSEC_TRUE;

    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  MACsec flow EAPOL consumed test\n"));
    }

    macsec_assert(data != NULL);

    macsec_test_mka_config(&data->cfg_tx, test_mac_a, test_cak_16, sizeof(test_cak_16), 10u);

    macsec_test_mka_config(&data->cfg_rx, test_mac_b, test_cak_16, sizeof(test_cak_16), 20u);

    ret = macsec_init(&data->tx, &data->cfg_tx);
    TEST_OK(ret);

    ret = macsec_init(&data->rx, &data->cfg_rx);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_clear(&data->tx);
        return ret;
    }

    TEST_TRUE(macsec_get_state(&data->tx) == MACSEC_STATE_WAIT_MKA);
    TEST_TRUE(macsec_get_state(&data->rx) == MACSEC_STATE_WAIT_MKA);

    ret = macsec_test_macsec_flow_build_control_frame(&data->tx, data->control, &control_len,
                                                      sizeof(data->control),
                                                      MACSEC_TEST_MACSEC_FLOW_MKA_TX_TIME_MS);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_clear(&data->tx);
        macsec_clear(&data->rx);
        return ret;
    }

    TEST_TRUE(control_len > 0u);

    plain_len = sizeof(data->plain);
    pass_to_stack = MACSEC_TRUE;

    ret = macsec_input(&data->rx, data->control, control_len, data->plain, &plain_len,
                       sizeof(data->plain), &pass_to_stack);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_clear(&data->tx);
        macsec_clear(&data->rx);
        return ret;
    }

    /*
     * A valid EAPOL/MKA frame is consumed internally and must not be
     * delivered to the application network stack.
     */
    TEST_TRUE(!pass_to_stack);
    TEST_EQ_U32(plain_len, 0u);

    /*
     * One received MKPDU is not necessarily sufficient to complete the
     * complete MKA exchange, but it must not put the participant into ERROR.
     */
    TEST_TRUE(macsec_get_state(&data->rx) != MACSEC_STATE_ERROR);

    macsec_clear(&data->tx);
    macsec_clear(&data->rx);

    return 0;
}

static int macsec_test_macsec_flow_bad_eapol_icv(macsec_test_macsec_flow_bad_eapol_icv_data_t *data,
                                                 int verbose)
{
    size_t control_len = 0u;
    size_t plain_len = sizeof(data->plain);

    macsec_bool_t pass_to_stack = MACSEC_TRUE;

    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  MACsec flow bad EAPOL ICV test\n"));
    }

    macsec_assert(data != NULL);

    macsec_test_mka_config(&data->cfg_tx, test_mac_a, test_cak_16, sizeof(test_cak_16), 10u);

    macsec_test_mka_config(&data->cfg_rx, test_mac_b, test_cak_16, sizeof(test_cak_16), 20u);

    ret = macsec_init(&data->tx, &data->cfg_tx);
    TEST_OK(ret);

    ret = macsec_init(&data->rx, &data->cfg_rx);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_clear(&data->tx);
        return ret;
    }

    TEST_TRUE(macsec_get_state(&data->tx) == MACSEC_STATE_WAIT_MKA);
    TEST_TRUE(macsec_get_state(&data->rx) == MACSEC_STATE_WAIT_MKA);

    ret = macsec_test_macsec_flow_build_control_frame(&data->tx, data->control, &control_len,
                                                      sizeof(data->control),
                                                      MACSEC_TEST_MACSEC_FLOW_MKA_TX_TIME_MS);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_clear(&data->tx);
        macsec_clear(&data->rx);
        return ret;
    }

    TEST_TRUE(control_len > 0u);

    /*
     * The MKA ICV is at the end of the MKPDU. Changing the final byte must
     * cause authentication failure.
     */
    data->control[control_len - 1u] ^= MACSEC_TEST_MACSEC_FLOW_TAMPER_MASK;

    plain_len = sizeof(data->plain);
    pass_to_stack = MACSEC_TRUE;

    ret = macsec_input(&data->rx, data->control, control_len, data->plain, &plain_len,
                       sizeof(data->plain), &pass_to_stack);

    TEST_TRUE(ret != MACSEC_ERR_OK);
    TEST_TRUE(!pass_to_stack);
    TEST_EQ_U32(plain_len, 0u);

    /*
     * The current top-level MACsec implementation enters ERROR after an
     * authenticated MKA control frame fails ICV verification.
     */
    TEST_TRUE(macsec_get_state(&data->rx) == MACSEC_STATE_ERROR);

    macsec_clear(&data->tx);
    macsec_clear(&data->rx);

    return 0;
}

static int macsec_test_macsec_flow_mka_wait_drops_data_tx(
    macsec_test_macsec_flow_mka_wait_drops_data_tx_data_t *data, int verbose)
{
    const size_t plain_len = MACSEC_TEST_MACSEC_FLOW_PLAIN_LEN;

    size_t secure_len = sizeof(data->secure);

    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  MACsec flow MKA WAIT drops data TX test\n"));
    }

    macsec_assert(data != NULL);

    macsec_test_mka_config(&data->cfg, test_mac_a, test_cak_16, sizeof(test_cak_16), 255u);

    ret = macsec_init(&data->ctx, &data->cfg);
    TEST_OK(ret);

    TEST_TRUE(macsec_get_state(&data->ctx) == MACSEC_STATE_WAIT_MKA);

    macsec_test_fill_plain_frame(data->plain, plain_len, test_mac_b, test_mac_a,
                                 MACSEC_TEST_MACSEC_FLOW_IPV4_ETHERTYPE, 0x77u);

    ret = macsec_output(&data->ctx, data->plain, plain_len, data->secure, &secure_len,
                        sizeof(data->secure));

    TEST_TRUE(ret == MACSEC_ERR_NOT_READY);
    TEST_EQ_U32(secure_len, 0u);
    TEST_TRUE(macsec_get_state(&data->ctx) == MACSEC_STATE_WAIT_MKA);

    macsec_clear(&data->ctx);

    return 0;
}

static int macsec_test_macsec_flow_mka_wait_drops_data_rx(
    macsec_test_macsec_flow_mka_wait_drops_data_rx_data_t *data, int verbose)
{
    const size_t plain_len = MACSEC_TEST_MACSEC_FLOW_PLAIN_LEN;

    size_t decrypted_len = sizeof(data->decrypted);

    macsec_bool_t pass_to_stack = MACSEC_TRUE;

    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  MACsec flow MKA WAIT drops data RX test\n"));
    }

    macsec_assert(data != NULL);

    macsec_test_mka_config(&data->cfg, test_mac_a, test_cak_16, sizeof(test_cak_16), 255u);

    ret = macsec_init(&data->ctx, &data->cfg);
    TEST_OK(ret);

    TEST_TRUE(macsec_get_state(&data->ctx) == MACSEC_STATE_WAIT_MKA);

    /*
     * This is an ordinary unprotected Ethernet data frame, not an
     * EAPOL/MKA control frame.
     */
    macsec_test_fill_plain_frame(data->plain, plain_len, test_mac_a, test_mac_b,
                                 MACSEC_TEST_MACSEC_FLOW_IPV4_ETHERTYPE, 0x78u);

    ret = macsec_input(&data->ctx, data->plain, plain_len, data->decrypted, &decrypted_len,
                       sizeof(data->decrypted), &pass_to_stack);

    /*
     * While MKA has not established a SAK, ordinary received data is
     * rejected by the top-level input API.
     */
    TEST_TRUE(ret == MACSEC_ERR_AUTH);
    TEST_EQ_U32(decrypted_len, 0u);
    TEST_TRUE(!pass_to_stack);
    TEST_TRUE(macsec_get_state(&data->ctx) == MACSEC_STATE_WAIT_MKA);

    macsec_clear(&data->ctx);

    return 0;
}

static int macsec_test_macsec_flow_tampered_secure_frame(
    macsec_test_macsec_flow_tampered_secure_frame_data_t *data, int verbose)
{
    const size_t plain_len = MACSEC_TEST_MACSEC_FLOW_PLAIN_LEN;

    size_t secure_len = 0u;
    size_t decrypted_len = sizeof(data->decrypted);

    macsec_bool_t pass_to_stack = MACSEC_TRUE;

    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  MACsec flow tampered secure frame test\n"));
    }

    macsec_test_static_config(&data->cfg_a, test_mac_a, MACSEC_TEST_MACSEC_FLOW_STATIC_AN);
    macsec_test_static_config(&data->cfg_b, test_mac_b, MACSEC_TEST_MACSEC_FLOW_STATIC_AN);

    ret = macsec_init(&data->a, &data->cfg_a);
    TEST_OK(ret);

    ret = macsec_init(&data->b, &data->cfg_b);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_clear(&data->a);
        return ret;
    }

    macsec_test_fill_plain_frame(data->plain, plain_len, test_mac_b, test_mac_a,
                                 MACSEC_TEST_MACSEC_FLOW_IPV4_ETHERTYPE, 0x91u);

    ret = macsec_output(&data->a, data->plain, plain_len, data->secure, &secure_len,
                        sizeof(data->secure));
    if (ret != MACSEC_ERR_OK)
    {
        macsec_clear(&data->a);
        macsec_clear(&data->b);
        return ret;
    }

    TEST_TRUE(secure_len > plain_len);

    data->secure[secure_len - 1u] ^= MACSEC_TEST_MACSEC_FLOW_TAMPER_MASK;

    ret = macsec_input(&data->b, data->secure, secure_len, data->decrypted, &decrypted_len,
                       sizeof(data->decrypted), &pass_to_stack);

    TEST_TRUE(ret != MACSEC_ERR_OK);
    TEST_EQ_U32(decrypted_len, 0u);
    TEST_TRUE(!pass_to_stack);
    TEST_TRUE(macsec_get_state(&data->b) == MACSEC_STATE_SECURED);

    macsec_clear(&data->a);
    macsec_clear(&data->b);

    return 0;
}

static int
macsec_test_macsec_flow_small_output_buffer(macsec_test_macsec_flow_small_buffer_data_t *data,
                                            int verbose)
{
    const size_t plain_len = MACSEC_TEST_MACSEC_FLOW_PLAIN_LEN;

    size_t tx_len = sizeof(data->secure);

    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  MACsec flow small output buffer test\n"));
    }

    macsec_test_static_config(&data->cfg, test_mac_a, MACSEC_TEST_MACSEC_FLOW_STATIC_AN);

    ret = macsec_init(&data->ctx, &data->cfg);
    TEST_OK(ret);

    macsec_test_fill_plain_frame(data->plain, plain_len, test_mac_b, test_mac_a,
                                 MACSEC_TEST_MACSEC_FLOW_IPV4_ETHERTYPE, 0xA1u);

    ret = macsec_output(&data->ctx, data->plain, plain_len, data->secure, &tx_len, plain_len);

    TEST_TRUE(ret == MACSEC_ERR_BUFFER);
    TEST_EQ_U32(tx_len, 0u);
    TEST_TRUE(macsec_get_state(&data->ctx) == MACSEC_STATE_SECURED);

    macsec_clear(&data->ctx);

    return 0;
}

static int
macsec_test_macsec_flow_small_input_buffer(macsec_test_macsec_flow_small_buffer_data_t *data,
                                           int verbose)
{
    const size_t plain_len = MACSEC_TEST_MACSEC_FLOW_PLAIN_LEN;

    size_t secure_len = 0u;
    size_t decrypted_len = sizeof(data->decrypted);

    macsec_bool_t pass_to_stack = MACSEC_TRUE;

    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  MACsec flow small input buffer test\n"));
    }

    macsec_test_static_config(&data->cfg, test_mac_a, MACSEC_TEST_MACSEC_FLOW_STATIC_AN);

    ret = macsec_init(&data->ctx, &data->cfg);
    TEST_OK(ret);

    macsec_test_fill_plain_frame(data->plain, plain_len, test_mac_a, test_mac_b,
                                 MACSEC_TEST_MACSEC_FLOW_IPV4_ETHERTYPE, 0xB1u);

    ret = macsec_output(&data->ctx, data->plain, plain_len, data->secure, &secure_len,
                        sizeof(data->secure));
    if (ret != MACSEC_ERR_OK)
    {
        macsec_clear(&data->ctx);
        return ret;
    }

    ret = macsec_input(&data->ctx, data->secure, secure_len, data->decrypted, &decrypted_len,
                       plain_len - 1u, &pass_to_stack);

    TEST_TRUE(ret == MACSEC_ERR_BUFFER);
    TEST_EQ_U32(decrypted_len, 0u);
    TEST_TRUE(!pass_to_stack);
    TEST_TRUE(macsec_get_state(&data->ctx) == MACSEC_STATE_SECURED);

    macsec_clear(&data->ctx);

    return 0;
}

static int
macsec_test_macsec_flow_disabled_small_buffer(macsec_test_macsec_flow_small_buffer_data_t *data,
                                              int verbose)
{
    const size_t plain_len = MACSEC_TEST_MACSEC_FLOW_PLAIN_LEN;

    size_t output_len = sizeof(data->secure);

    macsec_bool_t pass_to_stack = MACSEC_TRUE;

    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  MACsec flow disabled mode small buffer test\n"));
    }

    macsec_test_disabled_config(&data->cfg, test_mac_a);

    ret = macsec_init(&data->ctx, &data->cfg);
    TEST_OK(ret);

    TEST_TRUE(macsec_get_state(&data->ctx) == MACSEC_STATE_SECURED);

    macsec_test_fill_plain_frame(data->plain, plain_len, test_mac_b, test_mac_a,
                                 MACSEC_TEST_MACSEC_FLOW_IPV4_ETHERTYPE, 0xC1u);

    ret = macsec_output(&data->ctx, data->plain, plain_len, data->secure, &output_len,
                        plain_len - 1u);

    TEST_TRUE(ret == MACSEC_ERR_BUFFER);
    TEST_EQ_U32(output_len, 0u);

    output_len = sizeof(data->decrypted);
    pass_to_stack = MACSEC_TRUE;

    ret = macsec_input(&data->ctx, data->plain, plain_len, data->decrypted, &output_len,
                       plain_len - 1u, &pass_to_stack);

    TEST_TRUE(ret == MACSEC_ERR_BUFFER);
    TEST_EQ_U32(output_len, 0u);
    TEST_TRUE(!pass_to_stack);

    macsec_clear(&data->ctx);

    return 0;
}

static int macsec_test_macsec_flow_short_frame(macsec_test_macsec_flow_short_frame_data_t *data,
                                               int verbose)
{
    size_t plain_len = sizeof(data->plain);

    macsec_bool_t pass_to_stack = MACSEC_TRUE;

    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  MACsec flow short Ethernet frame test\n"));
    }

    macsec_test_static_config(&data->cfg, test_mac_a, MACSEC_TEST_MACSEC_FLOW_STATIC_AN);

    ret = macsec_init(&data->ctx, &data->cfg);
    TEST_OK(ret);

    memset(data->short_frame, 0xA5, sizeof(data->short_frame));

    ret = macsec_input(&data->ctx, data->short_frame, sizeof(data->short_frame), data->plain,
                       &plain_len, sizeof(data->plain), &pass_to_stack);

    TEST_TRUE(ret == MACSEC_ERR_AUTH);
    TEST_EQ_U32(plain_len, 0u);
    TEST_TRUE(!pass_to_stack);
    TEST_TRUE(macsec_get_state(&data->ctx) == MACSEC_STATE_SECURED);

    macsec_clear(&data->ctx);

    return 0;
}

static int macsec_test_macsec_flow_exchange_control_frame(macsec_ctx_t *tx, macsec_ctx_t *rx,
                                                          uint8_t *control, size_t control_max_len,
                                                          uint8_t *plain, size_t plain_max_len,
                                                          uint32_t now_ms,
                                                          macsec_bool_t *frame_sent)
{
    size_t control_len;
    size_t plain_len;

    macsec_bool_t pass_to_stack;

    int ret;

    macsec_assert(tx != NULL);
    macsec_assert(rx != NULL);
    macsec_assert(control != NULL);
    macsec_assert(plain != NULL);
    macsec_assert(frame_sent != NULL);

    *frame_sent = MACSEC_FALSE;

    ret = macsec_tick(tx, now_ms);
    if (ret != MACSEC_ERR_OK)
    {
        return ret;
    }

    control_len = 0u;

    ret = macsec_get_control_frame(tx, control, &control_len, control_max_len);

    if (ret == MACSEC_ERR_NOT_READY)
    {
        return MACSEC_ERR_OK;
    }

    if (ret != MACSEC_ERR_OK)
    {
        return ret;
    }

    plain_len = plain_max_len;
    pass_to_stack = MACSEC_TRUE;

    ret = macsec_input(rx, control, control_len, plain, &plain_len, plain_max_len, &pass_to_stack);

    if (ret != MACSEC_ERR_OK)
    {
        (void) macsec_notify_control_tx_failure(tx);
        return ret;
    }

    if ((plain_len != 0u) || pass_to_stack)
    {
        (void) macsec_notify_control_tx_failure(tx);
        return MACSEC_ERR_AUTH;
    }

    ret = macsec_notify_control_tx_success(tx, now_ms);
    if (ret != MACSEC_ERR_OK)
    {
        return ret;
    }

    *frame_sent = MACSEC_TRUE;

    return MACSEC_ERR_OK;
}

static int macsec_test_macsec_flow_complete_mka(macsec_ctx_t *a, macsec_ctx_t *b,
                                                uint8_t *control_a, size_t control_a_max_len,
                                                uint8_t *control_b, size_t control_b_max_len,
                                                uint8_t *plain, size_t plain_max_len)
{
    uint32_t now_ms;
    uint32_t round;

    macsec_bool_t sent_a;
    macsec_bool_t sent_b;

    int ret;

    macsec_assert(a != NULL);
    macsec_assert(b != NULL);
    macsec_assert(control_a != NULL);
    macsec_assert(control_b != NULL);
    macsec_assert(plain != NULL);

    now_ms = 0u;

    for (round = 0u; round < 32u; round++)
    {
        sent_a = MACSEC_FALSE;
        sent_b = MACSEC_FALSE;

        ret = macsec_test_macsec_flow_exchange_control_frame(a, b, control_a, control_a_max_len,
                                                             plain, plain_max_len, now_ms, &sent_a);
        if (ret != MACSEC_ERR_OK)
        {
            return ret;
        }

        ret = macsec_test_macsec_flow_exchange_control_frame(b, a, control_b, control_b_max_len,
                                                             plain, plain_max_len, now_ms, &sent_b);
        if (ret != MACSEC_ERR_OK)
        {
            return ret;
        }

        if (macsec_is_secured(a) && macsec_is_secured(b))
        {
            return MACSEC_ERR_OK;
        }

        if ((!sent_a) && (!sent_b))
        {
            now_ms += MACSEC_TEST_MACSEC_FLOW_TX_INTERVAL_MS;
        }
        else
        {
            now_ms++;
        }
    }

    return MACSEC_ERR_NOT_READY;
}

static int macsec_test_macsec_flow_mka_secure_bidirectional(
    macsec_test_macsec_flow_mka_secure_bidirectional_data_t *data, int verbose)
{
    const size_t plain_len = MACSEC_TEST_MACSEC_FLOW_PLAIN_LEN;

    size_t secure_len;
    size_t decrypted_len;

    macsec_bool_t pass_to_stack;

    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  MACsec flow MKA secure bidirectional test\n"));
    }

    macsec_test_mka_config(&data->cfg_a, test_mac_a, test_cak_16, sizeof(test_cak_16),
                           MACSEC_TEST_MACSEC_FLOW_KEY_SERVER_PRIORITY);

    macsec_test_mka_config(&data->cfg_b, test_mac_b, test_cak_16, sizeof(test_cak_16),
                           MACSEC_TEST_MACSEC_FLOW_PEER_PRIORITY);

    ret = macsec_init(&data->a, &data->cfg_a);
    TEST_OK(ret);

    ret = macsec_init(&data->b, &data->cfg_b);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_clear(&data->a);
        return ret;
    }

    TEST_TRUE(macsec_get_state(&data->a) == MACSEC_STATE_WAIT_MKA);
    TEST_TRUE(macsec_get_state(&data->b) == MACSEC_STATE_WAIT_MKA);

    ret = macsec_test_macsec_flow_complete_mka(
        &data->a, &data->b, data->control_a, sizeof(data->control_a), data->control_b,
        sizeof(data->control_b), data->decrypted, sizeof(data->decrypted));
    if (ret != MACSEC_ERR_OK)
    {
        macsec_clear(&data->a);
        macsec_clear(&data->b);
        return ret;
    }

    TEST_TRUE(macsec_get_state(&data->a) == MACSEC_STATE_SECURED);
    TEST_TRUE(macsec_get_state(&data->b) == MACSEC_STATE_SECURED);
    TEST_TRUE(macsec_is_secured(&data->a));
    TEST_TRUE(macsec_is_secured(&data->b));

    macsec_test_fill_plain_frame(data->plain_a, plain_len, test_mac_b, test_mac_a,
                                 MACSEC_TEST_MACSEC_FLOW_IPV4_ETHERTYPE, 0x20u);

    secure_len = 0u;

    ret = macsec_output(&data->a, data->plain_a, plain_len, data->secure, &secure_len,
                        sizeof(data->secure));
    TEST_OK(ret);

    TEST_TRUE(secure_len > plain_len);
    TEST_TRUE(macsec_frame_is_macsec(data->secure, secure_len));

    decrypted_len = 0u;
    pass_to_stack = MACSEC_FALSE;

    ret = macsec_input(&data->b, data->secure, secure_len, data->decrypted, &decrypted_len,
                       sizeof(data->decrypted), &pass_to_stack);
    TEST_OK(ret);

    TEST_TRUE(pass_to_stack);
    TEST_EQ_U32(decrypted_len, plain_len);
    TEST_MEM_EQ(data->decrypted, data->plain_a, plain_len);

    macsec_test_fill_plain_frame(data->plain_b, plain_len, test_mac_a, test_mac_b,
                                 MACSEC_TEST_MACSEC_FLOW_IPV4_ETHERTYPE, 0x60u);

    secure_len = 0u;

    ret = macsec_output(&data->b, data->plain_b, plain_len, data->secure, &secure_len,
                        sizeof(data->secure));
    TEST_OK(ret);

    TEST_TRUE(secure_len > plain_len);
    TEST_TRUE(macsec_frame_is_macsec(data->secure, secure_len));

    decrypted_len = 0u;
    pass_to_stack = MACSEC_FALSE;

    ret = macsec_input(&data->a, data->secure, secure_len, data->decrypted, &decrypted_len,
                       sizeof(data->decrypted), &pass_to_stack);
    TEST_OK(ret);

    TEST_TRUE(pass_to_stack);
    TEST_EQ_U32(decrypted_len, plain_len);
    TEST_MEM_EQ(data->decrypted, data->plain_b, plain_len);

    macsec_clear(&data->a);
    macsec_clear(&data->b);

    return 0;
}
int macsec_test_macsec_flow(macsec_test_macsec_flow_data_t *data, int verbose)
{
    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("MACsec communication flow tests\n"));
    }

    ret = macsec_test_macsec_flow_static_bidirectional(&data->test_static_bidirectional_data,
                                                       verbose);
    if (ret != 0)
    {
        return ret;
    }

    ret = macsec_test_macsec_flow_disabled_passthrough(&data->test_disabled_passthrough_data,
                                                       verbose);
    if (ret != 0)
    {
        return ret;
    }

    ret = macsec_test_macsec_flow_static_bad_key_rejected(&data->test_static_bad_key_rejected_data,
                                                          verbose);
    if (ret != 0)
    {
        return ret;
    }

    ret = macsec_test_macsec_flow_eapol_consumed(&data->test_eapol_consumed_data, verbose);
    if (ret != 0)
    {
        return ret;
    }

    ret = macsec_test_macsec_flow_bad_eapol_icv(&data->test_bad_eapol_icv_data, verbose);
    if (ret != 0)
    {
        return ret;
    }

    ret = macsec_test_macsec_flow_mka_wait_drops_data_tx(&data->test_mka_wait_drops_data_tx_data,
                                                         verbose);
    if (ret != 0)
    {
        return ret;
    }

    ret = macsec_test_macsec_flow_mka_wait_drops_data_rx(&data->test_mka_wait_drops_data_rx_data,
                                                         verbose);
    if (ret != 0)
    {
        return ret;
    }

    ret = macsec_test_macsec_flow_tampered_secure_frame(&data->test_tampered_secure_frame_data,
                                                        verbose);
    if (ret != 0)
    {
        return ret;
    }

    ret = macsec_test_macsec_flow_small_output_buffer(&data->test_small_buffer_data, verbose);
    if (ret != 0)
    {
        return ret;
    }

    ret = macsec_test_macsec_flow_small_input_buffer(&data->test_small_buffer_data, verbose);
    if (ret != 0)
    {
        return ret;
    }

    ret = macsec_test_macsec_flow_disabled_small_buffer(&data->test_small_buffer_data, verbose);
    if (ret != 0)
    {
        return ret;
    }

    ret = macsec_test_macsec_flow_short_frame(&data->test_short_frame_data, verbose);
    if (ret != 0)
    {
        return ret;
    }

    ret = macsec_test_macsec_flow_mka_secure_bidirectional(
        &data->test_mka_secure_bidirectional_data, verbose);
    if (ret != 0)
    {
        return ret;
    }

    if (verbose)
    {
        MACSEC_PRINT(("MACsec communication flow tests passed\n"));
    }

    return 0;
}

#endif /* MACSEC_SELF_TEST */
