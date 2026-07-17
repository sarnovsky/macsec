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
    macsec_assert(len >= 14u);

    memcpy(&frame[0], dst_mac, 6u);
    memcpy(&frame[6], src_mac, 6u);
    macsec_wr_be16(&frame[12], ethertype);

    for (i = 14u; i < len; i++)
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

    memcpy(cfg->local_mac.addr, local_mac, 6u);
    cfg->port_id = 1u;

    memcpy(cfg->static_sak, test_static_sak, sizeof(test_static_sak));

    cfg->static_sak_len = sizeof(test_static_sak);
    cfg->static_an = an & 0x03u;

    cfg->replay_protect = MACSEC_FALSE;
    cfg->replay_window = 0u;
}

static void macsec_test_mka_config(macsec_config_t *cfg, const uint8_t local_mac[6],
                                   const uint8_t *cak, size_t cak_len, uint8_t priority)
{
    macsec_assert(cfg != NULL);
    macsec_assert(local_mac != NULL);
    macsec_assert(cak != NULL);
    macsec_assert((cak_len == 16u) || (cak_len == 32u));
    macsec_assert(cak_len <= sizeof(cfg->cak));

    memset(cfg, 0, sizeof(*cfg));

    cfg->mode = MACSEC_MODE_MKA_PSK;

    memcpy(cfg->local_mac.addr, local_mac, 6u);
    cfg->port_id = 1u;

    memcpy(cfg->cak, cak, cak_len);
    cfg->cak_len = cak_len;

    memcpy(cfg->ckn, test_ckn, sizeof(test_ckn));
    cfg->ckn_len = sizeof(test_ckn);

    cfg->key_server_priority = priority;
    cfg->mka_tx_interval_ms = 2000u;

    cfg->replay_protect = MACSEC_FALSE;
    cfg->replay_window = 0u;
}

/*
 * Build an MKPDU and simulate successful transmission.
 *
 * Direct MKA tests use this helper when the generated frame is subsequently
 * delivered to another participant. The success notification commits the
 * message number, transmission time and transmitted scheduling reasons.
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

static int macsec_test_macsec_flow_static_bidirectional(
    macsec_test_macsec_flow_static_bidirectional_data_t *data, int verbose)
{
    size_t plain_len = 96u;
    size_t secure_len = 0u;
    size_t decrypted_len = 0u;

    macsec_bool_t pass_to_stack = MACSEC_FALSE;

    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  MACsec flow static bidirectional test\n"));
    }

    macsec_test_static_config(&data->cfg_a, test_mac_a, 0u);
    macsec_test_static_config(&data->cfg_b, test_mac_b, 0u);

    ret = macsec_init(&data->a, &data->cfg_a);
    TEST_OK(ret);

    ret = macsec_init(&data->b, &data->cfg_b);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_clear(&data->a);
        return ret;
    }

    macsec_test_fill_plain_frame(data->plain_a, plain_len, test_mac_b, test_mac_a, 0x0800u, 0x10u);

    ret = macsec_output(&data->a, data->plain_a, plain_len, data->secure, &secure_len,
                        sizeof(data->secure));
    if (ret != MACSEC_ERR_OK)
    {
        macsec_clear(&data->a);
        macsec_clear(&data->b);
        return ret;
    }

    ret = macsec_input(&data->b, data->secure, secure_len, data->decrypted, &decrypted_len,
                       sizeof(data->decrypted), &pass_to_stack);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_clear(&data->a);
        macsec_clear(&data->b);
        return ret;
    }

    TEST_TRUE(pass_to_stack);
    TEST_TRUE(decrypted_len == plain_len);
    TEST_TRUE(memcmp(data->plain_a, data->decrypted, plain_len) == 0);

    macsec_test_fill_plain_frame(data->plain_b, plain_len, test_mac_a, test_mac_b, 0x0800u, 0x30u);

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

    ret = macsec_input(&data->a, data->secure, secure_len, data->decrypted, &decrypted_len,
                       sizeof(data->decrypted), &pass_to_stack);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_clear(&data->a);
        macsec_clear(&data->b);
        return ret;
    }

    TEST_TRUE(pass_to_stack);
    TEST_TRUE(decrypted_len == plain_len);
    TEST_TRUE(memcmp(data->plain_b, data->decrypted, plain_len) == 0);

    macsec_clear(&data->a);
    macsec_clear(&data->b);

    return 0;
}

static int
macsec_test_macsec_flow_eapol_consumed(macsec_test_macsec_flow_eapol_consumed_data_t *data,
                                       const uint8_t *cak, size_t cak_len, int verbose)
{
    size_t eapol_len = 0u;
    size_t plain_len = 0u;

    macsec_bool_t pass_to_stack = MACSEC_TRUE;

    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  MACsec flow EAPOL consumed test, %u-byte CAK\n", (unsigned int) cak_len));
    }

    macsec_assert(cak != NULL);
    macsec_assert((cak_len == 16u) || (cak_len == 32u));

    macsec_test_mka_config(&data->cfg, test_mac_a, cak, cak_len, 255u);

    TEST_TRUE(data->cfg.cak_len == cak_len);
    TEST_TRUE(memcmp(data->cfg.cak, cak, cak_len) == 0);

    ret = macsec_init(&data->macsec, &data->cfg);
    TEST_OK(ret);

    ret = macsec_mka_init(&data->mka_tx, cak, cak_len, test_ckn, sizeof(test_ckn), test_mac_b, 1u,
                          100u, 2000u);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_clear(&data->macsec);
        return ret;
    }

    ret = macsec_test_mka_build_and_commit_tx(&data->mka_tx, data->eapol, &eapol_len,
                                              sizeof(data->eapol), 1000u);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_clear(&data->macsec);
        macsec_mka_clear(&data->mka_tx);
        return ret;
    }

    ret = macsec_input(&data->macsec, data->eapol, eapol_len, data->plain, &plain_len,
                       sizeof(data->plain), &pass_to_stack);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_clear(&data->macsec);
        macsec_mka_clear(&data->mka_tx);
        return ret;
    }

    TEST_TRUE(!pass_to_stack);
    TEST_TRUE(plain_len == 0u);
    TEST_TRUE(data->macsec.mka.peer.valid);

    macsec_clear(&data->macsec);
    macsec_mka_clear(&data->mka_tx);

    return 0;
}

static int macsec_test_macsec_flow_mka_wait_drops_data_tx(
    macsec_test_macsec_flow_mka_wait_drops_data_tx_data_t *data, const uint8_t *cak, size_t cak_len,
    int verbose)
{
    size_t plain_len = 96u;
    size_t secure_len = 0u;

    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  MACsec flow MKA WAIT drops data TX test, "
                      "%u-byte CAK\n",
                      (unsigned int) cak_len));
    }

    macsec_assert(cak != NULL);
    macsec_assert((cak_len == 16u) || (cak_len == 32u));

    macsec_test_mka_config(&data->cfg, test_mac_a, cak, cak_len, 255u);

    TEST_TRUE(data->cfg.cak_len == cak_len);
    TEST_TRUE(memcmp(data->cfg.cak, cak, cak_len) == 0);

    ret = macsec_init(&data->ctx, &data->cfg);
    TEST_OK(ret);

    TEST_TRUE(macsec_get_state(&data->ctx) == MACSEC_STATE_WAIT_MKA);

    macsec_test_fill_plain_frame(data->plain, plain_len, test_mac_b, test_mac_a, 0x0800u,
                                 (cak_len == 16u) ? 0x77u : 0x78u);

    ret = macsec_output(&data->ctx, data->plain, plain_len, data->secure, &secure_len,
                        sizeof(data->secure));

    TEST_TRUE(ret == MACSEC_ERR_NOT_READY);
    TEST_TRUE(secure_len == 0u);

    macsec_clear(&data->ctx);

    return 0;
}

static int macsec_test_macsec_flow_static_bad_key_rejected(
    macsec_test_macsec_flow_static_bad_key_rejected_data_t *data, int verbose)
{
    size_t plain_len = 96u;
    size_t secure_len = 0u;
    size_t decrypted_len = 0u;

    macsec_bool_t pass_to_stack = MACSEC_FALSE;

    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  MACsec flow static bad key rejected test\n"));
    }

    macsec_test_static_config(&data->cfg_a, test_mac_a, 0u);
    macsec_test_static_config(&data->cfg_b, test_mac_b, 0u);

    data->cfg_b.static_sak[0] ^= 0x01u;

    ret = macsec_init(&data->a, &data->cfg_a);
    TEST_OK(ret);

    ret = macsec_init(&data->b, &data->cfg_b);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_clear(&data->a);
        return ret;
    }

    macsec_test_fill_plain_frame(data->plain, plain_len, test_mac_b, test_mac_a, 0x0800u, 0x88u);

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
    TEST_TRUE(!pass_to_stack);

    return 0;
}

int macsec_test_macsec_flow(macsec_test_macsec_flow_data_t *data, int verbose)
{
    if (verbose)
    {
        MACSEC_PRINT(("MACsec top-level flow tests\n"));
    }

    TEST_OK(macsec_test_macsec_flow_static_bidirectional(
        &data->test_macsec_flow_static_bidirectional_data, verbose));

    TEST_OK(macsec_test_macsec_flow_eapol_consumed(&data->test_macsec_flow_eapol_consumed_data,
                                                   test_cak_16, sizeof(test_cak_16), verbose));

    TEST_OK(macsec_test_macsec_flow_eapol_consumed(&data->test_macsec_flow_eapol_consumed_data,
                                                   test_cak_32, sizeof(test_cak_32), verbose));

    TEST_OK(macsec_test_macsec_flow_mka_wait_drops_data_tx(
        &data->test_macsec_flow_mka_wait_drops_data_tx_data, test_cak_16, sizeof(test_cak_16),
        verbose));

    TEST_OK(macsec_test_macsec_flow_mka_wait_drops_data_tx(
        &data->test_macsec_flow_mka_wait_drops_data_tx_data, test_cak_32, sizeof(test_cak_32),
        verbose));

    TEST_OK(macsec_test_macsec_flow_static_bad_key_rejected(
        &data->test_macsec_flow_static_bad_key_rejected_data, verbose));

    return 0;
}

#endif /* MACSEC_SELF_TEST */
