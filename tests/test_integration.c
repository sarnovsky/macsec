/*
 * test_integration.c
 *
 * Lightweight MACsec stack
 * End-to-end integration tests.
 * This file verifies correct interaction between the MACsec, MKA and
 * cryptographic modules under realistic operating conditions.
 *
 * Copyright (c) 2026 Michal Sarnovský
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */

#include <tests/test_integration.h>
#include <tests/unit_tests.h>

#include <string.h>

#if (MACSEC_SELF_TEST != 0)

static void macsec_test_fill_plain_frame(uint8_t *frame,
                                         size_t len,
                                         uint16_t ethertype,
                                         uint8_t seed)
{
    size_t i;

    macsec_assert(frame != NULL);
    macsec_assert(len >= 14u);

    frame[0] = 0x02u;
    frame[1] = 0x00u;
    frame[2] = 0x00u;
    frame[3] = 0x00u;
    frame[4] = 0x00u;
    frame[5] = 0x02u;

    frame[6] = 0x02u;
    frame[7] = 0x00u;
    frame[8] = 0x00u;
    frame[9] = 0x00u;
    frame[10] = 0x00u;
    frame[11] = 0x01u;

    macsec_wr_be16(&frame[12], ethertype);

    for (i = 14u; i < len; i++)
    {
        frame[i] = (uint8_t)(seed + (uint8_t)i);
    }
}

static void macsec_test_fill_static_config(macsec_config_t *cfg,
                                           const uint8_t local_mac[6])
{
    static const uint8_t static_sak[16] =
    {
        0x00u, 0x11u, 0x22u, 0x33u,
        0x44u, 0x55u, 0x66u, 0x77u,
        0x88u, 0x99u, 0xAAu, 0xBBu,
        0xCCu, 0xDDu, 0xEEu, 0xFFu
    };

    macsec_assert(cfg != NULL);
    macsec_assert(local_mac != NULL);

    memset(cfg, 0, sizeof(*cfg));

    cfg->mode = MACSEC_MODE_STATIC_SAK;

    memcpy(cfg->local_mac.addr, local_mac, 6u);
    cfg->port_id = 1u;

    memcpy(cfg->static_sak, static_sak, sizeof(static_sak));
    cfg->static_sak_len = sizeof(static_sak);
    cfg->static_an = 0u;

    cfg->replay_protect = MACSEC_FALSE;
    cfg->replay_window = 0u;
}

static int macsec_test_integration_static_sak_ping_like(macsec_test_integration_static_sak_ping_like_data_t *data, int verbose)
{
    static const uint8_t mac_a[6] =
    {
        0x02u, 0x00u, 0x00u, 0x00u, 0x00u, 0x01u
    };

    static const uint8_t mac_b[6] =
    {
        0x02u, 0x00u, 0x00u, 0x00u, 0x00u, 0x02u
    };

    size_t plain_tx_len = 96u;
    size_t secure_len = 0u;
    size_t plain_rx_len = 0u;

    macsec_bool_t pass_to_stack = MACSEC_FALSE;

    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  Integration static SAK encrypt/decrypt test\n"));
    }

    macsec_test_fill_static_config(&data->cfg_a, mac_a);
    macsec_test_fill_static_config(&data->cfg_b, mac_b);

    ret = macsec_init(&data->a, &data->cfg_a);
    TEST_OK(ret);

    ret = macsec_init(&data->b, &data->cfg_b);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_clear(&data->a);
        return ret;
    }

    TEST_TRUE(macsec_is_secured(&data->a));
    TEST_TRUE(macsec_is_secured(&data->b));

    macsec_test_fill_plain_frame(data->plain_tx, plain_tx_len, 0x0800u, 0x33u);

    ret = macsec_output(&data->a,
                        data->plain_tx,
                        plain_tx_len,
                        data->secure_frame,
                        &secure_len,
                        sizeof(data->secure_frame));
    if (ret != MACSEC_ERR_OK)
    {
        macsec_clear(&data->a);
        macsec_clear(&data->b);
        return ret;
    }

    TEST_TRUE(macsec_frame_is_macsec(data->secure_frame, secure_len));

    ret = macsec_input(&data->b,
                       data->secure_frame,
                       secure_len,
                       data->plain_rx,
                       &plain_rx_len,
                       sizeof(data->plain_rx),
                       &pass_to_stack);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_clear(&data->a);
        macsec_clear(&data->b);
        return ret;
    }

    TEST_TRUE(pass_to_stack);
    TEST_TRUE(plain_rx_len == plain_tx_len);
    TEST_TRUE(memcmp(data->plain_tx, data->plain_rx, plain_tx_len) == 0);

    macsec_clear(&data->a);
    macsec_clear(&data->b);

    return 0;
}

static int macsec_test_integration_disabled_passthrough(macsec_test_integration_disabled_passthrough_data_t *data, int verbose)
{
    static const uint8_t mac_a[6] =
    {
        0x02u, 0x00u, 0x00u, 0x00u, 0x00u, 0x01u
    };

    size_t plain_tx_len = 80u;
    size_t tx_len = 0u;
    size_t rx_len = 0u;

    macsec_bool_t pass_to_stack = MACSEC_FALSE;

    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  Integration disabled pass-through test\n"));
    }

    memset(&data->cfg, 0, sizeof(data->cfg));

    data->cfg.mode = MACSEC_MODE_DISABLED;
    memcpy(data->cfg.local_mac.addr, mac_a, 6u);
    data->cfg.port_id = 1u;

    ret = macsec_init(&data->ctx, &data->cfg);
    TEST_OK(ret);

    TEST_TRUE(macsec_is_secured(&data->ctx));

    macsec_test_fill_plain_frame(data->plain_tx, plain_tx_len, 0x0800u, 0x44u);

    ret = macsec_output(&data->ctx,
                        data->plain_tx,
                        plain_tx_len,
                        data->tx_frame,
                        &tx_len,
                        sizeof(data->tx_frame));
    if (ret != MACSEC_ERR_OK)
    {
        macsec_clear(&data->ctx);
        return ret;
    }

    TEST_TRUE(tx_len == plain_tx_len);
    TEST_TRUE(memcmp(data->plain_tx, data->tx_frame, plain_tx_len) == 0);

    ret = macsec_input(&data->ctx,
                       data->tx_frame,
                       tx_len,
                       data->rx_frame,
                       &rx_len,
                       sizeof(data->rx_frame),
                       &pass_to_stack);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_clear(&data->ctx);
        return ret;
    }

    TEST_TRUE(pass_to_stack);
    TEST_TRUE(rx_len == plain_tx_len);
    TEST_TRUE(memcmp(data->plain_tx, data->rx_frame, plain_tx_len) == 0);

    macsec_clear(&data->ctx);

    return 0;
}

static int macsec_test_integration_protected_drops_plain(macsec_test_integration_protected_drops_plain_data_t *data, int verbose)
{
    static const uint8_t mac_a[6] =
    {
        0x02u, 0x00u, 0x00u, 0x00u, 0x00u, 0x01u
    };

    size_t plain_len = 80u;
    size_t out_len = 0u;

    macsec_bool_t pass_to_stack = MACSEC_FALSE;

    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  Integration protected mode drops plain frame test\n"));
    }

    macsec_test_fill_static_config(&data->cfg, mac_a);

    ret = macsec_init(&data->ctx, &data->cfg);
    TEST_OK(ret);

    macsec_test_fill_plain_frame(data->plain, plain_len, 0x0800u, 0x55u);

    ret = macsec_input(&data->ctx,
                       data->plain,
                       plain_len,
                       data->out,
                       &out_len,
                       sizeof(data->out),
                       &pass_to_stack);

    TEST_TRUE(ret == MACSEC_ERR_AUTH);
    TEST_TRUE(!pass_to_stack);
    TEST_TRUE(out_len == 0u);

    macsec_clear(&data->ctx);

    return 0;
}

static int macsec_test_integration_output_not_ready_mka(macsec_test_integration_output_not_ready_mka_data_t *data, int verbose)
{
    static const uint8_t mac_a[6] =
    {
        0x02u, 0x00u, 0x00u, 0x00u, 0x00u, 0x01u
    };

    static const uint8_t cak[16] =
    {
        0x00u, 0x11u, 0x22u, 0x33u,
        0x44u, 0x55u, 0x66u, 0x77u,
        0x88u, 0x99u, 0xAAu, 0xBBu,
        0xCCu, 0xDDu, 0xEEu, 0xFFu
    };

    static const uint8_t ckn[24] =
    {
        0x00u, 0x11u, 0x22u, 0x33u,
        0x44u, 0x55u, 0x66u, 0x77u,
        0x88u, 0x99u, 0xAAu, 0xBBu,
        0xCCu, 0xDDu, 0xEEu, 0xFFu,
        0x00u, 0x11u, 0x22u, 0x33u,
        0x44u, 0x55u, 0x66u, 0x77u
    };

    size_t plain_len = 80u;
    size_t secure_len = 0u;

    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  Integration MKA output not ready test\n"));
    }

    memset(&data->cfg, 0, sizeof(data->cfg));

    data->cfg.mode = MACSEC_MODE_MKA_PSK;
    memcpy(data->cfg.local_mac.addr, mac_a, 6u);
    data->cfg.port_id = 1u;

    memcpy(data->cfg.cak, cak, sizeof(cak));
    data->cfg.cak_len = sizeof(cak);

    memcpy(data->cfg.ckn, ckn, sizeof(ckn));
    data->cfg.ckn_len = sizeof(ckn);

    data->cfg.key_server_priority = 255u;
    data->cfg.mka_tx_interval_ms = 2000u;

    ret = macsec_init(&data->ctx, &data->cfg);
    TEST_OK(ret);

    TEST_TRUE(macsec_get_state(&data->ctx) == MACSEC_STATE_WAIT_MKA);

    macsec_test_fill_plain_frame(data->plain, plain_len, 0x0800u, 0x66u);

    ret = macsec_output(&data->ctx,
                        data->plain,
                        plain_len,
                        data->secure,
                        &secure_len,
                        sizeof(data->secure));

    TEST_TRUE(ret == MACSEC_ERR_NOT_READY);
    TEST_TRUE(secure_len == 0u);

    macsec_clear(&data->ctx);

    return 0;
}

int macsec_test_integration(macsec_test_integration_data_t *data, int verbose)
{
    if (verbose)
    {
        MACSEC_PRINT(("MACsec integration tests\n"));
    }

    TEST_OK(macsec_test_integration_disabled_passthrough(&data->test_integration_disabled_passthrough_data, verbose));
    TEST_OK(macsec_test_integration_static_sak_ping_like(&data->test_integration_static_sak_ping_like_data, verbose));
    TEST_OK(macsec_test_integration_protected_drops_plain(&data->test_integration_protected_drops_plain_data, verbose));
    TEST_OK(macsec_test_integration_output_not_ready_mka(&data->test_integration_output_not_ready_mka_data, verbose));

    return 0;
}

#endif /* MACSEC_SELF_TEST */
