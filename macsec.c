/*
 * macsec.c
 *
 * Lightweight MACsec stack
 * Top-level MACsec integration layer.
 * This file connects the individual MACsec modules together and provides
 * the main public entry points used by the application or network driver.
 *
 * Copyright (c) 2026 Michal Sarnovský
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */

#include "macsec.h"


static void macsec_build_sci(macsec_frame_sci_t *sci,
                             const macsec_mac_addr_t *mac,
                             uint16_t port_id)
{
    macsec_assert(sci != NULL);
    macsec_assert(mac != NULL);

    memcpy(&sci->bytes[0], mac->addr, 6u);
    macsec_wr_be16(&sci->bytes[6], port_id);

    MACSEC_MEDIUM(("MACsec SCI build: port_id=%u\n", port_id));
    MACSEC_MEDIUM_HEX(("MACsec SCI", sci->bytes, 8));
}

static macsec_bool_t macsec_sak_equal(const macsec_frame_sak_t *sak,
                                      const uint8_t *key,
                                      size_t key_len)
{
    macsec_assert(sak != NULL);
    macsec_assert(key != NULL);

    return sak->valid &&
           sak->key_len == key_len &&
           memcmp(sak->key, key, key_len) == 0;
}

static int macsec_install_rx_sak(macsec_ctx_t *ctx,
                                 const uint8_t *sak_key,
                                 size_t sak_len,
                                 uint8_t an,
                                 uint32_t lowest_pn)
{
    macsec_frame_sak_t sak;
    uint8_t real_an;
    int ret;

    macsec_check(ctx != NULL, MACSEC_ERR_PARAM);
    macsec_check(sak_key != NULL, MACSEC_ERR_PARAM);
    macsec_check((sak_len == 16u) || (sak_len == 32u),
                 MACSEC_ERR_PARAM);
    macsec_check(an < MACSEC_FRAME_MAX_SA,
                 MACSEC_ERR_PARAM);

    real_an = an;

    if (lowest_pn == 0u)
    {
        lowest_pn = 1u;
    }

    if (macsec_sak_equal(&ctx->frame_crypto.rx_sak[real_an],
                         sak_key,
                         sak_len))
    {
        return MACSEC_ERR_OK;
    }

    memset(&sak, 0, sizeof(sak));
    memcpy(sak.key, sak_key, sak_len);

    sak.key_len = (uint8_t)sak_len;
    sak.an = real_an;
    sak.lowest_acceptable_pn = lowest_pn;
    sak.next_pn = 1u;
    sak.valid = MACSEC_TRUE;

    MACSEC_MEDIUM((
        "MACsec install RX SAK: an=%u sak_len=%lu lowest_pn=%lu\n",
        real_an,
        (unsigned long)sak_len,
        (unsigned long)lowest_pn));

    ret = macsec_frame_crypto_set_rx_sak(
        &ctx->frame_crypto,
        &sak);

    if (ret != MACSEC_ERR_OK)
    {
        return MACSEC_ERR_CRYPTO;
    }

    return MACSEC_ERR_OK;
}

static int macsec_install_tx_sak(macsec_ctx_t *ctx,
                                 const uint8_t *sak_key,
                                 size_t sak_len,
                                 uint8_t an)
{
    macsec_frame_sak_t sak;
    uint8_t real_an;
    int ret;

    macsec_check(ctx != NULL, MACSEC_ERR_PARAM);
    macsec_check(sak_key != NULL, MACSEC_ERR_PARAM);
    macsec_check((sak_len == 16u) || (sak_len == 32u), MACSEC_ERR_PARAM);

    macsec_check(an < MACSEC_FRAME_MAX_SA,
                 MACSEC_ERR_PARAM);

    real_an = an;

    if (macsec_sak_equal(&ctx->frame_crypto.tx_sak, sak_key, sak_len) &&
        ((ctx->frame_crypto.tx_sak.an & 0x03u) == real_an))
    {
        return MACSEC_ERR_OK;
    }

    memset(&sak, 0, sizeof(sak));
    memcpy(sak.key, sak_key, sak_len);

    sak.key_len = (uint8_t)sak_len;
    sak.an = real_an;
    sak.next_pn = 1u;
    sak.lowest_acceptable_pn = 1u;
    sak.valid = MACSEC_TRUE;

    MACSEC_MEDIUM(("MACsec activate TX SAK: an=%u sak_len=%lu\n",
                   real_an,
                   (unsigned long)sak_len));

    ret = macsec_frame_crypto_set_tx_sak(&ctx->frame_crypto, &sak);
    if (ret != MACSEC_ERR_OK)
    {
        return MACSEC_ERR_CRYPTO;
    }

    return MACSEC_ERR_OK;
}

static int macsec_install_static_sak(macsec_ctx_t *ctx)
{
    int ret;
    uint8_t an;

    macsec_check(ctx != NULL, MACSEC_ERR_PARAM);
    macsec_check(ctx->cfg.static_an < MACSEC_FRAME_MAX_SA,
                 MACSEC_ERR_PARAM);

    an = ctx->cfg.static_an;

    MACSEC_MEDIUM(("MACsec install static SAK an=%u\n", an));

    ret = macsec_install_rx_sak(ctx,
                                ctx->cfg.static_sak,
                                ctx->cfg.static_sak_len,
                                an,
                                1u);
    if (ret != MACSEC_ERR_OK)
    {
        return ret;
    }

    ret = macsec_install_tx_sak(ctx,
                                ctx->cfg.static_sak,
                                ctx->cfg.static_sak_len,
                                an);
    if (ret != MACSEC_ERR_OK)
    {
        return ret;
    }

    ctx->state = MACSEC_STATE_SECURED;

    return MACSEC_ERR_OK;
}

static int macsec_process_mka_sak_install(macsec_ctx_t *ctx)
{
    macsec_mka_sak_t sak;
    int ret;

    macsec_check(ctx != NULL, MACSEC_ERR_PARAM);

    memset(&sak, 0, sizeof(sak));

    ret = macsec_mka_take_sak_for_install(
        &ctx->mka,
        &sak);

    if (ret == MACSEC_ERR_NOT_READY)
    {
        return MACSEC_ERR_OK;
    }

    if (ret != MACSEC_ERR_OK)
    {
        MACSEC_ERROR((
            "MACsec MKA SAK take failed ret=%d\n",
            ret));

        return ret;
    }

    if (!sak.valid ||
        ((sak.sak_len != 16u) &&
         (sak.sak_len != 32u)) ||
        (sak.an >= MACSEC_FRAME_MAX_SA))
    {
        ret = MACSEC_ERR_STATE;
        goto cleanup;
    }

    /*
     * Install and confirm RX only if it has not already been confirmed.
     */
    if (!sak.rx_installed)
    {
        ret = macsec_install_rx_sak(
            ctx,
            sak.sak,
            sak.sak_len,
            sak.an,
            sak.lowest_pn);

        if (ret != MACSEC_ERR_OK)
        {
            MACSEC_ERROR((
                "MACsec MKA RX SAK install failed: "
                "ret=%d key_number=%lu an=%u\n",
                ret,
                (unsigned long)sak.key_number,
                sak.an));

            goto cleanup;
        }

        ret = macsec_mka_notify_sak_installed(
            &ctx->mka,
            sak.key_number,
            sak.an,
            MACSEC_MKA_INSTALL_RX,
            sak.lowest_pn);

        if (ret != MACSEC_ERR_OK)
        {
            MACSEC_ERROR((
                "MACsec MKA RX SAK confirmation failed: "
                "ret=%d key_number=%lu an=%u\n",
                ret,
                (unsigned long)sak.key_number,
                sak.an));

            goto cleanup;
        }
    }

    /*
     * Install and confirm TX only if it has not already been confirmed.
     */
    if (!sak.tx_installed)
    {
        ret = macsec_install_tx_sak(
            ctx,
            sak.sak,
            sak.sak_len,
            sak.an);

        if (ret != MACSEC_ERR_OK)
        {
            MACSEC_ERROR((
                "MACsec MKA TX SAK install failed: "
                "ret=%d key_number=%lu an=%u\n",
                ret,
                (unsigned long)sak.key_number,
                sak.an));

            goto cleanup;
        }

        ret = macsec_mka_notify_sak_installed(
            &ctx->mka,
            sak.key_number,
            sak.an,
            MACSEC_MKA_INSTALL_TX,
            sak.lowest_pn);

        if (ret != MACSEC_ERR_OK)
        {
            MACSEC_ERROR((
                "MACsec MKA TX SAK confirmation failed: "
                "ret=%d key_number=%lu an=%u\n",
                ret,
                (unsigned long)sak.key_number,
                sak.an));

            goto cleanup;
        }
    }

    MACSEC_MEDIUM((
        "MACsec MKA SAK installed: "
        "key_number=%lu an=%u sak_len=%lu\n",
        (unsigned long)sak.key_number,
        sak.an,
        (unsigned long)sak.sak_len));

    ret = MACSEC_ERR_OK;

cleanup:
    macsec_zeroize(&sak, sizeof(sak));

    return ret;
}

static int macsec_process_mka_events(macsec_ctx_t *ctx)
{
    macsec_mka_event_flags_t events;

    macsec_check(ctx != NULL, MACSEC_ERR_PARAM);

    events = macsec_mka_take_events(&ctx->mka);

    if (events == MACSEC_MKA_EVENT_NONE)
    {
        return MACSEC_ERR_OK;
    }

    MACSEC_INFO((
        "MACsec process MKA events: 0x%08lX\n",
        (unsigned long)events));

    if ((events & MACSEC_MKA_EVENT_ERROR) != 0u)
    {
        ctx->state = MACSEC_STATE_ERROR;

        MACSEC_ERROR((
            "MACsec state: ERROR after MKA error event\n"));

        return MACSEC_ERR_STATE;
    }

    if ((events & MACSEC_MKA_EVENT_PEER_LOST) != 0u)
    {
        /*
         * For the current one-SAK design, loss of the peer means the
         * connection is no longer considered operational.
         *
         * Retaining or removing an old RX/TX SAK can be refined when the
         * rekey and peer timeout policy is implemented.
         */
        ctx->state = MACSEC_STATE_WAIT_MKA;

        MACSEC_MEDIUM((
            "MACsec state: WAIT_MKA after peer loss\n"));
    }

    if ((events & MACSEC_MKA_EVENT_SAK_ACTIVE) != 0u)
    {
        ctx->state = MACSEC_STATE_SECURED;
        ctx->pending_tx_sak_valid = MACSEC_FALSE;

        MACSEC_MEDIUM((
            "MACsec state: SECURED after active MKA SAK\n"));
    }

    if ((events & MACSEC_MKA_EVENT_SAK_RETIRED) != 0u)
    {
        if (ctx->mka.state != MACSEC_MKA_STATE_OPERATIONAL)
        {
            ctx->state = MACSEC_STATE_WAIT_MKA;

            MACSEC_MEDIUM((
                "MACsec state: WAIT_MKA after SAK retirement\n"));
        }
    }

    return MACSEC_ERR_OK;
}

static int macsec_service_mka(macsec_ctx_t *ctx)
{
    int ret;

    macsec_check(ctx != NULL, MACSEC_ERR_PARAM);

    ret = macsec_process_mka_sak_install(ctx);
    if (ret != MACSEC_ERR_OK)
    {
        return ret;
    }

    ret = macsec_process_mka_events(ctx);
    if (ret != MACSEC_ERR_OK)
    {
        return ret;
    }

    return MACSEC_ERR_OK;
}

static int macsec_init_frame_crypto(macsec_ctx_t *ctx)
{
    macsec_frame_sci_t sci;
    int ret;

    macsec_assert(ctx != NULL);

    macsec_build_sci(&sci, &ctx->cfg.local_mac, ctx->cfg.port_id);

    ret = macsec_frame_crypto_init(&ctx->frame_crypto, &sci);
    if (ret != MACSEC_ERR_OK)
    {
        MACSEC_ERROR(("MACsec frame crypto init failed ret=%d\n", ret));
        return ret;
    }

    ctx->frame_crypto.replay_protect = ctx->cfg.replay_protect;
    ctx->frame_crypto.replay_window = ctx->cfg.replay_window;

    MACSEC_MEDIUM(("MACsec frame crypto init OK: replay=%u window=%lu\n",
                   ctx->frame_crypto.replay_protect ? 1u : 0u,
                   (unsigned long)ctx->frame_crypto.replay_window));

    return MACSEC_ERR_OK;
}

static int macsec_init_mka(macsec_ctx_t *ctx)
{
    uint8_t priority;
    int ret;

    macsec_assert(ctx != NULL);

    priority = ctx->cfg.key_server_priority;

    MACSEC_MEDIUM(("MACsec MKA init: priority=%u tx_interval=%lu\n",
                   priority,
                   (unsigned long)ctx->cfg.mka_tx_interval_ms));

    ret = macsec_mka_init(&ctx->mka,
                          ctx->cfg.cak,
                          ctx->cfg.cak_len,
                          ctx->cfg.ckn,
                          ctx->cfg.ckn_len,
                          ctx->cfg.local_mac.addr,
                          ctx->cfg.port_id,
                          priority,
                          ctx->cfg.mka_tx_interval_ms);

    if (ret != MACSEC_ERR_OK)
    {
        MACSEC_ERROR(("MACsec MKA init failed ret=%d\n", ret));
    }
    else
    {
        MACSEC_MEDIUM(("MACsec MKA init OK\n"));
    }

    return ret;
}

int macsec_init(macsec_ctx_t *ctx, const macsec_config_t *cfg)
{
    int ret;

    macsec_assert(ctx != NULL);
    macsec_assert(cfg != NULL);

    memset(ctx, 0, sizeof(macsec_ctx_t));

    ctx->cfg = *cfg;
    ctx->state = MACSEC_STATE_INIT;

    if (ctx->cfg.port_id == 0u)
    {
        ctx->cfg.port_id = 1u;
    }

    MACSEC_MEDIUM(("MACsec init: mode=%u port_id=%u\n",
                   ctx->cfg.mode,
                   ctx->cfg.port_id));

    MACSEC_MEDIUM_HEX(("MACsec local MAC", ctx->cfg.local_mac.addr, 6));

    ret = macsec_init_frame_crypto(ctx);
    if (ret != MACSEC_ERR_OK)
    {
        ctx->state = MACSEC_STATE_ERROR;
        return ret;
    }

    if (ctx->cfg.mode == MACSEC_MODE_DISABLED)
    {
        ctx->state = MACSEC_STATE_SECURED;
        MACSEC_MEDIUM(("MACsec disabled mode: pass-through enabled\n"));
        return MACSEC_ERR_OK;
    }

    if (ctx->cfg.mode == MACSEC_MODE_STATIC_SAK)
    {
        ret = macsec_install_static_sak(ctx);
        if (ret != MACSEC_ERR_OK)
        {
            ctx->state = MACSEC_STATE_ERROR;
            return ret;
        }

        return MACSEC_ERR_OK;
    }

    if (ctx->cfg.mode == MACSEC_MODE_MKA_PSK)
    {
        ret = macsec_init_mka(ctx);
        if (ret != MACSEC_ERR_OK)
        {
            ctx->state = MACSEC_STATE_ERROR;
            return ret;
        }

        ctx->state = MACSEC_STATE_WAIT_MKA;

        MACSEC_MEDIUM(("MACsec state: WAIT_MKA\n"));

        return MACSEC_ERR_OK;
    }

    ctx->state = MACSEC_STATE_ERROR;

    MACSEC_ERROR(("MACsec unsupported mode=%u\n", ctx->cfg.mode));

    return MACSEC_ERR_UNSUPPORTED;
}

void macsec_clear(macsec_ctx_t *ctx)
{
    if (ctx == NULL)
    {
        return;
    }

    MACSEC_MEDIUM(("MACsec clear\n"));

    macsec_frame_crypto_clear(&ctx->frame_crypto);
    macsec_mka_clear(&ctx->mka);

    macsec_zeroize(ctx, sizeof(*ctx));
}

macsec_state_t macsec_get_state(const macsec_ctx_t *ctx)
{
    if (ctx == NULL)
    {
        return MACSEC_STATE_ERROR;
    }

    return ctx->state;
}

macsec_bool_t macsec_is_secured(const macsec_ctx_t *ctx)
{
    macsec_assert(ctx != NULL);

    return ctx->state == MACSEC_STATE_SECURED;
}

int macsec_input(macsec_ctx_t *ctx,
                 const uint8_t *rx_frame,
                 size_t rx_len,
                 uint8_t *plain_frame,
                 size_t *plain_len,
                 size_t plain_max_len,
                 macsec_bool_t *pass_to_stack)
{
    int ret;

    macsec_assert(ctx != NULL);
    macsec_assert(rx_frame != NULL);
    macsec_assert(plain_frame != NULL);
    macsec_assert(plain_len != NULL);
    macsec_assert(pass_to_stack != NULL);

    *plain_len = 0u;
    *pass_to_stack = MACSEC_FALSE;

    MACSEC_INFO(("MACsec RX frame: len=%lu state=%u mode=%u ethertype=0x%04X\n",
                 (unsigned long)rx_len,
                 ctx->state,
                 ctx->cfg.mode,
                 (rx_len >= 14u) ? macsec_rd_be16(&rx_frame[12]) : 0u));

    if (ctx->cfg.mode == MACSEC_MODE_DISABLED)
    {
        macsec_check(rx_len <= plain_max_len, MACSEC_ERR_BUFFER);

        memcpy(plain_frame, rx_frame, rx_len);

        *plain_len = rx_len;
        *pass_to_stack = MACSEC_TRUE;

        MACSEC_INFO(("MACsec RX pass-through len=%lu\n",
                     (unsigned long)*plain_len));

        return MACSEC_ERR_OK;
    }

    if (macsec_mka_is_eapol_mka(rx_frame, rx_len))
    {
        MACSEC_INFO(("MACsec RX EAPOL/MKA len=%lu\n",
                     (unsigned long)rx_len));

        ret = macsec_mka_input(&ctx->mka,
                               rx_frame,
                               rx_len,
                               ctx->last_tick_ms);

        *pass_to_stack = MACSEC_FALSE;

        if (ret != MACSEC_ERR_OK)
        {
            ctx->state = MACSEC_STATE_ERROR;
            MACSEC_ERROR(("MACsec MKA input failed ret=%d\n", ret));
            return ret;
        }

        MACSEC_INFO(("MACsec MKA input OK: peer=%u live=%u local_ks=%u tx_pending=%u\n",
                     ctx->mka.peer.valid ? 1u : 0u,
                     ctx->mka.peer.live ? 1u : 0u,
                     ctx->mka.local_key_server ? 1u : 0u,
                     ctx->mka.tx_pending ? 1u : 0u));

        ret = macsec_service_mka(ctx);
        if (ret != MACSEC_ERR_OK)
        {
            ctx->state = MACSEC_STATE_ERROR;

            MACSEC_ERROR((
                "MACsec MKA service after input failed ret=%d\n",
                ret));

            return ret;
        }

        return MACSEC_ERR_OK;
    }

    if (macsec_frame_is_macsec(rx_frame, rx_len))
    {
        MACSEC_INFO(("MACsec RX protected frame len=%lu\n",
                     (unsigned long)rx_len));

        if (ctx->state != MACSEC_STATE_SECURED)
        {
            *pass_to_stack = MACSEC_FALSE;
            MACSEC_ERROR(("MACsec RX protected frame but state=%u not SECURED\n",
                          ctx->state));
            return MACSEC_ERR_NOT_READY;
        }

        ret = macsec_frame_decrypt(&ctx->frame_crypto,
                                   rx_frame,
                                   rx_len,
                                   plain_frame,
                                   plain_len,
                                   plain_max_len);

        if (ret != MACSEC_ERR_OK)
        {
            *pass_to_stack = MACSEC_FALSE;
            MACSEC_ERROR(("MACsec decrypt failed ret=%d\n", ret));
            return ret;
        }

        *pass_to_stack = MACSEC_TRUE;

        MACSEC_INFO(("MACsec decrypt OK plain_len=%lu\n",
                     (unsigned long)*plain_len));

        return MACSEC_ERR_OK;
    }

    *pass_to_stack = MACSEC_FALSE;

    MACSEC_INFO(("MACsec RX plain frame dropped in protected mode len=%lu\n",
                 (unsigned long)rx_len));

    if ((rx_len >= 14u) && macsec_rd_be16(&rx_frame[12]) == MACSEC_ETHERTYPE_EAPOL)
    {
        MACSEC_INFO(("MACsec RX non-MKA EAPOL frame dropped len=%lu\n", (unsigned long)rx_len));
        return MACSEC_ERR_UNSUPPORTED;
    }

    return MACSEC_ERR_AUTH;
}

int macsec_output(macsec_ctx_t *ctx,
                  const uint8_t *plain_frame,
                  size_t plain_len,
                  uint8_t *tx_frame,
                  size_t *tx_len,
                  size_t tx_max_len)
{
    int ret;

    macsec_assert(ctx != NULL);
    macsec_assert(plain_frame != NULL);
    macsec_assert(tx_frame != NULL);
    macsec_assert(tx_len != NULL);

    *tx_len = 0u;

    MACSEC_INFO(("MACsec TX frame: plain_len=%lu state=%u mode=%u\n",
                 (unsigned long)plain_len,
                 ctx->state,
                 ctx->cfg.mode));

    if (ctx->cfg.mode == MACSEC_MODE_DISABLED)
    {
        macsec_check(plain_len <= tx_max_len, MACSEC_ERR_BUFFER);

        memcpy(tx_frame, plain_frame, plain_len);

        *tx_len = plain_len;

        MACSEC_INFO(("MACsec TX pass-through len=%lu\n",
                     (unsigned long)*tx_len));

        return MACSEC_ERR_OK;
    }

    if (ctx->state != MACSEC_STATE_SECURED)
    {
        MACSEC_INFO(("MACsec TX rejected, state=%u not SECURED\n", ctx->state));
        return MACSEC_ERR_NOT_READY;
    }

    if (!ctx->frame_crypto.tx_sak.valid)
    {
        MACSEC_INFO(("MACsec TX deferred: TX SAK is not active yet\n"));
    
        return MACSEC_ERR_NOT_READY;
    }

    ret = macsec_frame_encrypt(&ctx->frame_crypto,
                               plain_frame,
                               plain_len,
                               tx_frame,
                               tx_len,
                               tx_max_len);

    if (ret != MACSEC_ERR_OK)
    {
        MACSEC_ERROR(("MACsec encrypt failed ret=%d\n", ret));
        return ret;
    }

    MACSEC_INFO(("MACsec encrypt OK tx_len=%lu\n",
                 (unsigned long)*tx_len));

    return MACSEC_ERR_OK;
}

int macsec_tick(macsec_ctx_t *ctx, uint32_t now_ms)
{
    int ret;

    macsec_assert(ctx != NULL);

    ctx->last_tick_ms = now_ms;

    MACSEC_INFO(("MACsec tick: now=%lu state=%u mode=%u\n",
                 (unsigned long)now_ms,
                 ctx->state,
                 ctx->cfg.mode));

    if (ctx->cfg.mode == MACSEC_MODE_MKA_PSK)
    {
        ret = macsec_mka_tick(&ctx->mka, now_ms);
        if (ret != MACSEC_ERR_OK)
        {
            ctx->state = MACSEC_STATE_ERROR;
            MACSEC_ERROR(("MACsec MKA tick failed ret=%d\n", ret));
            return ret;
        }

        ret = macsec_service_mka(ctx);
        if (ret != MACSEC_ERR_OK)
        {
            ctx->state = MACSEC_STATE_ERROR;

            MACSEC_ERROR((
                "MACsec MKA service after tick failed ret=%d\n",
                ret));

            return ret;
        }
    }

    return MACSEC_ERR_OK;
}

int macsec_get_control_frame(macsec_ctx_t *ctx,
                             uint8_t *tx_frame,
                             size_t *tx_len,
                             size_t tx_max_len)
{
    int ret;

    macsec_assert(ctx != NULL);
    macsec_assert(tx_frame != NULL);
    macsec_assert(tx_len != NULL);

    *tx_len = 0u;

    if (ctx->cfg.mode != MACSEC_MODE_MKA_PSK)
    {
        return MACSEC_ERR_NOT_READY;
    }

    ret = macsec_mka_get_tx_frame(&ctx->mka,
                                  tx_frame,
                                  tx_len,
                                  tx_max_len);

    if (ret == MACSEC_ERR_OK)
    {
        int service_ret;

        /*
         * The legacy macsec_mka_get_tx_frame() currently commits successful
         * construction as transmission. For a local Key Server this may move
         * a SAK from DISTRIBUTION_PENDING to DISTRIBUTED, making it available
         * for local installation.
         */
        service_ret = macsec_service_mka(ctx);

        if (service_ret != MACSEC_ERR_OK)
        {
            ctx->state = MACSEC_STATE_ERROR;

            MACSEC_ERROR((
                "MACsec MKA service after control TX build failed ret=%d\n",
                service_ret));

            return service_ret;
        }

        MACSEC_INFO((
            "MACsec TX control MKA frame len=%lu\n",
            (unsigned long)*tx_len));
    }
    else if (ret != MACSEC_ERR_NOT_READY)
    {
        MACSEC_ERROR((
            "MACsec get control frame failed ret=%d\n",
            ret));
    }

    return ret;
}
