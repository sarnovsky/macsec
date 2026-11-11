/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Michal Sarnovsky
 * Host-test adapter. Each shared object contains its own compiled role profile.
 * This file is not part of the embedded build.
 */
#include "macsec.h"
#include "port/port.h"
#include <stdlib.h>

#define HOST_API __attribute__((visibility("default")))

HOST_API macsec_ctx_t *role_create(unsigned id, unsigned priority, unsigned cak_len)
{
    macsec_config_t cfg;
    macsec_ctx_t *ctx;
    static uint32_t instance = 0u;
    unsigned i;

    memset(&cfg, 0, sizeof(cfg));
    cfg.mode = MACSEC_MODE_MKA_PSK;
    cfg.local_mac.addr[0] = 2u;
    cfg.local_mac.addr[5] = (uint8_t) id;
    cfg.port_id = 1u;
    cfg.cak_len = cak_len;
    cfg.ckn_len = 24u;
    cfg.key_server_priority = (uint8_t) priority;
    cfg.mka_tx_interval_ms = 2000u;
    cfg.replay_protect = MACSEC_TRUE;
    cfg.replay_window = 32u;
    if ((cak_len != 16u) && (cak_len != 32u))
    {
        return NULL;
    }
    for (i = 0; i < cak_len; ++i) { cfg.cak[i] = (uint8_t) (i * 11u + 3u); }
    for (i = 0; i < cfg.ckn_len; ++i) { cfg.ckn[i] = (uint8_t) (i + 16u); }
    /* Reproducible test RNG only; each restart gets a different MI. */
    macsec_randomInit(0x731eac29u ^ (id * 0x12345u) ^ (++instance * 0x7654321u));
    ctx = (macsec_ctx_t *) calloc(1u, sizeof(*ctx));
    if (ctx && macsec_init(ctx, &cfg) != MACSEC_ERR_OK)
    {
        free(ctx);
        ctx = NULL;
    }
    return ctx;
}

HOST_API void role_destroy(macsec_ctx_t *ctx)
{
    if (ctx) { macsec_clear(ctx); free(ctx); }
}

HOST_API int role_tick(macsec_ctx_t *ctx, uint32_t now)
{
    return macsec_tick(ctx, now);
}

HOST_API int role_control(macsec_ctx_t *ctx, uint8_t *out, size_t capacity, uint32_t now)
{
    size_t len = 0u;
    int ret = macsec_build_control_frame(ctx, out, &len, capacity);
    if (ret == MACSEC_ERR_OK) { ret = macsec_notify_control_tx_success(ctx, now); }
    return (ret == MACSEC_ERR_OK) ? (int) len : ret;
}

HOST_API int role_receive(macsec_ctx_t *ctx, const uint8_t *frame, size_t len,
                          uint8_t *out, size_t capacity)
{
    size_t out_len = 0u;
    macsec_bool_t pass = MACSEC_FALSE;
    int ret = macsec_input(ctx, frame, len, out, &out_len, capacity, &pass);
    if (ret != MACSEC_ERR_OK) { return ret; }
    if (!pass && out_len != 0u) { return MACSEC_ERR_STATE; }
    return (int) out_len;
}

HOST_API int role_output(macsec_ctx_t *ctx, const uint8_t *plain, size_t len,
                         uint8_t *out, size_t capacity)
{
    size_t out_len = 0u;
    int ret = macsec_output(ctx, plain, len, out, &out_len, capacity);
    return (ret == MACSEC_ERR_OK) ? (int) out_len : ret;
}

HOST_API uint32_t role_value(const macsec_ctx_t *ctx, unsigned field)
{
    switch (field)
    {
        case 0: return macsec_is_secured(ctx);
        case 1: return ctx->mka.local_key_server;
        case 2: return ctx->mka.latest_sak.key_number;
        case 3: return ctx->frame_crypto.tx_sak.an;
        case 4: return ctx->frame_crypto.tx_sak.next_pn;
        case 5: return ctx->mka.latest_sak.peer_rx_confirmed && ctx->mka.latest_sak.peer_tx_confirmed;
        case 6: return ctx->mka.old_sak.lifecycle_state;
        case 7: return ctx->state == MACSEC_STATE_ERROR;
        default: return UINT32_MAX;
    }
}

HOST_API void role_set_pn(macsec_ctx_t *ctx, uint32_t pn)
{
    /* Only jump forward, for a freshly installed test key. */
    if (pn > ctx->frame_crypto.tx_sak.next_pn) { ctx->frame_crypto.tx_sak.next_pn = pn; }
}

HOST_API int role_key(const macsec_ctx_t *ctx, uint8_t *out)
{
    memcpy(out, ctx->frame_crypto.tx_sak.key, ctx->frame_crypto.tx_sak.key_len);
    return ctx->frame_crypto.tx_sak.key_len;
}

HOST_API int role_rekey(macsec_ctx_t *ctx)
{
    return macsec_mka_request_rekey(&ctx->mka);
}
