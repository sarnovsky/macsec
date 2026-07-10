/*
 * mka.c
 *
 * Lightweight MACsec stack
 * MACsec Key Agreement protocol layer.
 * This file contains the MKA protocol logic used to build, parse and process
 * MKA-related protocol data structures required for MACsec key management.
 *
 * Copyright (c) 2026 Michal Sarnovský
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */

#include "mka.h"

static const uint8_t macsec_mka_dst_mac[6] =
{
    0x01u, 0x80u, 0xC2u, 0x00u, 0x00u, 0x03u
};

#define MACSEC_MKA_VERSION_ID              1u
#define MACSEC_MKA_ALGORITHM_AGILITY       0x0080C201u
#define MACSEC_MKA_DEFAULT_TX_INTERVAL_MS  2000u
#define MACSEC_MKA_DEFAULT_CAPABILITY      2u

#define MACSEC_MKA_PARAM_LIVE_PEER_LIST       1u
#define MACSEC_MKA_PARAM_POTENTIAL_PEER_LIST  2u
#define MACSEC_MKA_PARAM_SAK_USE          3u
#define MACSEC_MKA_PARAM_DISTRIBUTED_SAK  4u


static void macsec_mka_build_sci(uint8_t sci[MACSEC_MKA_SCI_LEN],
                                 const uint8_t mac[6],
                                 uint16_t port_id)
{
    memcpy(&sci[0], mac, 6u);
    macsec_wr_be16(&sci[6], port_id);
}

static macsec_bool_t macsec_mka_local_wins_key_server(const macsec_mka_ctx_t *ctx)
{
    if (!ctx->peer.valid)
    {
        return MACSEC_TRUE;
    }

    if (ctx->key_server_priority < ctx->peer.key_server_priority)
    {
        return MACSEC_TRUE;
    }

    if (ctx->key_server_priority > ctx->peer.key_server_priority)
    {
        return MACSEC_FALSE;
    }

    /*
     * Tie-breaker for early implementation.
     * Lower SCI wins.
     */
    return memcmp(ctx->local_sci, ctx->peer.sci, MACSEC_MKA_SCI_LEN) < 0;
}

macsec_bool_t macsec_mka_is_eapol_mka(const uint8_t *frame,
                             size_t frame_len)
{
    if ((frame == NULL) || (frame_len < 18u))
    {
        return MACSEC_FALSE;
    }

    if (macsec_rd_be16(&frame[12]) != MACSEC_MKA_ETHERTYPE_EAPOL)
    {
        return MACSEC_FALSE;
    }

    if (frame[15] != MACSEC_MKA_EAPOL_TYPE_MKA)
    {
        return MACSEC_FALSE;
    }

    return MACSEC_TRUE;
}

int macsec_mka_parse_basic(const uint8_t *frame,
                           size_t frame_len,
                           macsec_mka_basic_t *out)
{
    const uint8_t *p;
    uint16_t eth_type;
    uint16_t eapol_len;
    uint16_t body_len;
    size_t expected_len;
    size_t cak_name_len;
    size_t basic_end_offset;
    size_t icv_offset;

    macsec_assert(frame != NULL);
    macsec_assert(out != NULL);
    macsec_check(frame_len >= (14u + 4u + 4u + 28u + 16u), MACSEC_ERR_BUFFER);

    memset(out, 0, sizeof(*out));

    memcpy(out->dst_mac, &frame[0], 6u);
    memcpy(out->src_mac, &frame[6], 6u);

    eth_type = macsec_rd_be16(&frame[12]);
    macsec_check(eth_type == MACSEC_MKA_ETHERTYPE_EAPOL, MACSEC_ERR_PARAM);

    p = &frame[14];

    out->eapol_version = p[0];
    out->eapol_type = p[1];
    out->eapol_len = macsec_rd_be16(&p[2]);

    macsec_check(out->eapol_type == MACSEC_MKA_EAPOL_TYPE_MKA,
                 MACSEC_ERR_UNSUPPORTED);

    eapol_len = out->eapol_len;
    expected_len = 14u + 4u + eapol_len;

    macsec_check(frame_len >= expected_len, MACSEC_ERR_BUFFER);
    macsec_check(eapol_len >= (4u + 28u + MACSEC_MKA_ICV_LEN),
                 MACSEC_ERR_BUFFER);

    /*
     * Basic Parameter Set starts immediately after EAPOL header.
     */
    p = &frame[18];

    out->mka_version = p[0];
    out->key_server_priority = p[1];

    out->key_server = (p[2] & 0x80u) ? 1 : 0;
    out->macsec_desired = (p[2] & 0x40u) ? 1 : 0;
    out->macsec_capability = (uint8_t)((p[2] >> 4u) & 0x03u);

    body_len = (uint16_t)(((uint16_t)(p[2] & 0x0Fu) << 8u) | p[3]);
    out->body_len = body_len;

    macsec_check(body_len >= 28u, MACSEC_ERR_BUFFER);

    /*
     * Basic parameter set total = 4 B header + body_len.
     * ICV follows at the end of the MKPDU.
     */
    basic_end_offset = 18u + 4u + body_len;
    icv_offset = 14u + 4u + eapol_len - MACSEC_MKA_ICV_LEN;

    macsec_check(basic_end_offset <= icv_offset, MACSEC_ERR_BUFFER);
    macsec_check((icv_offset + MACSEC_MKA_ICV_LEN) <= frame_len, MACSEC_ERR_BUFFER);

    p += 4u;

    memcpy(out->sci, p, MACSEC_MKA_SCI_LEN);
    p += MACSEC_MKA_SCI_LEN;

    memcpy(out->actor_mi, p, MACSEC_MKA_MI_LEN);
    p += MACSEC_MKA_MI_LEN;

    out->actor_mn = macsec_rd_be32(p);
    p += 4u;

    out->algorithm_agility = macsec_rd_be32(p);
    p += 4u;

    cak_name_len = body_len - 28u;
    macsec_check(cak_name_len <= MACSEC_MKA_CA_NAME_MAX_LEN, MACSEC_ERR_BUFFER);

    memcpy(out->cak_name, p, cak_name_len);
    out->cak_name_len = cak_name_len;

    memcpy(out->icv, &frame[icv_offset], MACSEC_MKA_ICV_LEN);

    MACSEC_INFO(("MKA Basic parsed: eapol_len=%u body_len=%u mn=%lu priority=%u key_server=%u desired=%u cap=%u cak_name_len=%lu\n",
                 out->eapol_len,
                 out->body_len,
                 (unsigned long)out->actor_mn,
                 out->key_server_priority,
                 out->key_server ? 1u : 0u,
                 out->macsec_desired ? 1u : 0u,
                 out->macsec_capability,
                 (unsigned long)out->cak_name_len));

    MACSEC_INFO_HEX(("MKA Basic src MAC", out->src_mac, 6));
    MACSEC_INFO_HEX(("MKA Basic SCI", out->sci, MACSEC_MKA_SCI_LEN));
    MACSEC_INFO_HEX(("MKA Basic actor MI", out->actor_mi, MACSEC_MKA_MI_LEN));
    MACSEC_INFO_HEX(("MKA Basic ICV", out->icv, MACSEC_MKA_ICV_LEN));

    return MACSEC_ERR_OK;
}

int macsec_mka_init(macsec_mka_ctx_t *ctx,
                    const uint8_t *cak,
                    size_t cak_len,
                    const uint8_t *ckn,
                    size_t ckn_len,
                    const uint8_t local_mac[6],
                    uint16_t port_id,
                    uint8_t key_server_priority,
                    uint32_t tx_interval_ms)
{
    int ret;

    macsec_assert(ctx != NULL);
    macsec_assert(local_mac != NULL);

    memset(ctx, 0, sizeof(macsec_mka_ctx_t));

    memcpy(ctx->local_mac, local_mac, 6u);
    macsec_mka_build_sci(ctx->local_sci, local_mac, port_id);

    macsec_random(ctx->local_mi, MACSEC_MKA_MI_LEN);

    ctx->local_mn = 1u;
    ctx->key_server_priority = key_server_priority;
    ctx->local_key_server = MACSEC_TRUE;
    ctx->macsec_desired = MACSEC_TRUE;
    ctx->macsec_capability = MACSEC_MKA_DEFAULT_CAPABILITY;
    ctx->key_server_next_key_number = 1u;
    ctx->key_server_next_an = 0u;

    if (tx_interval_ms == 0u)
    {
        ctx->tx_interval_ms = MACSEC_MKA_DEFAULT_TX_INTERVAL_MS;
    }
    else
    {
        ctx->tx_interval_ms = tx_interval_ms;
    }

    ctx->tx_pending = MACSEC_TRUE;

    MACSEC_MEDIUM(("MKA init: priority=%u tx_interval=%lu ms port=%u\n",
                   ctx->key_server_priority,
                   (unsigned long)ctx->tx_interval_ms,
                   (unsigned)port_id));

    MACSEC_MEDIUM_HEX(("MKA local MAC", ctx->local_mac, 6));
    MACSEC_MEDIUM_HEX(("MKA local SCI", ctx->local_sci, MACSEC_MKA_SCI_LEN));
    MACSEC_MEDIUM_HEX(("MKA local MI", ctx->local_mi, MACSEC_MKA_MI_LEN));

    ret = macsec_mka_crypto_init(&ctx->crypto);
    if (ret != MACSEC_ERR_OK)
    {
        MACSEC_ERROR(("MKA crypto init failed ret=%d\n", ret));
        ctx->state = MACSEC_MKA_STATE_ERROR;
        return ret;
    }

    ret = macsec_mka_crypto_set_psk(&ctx->crypto,
                                    cak,
                                    cak_len,
                                    ckn,
                                    ckn_len);
    if (ret != MACSEC_ERR_OK)
    {
        MACSEC_ERROR(("MKA set PSK failed ret=%d cak_len=%lu ckn_len=%lu\n",
                      ret,
                      (unsigned long)cak_len,
                      (unsigned long)ckn_len));
        ctx->state = MACSEC_MKA_STATE_ERROR;
        return ret;
    }

    ret = macsec_mka_crypto_derive_ick_kek(&ctx->crypto);
    if (ret != MACSEC_ERR_OK)
    {
        MACSEC_ERROR(("MKA derive ICK/KEK failed ret=%d\n", ret));
        ctx->state = MACSEC_MKA_STATE_ERROR;
        return ret;
    }

    MACSEC_MEDIUM_HEX(("MKA derived ICK", ctx->crypto.keys.ick, 16));
    MACSEC_MEDIUM_HEX(("MKA derived KEK", ctx->crypto.keys.kek, 16));

    ctx->verify_icv = MACSEC_TRUE;
    ctx->last_icv_valid = MACSEC_FALSE;
    ctx->state = MACSEC_MKA_STATE_WAIT_PEER;

    MACSEC_MEDIUM(("MKA init done: state=%u tx_pending=%u\n",
                   ctx->state,
                   ctx->tx_pending ? 1u : 0u));

    return MACSEC_ERR_OK;
}

void macsec_mka_clear(macsec_mka_ctx_t *ctx)
{
    if (ctx == NULL)
    {
        return;
    }

    MACSEC_MEDIUM(("MKA clear\n"));

    macsec_mka_crypto_clear(&ctx->crypto);
    macsec_zeroize(ctx, sizeof(*ctx));
}

macsec_mka_state_t macsec_mka_get_state(const macsec_mka_ctx_t *ctx)
{
    if (ctx == NULL)
    {
        return MACSEC_MKA_STATE_ERROR;
    }

    return ctx->state;
}

static macsec_bool_t macsec_mka_frame_contains_peer_entry(const uint8_t *frame,
                                                 size_t frame_len,
                                                 const uint8_t mi[MACSEC_MKA_MI_LEN],
                                                 uint32_t *mn_out)
{
    uint16_t eapol_len;
    size_t pos;
    size_t end;

    if ((frame == NULL) || (mi == NULL) || (frame_len < 90u))
    {
        MACSEC_INFO(("MKA peer-list scan skipped: frame_len=%lu\n",
                     (unsigned long)frame_len));
        return MACSEC_FALSE;
    }

    eapol_len = macsec_rd_be16(&frame[16]);
    end = 14u + 4u + eapol_len - MACSEC_MKA_ICV_LEN;

    if (end > frame_len)
    {
        MACSEC_ERROR(("MKA peer-list scan invalid end=%lu frame_len=%lu\n",
                      (unsigned long)end,
                      (unsigned long)frame_len));
        return MACSEC_FALSE;
    }

    pos = 18u;

    while ((pos + 4u) <= end)
    {
        uint8_t type;
        uint16_t body_len;
        size_t body_pos;
        size_t body_end;

        if (pos == 18u)
        {
            body_len = (uint16_t)(((uint16_t)(frame[pos + 2u] & 0x0Fu) << 8u) |
                                  frame[pos + 3u]);

            MACSEC_INFO(("MKA parameter set: Basic body_len=%u pos=%lu\n",
                         body_len,
                         (unsigned long)pos));

            pos += 4u + body_len;
            continue;
        }

        type = frame[pos];
        body_len = (uint16_t)(((uint16_t)(frame[pos + 2u] & 0x0Fu) << 8u) |
                              frame[pos + 3u]);

        body_pos = pos + 4u;
        body_end = body_pos + body_len;

        MACSEC_INFO(("MKA parameter set: type=%u body_len=%u pos=%lu body_end=%lu\n",
                     type,
                     body_len,
                     (unsigned long)pos,
                     (unsigned long)body_end));

        if (body_end > end)
        {
            MACSEC_ERROR(("MKA parameter set overflow: type=%u body_end=%lu end=%lu\n",
                          type,
                          (unsigned long)body_end,
                          (unsigned long)end));
            return MACSEC_FALSE;
        }

        if ((type == MACSEC_MKA_PARAM_LIVE_PEER_LIST) ||
            (type == MACSEC_MKA_PARAM_POTENTIAL_PEER_LIST))
        {
            while ((body_pos + 16u) <= body_end)
            {
                MACSEC_INFO_HEX(("MKA peer-list entry MI",
                                 &frame[body_pos],
                                 MACSEC_MKA_MI_LEN));

                if (memcmp(&frame[body_pos], mi, MACSEC_MKA_MI_LEN) == 0)
                {
                    uint32_t listed_mn;

                    listed_mn = macsec_rd_be32(&frame[body_pos + MACSEC_MKA_MI_LEN]);

                    if (mn_out != NULL)
                    {
                        *mn_out = listed_mn;
                    }

                    MACSEC_MEDIUM(("MKA local MI found in peer list: type=%u listed_mn=%lu\n",
                                   type,
                                   (unsigned long)listed_mn));

                    return MACSEC_TRUE;
                }

                body_pos += 16u;
            }
        }

        pos = body_end;
    }

    MACSEC_INFO(("MKA local MI not found in peer lists\n"));

    return MACSEC_FALSE;
}

static int macsec_mka_parse_distributed_sak(macsec_mka_ctx_t *ctx,
                                            const uint8_t *frame,
                                            size_t frame_len)
{
    uint16_t eapol_len;
    size_t pos;
    size_t end;
    uint32_t key_number;

    macsec_assert(ctx != NULL);
    macsec_assert(frame != NULL);

    if (frame_len < 90u)
    {
        return MACSEC_ERR_NOT_READY;
    }

    eapol_len = macsec_rd_be16(&frame[16]);
    end = 14u + 4u + eapol_len - MACSEC_MKA_ICV_LEN;

    if (end > frame_len)
    {
        return MACSEC_ERR_BUFFER;
    }

    pos = 18u;

    while ((pos + 4u) <= end)
    {
        uint8_t type;
        uint16_t body_len;
        size_t body_pos;
        size_t body_end;

        if (pos == 18u)
        {
            body_len = (uint16_t)(((uint16_t)(frame[pos + 2u] & 0x0Fu) << 8u) |
                                  frame[pos + 3u]);
            pos += 4u + body_len;
            continue;
        }

        type = frame[pos];
        body_len = (uint16_t)(((uint16_t)(frame[pos + 2u] & 0x0Fu) << 8u) |
                              frame[pos + 3u]);

        body_pos = pos + 4u;
        body_end = body_pos + body_len;

        if (body_end > end)
        {
            return MACSEC_ERR_BUFFER;
        }

        if (type == MACSEC_MKA_PARAM_DISTRIBUTED_SAK)
        {
            uint8_t an;
            const uint8_t *wrapped_sak;
            size_t wrapped_sak_len;
            size_t sak_len;
            int ret;

            /*
             * Linux log:
             * Distributed SAK Body Length = 28
             * AES Key Wrap of SAK = 24 B
             *
             * Minimal supported layout here:
             *   byte 0      : flags / AN / confidentiality offset
             *   bytes 4..27 : wrapped SAK
             *
             * For this debug implementation we only need AN + wrapped SAK.
             */
            if (body_len < 28u)
            {
                return MACSEC_ERR_BUFFER;
            }

            MACSEC_ERROR_HEX(("MKA Distributed SAK body first 4",
                              &frame[body_pos],
                              4));

            MACSEC_ERROR(("MKA Distributed SAK header: b0=0x%02X b1=0x%02X b2=0x%02X b3=0x%02X an_old=%u\n",
                          frame[body_pos + 0u],
                          frame[body_pos + 1u],
                          frame[body_pos + 2u],
                          frame[body_pos + 3u],
                          (unsigned)((frame[body_pos] >> 6u) & 0x03u)));

            key_number = macsec_rd_be32(&frame[body_pos]);

            if (key_number == 0u)
            {
            	an = 0u;
            }
            else
            {
                an = (uint8_t)((key_number - 1u) & 0x03u);
            }

            wrapped_sak = &frame[body_pos + 4u];
            wrapped_sak_len = body_len - 4u;

            if (wrapped_sak_len > 40u)
            {
                return MACSEC_ERR_BUFFER;
            }

            memset(&ctx->latest_sak, 0, sizeof(ctx->latest_sak));

            sak_len = 0u;

            ret = macsec_mka_crypto_unwrap_sak(&ctx->crypto,
                                               wrapped_sak,
                                               wrapped_sak_len,
                                               ctx->latest_sak.sak,
                                               &sak_len,
                                               sizeof(ctx->latest_sak.sak));

            if (ret != MACSEC_ERR_OK)
            {
                MACSEC_ERROR(("MKA Distributed SAK unwrap failed ret=%d body_len=%u wrapped_len=%lu\n",
                              ret,
                              body_len,
                              (unsigned long)wrapped_sak_len));
                MACSEC_ERROR_HEX(("MKA wrapped SAK", wrapped_sak, (int)wrapped_sak_len));
                return ret;
            }

            ctx->latest_sak.sak_len = sak_len;
            ctx->latest_sak.an = an;
            ctx->latest_sak.key_number = key_number;
            ctx->latest_sak.valid = MACSEC_TRUE;
            ctx->latest_key_rx = MACSEC_TRUE;

            MACSEC_MEDIUM(("MKA Distributed SAK installed candidate: an=%u sak_len=%lu\n",
                           ctx->latest_sak.an,
                           (unsigned long)ctx->latest_sak.sak_len));
            MACSEC_MEDIUM_HEX(("MKA unwrapped SAK",
                               ctx->latest_sak.sak,
                               (int)ctx->latest_sak.sak_len));

            return MACSEC_ERR_OK;
        }

        pos = body_end;
    }

    return MACSEC_ERR_NOT_READY;
}

int macsec_mka_input(macsec_mka_ctx_t *ctx,
                     const uint8_t *frame,
                     size_t frame_len,
                     uint32_t now_ms)
{
    int ret;
    macsec_mka_basic_t basic;
    macsec_bool_t peer_changed;
    macsec_bool_t local_seen_by_peer;
    macsec_bool_t local_key_server_before;
    uint32_t listed_mn;

    macsec_assert(ctx != NULL);
    macsec_assert(frame != NULL);

    MACSEC_INFO(("MKA RX frame len=%lu now=%lu\n",
                 (unsigned long)frame_len,
                 (unsigned long)now_ms));

    if (!macsec_mka_is_eapol_mka(frame, frame_len))
    {
        MACSEC_ERROR(("MKA RX unsupported/non-MKA frame len=%lu\n",
                      (unsigned long)frame_len));
        return MACSEC_ERR_PARAM;
    }

    ret = macsec_mka_parse_basic(frame, frame_len, &basic);
    if (ret != MACSEC_ERR_OK)
    {
        MACSEC_ERROR(("MKA RX parse Basic failed ret=%d\n", ret));
        ctx->state = MACSEC_MKA_STATE_ERROR;
        return ret;
    }

    if ((memcmp(basic.src_mac, ctx->local_mac, 6u) == 0) ||
        (memcmp(basic.sci, ctx->local_sci, MACSEC_MKA_SCI_LEN) == 0) ||
        (memcmp(basic.actor_mi, ctx->local_mi, MACSEC_MKA_MI_LEN) == 0))
    {
        MACSEC_INFO(("MKA RX ignored own frame\n"));
        return MACSEC_ERR_OK;
    }

    ctx->last_basic = basic;
    ctx->last_rx_ms = now_ms;
    ctx->last_icv_valid = MACSEC_FALSE;

    if (ctx->verify_icv)
    {
        ret = macsec_mka_verify_icv(ctx, frame, frame_len, &basic);
        if (ret != MACSEC_ERR_OK)
        {
            MACSEC_ERROR(("MKA RX ICV failed ret=%d\n", ret));
            MACSEC_ERROR_HEX(("MKA RX expected ICV", basic.icv, MACSEC_MKA_ICV_LEN));

            ctx->state = MACSEC_MKA_STATE_ERROR;
            return ret;
        }

        ctx->last_icv_valid = MACSEC_TRUE;


        MACSEC_INFO(("MKA RX ICV OK\n"));
    }

    /*
     * Parse optional parameter sets after Basic Parameter Set.
     * In particular, this looks for Distributed SAK.
     *
     * Important:
     * - with verify_icv enabled, this runs only after ICV passed
     * - with verify_icv disabled, this still works for debug
     */
    ret = macsec_mka_parse_distributed_sak(ctx, frame, frame_len);
    if ((ret != MACSEC_ERR_OK) && (ret != MACSEC_ERR_NOT_READY))
    {
        MACSEC_ERROR(("MKA RX Distributed SAK parse failed ret=%d\n", ret));
        ctx->state = MACSEC_MKA_STATE_ERROR;
        return ret;
    }

    listed_mn = 0u;
    local_seen_by_peer = macsec_mka_frame_contains_peer_entry(frame,
                                                              frame_len,
                                                              ctx->local_mi,
                                                              &listed_mn);

    peer_changed = (!ctx->peer.valid) ||
                   (memcmp(ctx->peer.mi, basic.actor_mi, MACSEC_MKA_MI_LEN) != 0) ||
                   (basic.actor_mn != ctx->peer.mn);

    local_key_server_before = ctx->local_key_server;

    MACSEC_MEDIUM(("MKA peer update: peer_changed=%u local_seen_by_peer=%u peer_mn=%lu local_key_server_before=%u\n",
                   peer_changed ? 1u : 0u,
                   local_seen_by_peer ? 1u : 0u,
                   (unsigned long)basic.actor_mn,
                   local_key_server_before ? 1u : 0u));

    memcpy(ctx->peer.mac, basic.src_mac, 6u);
    memcpy(ctx->peer.sci, basic.sci, MACSEC_MKA_SCI_LEN);
    memcpy(ctx->peer.mi, basic.actor_mi, MACSEC_MKA_MI_LEN);

    ctx->peer.mn = basic.actor_mn;
    ctx->peer.key_server_priority = basic.key_server_priority;
    ctx->peer.key_server = basic.key_server;
    ctx->peer.macsec_desired = basic.macsec_desired;
    ctx->peer.macsec_capability = basic.macsec_capability;
    ctx->peer.last_seen_ms = now_ms;
    ctx->peer.valid = MACSEC_TRUE;

    if (local_seen_by_peer)
    {
        ctx->peer.seen_in_peer_list = MACSEC_TRUE;
        ctx->peer.live = MACSEC_TRUE;
        ctx->state = MACSEC_MKA_STATE_AUTHENTICATED;
        ctx->tx_pending = MACSEC_TRUE;

        MACSEC_MEDIUM(("MKA peer is LIVE: peer_mn=%lu listed_mn=%lu\n",
                       (unsigned long)ctx->peer.mn,
                       (unsigned long)listed_mn));
    }
    else
    {
        ctx->state = MACSEC_MKA_STATE_PEER_FOUND;
    }

    ctx->local_key_server = macsec_mka_local_wins_key_server(ctx);

    MACSEC_MEDIUM(("MKA key server election: local_priority=%u peer_priority=%u local_key_server=%u\n",
                   ctx->key_server_priority,
                   ctx->peer.key_server_priority,
                   ctx->local_key_server ? 1u : 0u));

    if (peer_changed)
    {
        ctx->tx_pending = MACSEC_TRUE;
    }

    MACSEC_INFO(("MKA RX done: state=%u peer_valid=%u peer_live=%u tx_pending=%u\n",
                 ctx->state,
                 ctx->peer.valid ? 1u : 0u,
                 ctx->peer.live ? 1u : 0u,
                 ctx->tx_pending ? 1u : 0u));

    return MACSEC_ERR_OK;
}

int macsec_mka_tick(macsec_mka_ctx_t *ctx, uint32_t now_ms)
{
    macsec_assert(ctx != NULL);

    ctx->last_tick_ms = now_ms;

    MACSEC_INFO(("MKA tick: now=%lu last_tx=%lu interval=%lu pending=%u\n",
                 (unsigned long)now_ms,
                 (unsigned long)ctx->last_tx_ms,
                 (unsigned long)ctx->tx_interval_ms,
                 ctx->tx_pending ? 1u : 0u));

    if (ctx->tx_pending)
    {
        return MACSEC_ERR_OK;
    }

    if (ctx->last_tx_ms == 0u)
    {
        ctx->tx_pending = MACSEC_TRUE;

        MACSEC_INFO(("MKA tick: first TX scheduled\n"));

        return MACSEC_ERR_OK;
    }

    if ((uint32_t)(now_ms - ctx->last_tx_ms) >= ctx->tx_interval_ms)
    {
        ctx->tx_pending = MACSEC_TRUE;

        MACSEC_INFO(("MKA tick: periodic TX scheduled\n"));
    }

    return MACSEC_ERR_OK;
}

static void macsec_mka_write_peer_list(uint8_t **p,
                                       uint8_t type,
                                       const macsec_mka_peer_t *peer)
{
    uint16_t body_len = 16u;

    MACSEC_INFO(("MKA TX peer list: type=%u peer_mn=%lu live=%u\n",
                 type,
                 (unsigned long)peer->mn,
                 peer->live ? 1u : 0u));

    MACSEC_INFO_HEX(("MKA TX peer MI", peer->mi, MACSEC_MKA_MI_LEN));

    (*p)[0] = type;
    (*p)[1] = 0u;
    (*p)[2] = (uint8_t)((body_len >> 8u) & 0x0Fu);
    (*p)[3] = (uint8_t)(body_len & 0xFFu);
    *p += 4u;

    memcpy(*p, peer->mi, MACSEC_MKA_MI_LEN);
    *p += MACSEC_MKA_MI_LEN;

    macsec_wr_be32(*p, peer->mn);
    *p += 4u;
}

static void macsec_mka_write_sak_use(uint8_t **p,
                                     const macsec_mka_ctx_t *ctx)
{
    uint16_t body_len = 40u;
    uint8_t flags = 0u;
    const uint8_t *key_server_mi;

    flags |= (uint8_t)((ctx->latest_sak.an & 0x03u) << 6u);

    if (ctx->latest_key_tx)
    {
        flags |= 0x20u;
    }

    if (ctx->latest_key_rx)
    {
        flags |= 0x10u;
    }

    (*p)[0] = MACSEC_MKA_PARAM_SAK_USE;
    (*p)[1] = flags;
    (*p)[2] = (uint8_t)((body_len >> 8u) & 0x0Fu);
    (*p)[3] = (uint8_t)(body_len & 0xFFu);
    *p += 4u;

    /*
     * Key Server MI:
     * - if we are Key Server, use our local MI
     * - if peer is Key Server, use peer MI
     */
    if (ctx->local_key_server)
    {
        key_server_mi = ctx->local_mi;
    }
    else
    {
        key_server_mi = ctx->peer.mi;
    }

    memcpy(*p, key_server_mi, MACSEC_MKA_MI_LEN);
    *p += MACSEC_MKA_MI_LEN;

    macsec_wr_be32(*p, ctx->latest_sak.key_number);
    *p += 4u;

    macsec_wr_be32(*p, ctx->latest_lowest_pn ? ctx->latest_lowest_pn : 1u);
    *p += 4u;

    memset(*p, 0, MACSEC_MKA_MI_LEN);
    *p += MACSEC_MKA_MI_LEN;

    macsec_wr_be32(*p, 0u);
    *p += 4u;

    macsec_wr_be32(*p, 1u);
    *p += 4u;
}

static int macsec_mka_key_server_ensure_sak(macsec_mka_ctx_t *ctx)
{
    macsec_check(ctx != NULL, MACSEC_ERR_PARAM);

    if (ctx->latest_sak.valid)
    {
        return MACSEC_ERR_OK;
    }

    memset(&ctx->latest_sak, 0, sizeof(ctx->latest_sak));

    macsec_random(ctx->latest_sak.sak, 16u);

    ctx->latest_sak.sak_len = 16u;
    ctx->latest_sak.an = ctx->key_server_next_an & 0x03u;
    ctx->latest_sak.key_number = ctx->key_server_next_key_number;
    ctx->latest_sak.valid = MACSEC_TRUE;

    ctx->latest_key_rx = MACSEC_TRUE;
    ctx->latest_key_tx = MACSEC_FALSE;
    ctx->latest_lowest_pn = 1u;

    MACSEC_MEDIUM(("MKA Key Server generated SAK: an=%u key_number=%lu\n",
                   ctx->latest_sak.an,
                   (unsigned long)ctx->latest_sak.key_number));

    MACSEC_MEDIUM_HEX(("MKA generated SAK",
                       ctx->latest_sak.sak,
                       (int)ctx->latest_sak.sak_len));

    return MACSEC_ERR_OK;
}

static int macsec_mka_write_distributed_sak(uint8_t **p,
                                            macsec_mka_ctx_t *ctx)
{
    uint8_t wrapped_sak[40];
    size_t wrapped_sak_len;
    uint16_t body_len;
    int ret;

    macsec_check(p != NULL, MACSEC_ERR_PARAM);
    macsec_check(*p != NULL, MACSEC_ERR_PARAM);
    macsec_check(ctx != NULL, MACSEC_ERR_PARAM);
    macsec_check(ctx->latest_sak.valid, MACSEC_ERR_STATE);

    wrapped_sak_len = 0u;

    ret = macsec_mka_crypto_wrap_sak(&ctx->crypto,
                                     ctx->latest_sak.sak,
                                     ctx->latest_sak.sak_len,
                                     wrapped_sak,
                                     &wrapped_sak_len,
                                     sizeof(wrapped_sak));
    if (ret != MACSEC_ERR_OK)
    {
        MACSEC_ERROR(("MKA wrap SAK failed ret=%d\n", ret));
        return ret;
    }

    body_len = (uint16_t)(4u + wrapped_sak_len);

    (*p)[0] = MACSEC_MKA_PARAM_DISTRIBUTED_SAK;
    (*p)[1] = 0u;
    (*p)[2] = (uint8_t)((body_len >> 8u) & 0x0Fu);
    (*p)[3] = (uint8_t)(body_len & 0xFFu);
    *p += 4u;

    macsec_wr_be32(*p, ctx->latest_sak.key_number);
    *p += 4u;

    memcpy(*p, wrapped_sak, wrapped_sak_len);
    *p += wrapped_sak_len;

    MACSEC_MEDIUM(("MKA TX Distributed SAK: an=%u key_number=%lu wrapped_len=%lu\n",
                   ctx->latest_sak.an,
                   (unsigned long)ctx->latest_sak.key_number,
                   (unsigned long)wrapped_sak_len));

    macsec_zeroize(wrapped_sak, sizeof(wrapped_sak));

    return MACSEC_ERR_OK;
}

int macsec_mka_get_tx_frame(macsec_mka_ctx_t *ctx,
                            uint8_t *frame,
                            size_t *frame_len,
                            size_t frame_max_len)
{
    uint8_t *p;
    uint16_t body_len;
    uint16_t peer_list_param_len;
    uint16_t sak_use_param_len;
    uint16_t eapol_len;
    size_t total_len;
    size_t mic_len;
    uint8_t flags_len_hi;
    uint32_t tx_mn;
    uint16_t distributed_sak_param_len;
    macsec_bool_t include_distributed_sak;
    int ret;

    macsec_assert(ctx != NULL);
    macsec_assert(frame != NULL);
    macsec_assert(frame_len != NULL);
    macsec_check(ctx->crypto.keys.valid, MACSEC_ERR_STATE);

    *frame_len = 0u;

    if (!ctx->tx_pending)
    {
        return MACSEC_ERR_NOT_READY;
    }

    macsec_check(ctx->crypto.psk.ckn_len <= MACSEC_MKA_CA_NAME_MAX_LEN,
                 MACSEC_ERR_BUFFER);

    body_len = (uint16_t)(28u + ctx->crypto.psk.ckn_len);

    peer_list_param_len = 0u;
    if (ctx->peer.valid)
    {
        peer_list_param_len = 4u + 16u;
    }

    include_distributed_sak = MACSEC_FALSE;
    distributed_sak_param_len = 0u;

    if (ctx->local_key_server && ctx->peer.live)
    {
        ret = macsec_mka_key_server_ensure_sak(ctx);
        if (ret != MACSEC_ERR_OK)
        {
            return ret;
        }

        include_distributed_sak = MACSEC_TRUE;

        /*
         * 4 B parameter header
         * 4 B key number
         * 24 B AES-KW wrapped 128-bit SAK
         */
        distributed_sak_param_len = 4u + 4u + 24u;
    }

    sak_use_param_len = 0u;
    if (ctx->latest_sak.valid && ctx->peer.live)
    {
        sak_use_param_len = 4u + 40u;
    }

    eapol_len = (uint16_t)(4u +
                           body_len +
                           peer_list_param_len +
                           distributed_sak_param_len +
                           sak_use_param_len +
                           MACSEC_MKA_ICV_LEN);

    total_len = 14u + 4u + eapol_len;

    macsec_check(total_len <= frame_max_len, MACSEC_ERR_BUFFER);
    macsec_check(total_len <= MACSEC_MKA_MAX_FRAME_LEN, MACSEC_ERR_BUFFER);

    tx_mn = ctx->local_mn;

    memset(frame, 0, total_len);

    memcpy(&frame[0], macsec_mka_dst_mac, 6u);
    memcpy(&frame[6], ctx->local_mac, 6u);
    macsec_wr_be16(&frame[12], MACSEC_MKA_ETHERTYPE_EAPOL);

    p = &frame[14];
    p[0] = MACSEC_MKA_EAPOL_VERSION_2010;
    p[1] = MACSEC_MKA_EAPOL_TYPE_MKA;
    macsec_wr_be16(&p[2], eapol_len);

    p = &frame[18];

    p[0] = MACSEC_MKA_VERSION_ID;
    p[1] = ctx->key_server_priority;

    flags_len_hi = (uint8_t)((body_len >> 8u) & 0x0Fu);

    if (ctx->local_key_server)
    {
        flags_len_hi |= 0x80u;
    }

    if (ctx->macsec_desired)
    {
        flags_len_hi |= 0x40u;
    }

    flags_len_hi |= (uint8_t)((ctx->macsec_capability & 0x03u) << 4u);

    p[2] = flags_len_hi;
    p[3] = (uint8_t)(body_len & 0xFFu);
    p += 4u;

    memcpy(p, ctx->local_sci, MACSEC_MKA_SCI_LEN);
    p += MACSEC_MKA_SCI_LEN;

    memcpy(p, ctx->local_mi, MACSEC_MKA_MI_LEN);
    p += MACSEC_MKA_MI_LEN;

    macsec_wr_be32(p, tx_mn);
    p += 4u;

    macsec_wr_be32(p, MACSEC_MKA_ALGORITHM_AGILITY);
    p += 4u;

    memcpy(p, ctx->crypto.psk.ckn, ctx->crypto.psk.ckn_len);
    p += ctx->crypto.psk.ckn_len;

    if (ctx->peer.valid)
    {
        macsec_mka_write_peer_list(&p,
                                   ctx->peer.live ?
                                   MACSEC_MKA_PARAM_LIVE_PEER_LIST :
                                   MACSEC_MKA_PARAM_POTENTIAL_PEER_LIST,
                                   &ctx->peer);
    }

    if (include_distributed_sak)
    {
        ret = macsec_mka_write_distributed_sak(&p, ctx);
        if (ret != MACSEC_ERR_OK)
        {
            return ret;
        }
    }

    if (ctx->latest_sak.valid && ctx->peer.live)
    {
        macsec_mka_write_sak_use(&p, ctx);
    }

    mic_len = total_len - MACSEC_MKA_ICV_LEN;

    ret = macsec_mka_crypto_calc_mic(&ctx->crypto,
                                     frame,
                                     mic_len,
                                     &frame[mic_len]);
    if (ret != MACSEC_ERR_OK)
    {
        MACSEC_ERROR(("MKA TX ICV calculation failed ret=%d\n", ret));
        return ret;
    }

    ctx->local_mn++;
    ctx->last_tx_ms = ctx->last_tick_ms;

    if (ctx->last_tx_ms == 0u)
    {
        ctx->last_tx_ms = 1u;
    }

    ctx->tx_pending = MACSEC_FALSE;
    *frame_len = total_len;

    MACSEC_MEDIUM(("MKA TX done: mn=%lu frame_len=%lu key_server=%u peer_list=%u dist_sak=%u sak_use=%u\n",
                   (unsigned long)tx_mn,
                   (unsigned long)*frame_len,
                   ctx->local_key_server ? 1u : 0u,
                   ctx->peer.valid ? 1u : 0u,
                   include_distributed_sak ? 1u : 0u,
                   sak_use_param_len ? 1u : 0u));

    return MACSEC_ERR_OK;
}

int macsec_mka_verify_icv(macsec_mka_ctx_t *ctx,
                          const uint8_t *frame,
                          size_t frame_len,
                          const macsec_mka_basic_t *basic)
{
    size_t mic_len;
    int ret;

    macsec_assert(ctx != NULL);
    macsec_assert(frame != NULL);
    macsec_assert(basic != NULL);
    macsec_check(ctx->crypto.keys.valid, MACSEC_ERR_STATE);

    /*
     * MKA ICV is calculated over:
     *
     *   DA || SA || EtherType || EAPOL header || MKPDU without ICV
     *
     * In other words, the input starts at the beginning of the Ethernet
     * frame and ends right before the 16-byte ICV field.
     *
     * The ICV field is not included and is not replaced by zero bytes.
     */
    mic_len = 14u + 4u + basic->eapol_len - MACSEC_MKA_ICV_LEN;

    MACSEC_INFO(("MKA verify ICV: frame_len=%lu mic_len=%lu eapol_len=%u\n",
                 (unsigned long)frame_len,
                 (unsigned long)mic_len,
                 basic->eapol_len));

    /*
     * The received frame must contain:
     *
     *   MIC input bytes + 16-byte ICV
     */
    macsec_check(frame_len >= (mic_len + MACSEC_MKA_ICV_LEN),
                 MACSEC_ERR_BUFFER);

    macsec_check(mic_len <= sizeof(ctx->mic_work),
                 MACSEC_ERR_BUFFER);

    memcpy(ctx->mic_work, frame, mic_len);

    MACSEC_INFO_HEX(("MKA MIC input", ctx->mic_work, (int)mic_len));
    MACSEC_INFO_HEX(("MKA RX ICV", basic->icv, MACSEC_MKA_ICV_LEN));

    /*
     * basic->icv was already extracted by macsec_mka_parse_basic().
     * macsec_mka_crypto_verify_mic() calculates AES-CMAC with ICK
     * and compares the result with the received ICV.
     */
    ret = macsec_mka_crypto_verify_mic(&ctx->crypto,
                                       ctx->mic_work,
                                       mic_len,
                                       basic->icv);

    if (ret != MACSEC_ERR_OK)
    {
        MACSEC_ERROR(("MKA verify ICV failed ret=%d\n", ret));
    }

    return ret;
}

void macsec_mka_print_basic(const macsec_mka_basic_t *basic)
{
    macsec_assert(basic != NULL);

    MACSEC_PRINT(("MKA Basic:\n"));
    MACSEC_PRINT(("  EAPOL version=%u type=%u len=%u\n",
                  basic->eapol_version,
                  basic->eapol_type,
                  basic->eapol_len));

    MACSEC_PRINT(("  MKA version=%u priority=%u key_server=%u desired=%u cap=%u body_len=%u\n",
                  basic->mka_version,
                  basic->key_server_priority,
                  basic->key_server,
                  basic->macsec_desired,
                  basic->macsec_capability,
                  basic->body_len));

    MACSEC_PRINT(("  MN=%u algorithm_agility=0x%08X CAKNameLen=%u\n",
                  basic->actor_mn,
                  basic->algorithm_agility,
                  (unsigned)basic->cak_name_len));

    MACSEC_PRINT_HEX(("Src MAC", basic->src_mac, 6));
    MACSEC_PRINT_HEX(("SCI", basic->sci, MACSEC_MKA_SCI_LEN));
    MACSEC_PRINT_HEX(("Actor MI", basic->actor_mi, MACSEC_MKA_MI_LEN));
    MACSEC_PRINT_HEX(("CAK Name", basic->cak_name, (int)basic->cak_name_len));
    MACSEC_PRINT_HEX(("ICV", basic->icv, MACSEC_MKA_ICV_LEN));
}

macsec_bool_t macsec_mka_has_sak(const macsec_mka_ctx_t *ctx)
{
    macsec_assert(ctx != NULL);

    return ctx->latest_sak.valid;
}

const macsec_mka_sak_t *macsec_mka_get_latest_sak(const macsec_mka_ctx_t *ctx)
{
    macsec_assert(ctx != NULL);

    if (!ctx->latest_sak.valid)
    {
        return NULL;
    }

    return &ctx->latest_sak;
}

void macsec_mka_set_latest_key_tx(macsec_mka_ctx_t *ctx,
                                  uint8_t an,
                                  uint32_t lowest_pn)
{
    macsec_assert(ctx != NULL);

    if (!ctx->latest_sak.valid)
    {
        return;
    }

    if ((ctx->latest_sak.an & 0x03u) != (an & 0x03u))
    {
        return;
    }

    ctx->latest_key_tx = MACSEC_TRUE;
    ctx->latest_key_rx = MACSEC_TRUE;
    ctx->latest_lowest_pn = (lowest_pn != 0u) ? lowest_pn : 1u;
    ctx->tx_pending = MACSEC_TRUE;
}
