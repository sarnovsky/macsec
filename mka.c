/*
 * mka.c
 *
 * Lightweight MACsec stack
 * MACsec Key Agreement protocol layer.
 * This file contains the MKA protocol logic used to build, parse and process
 * MKA-related protocol data structures required for MACsec key management.
 *
 * Copyright (c) 2026 Michal Sarnovsky
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */

#include "mka.h"

static const uint8_t macsec_mka_dst_mac[6] = {0x01u, 0x80u, 0xC2u, 0x00u, 0x00u, 0x03u};

#define MACSEC_MKA_VERSION_ID 1u
#define MACSEC_MKA_ALGORITHM_AGILITY 0x0080C201u
#define MACSEC_MKA_DEFAULT_TX_INTERVAL_MS 2000u
#define MACSEC_MKA_DEFAULT_CAPABILITY 2u

#define MACSEC_MKA_PARAM_LIVE_PEER_LIST 1u
#define MACSEC_MKA_PARAM_POTENTIAL_PEER_LIST 2u
#define MACSEC_MKA_PARAM_SAK_USE 3u
#define MACSEC_MKA_PARAM_DISTRIBUTED_SAK 4u

static void macsec_mka_raise_events(macsec_mka_ctx_t *ctx, macsec_mka_event_flags_t events);

static void macsec_mka_schedule_tx(macsec_mka_ctx_t *ctx, macsec_mka_tx_reason_flags_t reasons);

#if (MACSEC_DEBUG_LEVEL >= MACSEC_DEBUG_LEVEL_ERROR)

static const char *macsec_mka_state_name(macsec_mka_state_t state)
{
    switch (state)
    {
    case MACSEC_MKA_STATE_INIT:
        return "INIT";

    case MACSEC_MKA_STATE_WAIT_PEER:
        return "WAIT_PEER";

    case MACSEC_MKA_STATE_PEER_DISCOVERED:
        return "PEER_DISCOVERED";

    case MACSEC_MKA_STATE_PEER_LIVE:
        return "PEER_LIVE";

    case MACSEC_MKA_STATE_OPERATIONAL:
        return "OPERATIONAL";

    case MACSEC_MKA_STATE_ERROR:
        return "ERROR";

    default:
        return "UNKNOWN";
    }
}

static const char *macsec_mka_sak_state_name(macsec_mka_sak_state_t state)
{
    switch (state)
    {
    case MACSEC_MKA_SAK_STATE_NONE:
        return "NONE";

    case MACSEC_MKA_SAK_STATE_CANDIDATE:
        return "CANDIDATE";

    case MACSEC_MKA_SAK_STATE_DISTRIBUTION_PENDING:
        return "DISTRIBUTION_PENDING";

    case MACSEC_MKA_SAK_STATE_DISTRIBUTED:
        return "DISTRIBUTED";

    case MACSEC_MKA_SAK_STATE_INSTALL_PENDING:
        return "INSTALL_PENDING";

    case MACSEC_MKA_SAK_STATE_ACTIVE:
        return "ACTIVE";

    case MACSEC_MKA_SAK_STATE_CONFIRMED:
        return "CONFIRMED";

    case MACSEC_MKA_SAK_STATE_RETIRING:
        return "RETIRING";

    default:
        return "UNKNOWN";
    }
}

#endif

static macsec_bool_t macsec_mka_state_transition_allowed(macsec_mka_state_t old_state,
                                                         macsec_mka_state_t new_state)
{
    if (old_state == new_state)
    {
        return MACSEC_TRUE;
    }

    /*
     * An unrecoverable error may be entered from any state.
     */
    if (new_state == MACSEC_MKA_STATE_ERROR)
    {
        return MACSEC_TRUE;
    }

    switch (old_state)
    {
    case MACSEC_MKA_STATE_INIT:
        return (new_state == MACSEC_MKA_STATE_WAIT_PEER) ? MACSEC_TRUE : MACSEC_FALSE;

    case MACSEC_MKA_STATE_WAIT_PEER:
        return ((new_state == MACSEC_MKA_STATE_PEER_DISCOVERED) ||
                (new_state == MACSEC_MKA_STATE_PEER_LIVE))
                   ? MACSEC_TRUE
                   : MACSEC_FALSE;

    case MACSEC_MKA_STATE_PEER_DISCOVERED:
        return ((new_state == MACSEC_MKA_STATE_WAIT_PEER) ||
                (new_state == MACSEC_MKA_STATE_PEER_LIVE))
                   ? MACSEC_TRUE
                   : MACSEC_FALSE;

    case MACSEC_MKA_STATE_PEER_LIVE:
        return ((new_state == MACSEC_MKA_STATE_WAIT_PEER) ||
                (new_state == MACSEC_MKA_STATE_PEER_DISCOVERED) ||
                (new_state == MACSEC_MKA_STATE_OPERATIONAL))
                   ? MACSEC_TRUE
                   : MACSEC_FALSE;

    case MACSEC_MKA_STATE_OPERATIONAL:
        return ((new_state == MACSEC_MKA_STATE_WAIT_PEER) ||
                (new_state == MACSEC_MKA_STATE_PEER_DISCOVERED) ||
                (new_state == MACSEC_MKA_STATE_PEER_LIVE))
                   ? MACSEC_TRUE
                   : MACSEC_FALSE;

    case MACSEC_MKA_STATE_ERROR:
        /*
         * Recovery requires clear + init, not a direct transition.
         */
        return MACSEC_FALSE;

    default:
        return MACSEC_FALSE;
    }
}

static void macsec_mka_set_state(macsec_mka_ctx_t *ctx, macsec_mka_state_t new_state,
                                 const char *reason)
{
    macsec_mka_state_t old_state;

    macsec_assert(ctx != NULL);

    old_state = ctx->state;

    if (old_state == new_state)
    {
        return;
    }

    if (!macsec_mka_state_transition_allowed(old_state, new_state))
    {
        MACSEC_ERROR(("MKA invalid state transition %s(%u) -> %s(%u): %s\n",
                      macsec_mka_state_name(old_state), (unsigned) old_state,
                      macsec_mka_state_name(new_state), (unsigned) new_state,
                      (reason != NULL) ? reason : "no reason"));

        macsec_mka_raise_events(ctx, MACSEC_MKA_EVENT_ERROR);
        macsec_mka_set_state(ctx, MACSEC_MKA_STATE_ERROR, "MKA initialization failed");
        ctx->pending_events |= MACSEC_MKA_EVENT_ERROR;

        return;
    }

    MACSEC_MEDIUM(("MKA state %s(%u) -> %s(%u): %s\n", macsec_mka_state_name(old_state),
                   (unsigned) old_state, macsec_mka_state_name(new_state), (unsigned) new_state,
                   (reason != NULL) ? reason : "no reason"));

    ctx->state = new_state;
}

static macsec_bool_t macsec_mka_sak_transition_allowed(macsec_mka_sak_state_t old_state,
                                                       macsec_mka_sak_state_t new_state)
{
    if (old_state == new_state)
    {
        return MACSEC_TRUE;
    }

    switch (old_state)
    {
    case MACSEC_MKA_SAK_STATE_NONE:
        return (new_state == MACSEC_MKA_SAK_STATE_CANDIDATE) ? MACSEC_TRUE : MACSEC_FALSE;

    case MACSEC_MKA_SAK_STATE_CANDIDATE:
        return ((new_state == MACSEC_MKA_SAK_STATE_DISTRIBUTION_PENDING) ||
                (new_state == MACSEC_MKA_SAK_STATE_INSTALL_PENDING) ||
                (new_state == MACSEC_MKA_SAK_STATE_NONE))
                   ? MACSEC_TRUE
                   : MACSEC_FALSE;

    case MACSEC_MKA_SAK_STATE_DISTRIBUTION_PENDING:
        return ((new_state == MACSEC_MKA_SAK_STATE_DISTRIBUTED) ||
                (new_state == MACSEC_MKA_SAK_STATE_NONE))
                   ? MACSEC_TRUE
                   : MACSEC_FALSE;

    case MACSEC_MKA_SAK_STATE_DISTRIBUTED:
        return ((new_state == MACSEC_MKA_SAK_STATE_INSTALL_PENDING) ||
                (new_state == MACSEC_MKA_SAK_STATE_RETIRING))
                   ? MACSEC_TRUE
                   : MACSEC_FALSE;

    case MACSEC_MKA_SAK_STATE_INSTALL_PENDING:
        return ((new_state == MACSEC_MKA_SAK_STATE_ACTIVE) ||
                (new_state == MACSEC_MKA_SAK_STATE_RETIRING))
                   ? MACSEC_TRUE
                   : MACSEC_FALSE;

    case MACSEC_MKA_SAK_STATE_ACTIVE:
        return ((new_state == MACSEC_MKA_SAK_STATE_CONFIRMED) ||
                (new_state == MACSEC_MKA_SAK_STATE_RETIRING))
                   ? MACSEC_TRUE
                   : MACSEC_FALSE;

    case MACSEC_MKA_SAK_STATE_CONFIRMED:
        return (new_state == MACSEC_MKA_SAK_STATE_RETIRING) ? MACSEC_TRUE : MACSEC_FALSE;

    case MACSEC_MKA_SAK_STATE_RETIRING:
        return (new_state == MACSEC_MKA_SAK_STATE_NONE) ? MACSEC_TRUE : MACSEC_FALSE;

    default:
        return MACSEC_FALSE;
    }
}

static void macsec_mka_set_sak_state(macsec_mka_ctx_t *ctx, macsec_mka_sak_state_t new_state,
                                     const char *reason)
{
    macsec_mka_sak_state_t old_state;

    macsec_assert(ctx != NULL);

    old_state = ctx->latest_sak.lifecycle_state;

    if (old_state == new_state)
    {
        return;
    }

    if (!macsec_mka_sak_transition_allowed(old_state, new_state))
    {
        MACSEC_ERROR(("MKA invalid SAK transition %s(%u) -> %s(%u): key=%lu an=%u reason=%s\n",
                      macsec_mka_sak_state_name(old_state), (unsigned) old_state,
                      macsec_mka_sak_state_name(new_state), (unsigned) new_state,
                      (unsigned long) ctx->latest_sak.key_number, ctx->latest_sak.an,
                      (reason != NULL) ? reason : "no reason"));

        macsec_mka_set_state(ctx, MACSEC_MKA_STATE_ERROR, "invalid SAK state transition");

        return;
    }

    MACSEC_MEDIUM(("MKA SAK state %s(%u) -> %s(%u): key=%lu an=%u reason=%s\n",
                   macsec_mka_sak_state_name(old_state), (unsigned) old_state,
                   macsec_mka_sak_state_name(new_state), (unsigned) new_state,
                   (unsigned long) ctx->latest_sak.key_number, ctx->latest_sak.an,
                   (reason != NULL) ? reason : "no reason"));

    ctx->latest_sak.lifecycle_state = new_state;

    /*
     * Keep the legacy valid field synchronized during migration.
     */
    ctx->latest_sak.valid = (new_state != MACSEC_MKA_SAK_STATE_NONE) ? MACSEC_TRUE : MACSEC_FALSE;
}

static void macsec_mka_raise_events(macsec_mka_ctx_t *ctx, macsec_mka_event_flags_t events)
{
    macsec_assert(ctx != NULL);

    if (events == MACSEC_MKA_EVENT_NONE)
    {
        return;
    }

    ctx->pending_events |= events;

    MACSEC_INFO(("MKA events raised: requested=0x%08lX pending=0x%08lX\n", (unsigned long) events,
                 (unsigned long) ctx->pending_events));
}

static void macsec_mka_schedule_tx(macsec_mka_ctx_t *ctx, macsec_mka_tx_reason_flags_t reasons)
{
    macsec_assert(ctx != NULL);

    if (reasons == MACSEC_MKA_TX_REASON_NONE)
    {
        return;
    }

    ctx->tx_reasons |= reasons;

    MACSEC_INFO(("MKA TX scheduled: requested=0x%08lX pending=0x%08lX\n", (unsigned long) reasons,
                 (unsigned long) ctx->tx_reasons));
}

static void macsec_mka_build_sci(uint8_t sci[MACSEC_MKA_SCI_LEN], const uint8_t mac[6],
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

macsec_bool_t macsec_mka_is_eapol_mka(const uint8_t *frame, size_t frame_len)
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

int macsec_mka_parse_basic(const uint8_t *frame, size_t frame_len, macsec_mka_basic_t *out)
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

    macsec_check(out->eapol_type == MACSEC_MKA_EAPOL_TYPE_MKA, MACSEC_ERR_UNSUPPORTED);

    eapol_len = out->eapol_len;
    expected_len = 14u + 4u + eapol_len;

    macsec_check(frame_len >= expected_len, MACSEC_ERR_BUFFER);
    macsec_check(eapol_len >= (4u + 28u + MACSEC_MKA_ICV_LEN), MACSEC_ERR_BUFFER);

    /*
     * Basic Parameter Set starts immediately after EAPOL header.
     */
    p = &frame[18];

    out->mka_version = p[0];
    out->key_server_priority = p[1];

    out->key_server = (p[2] & 0x80u) ? 1 : 0;
    out->macsec_desired = (p[2] & 0x40u) ? 1 : 0;
    out->macsec_capability = (uint8_t) ((p[2] >> 4u) & 0x03u);

    body_len = (uint16_t) (((uint16_t) (p[2] & 0x0Fu) << 8u) | p[3]);
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

    MACSEC_INFO(("MKA Basic parsed: eapol_len=%u body_len=%u mn=%lu priority=%u key_server=%u "
                 "desired=%u cap=%u cak_name_len=%lu\n",
                 out->eapol_len, out->body_len, (unsigned long) out->actor_mn,
                 out->key_server_priority, out->key_server ? 1u : 0u, out->macsec_desired ? 1u : 0u,
                 out->macsec_capability, (unsigned long) out->cak_name_len));

    MACSEC_INFO_HEX(("MKA Basic src MAC", out->src_mac, 6));
    MACSEC_INFO_HEX(("MKA Basic SCI", out->sci, MACSEC_MKA_SCI_LEN));
    MACSEC_INFO_HEX(("MKA Basic actor MI", out->actor_mi, MACSEC_MKA_MI_LEN));
    MACSEC_INFO_HEX(("MKA Basic ICV", out->icv, MACSEC_MKA_ICV_LEN));

    return MACSEC_ERR_OK;
}

int macsec_mka_init(macsec_mka_ctx_t *ctx, const uint8_t *cak, size_t cak_len, const uint8_t *ckn,
                    size_t ckn_len, const uint8_t local_mac[6], uint16_t port_id,
                    uint8_t key_server_priority, uint32_t tx_interval_ms)
{
    int ret;

    macsec_assert(ctx != NULL);
    macsec_assert(local_mac != NULL);

    memset(ctx, 0, sizeof(*ctx));

    /*
     * These values are also produced by memset(), but keeping them explicit
     * documents the initial states and protects the code if enum values are
     * changed later.
     */
    ctx->state = MACSEC_MKA_STATE_INIT;
    ctx->latest_sak.lifecycle_state = MACSEC_MKA_SAK_STATE_NONE;
    ctx->latest_sak.origin = MACSEC_MKA_SAK_ORIGIN_NONE;

    memcpy(ctx->local_mac, local_mac, MACSEC_MKA_SRC_LEN);

    macsec_mka_build_sci(ctx->local_sci, local_mac, port_id);

    macsec_random(ctx->local_mi, MACSEC_MKA_MI_LEN);

    ctx->local_mn = 1u;

    ctx->key_server_priority = key_server_priority;

    /*
     * Until a valid peer is known, the local participant provisionally
     * considers itself the Key Server. Election is repeated after peer data
     * is received.
     */
    ctx->local_key_server = MACSEC_TRUE;

    ctx->macsec_desired = MACSEC_TRUE;
    ctx->macsec_capability = MACSEC_MKA_DEFAULT_CAPABILITY;

    ctx->key_server_next_key_number = 1u;
    ctx->key_server_next_an = 0u;

    ctx->tx_interval_ms =
        (tx_interval_ms != 0u) ? tx_interval_ms : MACSEC_MKA_DEFAULT_TX_INTERVAL_MS;

    MACSEC_MEDIUM(("MKA init: priority=%u tx_interval=%lu ms port=%u\n", ctx->key_server_priority,
                   (unsigned long) ctx->tx_interval_ms, (unsigned) port_id));

    MACSEC_MEDIUM_HEX(("MKA local MAC", ctx->local_mac, MACSEC_MKA_SRC_LEN));

    MACSEC_MEDIUM_HEX(("MKA local SCI", ctx->local_sci, MACSEC_MKA_SCI_LEN));

    MACSEC_MEDIUM_HEX(("MKA local MI", ctx->local_mi, MACSEC_MKA_MI_LEN));

    ret = macsec_mka_crypto_init(&ctx->crypto);
    if (ret != MACSEC_ERR_OK)
    {
        MACSEC_ERROR(("MKA crypto init failed ret=%d\n", ret));

        macsec_mka_raise_events(ctx, MACSEC_MKA_EVENT_ERROR);

        macsec_mka_set_state(ctx, MACSEC_MKA_STATE_ERROR, "crypto initialization failed");

        return ret;
    }

    ret = macsec_mka_crypto_set_psk(&ctx->crypto, cak, cak_len, ckn, ckn_len);
    if (ret != MACSEC_ERR_OK)
    {
        MACSEC_ERROR(("MKA set PSK failed ret=%d cak_len=%lu ckn_len=%lu\n", ret,
                      (unsigned long) cak_len, (unsigned long) ckn_len));

        macsec_mka_raise_events(ctx, MACSEC_MKA_EVENT_ERROR);

        macsec_mka_set_state(ctx, MACSEC_MKA_STATE_ERROR, "PSK configuration failed");

        return ret;
    }

    ret = macsec_mka_crypto_derive_ick_kek(&ctx->crypto);
    if (ret != MACSEC_ERR_OK)
    {
        MACSEC_ERROR(("MKA derive ICK/KEK failed ret=%d\n", ret));

        macsec_mka_raise_events(ctx, MACSEC_MKA_EVENT_ERROR);

        macsec_mka_set_state(ctx, MACSEC_MKA_STATE_ERROR, "ICK/KEK derivation failed");

        return ret;
    }

    MACSEC_MEDIUM_HEX(("MKA derived ICK", ctx->crypto.keys.ick, 16));

    MACSEC_MEDIUM_HEX(("MKA derived KEK", ctx->crypto.keys.kek, 16));

    ctx->verify_icv = MACSEC_TRUE;
    ctx->last_icv_valid = MACSEC_FALSE;

    macsec_mka_set_state(ctx, MACSEC_MKA_STATE_WAIT_PEER, "MKA initialization complete");

    /*
     * Initial transmission is scheduled only after crypto initialization,
     * PSK setup and key derivation have all succeeded.
     */
    macsec_mka_raise_events(ctx, MACSEC_MKA_EVENT_TX_INITIAL);

    macsec_mka_schedule_tx(ctx, MACSEC_MKA_TX_REASON_INITIAL);

    MACSEC_MEDIUM(("MKA init done: state=%u events=0x%08lX tx_reasons=0x%08lX\n",
                   (unsigned) ctx->state, (unsigned long) ctx->pending_events,
                   (unsigned long) ctx->tx_reasons));

    return MACSEC_ERR_OK;
}

void macsec_mka_clear(macsec_mka_ctx_t *ctx)
{
    macsec_assert(ctx != NULL);

    MACSEC_MEDIUM(("MKA clear\n"));

    macsec_mka_crypto_clear(&ctx->crypto);
    macsec_zeroize(ctx, sizeof(*ctx));
}

macsec_mka_state_t macsec_mka_get_state(const macsec_mka_ctx_t *ctx)
{
    macsec_assert(ctx != NULL);

    return ctx->state;
}

macsec_mka_event_flags_t macsec_mka_take_events(macsec_mka_ctx_t *ctx)
{
    macsec_mka_event_flags_t events;

    macsec_assert(ctx != NULL);

    events = ctx->pending_events;
    ctx->pending_events = MACSEC_MKA_EVENT_NONE;

    MACSEC_INFO(("MKA events taken: events=0x%08lX\n", (unsigned long) events));

    return events;
}

int macsec_mka_take_sak_for_install(macsec_mka_ctx_t *ctx, macsec_mka_sak_t *sak)
{
    macsec_bool_t available;

    macsec_check(ctx != NULL, MACSEC_ERR_PARAM);
    macsec_check(sak != NULL, MACSEC_ERR_PARAM);

    /*
     * The output must never contain stale key material when no SAK can
     * currently be returned.
     */
    memset(sak, 0, sizeof(*sak));

    if (!ctx->latest_sak.valid)
    {
        return MACSEC_ERR_NOT_READY;
    }

    /*
     * Validate the stored SAK before exposing it to macsec.c.
     *
     * Invalid internal SAK data indicates an MKA state-machine error rather
     * than a caller parameter error.
     */
    if ((ctx->latest_sak.sak_len != 16u) && (ctx->latest_sak.sak_len != 32u))
    {
        return MACSEC_ERR_STATE;
    }

    if (ctx->latest_sak.an >= MACSEC_FRAME_MAX_SA)
    {
        return MACSEC_ERR_STATE;
    }

    if (ctx->latest_sak.key_number == 0u)
    {
        return MACSEC_ERR_STATE;
    }

    available = MACSEC_FALSE;

    /*
     * A SAK received from the remote Key Server can be installed as soon
     * as it has been successfully authenticated and unwrapped.
     */
    if ((ctx->latest_sak.origin == MACSEC_MKA_SAK_ORIGIN_REMOTE_KEY_SERVER) &&
        (ctx->latest_sak.lifecycle_state == MACSEC_MKA_SAK_STATE_CANDIDATE))
    {
        available = MACSEC_TRUE;
    }

    /*
     * A locally generated Key Server SAK must first be distributed in a
     * successfully transmitted MKPDU.
     */
    if ((ctx->latest_sak.origin == MACSEC_MKA_SAK_ORIGIN_LOCAL_KEY_SERVER) &&
        (ctx->latest_sak.lifecycle_state == MACSEC_MKA_SAK_STATE_DISTRIBUTED))
    {
        available = MACSEC_TRUE;
    }

    /*
     * INSTALL_PENDING is intentionally returned again.
     *
     * This supports retry when RX or TX installation failed, or when the
     * corresponding installation confirmation could not be completed.
     */
    if (ctx->latest_sak.lifecycle_state == MACSEC_MKA_SAK_STATE_INSTALL_PENDING)
    {
        if ((ctx->latest_sak.origin == MACSEC_MKA_SAK_ORIGIN_REMOTE_KEY_SERVER) ||
            (ctx->latest_sak.origin == MACSEC_MKA_SAK_ORIGIN_LOCAL_KEY_SERVER))
        {
            available = MACSEC_TRUE;
        }
    }

    if (!available)
    {
        return MACSEC_ERR_NOT_READY;
    }

    /*
     * A fully installed SAK should already be ACTIVE. Do not repeatedly
     * return it even if the lifecycle state was left inconsistent.
     */
    if (ctx->latest_sak.rx_installed && ctx->latest_sak.tx_installed)
    {
        return MACSEC_ERR_NOT_READY;
    }

    /*
     * Move the SAK into the installation lifecycle only on its first
     * handoff. Retry calls keep the existing direction flags unchanged.
     */
    if (ctx->latest_sak.lifecycle_state != MACSEC_MKA_SAK_STATE_INSTALL_PENDING)
    {
        macsec_mka_set_sak_state(ctx, MACSEC_MKA_SAK_STATE_INSTALL_PENDING,
                                 "SAK handed to MACsec data-plane");
    }

    /*
     * Copy the current state after the lifecycle transition so that the
     * caller receives INSTALL_PENDING together with the current RX/TX
     * installation flags.
     */
    *sak = ctx->latest_sak;

    return MACSEC_ERR_OK;
}

int macsec_mka_notify_sak_installed(macsec_mka_ctx_t *ctx, uint32_t key_number, uint8_t an,
                                    macsec_mka_install_directions_t installed_directions,
                                    uint32_t lowest_pn)
{
    uint32_t normalized_lowest_pn;

    macsec_assert(ctx != NULL);

    if (!ctx->latest_sak.valid)
    {
        return MACSEC_ERR_NOT_READY;
    }

    if (ctx->latest_sak.lifecycle_state != MACSEC_MKA_SAK_STATE_INSTALL_PENDING)
    {
        return MACSEC_ERR_STATE;
    }

    if (ctx->latest_sak.key_number != key_number)
    {
        return MACSEC_ERR_PARAM;
    }

    if ((ctx->latest_sak.an & 0x03u) != (an & 0x03u))
    {
        return MACSEC_ERR_PARAM;
    }

    if ((installed_directions == MACSEC_MKA_INSTALL_NONE) ||
        ((installed_directions & (uint8_t) ~(MACSEC_MKA_INSTALL_RX | MACSEC_MKA_INSTALL_TX)) != 0u))
    {
        return MACSEC_ERR_PARAM;
    }

    normalized_lowest_pn = (lowest_pn != 0u) ? lowest_pn : 1u;

    if ((installed_directions & MACSEC_MKA_INSTALL_RX) != 0u)
    {
        ctx->latest_sak.rx_installed = MACSEC_TRUE;

        ctx->latest_key_rx = MACSEC_TRUE;
    }

    if ((installed_directions & MACSEC_MKA_INSTALL_TX) != 0u)
    {
        ctx->latest_sak.tx_installed = MACSEC_TRUE;

        ctx->latest_key_tx = MACSEC_TRUE;
    }

    ctx->latest_sak.lowest_pn = normalized_lowest_pn;

    ctx->latest_lowest_pn = normalized_lowest_pn;

    MACSEC_MEDIUM(("MKA SAK installation notified: key_number=%lu an=%u directions=0x%02X rx=%u "
                   "tx=%u lowest_pn=%lu\n",
                   (unsigned long) ctx->latest_sak.key_number, ctx->latest_sak.an,
                   installed_directions, ctx->latest_sak.rx_installed ? 1u : 0u,
                   ctx->latest_sak.tx_installed ? 1u : 0u, (unsigned long) normalized_lowest_pn));

    if (!ctx->latest_sak.rx_installed || !ctx->latest_sak.tx_installed)
    {
        return MACSEC_ERR_OK;
    }

    macsec_mka_set_sak_state(ctx, MACSEC_MKA_SAK_STATE_ACTIVE, "SAK installed for RX and TX");

    if (ctx->latest_sak.lifecycle_state != MACSEC_MKA_SAK_STATE_ACTIVE)
    {
        return MACSEC_ERR_STATE;
    }

    macsec_mka_raise_events(ctx, MACSEC_MKA_EVENT_SAK_ACTIVE | MACSEC_MKA_EVENT_TX_SAK_USE);

    macsec_mka_schedule_tx(ctx, MACSEC_MKA_TX_REASON_SAK_USE);

    if (ctx->peer.valid && ctx->peer.live)
    {
        macsec_mka_set_state(ctx, MACSEC_MKA_STATE_OPERATIONAL,
                             "active SAK installed in data-plane");

        if (ctx->state != MACSEC_MKA_STATE_OPERATIONAL)
        {
            return MACSEC_ERR_STATE;
        }
    }

    return MACSEC_ERR_OK;
}

int macsec_mka_notify_sak_retired(macsec_mka_ctx_t *ctx, uint32_t key_number, uint8_t an)
{
    macsec_assert(ctx != NULL);

    if (!ctx->latest_sak.valid)
    {
        return MACSEC_ERR_NOT_READY;
    }

    if (ctx->latest_sak.key_number != key_number)
    {
        MACSEC_ERROR(("MKA SAK retirement rejected: key_number=%lu expected=%lu\n",
                      (unsigned long) key_number, (unsigned long) ctx->latest_sak.key_number));

        return MACSEC_ERR_PARAM;
    }

    if ((ctx->latest_sak.an & 0x03u) != (an & 0x03u))
    {
        MACSEC_ERROR(("MKA SAK retirement rejected: AN=%u expected=%u\n", an & 0x03u,
                      ctx->latest_sak.an & 0x03u));

        return MACSEC_ERR_PARAM;
    }

    if (ctx->latest_sak.lifecycle_state != MACSEC_MKA_SAK_STATE_RETIRING)
    {
        return MACSEC_ERR_STATE;
    }

    MACSEC_MEDIUM(("MKA SAK retired: key_number=%lu an=%u\n",
                   (unsigned long) ctx->latest_sak.key_number, ctx->latest_sak.an));

    macsec_mka_set_sak_state(ctx, MACSEC_MKA_SAK_STATE_NONE,
                             "retiring SAK removed from data-plane");

    if (ctx->latest_sak.lifecycle_state != MACSEC_MKA_SAK_STATE_NONE)
    {
        return MACSEC_ERR_STATE;
    }

    /*
     * Remove all key material and SAK metadata after completing the
     * lifecycle transition.
     */
    macsec_zeroize(&ctx->latest_sak, sizeof(ctx->latest_sak));

    ctx->latest_sak.lifecycle_state = MACSEC_MKA_SAK_STATE_NONE;

    ctx->latest_sak.origin = MACSEC_MKA_SAK_ORIGIN_NONE;

    /*
     * Clear legacy SAK Use state.
     */
    ctx->latest_key_rx = MACSEC_FALSE;
    ctx->latest_key_tx = MACSEC_FALSE;
    ctx->latest_lowest_pn = 0u;

    macsec_mka_raise_events(ctx, MACSEC_MKA_EVENT_SAK_RETIRED);

    /*
     * With the current single-SAK representation, retirement means that
     * no active data-plane key remains. During the later two-slot rekey
     * implementation, retiring the old slot will not necessarily change
     * the participant state.
     */
    if (ctx->state == MACSEC_MKA_STATE_OPERATIONAL)
    {
        if (ctx->peer.valid && ctx->peer.live)
        {
            macsec_mka_set_state(ctx, MACSEC_MKA_STATE_PEER_LIVE, "active SAK retired");
        }
        else
        {
            macsec_mka_set_state(ctx, MACSEC_MKA_STATE_WAIT_PEER, "SAK retired without live peer");
        }
    }

    return MACSEC_ERR_OK;
}

static macsec_bool_t macsec_mka_frame_contains_peer_entry(const uint8_t *frame, size_t frame_len,
                                                          const uint8_t mi[MACSEC_MKA_MI_LEN],
                                                          uint32_t *mn_out, uint8_t *list_type_out)
{
    uint16_t eapol_len;
    size_t pos;
    size_t end;

    if ((frame == NULL) || (mi == NULL) || (frame_len < 90u))
    {
        MACSEC_INFO(("MKA peer-list scan skipped: frame_len=%lu\n", (unsigned long) frame_len));
        return MACSEC_FALSE;
    }

    if (list_type_out != NULL)
    {
        *list_type_out = 0u;
    }

    eapol_len = macsec_rd_be16(&frame[16]);
    if (eapol_len < MACSEC_MKA_ICV_LEN)
    {
        MACSEC_ERROR(("MKA peer-list scan invalid EAPOL length=%u\n", eapol_len));

        return MACSEC_FALSE;
    }
    end = 14u + 4u + eapol_len - MACSEC_MKA_ICV_LEN;

    if (end > frame_len)
    {
        MACSEC_ERROR(("MKA peer-list scan invalid end=%lu frame_len=%lu\n", (unsigned long) end,
                      (unsigned long) frame_len));
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
            body_len = (uint16_t) (((uint16_t) (frame[pos + 2u] & 0x0Fu) << 8u) |
                                   (uint16_t) frame[pos + 3u]);

            if ((pos + 4u + body_len) > end)
            {
                MACSEC_ERROR(("MKA Basic parameter overflow: body_len=%u end=%lu\n", body_len,
                              (unsigned long) end));
                return MACSEC_FALSE;
            }

            pos += 4u + body_len;
            continue;
        }

        type = frame[pos];
        body_len = (uint16_t) (((uint16_t) (frame[pos + 2u] & 0x0Fu) << 8u) | frame[pos + 3u]);

        body_pos = pos + 4u;
        body_end = body_pos + body_len;

        MACSEC_INFO(("MKA parameter set: type=%u body_len=%u pos=%lu body_end=%lu\n", type,
                     body_len, (unsigned long) pos, (unsigned long) body_end));

        if (body_end > end)
        {
            MACSEC_ERROR(("MKA parameter set overflow: type=%u body_end=%lu end=%lu\n", type,
                          (unsigned long) body_end, (unsigned long) end));
            return MACSEC_FALSE;
        }

        if ((type == MACSEC_MKA_PARAM_LIVE_PEER_LIST) ||
            (type == MACSEC_MKA_PARAM_POTENTIAL_PEER_LIST))
        {
            while ((body_pos + 16u) <= body_end)
            {
                MACSEC_INFO_HEX(("MKA peer-list entry MI", &frame[body_pos], MACSEC_MKA_MI_LEN));

                if (memcmp(&frame[body_pos], mi, MACSEC_MKA_MI_LEN) == 0)
                {
                    uint32_t listed_mn;

                    listed_mn = macsec_rd_be32(&frame[body_pos + MACSEC_MKA_MI_LEN]);

                    if (mn_out != NULL)
                    {
                        *mn_out = listed_mn;
                    }

                    if (list_type_out != NULL)
                    {
                        *list_type_out = type;
                    }

                    MACSEC_MEDIUM(("MKA local MI found in peer list: type=%u listed_mn=%lu\n", type,
                                   (unsigned long) listed_mn));

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

static int macsec_mka_parse_distributed_sak(macsec_mka_ctx_t *ctx, const uint8_t *frame,
                                            size_t frame_len)
{
    uint16_t eapol_len;
    size_t pos;
    size_t end;

    macsec_assert(ctx != NULL);
    macsec_assert(frame != NULL);

    if (frame_len < 90u)
    {
        return MACSEC_ERR_NOT_READY;
    }

    eapol_len = macsec_rd_be16(&frame[16]);

    if (eapol_len < MACSEC_MKA_ICV_LEN)
    {
        return MACSEC_ERR_BUFFER;
    }

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
            /*
             * Skip Basic Parameter Set.
             */
            body_len = (uint16_t) (((uint16_t) (frame[pos + 2u] & 0x0Fu) << 8u) |
                                   (uint16_t) frame[pos + 3u]);

            if ((pos + 4u + body_len) > end)
            {
                return MACSEC_ERR_BUFFER;
            }

            pos += 4u + body_len;
            continue;
        }

        type = frame[pos];

        body_len =
            (uint16_t) (((uint16_t) (frame[pos + 2u] & 0x0Fu) << 8u) | (uint16_t) frame[pos + 3u]);

        body_pos = pos + 4u;
        body_end = body_pos + body_len;

        if (body_end > end)
        {
            return MACSEC_ERR_BUFFER;
        }

        if (type == MACSEC_MKA_PARAM_DISTRIBUTED_SAK)
        {
            uint8_t unwrapped_sak[32];
            uint8_t an;
            const uint8_t *wrapped_sak;
            size_t wrapped_sak_len;
            size_t sak_len;
            uint32_t key_number;
            macsec_bool_t same_sak;
            int ret;

            /*
             * Supported Distributed SAK body:
             *
             *   bytes 0..3 : Key Number
             *   bytes 4..  : AES-KW wrapped SAK
             *
             * A wrapped 128-bit SAK occupies 24 bytes.
             * A wrapped 256-bit SAK occupies 40 bytes.
             */
            if (body_len < (4u + 24u))
            {
                return MACSEC_ERR_BUFFER;
            }

            key_number = macsec_rd_be32(&frame[body_pos]);

            /*
             * In the current stack, AN rotates together with Key Number:
             *
             *   Key Number 1 -> AN 0
             *   Key Number 2 -> AN 1
             *   ...
             */
            if (key_number == 0u)
            {
                an = 0u;
            }
            else
            {
                an = (uint8_t) ((key_number - 1u) & 0x03u);
            }

            wrapped_sak = &frame[body_pos + 4u];
            wrapped_sak_len = body_len - 4u;

            if ((wrapped_sak_len != 24u) && (wrapped_sak_len != 40u))
            {
                MACSEC_ERROR(("MKA Distributed SAK invalid wrapped length=%lu\n",
                              (unsigned long) wrapped_sak_len));

                return MACSEC_ERR_BUFFER;
            }

            MACSEC_INFO(("MKA Distributed SAK: key_number=%lu an=%u wrapped_len=%lu\n",
                         (unsigned long) key_number, an, (unsigned long) wrapped_sak_len));

            memset(unwrapped_sak, 0, sizeof(unwrapped_sak));
            sak_len = 0u;

            ret = macsec_mka_crypto_unwrap_sak(&ctx->crypto, wrapped_sak, wrapped_sak_len,
                                               unwrapped_sak, &sak_len, sizeof(unwrapped_sak));
            if (ret != MACSEC_ERR_OK)
            {
                MACSEC_ERROR(
                    ("MKA Distributed SAK unwrap failed ret=%d body_len=%u wrapped_len=%lu\n", ret,
                     body_len, (unsigned long) wrapped_sak_len));

                MACSEC_ERROR_HEX(("MKA wrapped SAK", wrapped_sak, (int) wrapped_sak_len));

                macsec_zeroize(unwrapped_sak, sizeof(unwrapped_sak));

                return ret;
            }

            if ((sak_len != 16u) && (sak_len != 32u))
            {
                MACSEC_ERROR(("MKA Distributed SAK invalid unwrapped length=%lu\n",
                              (unsigned long) sak_len));

                macsec_zeroize(unwrapped_sak, sizeof(unwrapped_sak));

                return MACSEC_ERR_BUFFER;
            }

            /*
             * The Key Server may repeat the same Distributed SAK in
             * subsequent periodic MKPDUs. Do not report it as a new key
             * and do not overwrite the currently installed candidate.
             */
            same_sak = ctx->latest_sak.valid && (ctx->latest_sak.key_number == key_number) &&
                       (ctx->latest_sak.an == an) && (ctx->latest_sak.sak_len == sak_len) &&
                       (memcmp(ctx->latest_sak.sak, unwrapped_sak, sak_len) == 0);

            if (same_sak)
            {
                MACSEC_INFO(("MKA Distributed SAK already known: key_number=%lu an=%u\n",
                             (unsigned long) key_number, an));

                macsec_zeroize(unwrapped_sak, sizeof(unwrapped_sak));

                return MACSEC_ERR_NOT_READY;
            }

            memset(&ctx->latest_sak, 0, sizeof(ctx->latest_sak));

            memcpy(ctx->latest_sak.sak, unwrapped_sak, sak_len);

            ctx->latest_sak.sak_len = sak_len;
            ctx->latest_sak.an = an;
            ctx->latest_sak.key_number = key_number;
            ctx->latest_sak.origin = MACSEC_MKA_SAK_ORIGIN_REMOTE_KEY_SERVER;
            ctx->latest_sak.lowest_pn = 1u;
            ctx->latest_sak.rx_installed = MACSEC_FALSE;
            ctx->latest_sak.tx_installed = MACSEC_FALSE;
            ctx->latest_sak.peer_rx_confirmed = MACSEC_FALSE;
            ctx->latest_sak.peer_tx_confirmed = MACSEC_FALSE;
            macsec_mka_set_sak_state(ctx, MACSEC_MKA_SAK_STATE_CANDIDATE,
                                     "remote Distributed SAK unwrapped");

            macsec_mka_raise_events(ctx, MACSEC_MKA_EVENT_SAK_AVAILABLE);

            /*
             * A newly received Distributed SAK is known on RX first.
             * TX becomes active after the top-level MACsec layer installs
             * and acknowledges it.
             */
            ctx->latest_key_rx = MACSEC_TRUE;
            ctx->latest_key_tx = MACSEC_FALSE;
            ctx->latest_lowest_pn = 1u;

            MACSEC_MEDIUM(("MKA Distributed SAK new candidate: key_number=%lu an=%u sak_len=%lu\n",
                           (unsigned long) ctx->latest_sak.key_number, ctx->latest_sak.an,
                           (unsigned long) ctx->latest_sak.sak_len));

            MACSEC_MEDIUM_HEX(
                ("MKA unwrapped SAK", ctx->latest_sak.sak, (int) ctx->latest_sak.sak_len));

            macsec_zeroize(unwrapped_sak, sizeof(unwrapped_sak));

            return MACSEC_ERR_OK;
        }

        pos = body_end;
    }

    return MACSEC_ERR_NOT_READY;
}

int macsec_mka_input(macsec_mka_ctx_t *ctx, const uint8_t *frame, size_t frame_len, uint32_t now_ms)
{
    macsec_mka_basic_t basic;

    macsec_bool_t peer_identity_changed;
    macsec_bool_t peer_became_live;
    macsec_bool_t peer_became_not_live;
    macsec_bool_t key_server_changed;

    macsec_bool_t previous_peer_live;
    macsec_bool_t previous_local_key_server;

    macsec_bool_t local_seen_by_peer;

    uint32_t listed_mn;
    uint8_t peer_list_type;
    int ret, distributed_sak_ret;

    macsec_assert(ctx != NULL);
    macsec_assert(frame != NULL);

    MACSEC_INFO(
        ("MKA RX frame len=%lu now=%lu\n", (unsigned long) frame_len, (unsigned long) now_ms));

    if (!macsec_mka_is_eapol_mka(frame, frame_len))
    {
        MACSEC_ERROR(("MKA RX unsupported/non-MKA frame len=%lu\n", (unsigned long) frame_len));

        return MACSEC_ERR_PARAM;
    }

    ret = macsec_mka_parse_basic(frame, frame_len, &basic);
    if (ret != MACSEC_ERR_OK)
    {
        MACSEC_ERROR(("MKA RX parse Basic failed ret=%d\n", ret));

        /*
         * A malformed received packet is not an unrecoverable participant
         * error. Persistent MKA state must remain unchanged.
         */
        return ret;
    }

    /*
     * Ignore frames originating from this participant.
     */
    if ((memcmp(basic.src_mac, ctx->local_mac, MACSEC_MKA_SRC_LEN) == 0) ||
        (memcmp(basic.sci, ctx->local_sci, MACSEC_MKA_SCI_LEN) == 0) ||
        (memcmp(basic.actor_mi, ctx->local_mi, MACSEC_MKA_MI_LEN) == 0))
    {
        MACSEC_INFO(("MKA RX ignored own frame\n"));
        return MACSEC_ERR_OK;
    }

    /*
     * Do not update persistent peer state until ICV verification succeeds.
     */
    ctx->last_icv_valid = MACSEC_FALSE;

    if (ctx->verify_icv)
    {
        ret = macsec_mka_verify_icv(ctx, frame, frame_len, &basic);
        if (ret != MACSEC_ERR_OK)
        {
            MACSEC_ERROR(("MKA RX ICV failed ret=%d\n", ret));

            MACSEC_ERROR_HEX(("MKA RX received ICV", basic.icv, MACSEC_MKA_ICV_LEN));

            /*
             * An unauthenticated frame must not modify peer state,
             * Key Server election or SAK state.
             */
            return ret;
        }

        ctx->last_icv_valid = MACSEC_TRUE;

        MACSEC_INFO(("MKA RX ICV OK\n"));
    }

    /*
     * From this point the received MKPDU is authenticated and may update
     * persistent state.
     */
    ctx->last_basic = basic;
    ctx->last_rx_ms = now_ms;

    previous_peer_live = ctx->peer.live;
    previous_local_key_server = ctx->local_key_server;

    /*
     * actor_mn normally increases in every MKPDU and is deliberately not
     * treated as a peer identity change.
     */
    peer_identity_changed = (!ctx->peer.valid) ||
                            (memcmp(ctx->peer.mi, basic.actor_mi, MACSEC_MKA_MI_LEN) != 0) ||
                            (memcmp(ctx->peer.sci, basic.sci, MACSEC_MKA_SCI_LEN) != 0) ||
                            (memcmp(ctx->peer.mac, basic.src_mac, MACSEC_MKA_SRC_LEN) != 0);

    /*
     * Distributed SAK parsing is permitted only after successful ICV
     * verification.
     *
     * MACSEC_ERR_OK:
     *   a genuinely new SAK was received;
     *
     * MACSEC_ERR_NOT_READY:
     *   no Distributed SAK was present, or the SAK was already known.
     */
    distributed_sak_ret = macsec_mka_parse_distributed_sak(ctx, frame, frame_len);

    if ((distributed_sak_ret != MACSEC_ERR_OK) && (distributed_sak_ret != MACSEC_ERR_NOT_READY))
    {
        MACSEC_ERROR(("MKA RX Distributed SAK parse failed ret=%d\n", distributed_sak_ret));

        /*
         * A malformed or non-decryptable received SAK does not represent
         * an unrecoverable internal participant error.
         */
        return distributed_sak_ret;
    }

    listed_mn = 0u;
    peer_list_type = 0u;

    local_seen_by_peer = macsec_mka_frame_contains_peer_entry(frame, frame_len, ctx->local_mi,
                                                              &listed_mn, &peer_list_type);

    MACSEC_MEDIUM(("MKA peer update: identity_changed=%u local_seen_by_peer=%u list_type=%u "
                   "peer_mn=%lu new_sak=%u\n",
                   peer_identity_changed ? 1u : 0u, local_seen_by_peer ? 1u : 0u, peer_list_type,
                   (unsigned long) basic.actor_mn,
                   (distributed_sak_ret == MACSEC_ERR_OK) ? 1u : 0u));

    /*
     * Update authenticated peer identity and advertised capabilities.
     */
    memcpy(ctx->peer.mac, basic.src_mac, MACSEC_MKA_SRC_LEN);

    memcpy(ctx->peer.sci, basic.sci, MACSEC_MKA_SCI_LEN);

    memcpy(ctx->peer.mi, basic.actor_mi, MACSEC_MKA_MI_LEN);

    ctx->peer.mn = basic.actor_mn;

    ctx->peer.key_server_priority = basic.key_server_priority;

    ctx->peer.key_server = basic.key_server;

    ctx->peer.macsec_desired = basic.macsec_desired;

    ctx->peer.macsec_capability = basic.macsec_capability;

    ctx->peer.last_seen_ms = now_ms;
    ctx->peer.valid = MACSEC_TRUE;

    /*
     * Migration behavior:
     *
     * Listing our MI in either Potential or Live Peer List establishes
     * liveness. Requiring only the Live Peer List would deadlock two newly
     * initialized participants.
     *
     * In the final state machine, loss of liveness will be driven by a
     * timeout rather than absence from one individual MKPDU.
     */
    if (local_seen_by_peer)
    {
        ctx->peer.seen_in_peer_list = MACSEC_TRUE;

        ctx->peer.live = MACSEC_TRUE;

        macsec_mka_set_state(ctx, MACSEC_MKA_STATE_PEER_LIVE,
                             "local MI listed by authenticated peer");

        MACSEC_MEDIUM(("MKA peer is LIVE: list_type=%u peer_mn=%lu listed_mn=%lu\n", peer_list_type,
                       (unsigned long) ctx->peer.mn, (unsigned long) listed_mn));
    }
    else
    {
        ctx->peer.seen_in_peer_list = MACSEC_FALSE;

        ctx->peer.live = MACSEC_FALSE;

        macsec_mka_set_state(ctx, MACSEC_MKA_STATE_PEER_DISCOVERED,
                             "authenticated peer does not list local MI");

        MACSEC_MEDIUM(("MKA peer found but local MI is not listed: peer_mn=%lu\n",
                       (unsigned long) ctx->peer.mn));
    }

    peer_became_live = (!previous_peer_live && ctx->peer.live) ? MACSEC_TRUE : MACSEC_FALSE;

    peer_became_not_live = (previous_peer_live && !ctx->peer.live) ? MACSEC_TRUE : MACSEC_FALSE;

    /*
     * Run Key Server election using the authenticated current peer data.
     */
    ctx->local_key_server = macsec_mka_local_wins_key_server(ctx);

    key_server_changed =
        (previous_local_key_server != ctx->local_key_server) ? MACSEC_TRUE : MACSEC_FALSE;

    MACSEC_MEDIUM(("MKA key server election: local_priority=%u peer_priority=%u "
                   "local_key_server=%u changed=%u\n",
                   ctx->key_server_priority, ctx->peer.key_server_priority,
                   ctx->local_key_server ? 1u : 0u, key_server_changed ? 1u : 0u));

    /*
     * Schedule immediate control traffic only for meaningful state
     * transitions. A normal actor_mn increment causes no immediate reply.
     */
    if (peer_identity_changed)
    {
        macsec_mka_raise_events(ctx,
                                MACSEC_MKA_EVENT_PEER_DISCOVERED | MACSEC_MKA_EVENT_TX_PEER_CHANGE);

        macsec_mka_schedule_tx(ctx, MACSEC_MKA_TX_REASON_PEER_CHANGE);
    }

    if (peer_became_live)
    {
        macsec_mka_raise_events(ctx, MACSEC_MKA_EVENT_PEER_LIVE | MACSEC_MKA_EVENT_TX_PEER_CHANGE);

        macsec_mka_schedule_tx(ctx, MACSEC_MKA_TX_REASON_PEER_CHANGE);
    }

    if (peer_became_not_live)
    {
        macsec_mka_raise_events(ctx, MACSEC_MKA_EVENT_PEER_LOST | MACSEC_MKA_EVENT_TX_PEER_CHANGE);

        macsec_mka_schedule_tx(ctx, MACSEC_MKA_TX_REASON_PEER_CHANGE);
    }

    if (key_server_changed)
    {
        macsec_mka_raise_events(ctx, MACSEC_MKA_EVENT_KEY_SERVER_CHANGED |
                                         MACSEC_MKA_EVENT_TX_KEY_SERVER_CHANGE);

        macsec_mka_schedule_tx(ctx, MACSEC_MKA_TX_REASON_KEY_SERVER_CHANGE);
    }

    MACSEC_INFO(("MKA RX done: state=%u peer_valid=%u peer_live=%u peer_list_type=%u "
                 "events=0x%08lX tx_reasons=0x%08lX new_sak=%u\n",
                 (unsigned) ctx->state, ctx->peer.valid ? 1u : 0u, ctx->peer.live ? 1u : 0u,
                 peer_list_type, (unsigned long) ctx->pending_events,
                 (unsigned long) ctx->tx_reasons,
                 (distributed_sak_ret == MACSEC_ERR_OK) ? 1u : 0u));

    return MACSEC_ERR_OK;
}

int macsec_mka_tick(macsec_mka_ctx_t *ctx, uint32_t now_ms)
{
    macsec_check(ctx != NULL, MACSEC_ERR_PARAM);

    ctx->last_tick_ms = now_ms;

    MACSEC_INFO(("MKA tick: now=%lu last_tx=%lu interval=%lu tx_reasons=0x%08lX\n",
                 (unsigned long) now_ms, (unsigned long) ctx->last_tx_ms,
                 (unsigned long) ctx->tx_interval_ms, (unsigned long) ctx->tx_reasons));

    /*
     * Do not schedule another periodic reason while an immediate or
     * previously scheduled transmission is already pending.
     */
    if (ctx->tx_reasons != MACSEC_MKA_TX_REASON_NONE)
    {
        return MACSEC_ERR_OK;
    }

    if (ctx->last_tx_ms == 0u)
    {
        macsec_mka_raise_events(ctx, MACSEC_MKA_EVENT_TX_INITIAL);

        macsec_mka_schedule_tx(ctx, MACSEC_MKA_TX_REASON_INITIAL);

        MACSEC_INFO(("MKA tick: first TX scheduled\n"));

        return MACSEC_ERR_OK;
    }

    if ((uint32_t) (now_ms - ctx->last_tx_ms) >= ctx->tx_interval_ms)
    {
        macsec_mka_raise_events(ctx, MACSEC_MKA_EVENT_TX_PERIODIC);

        macsec_mka_schedule_tx(ctx, MACSEC_MKA_TX_REASON_PERIODIC);

        MACSEC_INFO(("MKA tick: periodic TX scheduled\n"));
    }

    return MACSEC_ERR_OK;
}

static void macsec_mka_write_peer_list(uint8_t **p, uint8_t type, const macsec_mka_peer_t *peer)
{
    uint16_t body_len = 16u;

    MACSEC_INFO(("MKA TX peer list: type=%u peer_mn=%lu live=%u\n", type, (unsigned long) peer->mn,
                 peer->live ? 1u : 0u));

    MACSEC_INFO_HEX(("MKA TX peer MI", peer->mi, MACSEC_MKA_MI_LEN));

    (*p)[0] = type;
    (*p)[1] = 0u;
    (*p)[2] = (uint8_t) ((body_len >> 8u) & 0x0Fu);
    (*p)[3] = (uint8_t) (body_len & 0xFFu);
    *p += 4u;

    memcpy(*p, peer->mi, MACSEC_MKA_MI_LEN);
    *p += MACSEC_MKA_MI_LEN;

    macsec_wr_be32(*p, peer->mn);
    *p += 4u;
}

static void macsec_mka_write_sak_use(uint8_t **p, const macsec_mka_ctx_t *ctx)
{
    uint16_t body_len = 40u;
    uint8_t flags = 0u;
    const uint8_t *key_server_mi;

    flags |= (uint8_t) ((ctx->latest_sak.an & 0x03u) << 6u);

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
    (*p)[2] = (uint8_t) ((body_len >> 8u) & 0x0Fu);
    (*p)[3] = (uint8_t) (body_len & 0xFFu);
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

    /*
     * Only the elected local Key Server may generate a SAK.
     */
    macsec_check(ctx->local_key_server, MACSEC_ERR_STATE);

    /*
     * SAK generation requires a live peer.
     */
    macsec_check(ctx->peer.valid && ctx->peer.live, MACSEC_ERR_NOT_READY);

    /*
     * An existing SAK must not be generated again.
     */
    if (ctx->latest_sak.lifecycle_state != MACSEC_MKA_SAK_STATE_NONE)
    {
        macsec_check(ctx->latest_sak.valid, MACSEC_ERR_STATE);

        macsec_check(ctx->latest_sak.origin == MACSEC_MKA_SAK_ORIGIN_LOCAL_KEY_SERVER,
                     MACSEC_ERR_STATE);

        return MACSEC_ERR_OK;
    }

    memset(&ctx->latest_sak, 0, sizeof(ctx->latest_sak));

    /*
     * The current implementation generates a 128-bit SAK.
     * Configurable 128/256-bit SAK generation can be added later.
     */
    macsec_random(ctx->latest_sak.sak, 16u);

    ctx->latest_sak.sak_len = 16u;

    ctx->latest_sak.an = ctx->key_server_next_an & 0x03u;

    ctx->latest_sak.key_number = ctx->key_server_next_key_number;

    ctx->latest_sak.origin = MACSEC_MKA_SAK_ORIGIN_LOCAL_KEY_SERVER;

    ctx->latest_sak.lowest_pn = 1u;

    /*
     * The SAK has not yet been installed in frame_crypto and has not yet
     * been confirmed by the peer.
     */
    ctx->latest_sak.rx_installed = MACSEC_FALSE;

    ctx->latest_sak.tx_installed = MACSEC_FALSE;

    ctx->latest_sak.peer_rx_confirmed = MACSEC_FALSE;

    ctx->latest_sak.peer_tx_confirmed = MACSEC_FALSE;

    /*
     * Legacy SAK Use state retained during migration.
     *
     * These fields do not represent actual frame_crypto installation.
     */
    ctx->latest_key_rx = MACSEC_TRUE;
    ctx->latest_key_tx = MACSEC_FALSE;
    ctx->latest_lowest_pn = 1u;

    macsec_mka_set_sak_state(ctx, MACSEC_MKA_SAK_STATE_CANDIDATE, "local Key Server generated SAK");

    macsec_mka_set_sak_state(ctx, MACSEC_MKA_SAK_STATE_DISTRIBUTION_PENDING,
                             "SAK ready for distribution");

    macsec_mka_raise_events(ctx, MACSEC_MKA_EVENT_TX_DISTRIBUTE_SAK);

    macsec_mka_schedule_tx(ctx, MACSEC_MKA_TX_REASON_DISTRIBUTE_SAK);

    MACSEC_MEDIUM(("MKA Key Server generated SAK: an=%u key_number=%lu lifecycle=%u\n",
                   ctx->latest_sak.an, (unsigned long) ctx->latest_sak.key_number,
                   (unsigned) ctx->latest_sak.lifecycle_state));

    MACSEC_MEDIUM_HEX(("MKA generated SAK", ctx->latest_sak.sak, (int) ctx->latest_sak.sak_len));

    return MACSEC_ERR_OK;
}

static int macsec_mka_write_distributed_sak(uint8_t **p, macsec_mka_ctx_t *ctx)
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

    ret = macsec_mka_crypto_wrap_sak(&ctx->crypto, ctx->latest_sak.sak, ctx->latest_sak.sak_len,
                                     wrapped_sak, &wrapped_sak_len, sizeof(wrapped_sak));
    if (ret != MACSEC_ERR_OK)
    {
        MACSEC_ERROR(("MKA wrap SAK failed ret=%d\n", ret));
        return ret;
    }

    body_len = (uint16_t) (4u + wrapped_sak_len);

    (*p)[0] = MACSEC_MKA_PARAM_DISTRIBUTED_SAK;
    (*p)[1] = 0u;
    (*p)[2] = (uint8_t) ((body_len >> 8u) & 0x0Fu);
    (*p)[3] = (uint8_t) (body_len & 0xFFu);
    *p += 4u;

    macsec_wr_be32(*p, ctx->latest_sak.key_number);
    *p += 4u;

    memcpy(*p, wrapped_sak, wrapped_sak_len);
    *p += wrapped_sak_len;

    MACSEC_MEDIUM(("MKA TX Distributed SAK: an=%u key_number=%lu wrapped_len=%lu\n",
                   ctx->latest_sak.an, (unsigned long) ctx->latest_sak.key_number,
                   (unsigned long) wrapped_sak_len));

    macsec_zeroize(wrapped_sak, sizeof(wrapped_sak));

    return MACSEC_ERR_OK;
}

int macsec_mka_build_tx_frame(macsec_mka_ctx_t *ctx, uint8_t *frame, size_t *frame_len,
                              size_t frame_max_len, macsec_mka_tx_meta_t *meta)
{
    uint8_t *p;
    uint16_t body_len;
    uint16_t peer_list_param_len;
    uint16_t sak_use_param_len;
    uint16_t distributed_sak_param_len;
    uint16_t eapol_len;
    size_t total_len;
    size_t mic_len;
    uint8_t flags_len_hi;
    macsec_bool_t include_peer_list;
    macsec_bool_t include_distributed_sak;
    macsec_bool_t include_sak_use;
    int ret;

    macsec_check(ctx != NULL, MACSEC_ERR_PARAM);
    macsec_check(frame != NULL, MACSEC_ERR_PARAM);
    macsec_check(frame_len != NULL, MACSEC_ERR_PARAM);
    macsec_check(meta != NULL, MACSEC_ERR_PARAM);
    macsec_check(ctx->crypto.keys.valid, MACSEC_ERR_STATE);

    *frame_len = 0u;
    memset(meta, 0, sizeof(*meta));

    /*
     * TX is scheduled whenever at least one reason is pending.
     */
    if (ctx->tx_reasons == MACSEC_MKA_TX_REASON_NONE)
    {
        return MACSEC_ERR_NOT_READY;
    }

    macsec_check(ctx->crypto.psk.ckn_len <= MACSEC_MKA_CA_NAME_MAX_LEN, MACSEC_ERR_BUFFER);

    /*
     * If the local participant is the elected Key Server and has a live
     * peer, ensure that a SAK exists before deciding which parameter sets
     * the frame must contain.
     *
     * SAK generation is persistent protocol state, but it does not commit
     * successful frame transmission.
     */
    if (ctx->local_key_server && ctx->peer.valid && ctx->peer.live)
    {
        ret = macsec_mka_key_server_ensure_sak(ctx);
        if (ret != MACSEC_ERR_OK)
        {
            return ret;
        }
    }

    /*
     * macsec_mka_key_server_ensure_sak() may have added the
     * DISTRIBUTE_SAK reason, so capture reasons only after that call.
     */
    meta->message_number = ctx->local_mn;
    meta->reasons = ctx->tx_reasons;

    body_len = (uint16_t) (28u + ctx->crypto.psk.ckn_len);

    include_peer_list = ctx->peer.valid ? MACSEC_TRUE : MACSEC_FALSE;

    peer_list_param_len = include_peer_list ? (4u + 16u) : 0u;

    include_distributed_sak = MACSEC_FALSE;
    distributed_sak_param_len = 0u;

    /*
     * Include Distributed SAK only while the locally generated SAK is
     * waiting for its first confirmed distribution.
     *
     * Later periodic redistribution policy may deliberately include an
     * already distributed SAK again, but that should be a separate rule.
     */
    if (ctx->local_key_server && ctx->peer.valid && ctx->peer.live && ctx->latest_sak.valid &&
        (ctx->latest_sak.origin == MACSEC_MKA_SAK_ORIGIN_LOCAL_KEY_SERVER) &&
        (ctx->latest_sak.lifecycle_state == MACSEC_MKA_SAK_STATE_DISTRIBUTION_PENDING))
    {
        include_distributed_sak = MACSEC_TRUE;

        if (ctx->latest_sak.sak_len == 16u)
        {
            /*
             * 4 B parameter header
             * 4 B key number
             * 24 B AES-KW wrapped 128-bit SAK
             */
            distributed_sak_param_len = 4u + 4u + 24u;
        }
        else if (ctx->latest_sak.sak_len == 32u)
        {
            /*
             * 4 B parameter header
             * 4 B key number
             * 40 B AES-KW wrapped 256-bit SAK
             */
            distributed_sak_param_len = 4u + 4u + 40u;
        }
        else
        {
            return MACSEC_ERR_STATE;
        }

        meta->distributed_key_number = ctx->latest_sak.key_number;

        meta->distributed_an = ctx->latest_sak.an;
    }

    include_sak_use =
        (ctx->latest_sak.valid && ctx->peer.valid && ctx->peer.live) ? MACSEC_TRUE : MACSEC_FALSE;

    sak_use_param_len = include_sak_use ? (4u + 40u) : 0u;

    eapol_len = (uint16_t) (4u + body_len + peer_list_param_len + distributed_sak_param_len +
                            sak_use_param_len + MACSEC_MKA_ICV_LEN);

    total_len = 14u + 4u + eapol_len;

    macsec_check(total_len <= frame_max_len, MACSEC_ERR_BUFFER);

    macsec_check(total_len <= MACSEC_MKA_MAX_FRAME_LEN, MACSEC_ERR_BUFFER);

    memset(frame, 0, total_len);

    /*
     * Ethernet header.
     */
    memcpy(&frame[0], macsec_mka_dst_mac, MACSEC_MKA_DST_LEN);

    memcpy(&frame[6], ctx->local_mac, MACSEC_MKA_SRC_LEN);

    macsec_wr_be16(&frame[12], MACSEC_MKA_ETHERTYPE_EAPOL);

    /*
     * EAPOL header.
     */
    p = &frame[14];

    p[0] = MACSEC_MKA_EAPOL_VERSION_2010;
    p[1] = MACSEC_MKA_EAPOL_TYPE_MKA;

    macsec_wr_be16(&p[2], eapol_len);

    /*
     * Basic Parameter Set.
     */
    p = &frame[18];

    p[0] = MACSEC_MKA_VERSION_ID;
    p[1] = ctx->key_server_priority;

    flags_len_hi = (uint8_t) ((body_len >> 8u) & 0x0Fu);

    if (ctx->local_key_server)
    {
        flags_len_hi |= 0x80u;
    }

    if (ctx->macsec_desired)
    {
        flags_len_hi |= 0x40u;
    }

    flags_len_hi |= (uint8_t) ((ctx->macsec_capability & 0x03u) << 4u);

    p[2] = flags_len_hi;
    p[3] = (uint8_t) (body_len & 0xFFu);
    p += 4u;

    memcpy(p, ctx->local_sci, MACSEC_MKA_SCI_LEN);
    p += MACSEC_MKA_SCI_LEN;

    memcpy(p, ctx->local_mi, MACSEC_MKA_MI_LEN);
    p += MACSEC_MKA_MI_LEN;

    /*
     * The current MN is written into the frame but is not incremented
     * until transmission success is reported.
     */
    macsec_wr_be32(p, meta->message_number);
    p += 4u;

    macsec_wr_be32(p, MACSEC_MKA_ALGORITHM_AGILITY);
    p += 4u;

    memcpy(p, ctx->crypto.psk.ckn, ctx->crypto.psk.ckn_len);
    p += ctx->crypto.psk.ckn_len;

    if (include_peer_list)
    {
        macsec_mka_write_peer_list(&p,
                                   ctx->peer.live ? MACSEC_MKA_PARAM_LIVE_PEER_LIST
                                                  : MACSEC_MKA_PARAM_POTENTIAL_PEER_LIST,
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

    if (include_sak_use)
    {
        macsec_mka_write_sak_use(&p, ctx);
    }

    mic_len = total_len - MACSEC_MKA_ICV_LEN;

    ret = macsec_mka_crypto_calc_mic(&ctx->crypto, frame, mic_len, &frame[mic_len]);

    if (ret != MACSEC_ERR_OK)
    {
        MACSEC_ERROR(("MKA TX ICV calculation failed ret=%d\n", ret));

        return ret;
    }

    meta->contains_peer_list = include_peer_list;

    meta->contains_distributed_sak = include_distributed_sak;

    meta->contains_sak_use = include_sak_use;

    *frame_len = total_len;

    MACSEC_MEDIUM(("MKA TX frame built: mn=%lu frame_len=%lu reasons=0x%08lX key_server=%u "
                   "peer_list=%u dist_sak=%u sak_use=%u\n",
                   (unsigned long) meta->message_number, (unsigned long) *frame_len,
                   (unsigned long) meta->reasons, ctx->local_key_server ? 1u : 0u,
                   meta->contains_peer_list ? 1u : 0u, meta->contains_distributed_sak ? 1u : 0u,
                   meta->contains_sak_use ? 1u : 0u));

    /*
     * Deliberately unchanged here:
     *
     *   ctx->local_mn
     *   ctx->last_tx_ms
     *   ctx->tx_reasons
     *   ctx->latest_sak.lifecycle_state
     */

    return MACSEC_ERR_OK;
}

int macsec_mka_notify_tx_success(macsec_mka_ctx_t *ctx, const macsec_mka_tx_meta_t *meta,
                                 uint32_t now_ms)
{
    macsec_check(ctx != NULL, MACSEC_ERR_PARAM);
    macsec_check(meta != NULL, MACSEC_ERR_PARAM);

    /*
     * The notification must refer to the current uncommitted MN.
     */
    if (meta->message_number != ctx->local_mn)
    {
        MACSEC_ERROR(("MKA TX success rejected: meta_mn=%lu current_mn=%lu\n",
                      (unsigned long) meta->message_number, (unsigned long) ctx->local_mn));

        return MACSEC_ERR_STATE;
    }

    if (meta->reasons == MACSEC_MKA_TX_REASON_NONE)
    {
        return MACSEC_ERR_PARAM;
    }

    /*
     * The successfully transmitted frame may acknowledge only reasons
     * that were actually pending when the frame was built.
     *
     * It is acceptable that some of these reasons are already absent if
     * the caller serializes TX operations through macsec.c. However, the
     * metadata must not contain unknown flag bits.
     */
    if ((meta->reasons &
         (uint32_t) ~(MACSEC_MKA_TX_REASON_INITIAL | MACSEC_MKA_TX_REASON_PERIODIC |
                      MACSEC_MKA_TX_REASON_PEER_CHANGE | MACSEC_MKA_TX_REASON_KEY_SERVER_CHANGE |
                      MACSEC_MKA_TX_REASON_DISTRIBUTE_SAK | MACSEC_MKA_TX_REASON_SAK_USE |
                      MACSEC_MKA_TX_REASON_REKEY)) != 0u)
    {
        return MACSEC_ERR_PARAM;
    }

    /*
     * Commit successful distribution only when this exact transmitted
     * frame contained the current pending local SAK.
     */
    if (meta->contains_distributed_sak)
    {
        if (!ctx->latest_sak.valid ||
            (ctx->latest_sak.origin != MACSEC_MKA_SAK_ORIGIN_LOCAL_KEY_SERVER) ||
            (ctx->latest_sak.lifecycle_state != MACSEC_MKA_SAK_STATE_DISTRIBUTION_PENDING) ||
            (ctx->latest_sak.key_number != meta->distributed_key_number) ||
            (ctx->latest_sak.an != meta->distributed_an))
        {
            MACSEC_ERROR(("MKA TX success Distributed SAK mismatch: meta_key=%lu meta_an=%u "
                          "current_key=%lu current_an=%u state=%u\n",
                          (unsigned long) meta->distributed_key_number, meta->distributed_an,
                          (unsigned long) ctx->latest_sak.key_number, ctx->latest_sak.an,
                          (unsigned) ctx->latest_sak.lifecycle_state));

            return MACSEC_ERR_STATE;
        }

        macsec_mka_set_sak_state(ctx, MACSEC_MKA_SAK_STATE_DISTRIBUTED,
                                 "Distributed SAK MKPDU transmitted successfully");

        if (ctx->latest_sak.lifecycle_state != MACSEC_MKA_SAK_STATE_DISTRIBUTED)
        {
            return MACSEC_ERR_STATE;
        }

        macsec_mka_raise_events(ctx,
                                MACSEC_MKA_EVENT_SAK_DISTRIBUTED | MACSEC_MKA_EVENT_SAK_AVAILABLE);

        /*
         * Reserve the next Key Number and AN for a future rekey.
         * This is done only on the first successful distribution.
         */
        ctx->key_server_next_key_number++;

        if (ctx->key_server_next_key_number == 0u)
        {
            /*
             * Key Number zero is not used by this implementation.
             */
            ctx->key_server_next_key_number = 1u;
        }

        ctx->key_server_next_an = (uint8_t) ((ctx->key_server_next_an + 1u) & 0x03u);
    }

    /*
     * Commit the transmitted message number only after successful TX.
     */
    ctx->local_mn++;

    if (ctx->local_mn == 0u)
    {
        /*
         * Actor MN zero is avoided by this implementation.
         */
        ctx->local_mn = 1u;
    }

    ctx->last_tx_ms = (now_ms != 0u) ? now_ms : 1u;

    /*
     * Clear only reasons represented by this frame. Reasons scheduled after
     * frame construction remain pending.
     */
    ctx->tx_reasons &= ~meta->reasons;

    MACSEC_MEDIUM(("MKA TX success: mn=%lu next_mn=%lu now=%lu sent_reasons=0x%08lX "
                   "remaining_reasons=0x%08lX dist_sak=%u\n",
                   (unsigned long) meta->message_number, (unsigned long) ctx->local_mn,
                   (unsigned long) ctx->last_tx_ms, (unsigned long) meta->reasons,
                   (unsigned long) ctx->tx_reasons, meta->contains_distributed_sak ? 1u : 0u));

    return MACSEC_ERR_OK;
}

void macsec_mka_notify_tx_failure(macsec_mka_ctx_t *ctx, const macsec_mka_tx_meta_t *meta)
{
    macsec_assert(ctx != NULL);
    macsec_assert(meta != NULL);

    /*
     * A failed transmission must not commit:
     *
     *   local_mn
     *   last_tx_ms
     *   SAK distribution
     *
     * Re-add the snapshot reasons in case additional code modified the
     * scheduler while the frame was awaiting transmission.
     */
    ctx->tx_reasons |= meta->reasons;

    MACSEC_MEDIUM(("MKA TX failure: mn=%lu reasons=0x%08lX pending_reasons=0x%08lX\n",
                   (unsigned long) meta->message_number, (unsigned long) meta->reasons,
                   (unsigned long) ctx->tx_reasons));
}

int macsec_mka_verify_icv(macsec_mka_ctx_t *ctx, const uint8_t *frame, size_t frame_len,
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
                 (unsigned long) frame_len, (unsigned long) mic_len, basic->eapol_len));

    /*
     * The received frame must contain:
     *
     *   MIC input bytes + 16-byte ICV
     */
    macsec_check(frame_len >= (mic_len + MACSEC_MKA_ICV_LEN), MACSEC_ERR_BUFFER);

    macsec_check(mic_len <= sizeof(ctx->mic_work), MACSEC_ERR_BUFFER);

    memcpy(ctx->mic_work, frame, mic_len);

    MACSEC_INFO_HEX(("MKA MIC input", ctx->mic_work, (int) mic_len));
    MACSEC_INFO_HEX(("MKA RX ICV", basic->icv, MACSEC_MKA_ICV_LEN));

    /*
     * basic->icv was already extracted by macsec_mka_parse_basic().
     * macsec_mka_crypto_verify_mic() calculates AES-CMAC with ICK
     * and compares the result with the received ICV.
     */
    ret = macsec_mka_crypto_verify_mic(&ctx->crypto, ctx->mic_work, mic_len, basic->icv);

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
    MACSEC_PRINT(("  EAPOL version=%u type=%u len=%u\n", basic->eapol_version, basic->eapol_type,
                  basic->eapol_len));

    MACSEC_PRINT(("  MKA version=%u priority=%u key_server=%u desired=%u cap=%u body_len=%u\n",
                  basic->mka_version, basic->key_server_priority, basic->key_server,
                  basic->macsec_desired, basic->macsec_capability, basic->body_len));

    MACSEC_PRINT(("  MN=%u algorithm_agility=0x%08X CAKNameLen=%u\n", basic->actor_mn,
                  basic->algorithm_agility, (unsigned) basic->cak_name_len));

    MACSEC_PRINT_HEX(("Src MAC", basic->src_mac, 6));
    MACSEC_PRINT_HEX(("SCI", basic->sci, MACSEC_MKA_SCI_LEN));
    MACSEC_PRINT_HEX(("Actor MI", basic->actor_mi, MACSEC_MKA_MI_LEN));
    MACSEC_PRINT_HEX(("CAK Name", basic->cak_name, (int) basic->cak_name_len));
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

void macsec_mka_set_latest_key_tx(macsec_mka_ctx_t *ctx, uint8_t an, uint32_t lowest_pn)
{
    uint32_t normalized_lowest_pn;
    macsec_bool_t state_changed;

    macsec_assert(ctx != NULL);

    if (!ctx->latest_sak.valid)
    {
        MACSEC_INFO(("MKA set latest key TX ignored: no valid SAK\n"));

        return;
    }

    if ((ctx->latest_sak.an & 0x03u) != (an & 0x03u))
    {
        MACSEC_INFO(("MKA set latest key TX ignored: requested AN=%u current AN=%u\n", an & 0x03u,
                     ctx->latest_sak.an & 0x03u));

        return;
    }

    normalized_lowest_pn = (lowest_pn != 0u) ? lowest_pn : 1u;

    state_changed = (!ctx->latest_key_tx) || (!ctx->latest_key_rx) ||
                    (!ctx->latest_sak.tx_installed) || (!ctx->latest_sak.rx_installed) ||
                    (ctx->latest_lowest_pn != normalized_lowest_pn) ||
                    (ctx->latest_sak.lowest_pn != normalized_lowest_pn);

    /*
     * Legacy SAK Use state.
     */
    ctx->latest_key_tx = MACSEC_TRUE;
    ctx->latest_key_rx = MACSEC_TRUE;
    ctx->latest_lowest_pn = normalized_lowest_pn;

    /*
     * New installation tracking.
     */
    ctx->latest_sak.rx_installed = MACSEC_TRUE;

    ctx->latest_sak.tx_installed = MACSEC_TRUE;

    ctx->latest_sak.lowest_pn = normalized_lowest_pn;

    if (state_changed)
    {
        macsec_mka_raise_events(ctx, MACSEC_MKA_EVENT_TX_SAK_USE);

        macsec_mka_schedule_tx(ctx, MACSEC_MKA_TX_REASON_SAK_USE);

        MACSEC_MEDIUM(
            ("MKA latest key TX/RX installed by legacy API: key_number=%lu an=%u lowest_pn=%lu\n",
             (unsigned long) ctx->latest_sak.key_number, ctx->latest_sak.an,
             (unsigned long) normalized_lowest_pn));
    }
}
