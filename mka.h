/*
 * mka.h
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

#ifndef MACSEC_MKA_H
#define MACSEC_MKA_H

#include <macsec/common.h>
#include <macsec/mka_crypto.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MACSEC_MKA_ETHERTYPE_EAPOL       0x888Eu
#define MACSEC_MKA_EAPOL_TYPE_MKA        5u
#define MACSEC_MKA_EAPOL_VERSION_2010    3u

#define MACSEC_MKA_DST_LEN               6u
#define MACSEC_MKA_SRC_LEN               6u
#define MACSEC_MKA_SCI_LEN               8u
#define MACSEC_MKA_MI_LEN                12u
#define MACSEC_MKA_ICV_LEN               16u
#define MACSEC_MKA_CA_NAME_MAX_LEN       32u

#define MACSEC_MKA_MAX_FRAME_LEN         512u

typedef enum
{
    MACSEC_MKA_STATE_INIT = 0,
    MACSEC_MKA_STATE_WAIT_PEER,
    MACSEC_MKA_STATE_PEER_FOUND,
    MACSEC_MKA_STATE_AUTHENTICATED,
    MACSEC_MKA_STATE_ERROR
} macsec_mka_state_t;

typedef struct
{
    uint8_t dst_mac[6];
    uint8_t src_mac[6];

    uint8_t eapol_version;
    uint8_t eapol_type;
    uint16_t eapol_len;

    uint8_t mka_version;
    uint8_t key_server_priority;

    macsec_bool_t key_server;
    macsec_bool_t macsec_desired;
    uint8_t macsec_capability;

    uint16_t body_len;

    uint8_t sci[MACSEC_MKA_SCI_LEN];
    uint8_t actor_mi[MACSEC_MKA_MI_LEN];
    uint32_t actor_mn;
    uint32_t algorithm_agility;

    uint8_t cak_name[MACSEC_MKA_CA_NAME_MAX_LEN];
    size_t cak_name_len;

    uint8_t icv[MACSEC_MKA_ICV_LEN];
} macsec_mka_basic_t;

typedef struct
{
    macsec_bool_t valid;

    uint8_t mac[6];
    uint8_t sci[MACSEC_MKA_SCI_LEN];
    uint8_t mi[MACSEC_MKA_MI_LEN];
    uint32_t mn;

    uint8_t key_server_priority;
    macsec_bool_t key_server;
    macsec_bool_t macsec_desired;
    uint8_t macsec_capability;

    uint32_t last_seen_ms;

    macsec_bool_t seen_in_peer_list;
    macsec_bool_t live;
} macsec_mka_peer_t;

typedef struct
{
    macsec_bool_t valid;

    /*
     * Secure Association Key received from MKA Distributed SAK.
     * 16 bytes = AES-128 SAK
     * 32 bytes = AES-256 SAK
     */
    uint8_t sak[MACSEC_MKA_SAK_MAX_LEN];
    size_t sak_len;

    /*
     * Association Number from MKA/SAK distribution.
     * Valid range is 0..3.
     */
    uint8_t an;

    uint32_t key_number;
} macsec_mka_sak_t;

typedef struct
{
    macsec_mka_state_t state;

    macsec_mka_crypto_ctx_t crypto;

    macsec_mka_peer_t peer;
    macsec_mka_basic_t last_basic;

    macsec_mka_sak_t latest_sak;

    macsec_bool_t verify_icv;
    macsec_bool_t last_icv_valid;

    uint8_t mic_work[MACSEC_MKA_MAX_FRAME_LEN];

    uint32_t last_rx_ms;

    uint8_t local_mac[6];
    uint8_t local_sci[MACSEC_MKA_SCI_LEN];
    uint8_t local_mi[MACSEC_MKA_MI_LEN];
    uint32_t local_mn;

    uint8_t key_server_priority;
    macsec_bool_t local_key_server;
    macsec_bool_t macsec_desired;
    uint8_t macsec_capability;
    uint32_t key_server_next_key_number;
    uint8_t key_server_next_an;
    uint32_t tx_interval_ms;
    uint32_t last_tx_ms;
    uint32_t last_tick_ms;
    macsec_bool_t tx_pending;

    macsec_bool_t latest_key_tx;
    macsec_bool_t latest_key_rx;
    uint32_t latest_lowest_pn;
} macsec_mka_ctx_t;

int macsec_mka_init(macsec_mka_ctx_t *ctx,
                    const uint8_t *cak,
                    size_t cak_len,
                    const uint8_t *ckn,
                    size_t ckn_len,
                    const uint8_t local_mac[6],
                    uint16_t port_id,
                    uint8_t key_server_priority,
                    uint32_t tx_interval_ms);

int macsec_mka_tick(macsec_mka_ctx_t *ctx, uint32_t now_ms);

int macsec_mka_get_tx_frame(macsec_mka_ctx_t *ctx,
                            uint8_t *frame,
                            size_t *frame_len,
                            size_t frame_max_len);

void macsec_mka_clear(macsec_mka_ctx_t *ctx);

macsec_mka_state_t macsec_mka_get_state(const macsec_mka_ctx_t *ctx);

macsec_bool_t macsec_mka_is_eapol_mka(const uint8_t *frame,
                             size_t frame_len);

int macsec_mka_parse_basic(const uint8_t *frame,
                           size_t frame_len,
                           macsec_mka_basic_t *out);

int macsec_mka_input(macsec_mka_ctx_t *ctx,
                     const uint8_t *frame,
                     size_t frame_len,
                     uint32_t now_ms);

int macsec_mka_verify_icv(macsec_mka_ctx_t *ctx,
                          const uint8_t *frame,
                          size_t frame_len,
                          const macsec_mka_basic_t *basic);

void macsec_mka_print_basic(const macsec_mka_basic_t *basic);

macsec_bool_t macsec_mka_has_sak(const macsec_mka_ctx_t *ctx);

const macsec_mka_sak_t *macsec_mka_get_latest_sak(const macsec_mka_ctx_t *ctx);

void macsec_mka_set_latest_key_tx(macsec_mka_ctx_t *ctx,
                                  uint8_t an,
                                  uint32_t lowest_pn);

#ifdef __cplusplus
}
#endif

#endif /* MACSEC_MKA_H */
