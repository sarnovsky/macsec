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

#include "macsec_common.h"
#include "mka_crypto.h"

/*
 * Platform-provided random number generator.
 */
#include "port/port.h"


#ifdef __cplusplus
extern "C" {
#endif


/******************************************************************************
 * MKA protocol constants
 *****************************************************************************/

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

#define MACSEC_FRAME_MAX_SA              4u

/******************************************************************************
 * MKA participant state
 *
 * This state describes the MKA relationship with the peer. It does not by
 * itself guarantee that the SAK has already been installed in frame_crypto.
 *****************************************************************************/

typedef enum
{
    /*
     * Context has not yet completed initialization.
     */
    MACSEC_MKA_STATE_INIT = 0,

    /*
     * Local participant is transmitting MKPDUs, but no valid authenticated
     * peer has yet been discovered.
     */
    MACSEC_MKA_STATE_WAIT_PEER,

    /*
     * A valid authenticated peer is known, but mutual peer-list recognition
     * is not yet complete.
     */
    MACSEC_MKA_STATE_PEER_DISCOVERED,

    /*
     * Mutual participant recognition is complete and Key Server election
     * has a stable result.
     */
    MACSEC_MKA_STATE_PEER_LIVE,

    /*
     * The MKA session has an active SAK confirmed between MKA and the
     * MACsec data-plane.
     */
    MACSEC_MKA_STATE_OPERATIONAL,

    /*
     * Unrecoverable protocol, cryptographic or internal state error.
     */
    MACSEC_MKA_STATE_ERROR
} macsec_mka_state_t;


/*
 * Temporary migration aliases.
 *
 * Remove these after mka.c and the existing tests have been migrated to the
 * new state names.
 */
#define MACSEC_MKA_STATE_PEER_FOUND    MACSEC_MKA_STATE_PEER_DISCOVERED
#define MACSEC_MKA_STATE_AUTHENTICATED MACSEC_MKA_STATE_PEER_LIVE


/******************************************************************************
 * SAK origin and lifecycle
 *****************************************************************************/

typedef enum
{
    /*
     * No SAK origin has been assigned.
     */
    MACSEC_MKA_SAK_ORIGIN_NONE = 0,

    /*
     * SAK was generated locally because this participant is Key Server.
     */
    MACSEC_MKA_SAK_ORIGIN_LOCAL_KEY_SERVER,

    /*
     * SAK was received from the remote Key Server in a Distributed SAK
     * Parameter Set.
     */
    MACSEC_MKA_SAK_ORIGIN_REMOTE_KEY_SERVER
} macsec_mka_sak_origin_t;


typedef enum
{
    /*
     * No valid SAK is currently known.
     */
    MACSEC_MKA_SAK_STATE_NONE = 0,

    /*
     * SAK was generated locally or received and successfully unwrapped,
     * but has not yet been handed to the MACsec data-plane.
     */
    MACSEC_MKA_SAK_STATE_CANDIDATE,

    /*
     * Local Key Server has a SAK waiting to be included in a Distributed
     * SAK Parameter Set.
     */
    MACSEC_MKA_SAK_STATE_DISTRIBUTION_PENDING,

    /*
     * Local Key Server has successfully transmitted at least one MKPDU
     * containing this Distributed SAK.
     */
    MACSEC_MKA_SAK_STATE_DISTRIBUTED,

    /*
     * SAK has been handed to macsec.c and is waiting for confirmation that
     * it was installed in frame_crypto.
     */
    MACSEC_MKA_SAK_STATE_INSTALL_PENDING,

    /*
     * SAK is installed for all required local RX and TX directions.
     */
    MACSEC_MKA_SAK_STATE_ACTIVE,

    /*
     * Active SAK has also been confirmed by the peer through SAK Use.
     */
    MACSEC_MKA_SAK_STATE_CONFIRMED,

    /*
     * SAK is retained temporarily during rekey, but is no longer the main
     * active transmit key.
     */
    MACSEC_MKA_SAK_STATE_RETIRING
} macsec_mka_sak_state_t;


/******************************************************************************
 * MKA event flags
 *
 * Event flags report one-time protocol changes to macsec.c. Persistent state
 * remains stored in macsec_mka_ctx_t and macsec_mka_sak_t.
 *****************************************************************************/

typedef uint32_t macsec_mka_event_flags_t;

#define MACSEC_MKA_EVENT_NONE                  0x00000000u

/*
 * Peer lifecycle events.
 */
#define MACSEC_MKA_EVENT_PEER_DISCOVERED       0x00000001u
#define MACSEC_MKA_EVENT_PEER_LIVE             0x00000002u
#define MACSEC_MKA_EVENT_PEER_LOST             0x00000004u

/*
 * Key Server election event.
 */
#define MACSEC_MKA_EVENT_KEY_SERVER_CHANGED    0x00000008u

/*
 * SAK lifecycle events.
 */
#define MACSEC_MKA_EVENT_SAK_AVAILABLE         0x00000010u
#define MACSEC_MKA_EVENT_SAK_DISTRIBUTED       0x00000020u
#define MACSEC_MKA_EVENT_SAK_ACTIVE            0x00000040u
#define MACSEC_MKA_EVENT_SAK_CONFIRMED         0x00000080u
#define MACSEC_MKA_EVENT_SAK_RETIRED           0x00000100u

/*
 * Control-frame scheduling events.
 */
#define MACSEC_MKA_EVENT_TX_INITIAL            0x00001000u
#define MACSEC_MKA_EVENT_TX_PERIODIC           0x00002000u
#define MACSEC_MKA_EVENT_TX_PEER_CHANGE        0x00004000u
#define MACSEC_MKA_EVENT_TX_KEY_SERVER_CHANGE  0x00008000u
#define MACSEC_MKA_EVENT_TX_DISTRIBUTE_SAK     0x00010000u
#define MACSEC_MKA_EVENT_TX_SAK_USE            0x00020000u

/*
 * Rekey and error events.
 */
#define MACSEC_MKA_EVENT_REKEY_REQUIRED        0x00100000u
#define MACSEC_MKA_EVENT_ERROR                 0x80000000u


/******************************************************************************
 * MKA transmit reasons
 *
 * These flags describe why an MKPDU must be transmitted. Unlike the legacy
 * tx_pending flag, individual reasons can be retained or cleared separately.
 *****************************************************************************/

typedef uint32_t macsec_mka_tx_reason_flags_t;

/*
 * Temporary compatibility alias.
 *
 * Remove after all existing code has migrated to
 * macsec_mka_tx_reason_flags_t.
 */
typedef macsec_mka_tx_reason_flags_t macsec_mka_tx_reason_t;

#define MACSEC_MKA_TX_REASON_NONE               0x00000000u
#define MACSEC_MKA_TX_REASON_INITIAL            0x00000001u
#define MACSEC_MKA_TX_REASON_PERIODIC           0x00000002u
#define MACSEC_MKA_TX_REASON_PEER_CHANGE        0x00000004u
#define MACSEC_MKA_TX_REASON_KEY_SERVER_CHANGE  0x00000008u
#define MACSEC_MKA_TX_REASON_DISTRIBUTE_SAK     0x00000010u
#define MACSEC_MKA_TX_REASON_SAK_USE            0x00000020u
#define MACSEC_MKA_TX_REASON_REKEY              0x00000040u


/******************************************************************************
 * SAK installation directions
 *****************************************************************************/

typedef uint8_t macsec_mka_install_directions_t;

#define MACSEC_MKA_INSTALL_NONE  0x00u
#define MACSEC_MKA_INSTALL_RX    0x01u
#define MACSEC_MKA_INSTALL_TX    0x02u


/******************************************************************************
 * Parsed MKA Basic Parameter Set
 *****************************************************************************/

typedef struct
{
    uint8_t dst_mac[MACSEC_MKA_DST_LEN];
    uint8_t src_mac[MACSEC_MKA_SRC_LEN];

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


/******************************************************************************
 * MKA peer
 *****************************************************************************/

typedef struct
{
    macsec_bool_t valid;

    uint8_t mac[MACSEC_MKA_SRC_LEN];
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


/******************************************************************************
 * MKA SAK
 *
 * The legacy valid member is temporarily retained so that the existing mka.c
 * and macsec.c continue to compile during state-machine migration.
 *****************************************************************************/

typedef struct
{
    /*
     * Legacy validity flag.
     *
     * During migration:
     *
     *   valid == false  normally corresponds to lifecycle_state == NONE
     *   valid == true   normally corresponds to lifecycle_state != NONE
     *
     * Remove after all code uses lifecycle_state.
     */
    macsec_bool_t valid;

    /*
     * Secure Association Key.
     *
     * 16 bytes = AES-128 SAK
     * 32 bytes = AES-256 SAK
     */
    uint8_t sak[MACSEC_MKA_SAK_MAX_LEN];
    size_t sak_len;

    /*
     * Association Number, valid range 0..3.
     */
    uint8_t an;

    /*
     * MKA Key Number.
     */
    uint32_t key_number;

    /*
     * New lifecycle information.
     */
    macsec_mka_sak_origin_t origin;
    macsec_mka_sak_state_t lifecycle_state;

    /*
     * Installation state reported by macsec.c.
     */
    macsec_bool_t rx_installed;
    macsec_bool_t tx_installed;

    /*
     * Peer confirmation received through SAK Use.
     */
    macsec_bool_t peer_rx_confirmed;
    macsec_bool_t peer_tx_confirmed;

    /*
     * Lowest acceptable packet number associated with the active SAK.
     */
    uint32_t lowest_pn;
} macsec_mka_sak_t;


/******************************************************************************
 * Metadata describing a built MKPDU
 *
 * The metadata is later passed to macsec_mka_notify_tx_success() or
 * macsec_mka_notify_tx_failure().
 *****************************************************************************/

typedef struct
{
    uint32_t message_number;

    macsec_mka_tx_reason_flags_t reasons;

    macsec_bool_t contains_peer_list;
    macsec_bool_t contains_distributed_sak;
    macsec_bool_t contains_sak_use;

    uint32_t distributed_key_number;
    uint8_t distributed_an;
} macsec_mka_tx_meta_t;

/******************************************************************************
 * MKA context
 *****************************************************************************/

typedef struct
{
    /*
     * MKA participant state.
     */
    macsec_mka_state_t state;

    macsec_mka_crypto_ctx_t crypto;

    macsec_mka_peer_t peer;
    macsec_mka_basic_t last_basic;

    /*
     * Current/latest SAK.
     *
     * The existing field name is retained for migration compatibility.
     */
    macsec_mka_sak_t latest_sak;

    macsec_bool_t verify_icv;
    macsec_bool_t last_icv_valid;

    uint8_t mic_work[MACSEC_MKA_MAX_FRAME_LEN];

    uint32_t last_rx_ms;

    uint8_t local_mac[MACSEC_MKA_SRC_LEN];
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

    /*
     * New event and TX-reason fields.
     *
     * These fields are introduced in phase 1 and will replace the legacy
     * tx_pending flag in later migration phases.
     */
    macsec_mka_event_flags_t pending_events;
    macsec_mka_tx_reason_flags_t tx_reasons;

    /*
     * Legacy TX scheduling field.
     *
     * Remove after macsec_mka_get_tx_frame() is replaced by the
     * build/notify TX lifecycle.
     */
    macsec_bool_t tx_pending;

    /*
     * Legacy SAK Use fields.
     *
     * Remove after all code uses latest_sak.rx_installed,
     * latest_sak.tx_installed and latest_sak.lowest_pn.
     */
    macsec_bool_t latest_key_tx;
    macsec_bool_t latest_key_rx;
    uint32_t latest_lowest_pn;
} macsec_mka_ctx_t;


/******************************************************************************
 * Existing MKA API
 *
 * These functions remain available during the migration.
 *****************************************************************************/

int macsec_mka_init(macsec_mka_ctx_t *ctx,
                    const uint8_t *cak,
                    size_t cak_len,
                    const uint8_t *ckn,
                    size_t ckn_len,
                    const uint8_t local_mac[MACSEC_MKA_SRC_LEN],
                    uint16_t port_id,
                    uint8_t key_server_priority,
                    uint32_t tx_interval_ms);

void macsec_mka_clear(macsec_mka_ctx_t *ctx);

macsec_mka_state_t macsec_mka_get_state(const macsec_mka_ctx_t *ctx);

int macsec_mka_tick(macsec_mka_ctx_t *ctx,
                    uint32_t now_ms);

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


/******************************************************************************
 * Legacy TX and SAK API
 *
 * Remove after macsec.c has been migrated to the event-driven API.
 *****************************************************************************/

macsec_bool_t macsec_mka_has_sak(const macsec_mka_ctx_t *ctx);

const macsec_mka_sak_t *
macsec_mka_get_latest_sak(const macsec_mka_ctx_t *ctx);

void macsec_mka_set_latest_key_tx(macsec_mka_ctx_t *ctx,
                                  uint8_t an,
                                  uint32_t lowest_pn);


/******************************************************************************
 * New event-driven MKA API
 *
 * These declarations are introduced in phase 1. Their implementation will be
 * added incrementally in the following phases.
 *****************************************************************************/

/*
 * Return and atomically clear all currently pending MKA events.
 */
macsec_mka_event_flags_t
macsec_mka_take_events(macsec_mka_ctx_t *ctx);


/*
 * Build an MKPDU without yet committing the transmission as successful.
 */
int macsec_mka_build_tx_frame(macsec_mka_ctx_t *ctx,
                              uint8_t *frame,
                              size_t *frame_len,
                              size_t frame_max_len,
                              macsec_mka_tx_meta_t *meta);


/*
 * Notify MKA that the previously built MKPDU was successfully transmitted.
 */
int macsec_mka_notify_tx_success(macsec_mka_ctx_t *ctx,
                                 const macsec_mka_tx_meta_t *meta,
                                 uint32_t now_ms);


/*
 * Notify MKA that transmission of the previously built MKPDU failed.
 *
 * Required TX reasons remain scheduled for a later retry.
 */
void macsec_mka_notify_tx_failure(macsec_mka_ctx_t *ctx,
                                  const macsec_mka_tx_meta_t *meta);


/*
 * Return a SAK that is ready for installation in the MACsec data-plane.
 *
 * On the first successful handoff, the lifecycle moves to INSTALL_PENDING.
 * A SAK in INSTALL_PENDING may be returned again until all required RX and
 * TX installation directions have been confirmed.
 */
int macsec_mka_take_sak_for_install(macsec_mka_ctx_t *ctx,
                                    macsec_mka_sak_t *sak);

/*
 * Notify MKA which SAK directions were successfully installed in the
 * MACsec data-plane.
 */
int macsec_mka_notify_sak_installed(
    macsec_mka_ctx_t *ctx,
    uint32_t key_number,
    uint8_t an,
    macsec_mka_install_directions_t installed_directions,
    uint32_t lowest_pn);


/*
 * Notify MKA that an old SAK has been removed from the MACsec data-plane.
 */
int macsec_mka_notify_sak_retired(macsec_mka_ctx_t *ctx,
                                  uint32_t key_number,
                                  uint8_t an);


#ifdef __cplusplus
}
#endif

#endif /* MACSEC_MKA_H */
