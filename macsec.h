/*
 * macsec.h
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

#ifndef MACSEC_MACSEC_H_
#define MACSEC_MACSEC_H_

#include "common.h"
#include "frame_crypto.h"
#include "mka.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MACSEC_ETHERTYPE_EAPOL     0x888Eu
#define MACSEC_MAC_ADDR_LEN        6u
#define MACSEC_CAK_MAX_LEN         32u
#define MACSEC_CKN_MAX_LEN         32u

/**
 * @brief MACsec operating mode.
 */
typedef enum
{
    /** MACsec disabled. Frames pass through unchanged. */
    MACSEC_MODE_DISABLED = 0,

    /** Static SAK mode. No MKA. SAK is installed directly from config. */
    MACSEC_MODE_STATIC_SAK,

    /** MKA PSK mode. CAK/CKN are used by MKA to authenticate peers. */
    MACSEC_MODE_MKA_PSK
} macsec_mode_t;

/**
 * @brief Top-level MACsec state.
 */
typedef enum
{
    /** Initial state before configuration is complete. */
    MACSEC_STATE_INIT = 0,

    /** Waiting for MKA peer/authentication/SAK installation. */
    MACSEC_STATE_WAIT_MKA,

    /** Secure data path is ready. Data frames can be encrypted/decrypted. */
    MACSEC_STATE_SECURED,

    /** Fatal or unrecoverable MACsec error. */
    MACSEC_STATE_ERROR
} macsec_state_t;

/**
 * @brief Ethernet MAC address.
 */
typedef struct
{
    /** 6-byte Ethernet MAC address. */
    uint8_t addr[MACSEC_MAC_ADDR_LEN];
} macsec_mac_addr_t;

/**
 * @brief Top-level MACsec configuration.
 */
typedef struct
{
    /** Selected MACsec mode. */
    macsec_mode_t mode;

    /** Local Ethernet MAC address used to build SCI and transmit MKA frames. */
    macsec_mac_addr_t local_mac;

    /**
     * MACsec port identifier.
     *
     * Usually 1. Together with local_mac it forms SCI:
     *   SCI = local_mac || port_id
     */
    uint16_t port_id;

    /**
     * Connectivity Association Key.
     *
     * Used only in MKA PSK mode.
     */
    uint8_t cak[MACSEC_CAK_MAX_LEN];

    /** Length of CAK in bytes. Usually 16 for AES-128. */
    size_t cak_len;

    /**
     * Connectivity Association Key Name.
     *
     * Used by MKA as CAK Name / CKN.
     */
    uint8_t ckn[MACSEC_CKN_MAX_LEN];

    /** Length of CKN in bytes. */
    size_t ckn_len;

    /**
     * Static Secure Association Key.
     *
     * Used only in MACSEC_MODE_STATIC_SAK.
     */
    uint8_t static_sak[MACSEC_FRAME_MAX_KEY_LEN];

    /** Length of static SAK in bytes. Usually 16 for AES-128. */
    size_t static_sak_len;

    /**
     * Static Association Number.
     *
     * Valid range is 0..3.
     */
    uint8_t static_an;

    /**
     * Enable MACsec replay protection.
     *
     * For first bring-up with static test keys it is often useful to keep this false.
     */
    macsec_bool_t replay_protect;

    /**
     * Replay protection window.
     *
     * 0 means strict monotonic PN checking.
     */
    uint32_t replay_window;

    /**
     * Seed for platform random generator.
     *
     * Used later by MKA for MI/SAK generation.
     */
    uint32_t seed;

    /**
     * MKA Key Server Priority.
     *
     * Lower value wins. Linux default in your log is 255.
     */
    uint8_t key_server_priority;

    /**
     * MKA transmit interval in milliseconds.
     *
     * 0 means default.
     */
    uint32_t mka_tx_interval_ms;
} macsec_config_t;

/**
 * @brief Top-level MACsec context.
 *
 * This object owns both:
 *   - data-plane frame crypto
 *   - MKA control-plane state
 */
typedef struct
{
    /** Stored copy of user configuration. */
    macsec_config_t cfg;

    /** Current top-level MACsec state. */
    macsec_state_t state;

    /** MACsec data-plane frame crypto context. */
    macsec_frame_crypto_ctx_t frame_crypto;

    /** MKA control-plane context. */
    macsec_mka_ctx_t mka;

    /** Last timestamp passed to macsec_tick(). */
    uint32_t last_tick_ms;

    uint8_t pending_tx_sak[MACSEC_MKA_SAK_MAX_LEN];
    size_t pending_tx_sak_len;
    uint8_t pending_tx_an;
    macsec_bool_t pending_tx_sak_valid;
} macsec_ctx_t;

/**
 * @brief Initialize top-level MACsec context.
 *
 * @param ctx MACsec context to initialize.
 * @param cfg MACsec configuration.
 *
 * @return MACSEC_ERR_OK on success, otherwise MACSEC_ERR_*.
 */
int macsec_init(macsec_ctx_t *ctx, const macsec_config_t *cfg);

/**
 * @brief Clear MACsec context and release internal resources.
 *
 * @param ctx MACsec context.
 */
void macsec_clear(macsec_ctx_t *ctx);

/**
 * @brief Get current MACsec state.
 *
 * @param ctx MACsec context.
 *
 * @return Current MACsec state.
 */
macsec_state_t macsec_get_state(const macsec_ctx_t *ctx);

/**
 * @brief Check whether data-plane is secured and ready.
 *
 * @param ctx MACsec context.
 *
 * @return true if secure data-plane is ready.
 */
macsec_bool_t macsec_is_secured(const macsec_ctx_t *ctx);

/**
 * @brief Process received Ethernet frame.
 *
 * This function is called by Ethernet driver/router for every received frame.
 *
 * Behavior:
 *   - EAPOL/MKA 0x888E frames are consumed by MKA and are not passed upward.
 *   - MACsec 0x88E5 frames are decrypted and passed upward if valid.
 *   - Plain frames are passed only when MACsec mode is disabled.
 *
 * @param ctx MACsec context.
 * @param rx_frame Received Ethernet frame.
 * @param rx_len Length of received frame.
 * @param plain_frame Output buffer for decrypted/plain frame.
 * @param plain_len Output length.
 * @param plain_max_len Output buffer size.
 * @param pass_to_stack Set to true when plain_frame should be passed upward.
 *
 * @return MACSEC_ERR_OK or MACSEC_ERR_*.
 */
int macsec_input(macsec_ctx_t *ctx,
                 const uint8_t *rx_frame,
                 size_t rx_len,
                 uint8_t *plain_frame,
                 size_t *plain_len,
                 size_t plain_max_len,
                 macsec_bool_t *pass_to_stack);

/**
 * @brief Protect outgoing Ethernet frame.
 *
 * This function is called for outgoing data frames from upper stack/router.
 *
 * Behavior:
 *   - In disabled mode, frame is copied unchanged.
 *   - In secured mode, frame is MACsec protected as 0x88E5.
 *   - In WAIT_MKA state, data traffic is rejected.
 *
 * @param ctx MACsec context.
 * @param plain_frame Plain Ethernet frame.
 * @param plain_len Length of plain Ethernet frame.
 * @param tx_frame Output buffer for protected frame.
 * @param tx_len Output length.
 * @param tx_max_len Output buffer size.
 *
 * @return MACSEC_ERR_OK or MACSEC_ERR_*.
 */
int macsec_output(macsec_ctx_t *ctx,
                  const uint8_t *plain_frame,
                  size_t plain_len,
                  uint8_t *tx_frame,
                  size_t *tx_len,
                  size_t tx_max_len);

/**
 * @brief Periodic MACsec processing.
 *
 * Called periodically by application/task.
 *
 * Later this will drive:
 *   - MKA timers
 *   - peer timeout
 *   - MKPDU transmission scheduling
 *   - SAK installation
 *
 * @param ctx MACsec context.
 * @param now_ms Current time in milliseconds.
 *
 * @return MACSEC_ERR_OK or MACSEC_ERR_*.
 */
int macsec_tick(macsec_ctx_t *ctx, uint32_t now_ms);

/**
 * @brief Get pending MKA control frame.
 *
 * If MKA wants to transmit an EAPOL/MKA frame, this function writes it to
 * tx_frame. The caller must send it as raw Ethernet frame, not through
 * macsec_output().
 *
 * @param ctx MACsec context.
 * @param tx_frame Output buffer.
 * @param tx_len Output frame length.
 * @param tx_max_len Output buffer size.
 *
 * @return MACSEC_ERR_OK when a control frame is ready.
 *         MACSEC_ERR_NOT_READY when no control frame is pending.
 */
int macsec_get_control_frame(macsec_ctx_t *ctx,
                             uint8_t *tx_frame,
                             size_t *tx_len,
                             size_t tx_max_len);

#ifdef __cplusplus
}
#endif

#endif /* MACSEC_MACSEC_H_ */
