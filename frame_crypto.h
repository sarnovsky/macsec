/*
 * frame_crypto.h
 *
 * Lightweight MACsec stack
 * MACsec frame protection and recovery layer.
 * This file implements encryption and decryption of Ethernet frames using
 * MACsec SecTAG/ICV handling and AES-GCM based authenticated encryption.
 *
 * Copyright (c) 2026 Michal Sarnovsky
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */

#ifndef MACSEC_FRAME_CRYPTO_H
#define MACSEC_FRAME_CRYPTO_H

#include "macsec_common.h"
#include "math/gcm.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define MACSEC_FRAME_ETHERTYPE 0x88E5u

#define MACSEC_FRAME_ETH_HDR_LEN 14u
#define MACSEC_FRAME_SECTAG_LEN 14u
#define MACSEC_FRAME_ICV_LEN 16u
#define MACSEC_FRAME_AAD_LEN (MACSEC_FRAME_ETH_HDR_LEN + MACSEC_FRAME_SECTAG_LEN)

#define MACSEC_FRAME_SCI_LEN 8u
#define MACSEC_FRAME_MAX_SA 4u
#define MACSEC_FRAME_MAX_KEY_LEN 32u

#define MACSEC_FRAME_MAX_PLAIN_SIZE 1600u
#define MACSEC_FRAME_MAX_SECURE_SIZE 1700u

typedef struct
{
    uint8_t bytes[MACSEC_FRAME_SCI_LEN];
} macsec_frame_sci_t;

typedef struct
{
    uint8_t key[MACSEC_FRAME_MAX_KEY_LEN];
    uint8_t key_len;

    uint8_t an;
    uint32_t next_pn;
    uint32_t lowest_acceptable_pn;

    macsec_bool_t valid;
} macsec_frame_sak_t;

typedef struct
{
    macsec_frame_sci_t local_sci;

    macsec_frame_sak_t tx_sak;
    macsec_frame_sak_t rx_sak[MACSEC_FRAME_MAX_SA];

    macsec_bool_t encrypt;
    macsec_bool_t replay_protect;
    uint32_t replay_window;

    math_gcm_context gcm;
    macsec_bool_t gcm_initialized;

    uint8_t current_gcm_key[MACSEC_FRAME_MAX_KEY_LEN];
    uint8_t current_gcm_key_len;
    macsec_bool_t current_gcm_key_valid;
} macsec_frame_crypto_ctx_t;

typedef struct
{
    macsec_frame_crypto_ctx_t tx_ctx;
    macsec_frame_crypto_ctx_t rx_ctx;

    uint8_t plain[MACSEC_FRAME_MAX_PLAIN_SIZE];
    uint8_t secure[MACSEC_FRAME_MAX_SECURE_SIZE];
    uint8_t decrypted[MACSEC_FRAME_MAX_PLAIN_SIZE];
} macsec_frame_crypto_self_test_ctx_t;

int macsec_frame_crypto_init(macsec_frame_crypto_ctx_t *ctx, const macsec_frame_sci_t *local_sci);

void macsec_frame_crypto_clear(macsec_frame_crypto_ctx_t *ctx);

int macsec_frame_crypto_set_tx_sak(macsec_frame_crypto_ctx_t *ctx, const macsec_frame_sak_t *sak);

int macsec_frame_crypto_set_rx_sak(macsec_frame_crypto_ctx_t *ctx, const macsec_frame_sak_t *sak);

macsec_bool_t macsec_frame_crypto_ready_tx(const macsec_frame_crypto_ctx_t *ctx);

macsec_bool_t macsec_frame_crypto_ready_rx(const macsec_frame_crypto_ctx_t *ctx, uint8_t an);

macsec_bool_t macsec_frame_is_macsec(const uint8_t *frame, size_t frame_len);

int macsec_frame_encrypt(macsec_frame_crypto_ctx_t *ctx, const uint8_t *plain_eth,
                         size_t plain_eth_len, uint8_t *secure_eth, size_t *secure_eth_len,
                         size_t secure_eth_max_len);

int macsec_frame_decrypt(macsec_frame_crypto_ctx_t *ctx, const uint8_t *secure_eth,
                         size_t secure_eth_len, uint8_t *plain_eth, size_t *plain_eth_len,
                         size_t plain_eth_max_len);

/*
 * Returns:
 *   0 = self-test OK
 *   1 = self-test failed
 */
int macsec_frame_crypto_self_test(macsec_frame_crypto_self_test_ctx_t *test_ctx, int verbose);

#ifdef __cplusplus
}
#endif

#endif /* MACSEC_FRAME_CRYPTO_H */
