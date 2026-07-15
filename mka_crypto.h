/*
 * mka_crypto.h
 *
 * Lightweight MACsec stack
 * Cryptographic helper functions for the MKA protocol.
 * This file contains MKA-specific cryptographic operations such as key
 * derivation, integrity calculation and other helpers built on top of the
 * selected cryptographic backend.
 *
 * Copyright (c) 2026 Michal Sarnovský
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */

#ifndef MACSEC_MKA_CRYPTO_H
#define MACSEC_MKA_CRYPTO_H

#include "macsec_common.h"
#include "math/aes.h"
#include "math/cmac.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MACSEC_MKA_CAK_MAX_LEN       32u
#define MACSEC_MKA_CKN_MAX_LEN       32u

#define MACSEC_MKA_ICK_MAX_LEN       32u
#define MACSEC_MKA_KEK_MAX_LEN       32u
#define MACSEC_MKA_MIC_LEN           16u

#define MACSEC_MKA_SAK_MAX_LEN       32u
#define MACSEC_MKA_WRAPPED_MAX_LEN   (MACSEC_MKA_SAK_MAX_LEN + 8u)

#define MACSEC_MKA_SELFTEST_BUF_LEN  256u

typedef struct
{
    uint8_t cak[MACSEC_MKA_CAK_MAX_LEN];
    uint8_t cak_len;

    uint8_t ckn[MACSEC_MKA_CKN_MAX_LEN];
    uint8_t ckn_len;

    macsec_bool_t valid;
} macsec_mka_psk_t;

typedef struct
{
    uint8_t ick[MACSEC_MKA_ICK_MAX_LEN];
    uint8_t ick_len;

    uint8_t kek[MACSEC_MKA_KEK_MAX_LEN];
    uint8_t kek_len;

    macsec_bool_t valid;
} macsec_mka_keys_t;

typedef struct
{
    macsec_mka_psk_t psk;
    macsec_mka_keys_t keys;

    math_cmac_context_t cmac_ctx;
    macsec_bool_t cmac_initialized;

    math_aes_context aes_ctx;
    macsec_bool_t aes_initialized;
} macsec_mka_crypto_ctx_t;

typedef struct
{
    macsec_mka_crypto_ctx_t ctx;

    uint8_t pdu[MACSEC_MKA_SELFTEST_BUF_LEN];
    uint8_t mic[MACSEC_MKA_MIC_LEN];
    uint8_t mic_check[MACSEC_MKA_MIC_LEN];

    uint8_t sak[MACSEC_MKA_SAK_MAX_LEN];
    uint8_t wrapped[MACSEC_MKA_WRAPPED_MAX_LEN];
    uint8_t unwrapped[MACSEC_MKA_SAK_MAX_LEN];
} macsec_mka_crypto_self_test_ctx_t;

int macsec_mka_crypto_init(macsec_mka_crypto_ctx_t *ctx);
void macsec_mka_crypto_clear(macsec_mka_crypto_ctx_t *ctx);

int macsec_mka_crypto_set_psk(macsec_mka_crypto_ctx_t *ctx,
                              const uint8_t *cak,
                              size_t cak_len,
                              const uint8_t *ckn,
                              size_t ckn_len);

int macsec_mka_crypto_derive_ick_kek(macsec_mka_crypto_ctx_t *ctx);

int macsec_mka_crypto_calc_mic(macsec_mka_crypto_ctx_t *ctx,
                               const uint8_t *pdu,
                               size_t pdu_len,
                               uint8_t mic[MACSEC_MKA_MIC_LEN]);

int macsec_mka_crypto_verify_mic(macsec_mka_crypto_ctx_t *ctx,
                                 const uint8_t *pdu,
                                 size_t pdu_len,
                                 const uint8_t mic[MACSEC_MKA_MIC_LEN]);

int macsec_mka_crypto_wrap_sak(macsec_mka_crypto_ctx_t *ctx,
                               const uint8_t *sak,
                               size_t sak_len,
                               uint8_t *wrapped_sak,
                               size_t *wrapped_sak_len,
                               size_t wrapped_sak_max_len);

int macsec_mka_crypto_unwrap_sak(macsec_mka_crypto_ctx_t *ctx,
                                 const uint8_t *wrapped_sak,
                                 size_t wrapped_sak_len,
                                 uint8_t *sak,
                                 size_t *sak_len,
                                 size_t sak_max_len);

/*
 * Returns:
 *   0 = self-test OK
 *   1 = self-test failed
 */
int macsec_mka_crypto_self_test(macsec_mka_crypto_self_test_ctx_t *test_ctx,
                                int verbose);

#ifdef __cplusplus
}
#endif

#endif /* MACSEC_MKA_CRYPTO_H */
