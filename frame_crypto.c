/*
 * frame_crypto.c
 *
 * Lightweight MACsec stack
 * MACsec frame protection and recovery layer.
 * This file implements encryption and decryption of Ethernet frames using
 * MACsec SecTAG/ICV handling and AES-GCM based authenticated encryption.
 *
 * Copyright (c) 2026 Michal Sarnovský
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */

#include "frame_crypto.h"

#define MACSEC_FRAME_TCI_BASE          0x2Cu
#define MACSEC_FRAME_SHORT_LEN_MAX     48u

static macsec_bool_t macsec_frame_key_len_valid(uint8_t key_len)
{
    return (key_len == 16u) || (key_len == 32u) ? MACSEC_TRUE : MACSEC_FALSE;
}

static int macsec_frame_gcm_setkey(macsec_frame_crypto_ctx_t *ctx,
                                   const uint8_t *key,
                                   uint8_t key_len)
{
    int ret;

    macsec_assert(ctx != NULL);
    macsec_assert(key != NULL);
    macsec_assert(macsec_frame_key_len_valid(key_len));

    if (ctx->gcm_initialized)
    {
        math_gcm_free(&ctx->gcm);
        ctx->gcm_initialized = MACSEC_FALSE;
    }

    math_gcm_init(&ctx->gcm);
    ctx->gcm_initialized = MACSEC_TRUE;

    ret = math_gcm_setkey(&ctx->gcm,
                          key,
                          (unsigned int)key_len * 8u);

    if (ret != 0)
    {
        return MACSEC_ERR_CRYPTO;
    }

    return MACSEC_ERR_OK;
}

int macsec_frame_crypto_init(macsec_frame_crypto_ctx_t *ctx,
                             const macsec_frame_sci_t *local_sci)
{
    macsec_assert(ctx != NULL);
    macsec_assert(local_sci != NULL);

    memset(ctx, 0, sizeof(macsec_frame_crypto_ctx_t));

    ctx->local_sci = *local_sci;
    ctx->encrypt = MACSEC_TRUE;
    ctx->replay_protect = MACSEC_TRUE;
    ctx->replay_window = 0u;

    math_gcm_init(&ctx->gcm);
    ctx->gcm_initialized = MACSEC_TRUE;

    MACSEC_MEDIUM(("Frame crypto init: encrypt=%u replay=%u window=%lu\n",
                   ctx->encrypt ? 1u : 0u,
                   ctx->replay_protect ? 1u : 0u,
                   (unsigned long)ctx->replay_window));
    MACSEC_MEDIUM_HEX(("Frame local SCI", ctx->local_sci.bytes, MACSEC_FRAME_SCI_LEN));

    return MACSEC_ERR_OK;
}

void macsec_frame_crypto_clear(macsec_frame_crypto_ctx_t *ctx)
{
    macsec_assert(ctx != NULL);

    MACSEC_MEDIUM(("Frame crypto clear\n"));

    if (ctx->gcm_initialized)
    {
        math_gcm_free(&ctx->gcm);
        ctx->gcm_initialized = MACSEC_FALSE;
    }

    macsec_zeroize(ctx, sizeof(*ctx));
}

int macsec_frame_crypto_set_tx_sak(macsec_frame_crypto_ctx_t *ctx,
                                   const macsec_frame_sak_t *sak)
{
    macsec_assert(ctx != NULL);
    macsec_assert(sak != NULL);
    macsec_check(sak->valid, MACSEC_ERR_PARAM);
    macsec_check(macsec_frame_key_len_valid(sak->key_len), MACSEC_ERR_PARAM);
    macsec_check(sak->an < MACSEC_FRAME_MAX_SA, MACSEC_ERR_PARAM);

    ctx->tx_sak = *sak;

    if (ctx->tx_sak.next_pn == 0u)
    {
        ctx->tx_sak.next_pn = 1u;
    }

    MACSEC_MEDIUM(("Frame TX SAK installed: an=%u key_len=%u next_pn=%lu\n",
                   ctx->tx_sak.an,
                   ctx->tx_sak.key_len,
                   (unsigned long)ctx->tx_sak.next_pn));
    MACSEC_INFO_HEX(("Frame TX SAK key", ctx->tx_sak.key, ctx->tx_sak.key_len));

    return MACSEC_ERR_OK;
}

int macsec_frame_crypto_set_rx_sak(macsec_frame_crypto_ctx_t *ctx,
                                   const macsec_frame_sak_t *sak)
{
    uint8_t an;

    macsec_assert(ctx != NULL);
    macsec_assert(sak != NULL);
    macsec_check(sak->valid, MACSEC_ERR_PARAM);
    macsec_check(macsec_frame_key_len_valid(sak->key_len), MACSEC_ERR_PARAM);
    macsec_check(sak->an < MACSEC_FRAME_MAX_SA, MACSEC_ERR_PARAM);

    an = sak->an;
    ctx->rx_sak[an] = *sak;

    if (ctx->rx_sak[an].lowest_acceptable_pn == 0u)
    {
        ctx->rx_sak[an].lowest_acceptable_pn = 1u;
    }

    MACSEC_MEDIUM(("Frame RX SAK installed: an=%u key_len=%u lowest_pn=%lu\n",
                   an,
                   ctx->rx_sak[an].key_len,
                   (unsigned long)ctx->rx_sak[an].lowest_acceptable_pn));
    MACSEC_INFO_HEX(("Frame RX SAK key", ctx->rx_sak[an].key, ctx->rx_sak[an].key_len));

    return MACSEC_ERR_OK;
}

macsec_bool_t macsec_frame_crypto_ready_tx(const macsec_frame_crypto_ctx_t *ctx)
{
    macsec_assert(ctx != NULL);

    return ctx->tx_sak.valid &&
        macsec_frame_key_len_valid(ctx->tx_sak.key_len);
}

macsec_bool_t macsec_frame_crypto_ready_rx(const macsec_frame_crypto_ctx_t *ctx,
                                           uint8_t an)
{
    macsec_assert(ctx != NULL);
    if (an >= MACSEC_FRAME_MAX_SA)
    {
        return MACSEC_FALSE;
    }

    return ctx->rx_sak[an].valid &&
           macsec_frame_key_len_valid(ctx->rx_sak[an].key_len);
}

macsec_bool_t macsec_frame_is_macsec(const uint8_t *frame,
                                     size_t frame_len)
{
    macsec_assert(frame != NULL);
    if (frame_len < MACSEC_FRAME_ETH_HDR_LEN)
    {
        return MACSEC_FALSE;
    }

    return macsec_rd_be16(&frame[12]) == MACSEC_FRAME_ETHERTYPE;
}

int macsec_frame_encrypt(macsec_frame_crypto_ctx_t *ctx,
                         const uint8_t *plain_eth,
                         size_t plain_eth_len,
                         uint8_t *secure_eth,
                         size_t *secure_eth_len,
                         size_t secure_eth_max_len)
{
    uint8_t iv[12];
    uint8_t *sectag;
    uint8_t *ciphertext;
    uint8_t *icv;
    const uint8_t *secure_data;
    size_t secure_len;
    size_t out_len;
    uint32_t pn;
    int ret;

    macsec_assert(ctx != NULL);
    macsec_assert(plain_eth != NULL);
    macsec_assert(secure_eth != NULL);
    macsec_assert(secure_eth_len != NULL);

    macsec_check(ctx->encrypt, MACSEC_ERR_UNSUPPORTED);
    macsec_check(macsec_frame_crypto_ready_tx(ctx), MACSEC_ERR_STATE);
    macsec_check(plain_eth_len >= MACSEC_FRAME_ETH_HDR_LEN, MACSEC_ERR_BUFFER);

    secure_data = plain_eth + 12u;
    secure_len = plain_eth_len - 12u;

    out_len = MACSEC_FRAME_ETH_HDR_LEN +
              MACSEC_FRAME_SECTAG_LEN +
              secure_len +
              MACSEC_FRAME_ICV_LEN;

    macsec_check(out_len <= secure_eth_max_len, MACSEC_ERR_BUFFER);

    pn = ctx->tx_sak.next_pn;
    macsec_check(pn != 0u, MACSEC_ERR_STATE);

    MACSEC_INFO(("Frame encrypt: plain_len=%lu secure_len=%lu out_len=%lu an=%u pn=%lu\n",
                 (unsigned long)plain_eth_len,
                 (unsigned long)secure_len,
                 (unsigned long)out_len,
                 ctx->tx_sak.an,
                 (unsigned long)pn));

    memcpy(secure_eth, plain_eth, 12u);
    macsec_wr_be16(&secure_eth[12], MACSEC_FRAME_ETHERTYPE);

    sectag = secure_eth + MACSEC_FRAME_ETH_HDR_LEN;

    sectag[0] = (uint8_t)(MACSEC_FRAME_TCI_BASE | (ctx->tx_sak.an & 0x03u));

    if (secure_len < MACSEC_FRAME_SHORT_LEN_MAX)
    {
        sectag[1] = (uint8_t)secure_len;
    }
    else
    {
        sectag[1] = 0u;
    }

    macsec_wr_be32(&sectag[2], pn);
    memcpy(&sectag[6], ctx->local_sci.bytes, MACSEC_FRAME_SCI_LEN);

    memcpy(&iv[0], ctx->local_sci.bytes, MACSEC_FRAME_SCI_LEN);
    memcpy(&iv[8], &sectag[2], 4u);

    ciphertext = secure_eth + MACSEC_FRAME_AAD_LEN;
    icv = secure_eth + MACSEC_FRAME_AAD_LEN + secure_len;

    MACSEC_INFO_HEX(("Frame encrypt IV", iv, sizeof(iv)));
    MACSEC_INFO_HEX(("Frame encrypt AAD", secure_eth, MACSEC_FRAME_AAD_LEN));

    ret = macsec_frame_gcm_setkey(ctx,
                                  ctx->tx_sak.key,
                                  ctx->tx_sak.key_len);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_zeroize(iv, sizeof(iv));
        return ret;
    }

    ret = math_gcm_crypt_and_tag(&ctx->gcm,
                                 MATH_GCM_ENCRYPT,
                                 secure_len,
                                 iv,
                                 sizeof(iv),
                                 secure_eth,
                                 MACSEC_FRAME_AAD_LEN,
                                 secure_data,
                                 ciphertext,
                                 MACSEC_FRAME_ICV_LEN,
                                 icv);

    macsec_zeroize(iv, sizeof(iv));

    if (ret != 0)
    {
        MACSEC_ERROR(("Frame encrypt GCM failed ret=%d\n", ret));
        return MACSEC_ERR_CRYPTO;
    }

    MACSEC_INFO_HEX(("Frame encrypt ICV", icv, MACSEC_FRAME_ICV_LEN));

    ctx->tx_sak.next_pn++;
    *secure_eth_len = out_len;

    MACSEC_INFO(("Frame encrypt OK: tx_len=%lu next_pn=%lu\n",
                 (unsigned long)*secure_eth_len,
                 (unsigned long)ctx->tx_sak.next_pn));

    return MACSEC_ERR_OK;
}

int macsec_frame_decrypt(macsec_frame_crypto_ctx_t *ctx,
                         const uint8_t *secure_eth,
                         size_t secure_eth_len,
                         uint8_t *plain_eth,
                         size_t *plain_eth_len,
                         size_t plain_eth_max_len)
{
    uint8_t iv[12];
    const uint8_t *sectag;
    const uint8_t *aad;
    const uint8_t *ciphertext;
    const uint8_t *icv;
    size_t ciphertext_len;
    uint8_t an;
    uint32_t pn;
    uint32_t new_lowest_pn;
    macsec_frame_sak_t *sak;
    int ret;

    macsec_assert(ctx != NULL);
    macsec_assert(secure_eth != NULL);
    macsec_assert(plain_eth != NULL);
    macsec_assert(plain_eth_len != NULL);

    macsec_check(macsec_frame_is_macsec(secure_eth, secure_eth_len), MACSEC_ERR_PARAM);
    macsec_check(secure_eth_len >= (MACSEC_FRAME_AAD_LEN + MACSEC_FRAME_ICV_LEN),
                 MACSEC_ERR_BUFFER);

    sectag = secure_eth + MACSEC_FRAME_ETH_HDR_LEN;

    an = sectag[0] & 0x03u;

    MACSEC_INFO(("Frame RX SecTAG: tci_an=0x%02X an=%u pn=%lu ready=%u%u%u%u\n",
              sectag[0],
              an,
              (unsigned long)macsec_rd_be32(&sectag[2]),
              macsec_frame_crypto_ready_rx(ctx, 0u) ? 1u : 0u,
              macsec_frame_crypto_ready_rx(ctx, 1u) ? 1u : 0u,
              macsec_frame_crypto_ready_rx(ctx, 2u) ? 1u : 0u,
              macsec_frame_crypto_ready_rx(ctx, 3u) ? 1u : 0u));

    macsec_check(macsec_frame_crypto_ready_rx(ctx, an), MACSEC_ERR_STATE);

    sak = &ctx->rx_sak[an];
    pn = macsec_rd_be32(&sectag[2]);

    MACSEC_INFO(("Frame decrypt: secure_len=%lu an=%u pn=%lu lowest_pn=%lu replay=%u\n",
                 (unsigned long)secure_eth_len,
                 an,
                 (unsigned long)pn,
                 (unsigned long)sak->lowest_acceptable_pn,
                 ctx->replay_protect ? 1u : 0u));

    macsec_check(pn != 0u, MACSEC_ERR_REPLAY);

    if (ctx->replay_protect)
    {
        if (pn < sak->lowest_acceptable_pn)
        {
            MACSEC_ERROR(("Frame replay rejected: pn=%lu lowest=%lu\n",
                          (unsigned long)pn,
                          (unsigned long)sak->lowest_acceptable_pn));
            return MACSEC_ERR_REPLAY;
        }
    }

    aad = secure_eth;
    ciphertext = secure_eth + MACSEC_FRAME_AAD_LEN;
    icv = secure_eth + secure_eth_len - MACSEC_FRAME_ICV_LEN;

    ciphertext_len = secure_eth_len - MACSEC_FRAME_AAD_LEN - MACSEC_FRAME_ICV_LEN;

    macsec_check((12u + ciphertext_len) <= plain_eth_max_len, MACSEC_ERR_BUFFER);

    memcpy(&iv[0], &sectag[6], MACSEC_FRAME_SCI_LEN);
    memcpy(&iv[8], &sectag[2], 4u);

    memcpy(plain_eth, secure_eth, 12u);

    MACSEC_INFO_HEX(("Frame decrypt IV", iv, sizeof(iv)));
    MACSEC_INFO_HEX(("Frame decrypt AAD", aad, MACSEC_FRAME_AAD_LEN));
    MACSEC_INFO_HEX(("Frame decrypt ICV", icv, MACSEC_FRAME_ICV_LEN));

    ret = macsec_frame_gcm_setkey(ctx,
                                  sak->key,
                                  sak->key_len);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_zeroize(iv, sizeof(iv));
        return ret;
    }

    ret = math_gcm_auth_decrypt(&ctx->gcm,
                                ciphertext_len,
                                iv,
                                sizeof(iv),
                                aad,
                                MACSEC_FRAME_AAD_LEN,
                                icv,
                                MACSEC_FRAME_ICV_LEN,
                                ciphertext,
                                plain_eth + 12u);

    macsec_zeroize(iv, sizeof(iv));

    if (ret != 0)
    {
        MACSEC_ERROR(("Frame decrypt GCM/auth failed ret=%d an=%u pn=%lu\n",
                      ret,
                      an,
                      (unsigned long)pn));
        return MACSEC_ERR_CRYPTO;
    }

    if (ctx->replay_protect)
    {
        if (ctx->replay_window == 0u)
        {
            sak->lowest_acceptable_pn = pn + 1u;
        }
        else
        {
            if (pn > ctx->replay_window)
            {
                new_lowest_pn = pn - ctx->replay_window + 1u;
            }
            else
            {
                new_lowest_pn = 1u;
            }

            if (new_lowest_pn > sak->lowest_acceptable_pn)
            {
                sak->lowest_acceptable_pn = new_lowest_pn;
            }
        }

        MACSEC_INFO(("Frame replay update: new_lowest_pn=%lu\n",
                     (unsigned long)sak->lowest_acceptable_pn));
    }

    *plain_eth_len = 12u + ciphertext_len;

    MACSEC_INFO(("Frame decrypt OK: plain_len=%lu\n",
                 (unsigned long)*plain_eth_len));

    return MACSEC_ERR_OK;
}

#if (MACSEC_SELF_TEST != 0)

static void macsec_frame_self_test_fill_packet(uint8_t *packet,
                                               size_t len,
                                               uint8_t seed)
{
    size_t i;

    macsec_assert(packet != NULL);
    macsec_assert(len >= MACSEC_FRAME_ETH_HDR_LEN);

    packet[0] = 0x02u;
    packet[1] = 0x00u;
    packet[2] = 0x00u;
    packet[3] = 0x00u;
    packet[4] = 0x00u;
    packet[5] = 0x01u;

    packet[6] = 0x02u;
    packet[7] = 0x00u;
    packet[8] = 0x00u;
    packet[9] = 0x00u;
    packet[10] = 0x00u;
    packet[11] = 0x02u;

    macsec_wr_be16(&packet[12], 0x0800u);

    for (i = MACSEC_FRAME_ETH_HDR_LEN; i < len; i++)
    {
        packet[i] = (uint8_t)(seed + (uint8_t)i);
    }
}

static int macsec_frame_self_test_one(macsec_frame_crypto_self_test_ctx_t *test_ctx,
                                      size_t plain_len,
                                      uint8_t seed)
{
    macsec_frame_sci_t sci;
    macsec_frame_sak_t sak;
    size_t secure_len;
    size_t decrypted_len;
    int ret;

    static const uint8_t test_key[16] =
    {
        0x00u, 0x11u, 0x22u, 0x33u,
        0x44u, 0x55u, 0x66u, 0x77u,
        0x88u, 0x99u, 0xAAu, 0xBBu,
        0xCCu, 0xDDu, 0xEEu, 0xFFu
    };

    macsec_assert(test_ctx != NULL);
    macsec_check(plain_len <= sizeof(test_ctx->plain), MACSEC_ERR_BUFFER);
    macsec_check(plain_len >= MACSEC_FRAME_ETH_HDR_LEN, MACSEC_ERR_BUFFER);

    sci.bytes[0] = 0x02u;
    sci.bytes[1] = 0x00u;
    sci.bytes[2] = 0x00u;
    sci.bytes[3] = 0x00u;
    sci.bytes[4] = 0x00u;
    sci.bytes[5] = 0x02u;
    sci.bytes[6] = 0x00u;
    sci.bytes[7] = 0x01u;

    memset(&sak, 0, sizeof(macsec_frame_sak_t));
    memcpy(sak.key, test_key, sizeof(test_key));
    sak.key_len = sizeof(test_key);
    sak.an = 0u;
    sak.next_pn = 1u;
    sak.lowest_acceptable_pn = 1u;
    sak.valid = MACSEC_TRUE;

    ret = macsec_frame_crypto_init(&test_ctx->tx_ctx, &sci);
    if (ret != MACSEC_ERR_OK)
    {
        return ret;
    }

    ret = macsec_frame_crypto_init(&test_ctx->rx_ctx, &sci);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_frame_crypto_clear(&test_ctx->tx_ctx);
        return ret;
    }

    test_ctx->tx_ctx.replay_protect = MACSEC_FALSE;
    test_ctx->rx_ctx.replay_protect = MACSEC_FALSE;

    ret = macsec_frame_crypto_set_tx_sak(&test_ctx->tx_ctx, &sak);
    if (ret != MACSEC_ERR_OK)
    {
        goto cleanup;
    }

    ret = macsec_frame_crypto_set_rx_sak(&test_ctx->rx_ctx, &sak);
    if (ret != MACSEC_ERR_OK)
    {
        goto cleanup;
    }

    macsec_frame_self_test_fill_packet(test_ctx->plain, plain_len, seed);

    secure_len = 0u;
    decrypted_len = 0u;

    ret = macsec_frame_encrypt(&test_ctx->tx_ctx,
                               test_ctx->plain,
                               plain_len,
                               test_ctx->secure,
                               &secure_len,
                               sizeof(test_ctx->secure));
    if (ret != MACSEC_ERR_OK)
    {
        goto cleanup;
    }

    ret = macsec_frame_decrypt(&test_ctx->rx_ctx,
                               test_ctx->secure,
                               secure_len,
                               test_ctx->decrypted,
                               &decrypted_len,
                               sizeof(test_ctx->decrypted));
    if (ret != MACSEC_ERR_OK)
    {
        goto cleanup;
    }

    if (decrypted_len != plain_len)
    {
        ret = MACSEC_ERR_AUTH;
        goto cleanup;
    }

    if (memcmp(test_ctx->plain, test_ctx->decrypted, plain_len) != 0)
    {
        ret = MACSEC_ERR_AUTH;
        goto cleanup;
    }

    ret = MACSEC_ERR_OK;

cleanup:
    macsec_frame_crypto_clear(&test_ctx->tx_ctx);
    macsec_frame_crypto_clear(&test_ctx->rx_ctx);

    return ret;
}

int macsec_frame_crypto_self_test(macsec_frame_crypto_self_test_ctx_t *test_ctx,
                                  int verbose)
{
    int ret;

    macsec_check(test_ctx != NULL, 1);

    memset(test_ctx, 0, sizeof(macsec_frame_crypto_self_test_ctx_t));

    if (verbose != 0)
    {
        MACSEC_PRINT(("  MACsec frame crypto self-test #1: "));
    }

    ret = macsec_frame_self_test_one(test_ctx, 60u, 0x10u);

    if (ret != MACSEC_ERR_OK)
    {
        if (verbose != 0)
        {
            MACSEC_PRINT(("failed (%d)\n", ret));
        }

        return 1;
    }

    if (verbose != 0)
    {
        MACSEC_PRINT(("passed\n"));
        MACSEC_PRINT(("  MACsec frame crypto self-test #2: "));
    }

    ret = macsec_frame_self_test_one(test_ctx, 128u, 0x20u);

    if (ret != MACSEC_ERR_OK)
    {
        if (verbose != 0)
        {
            MACSEC_PRINT(("failed (%d)\n", ret));
        }

        return 1;
    }

    if (verbose != 0)
    {
        MACSEC_PRINT(("passed\n"));
        MACSEC_PRINT(("  MACsec frame crypto self-test #3: "));
    }

    ret = macsec_frame_self_test_one(test_ctx, 1514u, 0x30u);

    if (ret != MACSEC_ERR_OK)
    {
        if (verbose != 0)
        {
            MACSEC_PRINT(("failed (%d)\n", ret));
        }

        return 1;
    }

    if (verbose != 0)
    {
        MACSEC_PRINT(("passed\n"));
    }

    macsec_zeroize(test_ctx, sizeof(*test_ctx));

    return 0;
}

#endif /* MACSEC_SELF_TEST */

