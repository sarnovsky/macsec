/*
 * test_rekey.c
 *
 * Lightweight MACsec stack
 * Rekeying and key update tests.
 * This file validates Secure Association Key (SAK) replacement, packet
 * number continuity and key transition procedures during MACsec operation.
 *
 * Copyright (c) 2026 Michal Sarnovsky
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */

#include <tests/test_rekey.h>
#include <tests/unit_tests.h>

#include <string.h>

#if (MACSEC_SELF_TEST != 0)

#define MACSEC_TEST_REKEY_ETHERNET_HEADER_LEN 14u
#define MACSEC_TEST_REKEY_IPV4_ETHERTYPE 0x0800u

#define MACSEC_TEST_REKEY_SECTAG_OFFSET MACSEC_FRAME_ETH_HDR_LEN
#define MACSEC_TEST_REKEY_SECTAG_TCI_AN 0u
#define MACSEC_TEST_REKEY_SECTAG_PN 2u

#define MACSEC_TEST_REKEY_SAK_LEN 16u
#define MACSEC_TEST_REKEY_AN_MASK 0x03u

static void macsec_test_rekey_fill_plain_frame(uint8_t *frame, size_t len, uint16_t ethertype,
                                               uint8_t seed)
{
    size_t i;

    macsec_assert(frame != NULL);
    macsec_assert(len >= MACSEC_TEST_REKEY_ETHERNET_HEADER_LEN);

    frame[0] = 0x02u;
    frame[1] = 0x00u;
    frame[2] = 0x00u;
    frame[3] = 0x00u;
    frame[4] = 0x00u;
    frame[5] = 0x02u;

    frame[6] = 0x02u;
    frame[7] = 0x00u;
    frame[8] = 0x00u;
    frame[9] = 0x00u;
    frame[10] = 0x00u;
    frame[11] = 0x01u;

    macsec_wr_be16(&frame[12], ethertype);

    for (i = MACSEC_TEST_REKEY_ETHERNET_HEADER_LEN; i < len; i++)
    {
        frame[i] = (uint8_t) (seed + (uint8_t) i);
    }
}

static void macsec_test_rekey_make_sak(macsec_frame_sak_t *sak, uint8_t an, uint8_t seed)
{
    size_t i;

    macsec_assert(sak != NULL);

    memset(sak, 0, sizeof(*sak));

    for (i = 0u; i < MACSEC_TEST_REKEY_SAK_LEN; i++)
    {
        sak->key[i] = (uint8_t) (seed + (uint8_t) (i * 7u));
    }

    sak->key_len = MACSEC_TEST_REKEY_SAK_LEN;
    sak->an = an & MACSEC_TEST_REKEY_AN_MASK;
    sak->next_pn = 1u;
    sak->lowest_acceptable_pn = 1u;
    sak->valid = MACSEC_TRUE;
}

static void macsec_test_rekey_make_tx_sci(macsec_frame_sci_t *sci)
{
    macsec_assert(sci != NULL);

    sci->bytes[0] = 0x02u;
    sci->bytes[1] = 0x00u;
    sci->bytes[2] = 0x00u;
    sci->bytes[3] = 0x00u;
    sci->bytes[4] = 0x00u;
    sci->bytes[5] = 0x01u;
    sci->bytes[6] = 0x00u;
    sci->bytes[7] = 0x01u;
}

static void macsec_test_rekey_make_rx_sci(macsec_frame_sci_t *rx_sci,
                                          const macsec_frame_sci_t *tx_sci)
{
    macsec_assert(rx_sci != NULL);
    macsec_assert(tx_sci != NULL);

    *rx_sci = *tx_sci;

    /*
     * The receive context represents another SecY and therefore has a
     * different local SCI. The SCI carried by an incoming SecTAG identifies
     * the transmitting Secure Channel, not the receiver's local channel.
     */
    rx_sci->bytes[5] ^= 0x01u;
}

static int macsec_test_rekey_init_context_pair(macsec_frame_crypto_ctx_t *tx_ctx,
                                               macsec_frame_crypto_ctx_t *rx_ctx,
                                               const macsec_frame_sci_t *tx_sci,
                                               const macsec_frame_sci_t *rx_sci)
{
    int ret;

    macsec_assert(tx_ctx != NULL);
    macsec_assert(rx_ctx != NULL);
    macsec_assert(tx_sci != NULL);
    macsec_assert(rx_sci != NULL);

    ret = macsec_frame_crypto_init(tx_ctx, tx_sci);
    if (ret != MACSEC_ERR_OK)
    {
        return ret;
    }

    ret = macsec_frame_crypto_init(rx_ctx, rx_sci);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_frame_crypto_clear(tx_ctx);
        return ret;
    }

    tx_ctx->replay_protect = MACSEC_FALSE;
    rx_ctx->replay_protect = MACSEC_FALSE;

    return MACSEC_ERR_OK;
}

static void macsec_test_rekey_clear_context_pair(macsec_frame_crypto_ctx_t *tx_ctx,
                                                 macsec_frame_crypto_ctx_t *rx_ctx)
{
    macsec_assert(tx_ctx != NULL);
    macsec_assert(rx_ctx != NULL);

    macsec_frame_crypto_clear(tx_ctx);
    macsec_frame_crypto_clear(rx_ctx);
}

static int
macsec_test_rekey_an_rotation_decrypts_all(macsec_test_rekey_an_rotation_decrypts_all_data_t *data,
                                           int verbose)
{
    const size_t plain_len = MACSEC_TEST_REKEY_PLAIN_LEN;

    macsec_frame_sci_t rx_sci;

    size_t secure_len;
    size_t decrypted_len;

    uint8_t an;

    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  Rekey AN rotation decrypts all AN test\n"));
    }

    macsec_assert(data != NULL);

    macsec_test_rekey_make_tx_sci(&data->sci);
    macsec_test_rekey_make_rx_sci(&rx_sci, &data->sci);

    ret = macsec_test_rekey_init_context_pair(&data->tx_ctx, &data->rx_ctx, &data->sci, &rx_sci);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_zeroize(&rx_sci, sizeof(rx_sci));
        return ret;
    }

    for (an = 0u; an < MACSEC_FRAME_MAX_SA; an++)
    {
        macsec_test_rekey_make_sak(&data->sak, an, (uint8_t) (0x10u + (an * 0x20u)));

        ret = macsec_frame_crypto_set_tx_sak(&data->tx_ctx, &data->sak);
        if (ret != MACSEC_ERR_OK)
        {
            macsec_test_rekey_clear_context_pair(&data->tx_ctx, &data->rx_ctx);
            macsec_zeroize(&rx_sci, sizeof(rx_sci));
            return ret;
        }

        ret = macsec_frame_crypto_set_rx_sak(&data->rx_ctx, &data->sak);
        if (ret != MACSEC_ERR_OK)
        {
            macsec_test_rekey_clear_context_pair(&data->tx_ctx, &data->rx_ctx);
            macsec_zeroize(&rx_sci, sizeof(rx_sci));
            return ret;
        }

        macsec_test_rekey_fill_plain_frame(data->plain, plain_len, MACSEC_TEST_REKEY_IPV4_ETHERTYPE,
                                           (uint8_t) (0x40u + an));

        secure_len = 0u;
        decrypted_len = 0u;

        ret = macsec_frame_encrypt(&data->tx_ctx, data->plain, plain_len, data->secure, &secure_len,
                                   sizeof(data->secure));
        if (ret != MACSEC_ERR_OK)
        {
            macsec_test_rekey_clear_context_pair(&data->tx_ctx, &data->rx_ctx);
            macsec_zeroize(&rx_sci, sizeof(rx_sci));
            return ret;
        }

        TEST_TRUE((data->secure[MACSEC_TEST_REKEY_SECTAG_OFFSET + MACSEC_TEST_REKEY_SECTAG_TCI_AN] &
                   MACSEC_TEST_REKEY_AN_MASK) == an);

        TEST_EQ_U32(
            macsec_rd_be32(
                &data->secure[MACSEC_TEST_REKEY_SECTAG_OFFSET + MACSEC_TEST_REKEY_SECTAG_PN]),
            1u);

        ret = macsec_frame_decrypt(&data->rx_ctx, data->secure, secure_len, data->decrypted,
                                   &decrypted_len, sizeof(data->decrypted));
        if (ret != MACSEC_ERR_OK)
        {
            macsec_test_rekey_clear_context_pair(&data->tx_ctx, &data->rx_ctx);
            macsec_zeroize(&rx_sci, sizeof(rx_sci));
            return ret;
        }

        TEST_EQ_U32(decrypted_len, plain_len);
        TEST_MEM_EQ(data->plain, data->decrypted, plain_len);
    }

    macsec_test_rekey_clear_context_pair(&data->tx_ctx, &data->rx_ctx);

    macsec_zeroize(&rx_sci, sizeof(rx_sci));

    return 0;
}

static int macsec_test_rekey_old_rx_sak_still_accepted(
    macsec_test_rekey_old_rx_sak_still_accepted_data_t *data, int verbose)
{
    const size_t plain_len = MACSEC_TEST_REKEY_PLAIN_LEN;

    macsec_frame_sci_t rx_sci;

    size_t secure0_len;
    size_t secure1_len;
    size_t decrypted_len;

    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  Rekey old RX SAK still accepted test\n"));
    }

    macsec_assert(data != NULL);

    macsec_test_rekey_make_tx_sci(&data->sci);
    macsec_test_rekey_make_rx_sci(&rx_sci, &data->sci);

    macsec_test_rekey_make_sak(&data->sak0, 0u, 0x11u);
    macsec_test_rekey_make_sak(&data->sak1, 1u, 0x55u);

    ret = macsec_test_rekey_init_context_pair(&data->tx_ctx, &data->rx_ctx, &data->sci, &rx_sci);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_zeroize(&rx_sci, sizeof(rx_sci));
        return ret;
    }

    ret = macsec_frame_crypto_set_tx_sak(&data->tx_ctx, &data->sak0);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_test_rekey_clear_context_pair(&data->tx_ctx, &data->rx_ctx);
        macsec_zeroize(&rx_sci, sizeof(rx_sci));
        return ret;
    }

    ret = macsec_frame_crypto_set_rx_sak(&data->rx_ctx, &data->sak0);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_test_rekey_clear_context_pair(&data->tx_ctx, &data->rx_ctx);
        macsec_zeroize(&rx_sci, sizeof(rx_sci));
        return ret;
    }

    macsec_test_rekey_fill_plain_frame(data->plain0, plain_len, MACSEC_TEST_REKEY_IPV4_ETHERTYPE,
                                       0x21u);

    secure0_len = 0u;

    ret = macsec_frame_encrypt(&data->tx_ctx, data->plain0, plain_len, data->secure0, &secure0_len,
                               sizeof(data->secure0));
    if (ret != MACSEC_ERR_OK)
    {
        macsec_test_rekey_clear_context_pair(&data->tx_ctx, &data->rx_ctx);
        macsec_zeroize(&rx_sci, sizeof(rx_sci));
        return ret;
    }

    /*
     * Install the new SAK under another AN. The previous RX SA must remain
     * available so that delayed frames protected with the old AN can still
     * be authenticated and decrypted.
     */
    ret = macsec_frame_crypto_set_tx_sak(&data->tx_ctx, &data->sak1);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_test_rekey_clear_context_pair(&data->tx_ctx, &data->rx_ctx);
        macsec_zeroize(&rx_sci, sizeof(rx_sci));
        return ret;
    }

    ret = macsec_frame_crypto_set_rx_sak(&data->rx_ctx, &data->sak1);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_test_rekey_clear_context_pair(&data->tx_ctx, &data->rx_ctx);
        macsec_zeroize(&rx_sci, sizeof(rx_sci));
        return ret;
    }

    macsec_test_rekey_fill_plain_frame(data->plain1, plain_len, MACSEC_TEST_REKEY_IPV4_ETHERTYPE,
                                       0x31u);

    secure1_len = 0u;

    ret = macsec_frame_encrypt(&data->tx_ctx, data->plain1, plain_len, data->secure1, &secure1_len,
                               sizeof(data->secure1));
    if (ret != MACSEC_ERR_OK)
    {
        macsec_test_rekey_clear_context_pair(&data->tx_ctx, &data->rx_ctx);
        macsec_zeroize(&rx_sci, sizeof(rx_sci));
        return ret;
    }

    TEST_TRUE((data->secure0[MACSEC_TEST_REKEY_SECTAG_OFFSET + MACSEC_TEST_REKEY_SECTAG_TCI_AN] &
               MACSEC_TEST_REKEY_AN_MASK) == 0u);

    TEST_TRUE((data->secure1[MACSEC_TEST_REKEY_SECTAG_OFFSET + MACSEC_TEST_REKEY_SECTAG_TCI_AN] &
               MACSEC_TEST_REKEY_AN_MASK) == 1u);

    TEST_EQ_U32(macsec_rd_be32(
                    &data->secure0[MACSEC_TEST_REKEY_SECTAG_OFFSET + MACSEC_TEST_REKEY_SECTAG_PN]),
                1u);

    TEST_EQ_U32(macsec_rd_be32(
                    &data->secure1[MACSEC_TEST_REKEY_SECTAG_OFFSET + MACSEC_TEST_REKEY_SECTAG_PN]),
                1u);

    decrypted_len = 0u;

    ret = macsec_frame_decrypt(&data->rx_ctx, data->secure0, secure0_len, data->decrypted,
                               &decrypted_len, sizeof(data->decrypted));
    if (ret != MACSEC_ERR_OK)
    {
        macsec_test_rekey_clear_context_pair(&data->tx_ctx, &data->rx_ctx);
        macsec_zeroize(&rx_sci, sizeof(rx_sci));
        return ret;
    }

    TEST_EQ_U32(decrypted_len, plain_len);
    TEST_MEM_EQ(data->plain0, data->decrypted, plain_len);

    decrypted_len = 0u;

    ret = macsec_frame_decrypt(&data->rx_ctx, data->secure1, secure1_len, data->decrypted,
                               &decrypted_len, sizeof(data->decrypted));
    if (ret != MACSEC_ERR_OK)
    {
        macsec_test_rekey_clear_context_pair(&data->tx_ctx, &data->rx_ctx);
        macsec_zeroize(&rx_sci, sizeof(rx_sci));
        return ret;
    }

    TEST_EQ_U32(decrypted_len, plain_len);
    TEST_MEM_EQ(data->plain1, data->decrypted, plain_len);

    macsec_test_rekey_clear_context_pair(&data->tx_ctx, &data->rx_ctx);

    macsec_zeroize(&rx_sci, sizeof(rx_sci));

    return 0;
}
static int
macsec_test_rekey_wrong_key_same_an_fails(macsec_test_rekey_wrong_key_same_an_fails_data_t *data,
                                          int verbose)
{
    const size_t plain_len = MACSEC_TEST_REKEY_PLAIN_LEN;

    macsec_frame_sci_t rx_sci;

    size_t secure_len;
    size_t decrypted_len;

    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  Rekey wrong key same AN fails test\n"));
    }

    macsec_assert(data != NULL);

    macsec_test_rekey_make_tx_sci(&data->sci);
    macsec_test_rekey_make_rx_sci(&rx_sci, &data->sci);

    macsec_test_rekey_make_sak(&data->tx_sak, 1u, 0x10u);
    macsec_test_rekey_make_sak(&data->wrong_rx_sak, 1u, 0x99u);

    ret = macsec_test_rekey_init_context_pair(&data->tx_ctx, &data->rx_ctx, &data->sci, &rx_sci);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_zeroize(&rx_sci, sizeof(rx_sci));
        return ret;
    }

    ret = macsec_frame_crypto_set_tx_sak(&data->tx_ctx, &data->tx_sak);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_test_rekey_clear_context_pair(&data->tx_ctx, &data->rx_ctx);
        macsec_zeroize(&rx_sci, sizeof(rx_sci));
        return ret;
    }

    ret = macsec_frame_crypto_set_rx_sak(&data->rx_ctx, &data->wrong_rx_sak);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_test_rekey_clear_context_pair(&data->tx_ctx, &data->rx_ctx);
        macsec_zeroize(&rx_sci, sizeof(rx_sci));
        return ret;
    }

    macsec_test_rekey_fill_plain_frame(data->plain, plain_len, MACSEC_TEST_REKEY_IPV4_ETHERTYPE,
                                       0x41u);

    secure_len = 0u;
    decrypted_len = 0u;

    ret = macsec_frame_encrypt(&data->tx_ctx, data->plain, plain_len, data->secure, &secure_len,
                               sizeof(data->secure));
    if (ret != MACSEC_ERR_OK)
    {
        macsec_test_rekey_clear_context_pair(&data->tx_ctx, &data->rx_ctx);
        macsec_zeroize(&rx_sci, sizeof(rx_sci));
        return ret;
    }

    TEST_TRUE((data->secure[MACSEC_TEST_REKEY_SECTAG_OFFSET + MACSEC_TEST_REKEY_SECTAG_TCI_AN] &
               MACSEC_TEST_REKEY_AN_MASK) == data->tx_sak.an);

    TEST_EQ_U32(macsec_rd_be32(
                    &data->secure[MACSEC_TEST_REKEY_SECTAG_OFFSET + MACSEC_TEST_REKEY_SECTAG_PN]),
                1u);

    ret = macsec_frame_decrypt(&data->rx_ctx, data->secure, secure_len, data->decrypted,
                               &decrypted_len, sizeof(data->decrypted));

    macsec_test_rekey_clear_context_pair(&data->tx_ctx, &data->rx_ctx);

    macsec_zeroize(&rx_sci, sizeof(rx_sci));

    /*
     * A frame protected with a different key under the same AN must fail
     * authentication. No unauthenticated plaintext may be returned.
     */
    TEST_TRUE(ret == MACSEC_ERR_AUTH);
    TEST_EQ_U32(decrypted_len, 0u);

    return 0;
}

int macsec_test_rekey(macsec_test_rekey_data_t *data, int verbose)
{
    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("MACsec rekey tests\n"));
    }

    macsec_assert(data != NULL);

    ret = macsec_test_rekey_an_rotation_decrypts_all(&data->rekey_an_rotation_decrypts_all_data,
                                                     verbose);
    if (ret != 0)
    {
        return ret;
    }

    ret = macsec_test_rekey_old_rx_sak_still_accepted(&data->rekey_old_rx_sak_still_accepted_data,
                                                      verbose);
    if (ret != 0)
    {
        return ret;
    }

    ret = macsec_test_rekey_wrong_key_same_an_fails(&data->rekey_wrong_key_same_an_fails_data,
                                                    verbose);
    if (ret != 0)
    {
        return ret;
    }

    if (verbose)
    {
        MACSEC_PRINT(("MACsec rekey tests passed\n"));
    }

    return 0;
}

#endif /* MACSEC_SELF_TEST */
