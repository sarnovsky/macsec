/*
 * test_frame_crypto.c
 *
 * Lightweight MACsec stack
 * Unit tests for MACsec frame protection.
 * This file validates Ethernet frame encryption, decryption, authentication,
 * packet-number handling, association-number selection, replay protection,
 * frame-length boundaries and output-buffer handling.
 *
 * Copyright (c) 2026 Michal Sarnovsky
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */

#include <tests/test_frame_crypto.h>
#include <tests/unit_tests.h>

#include <stdint.h>
#include <string.h>

#if (MACSEC_SELF_TEST != 0)

#define MACSEC_TEST_SECTAG_OFFSET MACSEC_FRAME_ETH_HDR_LEN
#define MACSEC_TEST_SECTAG_TCI_AN 0u
#define MACSEC_TEST_SECTAG_SL 1u
#define MACSEC_TEST_SECTAG_PN 2u
#define MACSEC_TEST_SECTAG_SCI 6u
#define MACSEC_TEST_SHORT_LEN_MAX 48u

static const uint8_t macsec_test_key_a[32] = {
    0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u, 0x88u, 0x99u, 0xAAu,
    0xBBu, 0xCCu, 0xDDu, 0xEEu, 0xFFu, 0x10u, 0x21u, 0x32u, 0x43u, 0x54u, 0x65u,
    0x76u, 0x87u, 0x98u, 0xA9u, 0xBAu, 0xCBu, 0xDCu, 0xEDu, 0xFEu, 0x0Fu};

static const uint8_t macsec_test_key_b[32] = {
    0xF0u, 0xE1u, 0xD2u, 0xC3u, 0xB4u, 0xA5u, 0x96u, 0x87u, 0x78u, 0x69u, 0x5Au,
    0x4Bu, 0x3Cu, 0x2Du, 0x1Eu, 0x0Fu, 0xEFu, 0xDEu, 0xCDu, 0xBCu, 0xABu, 0x9Au,
    0x89u, 0x78u, 0x67u, 0x56u, 0x45u, 0x34u, 0x23u, 0x12u, 0x01u, 0xF0u};

static void macsec_test_fill_plain_frame(uint8_t *frame, size_t len, uint16_t ethertype,
                                         uint8_t seed)
{
    size_t i;

    macsec_assert(frame != NULL);
    macsec_assert(len >= MACSEC_FRAME_ETH_HDR_LEN);

    frame[0] = 0x02u;
    frame[1] = 0x00u;
    frame[2] = 0x00u;
    frame[3] = 0x00u;
    frame[4] = 0x00u;
    frame[5] = 0x01u;

    frame[6] = 0x02u;
    frame[7] = 0x00u;
    frame[8] = 0x00u;
    frame[9] = 0x00u;
    frame[10] = 0x00u;
    frame[11] = 0x02u;

    macsec_wr_be16(&frame[12], ethertype);

    for (i = MACSEC_FRAME_ETH_HDR_LEN; i < len; i++)
    {
        frame[i] = (uint8_t) (seed + (uint8_t) i);
    }
}

static void macsec_test_fill_sci(macsec_frame_sci_t *sci)
{
    macsec_assert(sci != NULL);

    sci->bytes[0] = 0x02u;
    sci->bytes[1] = 0x00u;
    sci->bytes[2] = 0x00u;
    sci->bytes[3] = 0x00u;
    sci->bytes[4] = 0x00u;
    sci->bytes[5] = 0x02u;
    sci->bytes[6] = 0x00u;
    sci->bytes[7] = 0x01u;
}

static void macsec_test_fill_sak_key(macsec_frame_sak_t *sak, const uint8_t *key, uint8_t an,
                                     size_t key_len, uint32_t next_pn)
{
    macsec_assert(sak != NULL);
    macsec_assert(key != NULL);
    macsec_assert((key_len == 16u) || (key_len == 32u));

    memset(sak, 0, sizeof(*sak));

    memcpy(sak->key, key, key_len);
    sak->key_len = (uint8_t) key_len;
    sak->an = an;
    sak->next_pn = next_pn;
    sak->lowest_acceptable_pn = 1u;
    sak->valid = MACSEC_TRUE;
}

static void macsec_test_fill_sak(macsec_frame_sak_t *sak, uint8_t an, size_t key_len)
{
    macsec_test_fill_sak_key(sak, macsec_test_key_a, an, key_len, 1u);
}

static int macsec_test_frame_crypto_init_pair(
    macsec_test_frame_crypto_encrypt_decrypt_one_data_t *data, const macsec_frame_sak_t *tx_sak,
    const macsec_frame_sak_t *rx_sak, macsec_bool_t replay_protect, uint32_t replay_window)
{
    macsec_frame_sak_t tx_sak_copy;
    macsec_frame_sak_t rx_sak_copy;
    int ret;

    macsec_assert(data != NULL);
    macsec_assert(tx_sak != NULL);
    macsec_assert(rx_sak != NULL);

    /*
     * The supplied SAK objects may be members of the same test workspace
     * that also contains the contexts initialized below. Preserve them
     * before modifying any part of that workspace.
     */
    tx_sak_copy = *tx_sak;
    rx_sak_copy = *rx_sak;

    macsec_test_fill_sci(&data->sci);

    ret = macsec_frame_crypto_init(&data->tx_ctx, &data->sci);
    if (ret != MACSEC_ERR_OK)
    {
        return ret;
    }

    ret = macsec_frame_crypto_init(&data->rx_ctx, &data->sci);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_frame_crypto_clear(&data->tx_ctx);
        return ret;
    }

    data->tx_ctx.replay_protect = MACSEC_FALSE;

    data->rx_ctx.replay_protect = replay_protect;
    data->rx_ctx.replay_window = replay_window;

    ret = macsec_frame_crypto_set_tx_sak(&data->tx_ctx, &tx_sak_copy);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_frame_crypto_clear(&data->tx_ctx);
        macsec_frame_crypto_clear(&data->rx_ctx);
        return ret;
    }

    ret = macsec_frame_crypto_set_rx_sak(&data->rx_ctx, &rx_sak_copy);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_frame_crypto_clear(&data->tx_ctx);
        macsec_frame_crypto_clear(&data->rx_ctx);
        return ret;
    }

    macsec_zeroize(&tx_sak_copy, sizeof(tx_sak_copy));
    macsec_zeroize(&rx_sak_copy, sizeof(rx_sak_copy));

    return MACSEC_ERR_OK;
}

static void
macsec_test_frame_crypto_clear_pair(macsec_test_frame_crypto_encrypt_decrypt_one_data_t *data)
{
    macsec_assert(data != NULL);

    macsec_frame_crypto_clear(&data->tx_ctx);
    macsec_frame_crypto_clear(&data->rx_ctx);
}

static int
macsec_test_frame_crypto_selftest_wrapper(macsec_test_frame_crypto_selftest_wrapper_data_t *data,
                                          int verbose)
{
    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  Frame crypto built-in self-test\n"));
    }

    ret = macsec_frame_crypto_self_test(&data->test_ctx, verbose ? 1 : 0);
    TEST_OK(ret);

    return 0;
}

static int
macsec_test_frame_crypto_encrypt_decrypt(macsec_test_frame_crypto_encrypt_decrypt_one_data_t *data,
                                         size_t sak_len, int verbose)
{
    size_t plain_len = 96u;
    size_t secure_len = 0u;
    size_t decrypted_len = 0u;
    int ret;

    if (verbose)
    {
        MACSEC_PRINT(
            ("  Frame crypto encrypt/decrypt test, %u-byte SAK\n", (unsigned int) sak_len));
    }

    macsec_test_fill_sak(&data->sak, 0u, sak_len);
    TEST_OK(macsec_test_frame_crypto_init_pair(data, &data->sak, &data->sak, MACSEC_FALSE, 0u));

    macsec_test_fill_plain_frame(data->plain, plain_len, 0x0800u, (sak_len == 16u) ? 0x20u : 0x21u);

    ret = macsec_frame_encrypt(&data->tx_ctx, data->plain, plain_len, data->secure, &secure_len,
                               sizeof(data->secure));
    TEST_OK(ret);

    TEST_TRUE(macsec_frame_is_macsec(data->secure, secure_len));
    TEST_TRUE(macsec_rd_be16(&data->secure[12]) == MACSEC_FRAME_ETHERTYPE);
    TEST_TRUE((data->secure[MACSEC_TEST_SECTAG_OFFSET] & 0x03u) == 0u);

    ret = macsec_frame_decrypt(&data->rx_ctx, data->secure, secure_len, data->decrypted,
                               &decrypted_len, sizeof(data->decrypted));
    TEST_OK(ret);

    TEST_TRUE(decrypted_len == plain_len);
    TEST_TRUE(macsec_compare(data->plain, data->decrypted, plain_len) == 0);

    macsec_test_frame_crypto_clear_pair(data);
    return 0;
}

static int
macsec_test_frame_crypto_bad_icv(macsec_test_frame_crypto_encrypt_decrypt_one_data_t *data,
                                 size_t sak_len, int verbose)
{
    size_t plain_len = 96u;
    size_t secure_len = 0u;
    size_t decrypted_len = 123u;
    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  Frame crypto bad ICV/auth test, %u-byte SAK\n", (unsigned int) sak_len));
    }

    macsec_test_fill_sak(&data->sak, 0u, sak_len);
    TEST_OK(macsec_test_frame_crypto_init_pair(data, &data->sak, &data->sak, MACSEC_FALSE, 0u));

    macsec_test_fill_plain_frame(data->plain, plain_len, 0x0800u, (sak_len == 16u) ? 0x30u : 0x31u);

    TEST_OK(macsec_frame_encrypt(&data->tx_ctx, data->plain, plain_len, data->secure, &secure_len,
                                 sizeof(data->secure)));

    data->secure[secure_len - 1u] ^= 0x01u;

    ret = macsec_frame_decrypt(&data->rx_ctx, data->secure, secure_len, data->decrypted,
                               &decrypted_len, sizeof(data->decrypted));

    TEST_TRUE(ret == MACSEC_ERR_AUTH);
    TEST_TRUE(decrypted_len == 0u);

    macsec_test_frame_crypto_clear_pair(data);
    return 0;
}

static int
macsec_test_frame_crypto_wrong_sak(macsec_test_frame_crypto_encrypt_decrypt_one_data_t *data,
                                   size_t sak_len, int verbose)
{
    macsec_frame_sak_t rx_sak;
    size_t secure_len = 0u;
    size_t decrypted_len = 77u;
    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  Frame crypto wrong SAK test, %u-byte SAK\n", (unsigned int) sak_len));
    }

    macsec_test_fill_sak_key(&data->sak, macsec_test_key_a, 0u, sak_len, 1u);
    macsec_test_fill_sak_key(&rx_sak, macsec_test_key_b, 0u, sak_len, 1u);

    TEST_OK(macsec_test_frame_crypto_init_pair(data, &data->sak, &rx_sak, MACSEC_FALSE, 0u));

    macsec_test_fill_plain_frame(data->plain, 96u, 0x0800u, 0x55u);
    TEST_OK(macsec_frame_encrypt(&data->tx_ctx, data->plain, 96u, data->secure, &secure_len,
                                 sizeof(data->secure)));

    ret = macsec_frame_decrypt(&data->rx_ctx, data->secure, secure_len, data->decrypted,
                               &decrypted_len, sizeof(data->decrypted));

    TEST_TRUE(ret == MACSEC_ERR_AUTH);
    TEST_TRUE(decrypted_len == 0u);

    macsec_test_frame_crypto_clear_pair(data);
    return 0;
}

static int
macsec_test_frame_crypto_tx_pn_increment(macsec_test_frame_crypto_encrypt_decrypt_one_data_t *data,
                                         int verbose)
{
    size_t secure_len = 0u;

    if (verbose)
    {
        MACSEC_PRINT(("  Frame crypto TX PN increment test\n"));
    }

    macsec_test_fill_sak(&data->sak, 0u, 16u);
    TEST_OK(macsec_test_frame_crypto_init_pair(data, &data->sak, &data->sak, MACSEC_FALSE, 0u));

    macsec_test_fill_plain_frame(data->plain, 96u, 0x0800u, 0x60u);

    TEST_OK(macsec_frame_encrypt(&data->tx_ctx, data->plain, 96u, data->secure, &secure_len,
                                 sizeof(data->secure)));
    TEST_TRUE(macsec_rd_be32(&data->secure[MACSEC_TEST_SECTAG_OFFSET + MACSEC_TEST_SECTAG_PN]) ==
              1u);
    TEST_TRUE(data->tx_ctx.tx_sak.next_pn == 2u);

    TEST_OK(macsec_frame_encrypt(&data->tx_ctx, data->plain, 96u, data->secure, &secure_len,
                                 sizeof(data->secure)));
    TEST_TRUE(macsec_rd_be32(&data->secure[MACSEC_TEST_SECTAG_OFFSET + MACSEC_TEST_SECTAG_PN]) ==
              2u);
    TEST_TRUE(data->tx_ctx.tx_sak.next_pn == 3u);

    macsec_test_frame_crypto_clear_pair(data);
    return 0;
}

static int macsec_test_frame_crypto_tx_error_preserves_pn(
    macsec_test_frame_crypto_encrypt_decrypt_one_data_t *data, int verbose)
{
    size_t secure_len = 999u;
    size_t required_len;
    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  Frame crypto TX error preserves PN test\n"));
    }

    macsec_test_fill_sak(&data->sak, 0u, 16u);
    TEST_OK(macsec_test_frame_crypto_init_pair(data, &data->sak, &data->sak, MACSEC_FALSE, 0u));

    macsec_test_fill_plain_frame(data->plain, 96u, 0x0800u, 0x61u);
    required_len =
        MACSEC_FRAME_ETH_HDR_LEN + MACSEC_FRAME_SECTAG_LEN + (96u - 12u) + MACSEC_FRAME_ICV_LEN;

    ret = macsec_frame_encrypt(&data->tx_ctx, data->plain, 96u, data->secure, &secure_len,
                               required_len - 1u);

    TEST_TRUE(ret == MACSEC_ERR_BUFFER);
    TEST_TRUE(secure_len == 0u);
    TEST_TRUE(data->tx_ctx.tx_sak.next_pn == 1u);

    macsec_test_frame_crypto_clear_pair(data);
    return 0;
}

static int
macsec_test_frame_crypto_tx_pn_exhaustion(macsec_test_frame_crypto_encrypt_decrypt_one_data_t *data,
                                          int verbose)
{
    size_t secure_len = 0u;
    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  Frame crypto TX PN exhaustion test\n"));
    }

    macsec_test_fill_sak_key(&data->sak, macsec_test_key_a, 0u, 16u, UINT32_MAX);
    TEST_OK(macsec_test_frame_crypto_init_pair(data, &data->sak, &data->sak, MACSEC_FALSE, 0u));

    macsec_test_fill_plain_frame(data->plain, 96u, 0x0800u, 0x62u);

    TEST_OK(macsec_frame_encrypt(&data->tx_ctx, data->plain, 96u, data->secure, &secure_len,
                                 sizeof(data->secure)));
    TEST_TRUE(macsec_rd_be32(&data->secure[MACSEC_TEST_SECTAG_OFFSET + MACSEC_TEST_SECTAG_PN]) ==
              UINT32_MAX);
    TEST_TRUE(data->tx_ctx.tx_sak.next_pn == 0u);
    TEST_TRUE(!macsec_frame_crypto_ready_tx(&data->tx_ctx));

    secure_len = 123u;
    ret = macsec_frame_encrypt(&data->tx_ctx, data->plain, 96u, data->secure, &secure_len,
                               sizeof(data->secure));
    TEST_TRUE(ret == MACSEC_ERR_STATE);
    TEST_TRUE(data->tx_ctx.tx_sak.next_pn == 0u);

    macsec_test_frame_crypto_clear_pair(data);
    return 0;
}

static int
macsec_test_frame_crypto_an_selection(macsec_test_frame_crypto_encrypt_decrypt_one_data_t *data,
                                      int verbose)
{
    macsec_frame_sak_t sak;
    size_t secure_len;
    size_t decrypted_len;
    uint8_t an;

    if (verbose)
    {
        MACSEC_PRINT(("  Frame crypto AN selection test\n"));
    }

    macsec_test_fill_sci(&data->sci);
    TEST_OK(macsec_frame_crypto_init(&data->tx_ctx, &data->sci));
    TEST_OK(macsec_frame_crypto_init(&data->rx_ctx, &data->sci));
    data->rx_ctx.replay_protect = MACSEC_FALSE;

    for (an = 0u; an < MACSEC_FRAME_MAX_SA; an++)
    {
        macsec_test_fill_sak(&sak, an, 16u);
        TEST_OK(macsec_frame_crypto_set_rx_sak(&data->rx_ctx, &sak));
    }

    macsec_test_fill_plain_frame(data->plain, 96u, 0x0800u, 0x70u);

    for (an = 0u; an < MACSEC_FRAME_MAX_SA; an++)
    {
        macsec_test_fill_sak(&sak, an, 16u);
        TEST_OK(macsec_frame_crypto_set_tx_sak(&data->tx_ctx, &sak));

        secure_len = 0u;
        decrypted_len = 0u;

        TEST_OK(macsec_frame_encrypt(&data->tx_ctx, data->plain, 96u, data->secure, &secure_len,
                                     sizeof(data->secure)));
        TEST_TRUE((data->secure[MACSEC_TEST_SECTAG_OFFSET] & 0x03u) == an);

        TEST_OK(macsec_frame_decrypt(&data->rx_ctx, data->secure, secure_len, data->decrypted,
                                     &decrypted_len, sizeof(data->decrypted)));
        TEST_TRUE(decrypted_len == 96u);
        TEST_TRUE(macsec_compare(data->plain, data->decrypted, 96u) == 0);
    }

    macsec_frame_crypto_clear(&data->tx_ctx);
    macsec_frame_crypto_clear(&data->rx_ctx);
    return 0;
}

static int
macsec_test_frame_crypto_lengths(macsec_test_frame_crypto_encrypt_decrypt_one_data_t *data,
                                 int verbose)
{
    static const size_t lengths[] = {14u, 15u, 59u, 60u, 61u, 96u, 1500u, 1600u};

    size_t secure_len;
    size_t decrypted_len;
    size_t secure_data_len;
    size_t expected_secure_len;
    size_t i;

    if (verbose)
    {
        MACSEC_PRINT(("  Frame crypto frame-length and Short Length test\n"));
    }

    for (i = 0u; i < (sizeof(lengths) / sizeof(lengths[0])); i++)
    {
        macsec_test_fill_sak(&data->sak, 0u, 16u);

        TEST_OK(macsec_test_frame_crypto_init_pair(data, &data->sak, &data->sak, MACSEC_FALSE, 0u));

        macsec_test_fill_plain_frame(data->plain, lengths[i], 0x0800u, (uint8_t) (0x80u + i));

        secure_len = 0u;
        decrypted_len = 0u;

        secure_data_len = lengths[i] - 12u;

        expected_secure_len = MACSEC_FRAME_ETH_HDR_LEN + MACSEC_FRAME_SECTAG_LEN + secure_data_len +
                              MACSEC_FRAME_ICV_LEN;

        TEST_OK(macsec_frame_encrypt(&data->tx_ctx, data->plain, lengths[i], data->secure,
                                     &secure_len, sizeof(data->secure)));

        TEST_TRUE(secure_len == expected_secure_len);

        if (secure_data_len < MACSEC_TEST_SHORT_LEN_MAX)
        {
            TEST_TRUE(data->secure[MACSEC_TEST_SECTAG_OFFSET + MACSEC_TEST_SECTAG_SL] ==
                      (uint8_t) secure_data_len);
        }
        else
        {
            TEST_TRUE(data->secure[MACSEC_TEST_SECTAG_OFFSET + MACSEC_TEST_SECTAG_SL] == 0u);
        }

        TEST_OK(macsec_frame_decrypt(&data->rx_ctx, data->secure, secure_len, data->decrypted,
                                     &decrypted_len, sizeof(data->decrypted)));

        TEST_TRUE(decrypted_len == lengths[i]);
        TEST_TRUE(macsec_compare(data->plain, data->decrypted, lengths[i]) == 0);

        macsec_test_frame_crypto_clear_pair(data);
    }

    return 0;
}

static int
macsec_test_frame_crypto_output_capacity(macsec_test_frame_crypto_encrypt_decrypt_one_data_t *data,
                                         int verbose)
{
    size_t secure_len = 0u;
    size_t decrypted_len = 55u;
    size_t required_secure_len;
    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  Frame crypto output-capacity test\n"));
    }

    macsec_test_fill_sak(&data->sak, 0u, 16u);
    TEST_OK(macsec_test_frame_crypto_init_pair(data, &data->sak, &data->sak, MACSEC_FALSE, 0u));

    macsec_test_fill_plain_frame(data->plain, 96u, 0x0800u, 0x90u);
    required_secure_len =
        MACSEC_FRAME_ETH_HDR_LEN + MACSEC_FRAME_SECTAG_LEN + (96u - 12u) + MACSEC_FRAME_ICV_LEN;

    TEST_OK(macsec_frame_encrypt(&data->tx_ctx, data->plain, 96u, data->secure, &secure_len,
                                 required_secure_len));
    TEST_TRUE(secure_len == required_secure_len);

    ret = macsec_frame_decrypt(&data->rx_ctx, data->secure, secure_len, data->decrypted,
                               &decrypted_len, 95u);
    TEST_TRUE(ret == MACSEC_ERR_BUFFER);
    TEST_TRUE(decrypted_len == 0u);

    decrypted_len = 0u;
    TEST_OK(macsec_frame_decrypt(&data->rx_ctx, data->secure, secure_len, data->decrypted,
                                 &decrypted_len, 96u));
    TEST_TRUE(decrypted_len == 96u);

    macsec_test_frame_crypto_clear_pair(data);
    return 0;
}

static int macsec_test_frame_crypto_missing_sak_and_detection(
    macsec_test_frame_crypto_encrypt_decrypt_one_data_t *data, int verbose)
{
    size_t secure_len = 0u;
    size_t decrypted_len = 22u;
    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  Frame crypto readiness and frame detection test\n"));
    }

    macsec_test_fill_sci(&data->sci);
    TEST_OK(macsec_frame_crypto_init(&data->tx_ctx, &data->sci));
    TEST_OK(macsec_frame_crypto_init(&data->rx_ctx, &data->sci));

    TEST_TRUE(!macsec_frame_crypto_ready_tx(&data->tx_ctx));
    TEST_TRUE(!macsec_frame_crypto_ready_rx(&data->rx_ctx, 0u));
    TEST_TRUE(!macsec_frame_crypto_ready_rx(&data->rx_ctx, 4u));

    macsec_test_fill_plain_frame(data->plain, 96u, 0x0800u, 0x91u);

    ret = macsec_frame_encrypt(&data->tx_ctx, data->plain, 96u, data->secure, &secure_len,
                               sizeof(data->secure));
    TEST_TRUE(ret == MACSEC_ERR_STATE);

    TEST_TRUE(!macsec_frame_is_macsec(data->plain, 13u));
    TEST_TRUE(!macsec_frame_is_macsec(data->plain, 96u));

    macsec_test_fill_sak(&data->sak, 0u, 16u);
    TEST_OK(macsec_frame_crypto_set_tx_sak(&data->tx_ctx, &data->sak));
    TEST_OK(macsec_frame_encrypt(&data->tx_ctx, data->plain, 96u, data->secure, &secure_len,
                                 sizeof(data->secure)));

    TEST_TRUE(macsec_frame_is_macsec(data->secure, secure_len));

    ret = macsec_frame_decrypt(&data->rx_ctx, data->secure, secure_len, data->decrypted,
                               &decrypted_len, sizeof(data->decrypted));
    TEST_TRUE(ret == MACSEC_ERR_STATE);
    TEST_TRUE(decrypted_len == 0u);

    macsec_frame_crypto_clear(&data->tx_ctx);
    macsec_frame_crypto_clear(&data->rx_ctx);
    return 0;
}

static int
macsec_test_frame_crypto_replay_reject(macsec_test_frame_crypto_encrypt_decrypt_one_data_t *data,
                                       size_t sak_len, int verbose)
{
    size_t secure_len = 0u;
    size_t decrypted_len = 0u;
    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  Frame crypto replay reject test, %u-byte SAK\n", (unsigned int) sak_len));
    }

    macsec_test_fill_sak(&data->sak, 0u, sak_len);
    TEST_OK(macsec_test_frame_crypto_init_pair(data, &data->sak, &data->sak, MACSEC_TRUE, 0u));

    macsec_test_fill_plain_frame(data->plain, 96u, 0x0800u, (sak_len == 16u) ? 0x40u : 0x41u);

    TEST_OK(macsec_frame_encrypt(&data->tx_ctx, data->plain, 96u, data->secure, &secure_len,
                                 sizeof(data->secure)));

    TEST_OK(macsec_frame_decrypt(&data->rx_ctx, data->secure, secure_len, data->decrypted,
                                 &decrypted_len, sizeof(data->decrypted)));

    decrypted_len = 123u;
    ret = macsec_frame_decrypt(&data->rx_ctx, data->secure, secure_len, data->decrypted,
                               &decrypted_len, sizeof(data->decrypted));

    TEST_TRUE(ret == MACSEC_ERR_REPLAY);
    TEST_TRUE(decrypted_len == 0u);

    macsec_test_frame_crypto_clear_pair(data);
    return 0;
}

static int macsec_test_frame_crypto_bad_icv_preserves_replay_state(
    macsec_test_frame_crypto_encrypt_decrypt_one_data_t *data, int verbose)
{
    size_t secure_len = 0u;
    size_t decrypted_len = 0u;
    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  Frame crypto bad ICV preserves replay state test\n"));
    }

    macsec_test_fill_sak_key(&data->sak, macsec_test_key_a, 0u, 16u, 100u);
    TEST_OK(macsec_test_frame_crypto_init_pair(data, &data->sak, &data->sak, MACSEC_TRUE, 0u));

    macsec_test_fill_plain_frame(data->plain, 96u, 0x0800u, 0xA0u);

    TEST_OK(macsec_frame_encrypt(&data->tx_ctx, data->plain, 96u, data->secure, &secure_len,
                                 sizeof(data->secure)));
    data->secure[secure_len - 1u] ^= 0x01u;

    ret = macsec_frame_decrypt(&data->rx_ctx, data->secure, secure_len, data->decrypted,
                               &decrypted_len, sizeof(data->decrypted));
    TEST_TRUE(ret == MACSEC_ERR_AUTH);
    TEST_TRUE(data->rx_ctx.rx_sak[0].lowest_acceptable_pn == 1u);

    data->tx_ctx.tx_sak.next_pn = 1u;
    secure_len = 0u;
    decrypted_len = 0u;

    TEST_OK(macsec_frame_encrypt(&data->tx_ctx, data->plain, 96u, data->secure, &secure_len,
                                 sizeof(data->secure)));
    TEST_OK(macsec_frame_decrypt(&data->rx_ctx, data->secure, secure_len, data->decrypted,
                                 &decrypted_len, sizeof(data->decrypted)));
    TEST_TRUE(data->rx_ctx.rx_sak[0].lowest_acceptable_pn == 2u);

    macsec_test_frame_crypto_clear_pair(data);
    return 0;
}

/*
 * Verify that a duplicate packet is rejected even while its PN remains
 * inside the active replay window.
 */
static int macsec_test_frame_crypto_replay_window_duplicate(
    macsec_test_frame_crypto_encrypt_decrypt_one_data_t *data, int verbose)
{
    size_t secure_len = 0u;
    size_t decrypted_len = 0u;
    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  Frame crypto replay-window duplicate test\n"));
    }

    macsec_test_fill_sak(&data->sak, 0u, 16u);
    TEST_OK(macsec_test_frame_crypto_init_pair(data, &data->sak, &data->sak, MACSEC_TRUE, 4u));

    macsec_test_fill_plain_frame(data->plain, 96u, 0x0800u, 0xB0u);

    data->tx_ctx.tx_sak.next_pn = 3u;
    TEST_OK(macsec_frame_encrypt(&data->tx_ctx, data->plain, 96u, data->secure, &secure_len,
                                 sizeof(data->secure)));

    TEST_OK(macsec_frame_decrypt(&data->rx_ctx, data->secure, secure_len, data->decrypted,
                                 &decrypted_len, sizeof(data->decrypted)));

    decrypted_len = 0u;
    ret = macsec_frame_decrypt(&data->rx_ctx, data->secure, secure_len, data->decrypted,
                               &decrypted_len, sizeof(data->decrypted));

    TEST_TRUE(ret == MACSEC_ERR_REPLAY);
    TEST_TRUE(decrypted_len == 0u);

    macsec_test_frame_crypto_clear_pair(data);
    return 0;
}

static int macsec_test_frame_crypto_replay_window_ordering(
    macsec_test_frame_crypto_encrypt_decrypt_one_data_t *data, int verbose)
{
    size_t secure_len;
    size_t decrypted_len;
    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  Frame crypto replay-window ordering test\n"));
    }

    macsec_test_fill_sak(&data->sak, 0u, 16u);
    TEST_OK(macsec_test_frame_crypto_init_pair(data, &data->sak, &data->sak, MACSEC_TRUE, 4u));

    macsec_test_fill_plain_frame(data->plain, 96u, 0x0800u, 0xB1u);

    /* Receive PN 3 first. */
    data->tx_ctx.tx_sak.next_pn = 3u;
    secure_len = 0u;
    decrypted_len = 0u;
    TEST_OK(macsec_frame_encrypt(&data->tx_ctx, data->plain, 96u, data->secure, &secure_len,
                                 sizeof(data->secure)));
    TEST_OK(macsec_frame_decrypt(&data->rx_ctx, data->secure, secure_len, data->decrypted,
                                 &decrypted_len, sizeof(data->decrypted)));
    TEST_TRUE(data->rx_ctx.rx_sak[0].highest_received_pn == 3u);
    TEST_TRUE(data->rx_ctx.rx_sak[0].lowest_acceptable_pn == 1u);
    TEST_TRUE(data->rx_ctx.rx_sak[0].replay_bitmap == 0x01u);

    /* Delayed PN 1 is still inside the window. */
    data->tx_ctx.tx_sak.next_pn = 1u;
    secure_len = 0u;
    decrypted_len = 0u;
    TEST_OK(macsec_frame_encrypt(&data->tx_ctx, data->plain, 96u, data->secure, &secure_len,
                                 sizeof(data->secure)));
    TEST_OK(macsec_frame_decrypt(&data->rx_ctx, data->secure, secure_len, data->decrypted,
                                 &decrypted_len, sizeof(data->decrypted)));
    TEST_TRUE(data->rx_ctx.rx_sak[0].replay_bitmap == 0x05u);

    /* Delayed PN 2 fills the remaining gap. */
    data->tx_ctx.tx_sak.next_pn = 2u;
    secure_len = 0u;
    decrypted_len = 0u;
    TEST_OK(macsec_frame_encrypt(&data->tx_ctx, data->plain, 96u, data->secure, &secure_len,
                                 sizeof(data->secure)));
    TEST_OK(macsec_frame_decrypt(&data->rx_ctx, data->secure, secure_len, data->decrypted,
                                 &decrypted_len, sizeof(data->decrypted)));
    TEST_TRUE(data->rx_ctx.rx_sak[0].replay_bitmap == 0x07u);

    /* The same PN 2 is now a duplicate inside the active window. */
    decrypted_len = 123u;
    ret = macsec_frame_decrypt(&data->rx_ctx, data->secure, secure_len, data->decrypted,
                               &decrypted_len, sizeof(data->decrypted));
    TEST_TRUE(ret == MACSEC_ERR_REPLAY);
    TEST_TRUE(decrypted_len == 0u);

    /* PN 7 moves the four-packet window to PN 4..7. */
    data->tx_ctx.tx_sak.next_pn = 7u;
    secure_len = 0u;
    decrypted_len = 0u;
    TEST_OK(macsec_frame_encrypt(&data->tx_ctx, data->plain, 96u, data->secure, &secure_len,
                                 sizeof(data->secure)));
    TEST_OK(macsec_frame_decrypt(&data->rx_ctx, data->secure, secure_len, data->decrypted,
                                 &decrypted_len, sizeof(data->decrypted)));
    TEST_TRUE(data->rx_ctx.rx_sak[0].highest_received_pn == 7u);
    TEST_TRUE(data->rx_ctx.rx_sak[0].lowest_acceptable_pn == 4u);
    TEST_TRUE(data->rx_ctx.rx_sak[0].replay_bitmap == 0x01u);

    /* PN 3 is now below the lower edge of the replay window. */
    data->tx_ctx.tx_sak.next_pn = 3u;
    secure_len = 0u;
    decrypted_len = 123u;
    TEST_OK(macsec_frame_encrypt(&data->tx_ctx, data->plain, 96u, data->secure, &secure_len,
                                 sizeof(data->secure)));
    ret = macsec_frame_decrypt(&data->rx_ctx, data->secure, secure_len, data->decrypted,
                               &decrypted_len, sizeof(data->decrypted));
    TEST_TRUE(ret == MACSEC_ERR_REPLAY);
    TEST_TRUE(decrypted_len == 0u);

    macsec_test_frame_crypto_clear_pair(data);
    return 0;
}

static int
macsec_test_frame_crypto_rx_pn_exhaustion(macsec_test_frame_crypto_encrypt_decrypt_one_data_t *data,
                                          int verbose)
{
    size_t secure_len = 0u;
    size_t decrypted_len = 0u;
    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  Frame crypto RX PN exhaustion test\n"));
    }

    macsec_test_fill_sak_key(&data->sak, macsec_test_key_a, 0u, 16u, UINT32_MAX);
    TEST_OK(macsec_test_frame_crypto_init_pair(data, &data->sak, &data->sak, MACSEC_TRUE, 0u));

    macsec_test_fill_plain_frame(data->plain, 96u, 0x0800u, 0xB2u);
    TEST_OK(macsec_frame_encrypt(&data->tx_ctx, data->plain, 96u, data->secure, &secure_len,
                                 sizeof(data->secure)));
    TEST_OK(macsec_frame_decrypt(&data->rx_ctx, data->secure, secure_len, data->decrypted,
                                 &decrypted_len, sizeof(data->decrypted)));

    TEST_TRUE(data->rx_ctx.rx_sak[0].highest_received_pn == UINT32_MAX);
    TEST_TRUE(data->rx_ctx.rx_sak[0].lowest_acceptable_pn == UINT32_MAX);
    TEST_TRUE(data->rx_ctx.rx_sak[0].replay_exhausted);
    TEST_TRUE(!macsec_frame_crypto_ready_rx(&data->rx_ctx, 0u));

    decrypted_len = 123u;
    ret = macsec_frame_decrypt(&data->rx_ctx, data->secure, secure_len, data->decrypted,
                               &decrypted_len, sizeof(data->decrypted));
    TEST_TRUE(ret == MACSEC_ERR_STATE);
    TEST_TRUE(decrypted_len == 0u);

    macsec_test_frame_crypto_clear_pair(data);
    return 0;
}

static int macsec_test_frame_crypto_distinct_local_sci(
    macsec_test_frame_crypto_encrypt_decrypt_one_data_t *data, int verbose)
{
    macsec_frame_sci_t rx_sci;

    size_t secure_len = 0u;
    size_t decrypted_len = 0u;

    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  Frame crypto distinct local SCI test\n"));
    }

    /*
     * The TX SCI identifies the transmitting Secure Channel and is written
     * into the SecTAG. The RX context has its own different local SCI.
     */
    macsec_test_fill_sci(&data->sci);

    rx_sci = data->sci;
    rx_sci.bytes[5] ^= 0x01u;

    macsec_test_fill_sak(&data->sak, 0u, 16u);

    TEST_OK(macsec_frame_crypto_init(&data->tx_ctx, &data->sci));
    TEST_OK(macsec_frame_crypto_init(&data->rx_ctx, &rx_sci));

    data->tx_ctx.replay_protect = MACSEC_FALSE;
    data->rx_ctx.replay_protect = MACSEC_FALSE;

    TEST_OK(macsec_frame_crypto_set_tx_sak(&data->tx_ctx, &data->sak));
    TEST_OK(macsec_frame_crypto_set_rx_sak(&data->rx_ctx, &data->sak));

    macsec_test_fill_plain_frame(data->plain, 96u, 0x0800u, 0xB3u);

    ret = macsec_frame_encrypt(&data->tx_ctx, data->plain, 96u, data->secure, &secure_len,
                               sizeof(data->secure));
    if (ret != MACSEC_ERR_OK)
    {
        macsec_frame_crypto_clear(&data->tx_ctx);
        macsec_frame_crypto_clear(&data->rx_ctx);
        return ret;
    }

    /*
     * The protected frame must carry the transmitter's SCI, not the
     * receiver's local SCI.
     */
    TEST_MEM_EQ(&data->secure[MACSEC_TEST_SECTAG_OFFSET + MACSEC_TEST_SECTAG_SCI], data->sci.bytes,
                MACSEC_FRAME_SCI_LEN);

    TEST_TRUE(macsec_compare(&data->secure[MACSEC_TEST_SECTAG_OFFSET + MACSEC_TEST_SECTAG_SCI],
                             rx_sci.bytes, MACSEC_FRAME_SCI_LEN) != 0);

    ret = macsec_frame_decrypt(&data->rx_ctx, data->secure, secure_len, data->decrypted,
                               &decrypted_len, sizeof(data->decrypted));
    if (ret != MACSEC_ERR_OK)
    {
        macsec_frame_crypto_clear(&data->tx_ctx);
        macsec_frame_crypto_clear(&data->rx_ctx);
        return ret;
    }

    TEST_EQ_U32(decrypted_len, 96u);
    TEST_MEM_EQ(data->plain, data->decrypted, 96u);

    macsec_frame_crypto_clear(&data->tx_ctx);
    macsec_frame_crypto_clear(&data->rx_ctx);

    return 0;
}

static int macsec_test_frame_crypto_sectag_validation(
    macsec_test_frame_crypto_encrypt_decrypt_one_data_t *data, int verbose)
{
    size_t secure_len = 0u;
    size_t decrypted_len;
    uint8_t original;
    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  Frame crypto TCI and Short Length validation test\n"));
    }

    macsec_test_fill_sak(&data->sak, 0u, 16u);
    TEST_OK(macsec_test_frame_crypto_init_pair(data, &data->sak, &data->sak, MACSEC_FALSE, 0u));
    macsec_test_fill_plain_frame(data->plain, 14u, 0x0800u, 0xB4u);
    TEST_OK(macsec_frame_encrypt(&data->tx_ctx, data->plain, 14u, data->secure, &secure_len,
                                 sizeof(data->secure)));

    original = data->secure[MACSEC_TEST_SECTAG_OFFSET + MACSEC_TEST_SECTAG_TCI_AN];
    data->secure[MACSEC_TEST_SECTAG_OFFSET + MACSEC_TEST_SECTAG_TCI_AN] ^= 0x40u;
    decrypted_len = 123u;
    ret = macsec_frame_decrypt(&data->rx_ctx, data->secure, secure_len, data->decrypted,
                               &decrypted_len, sizeof(data->decrypted));
    TEST_TRUE(ret == MACSEC_ERR_UNSUPPORTED);
    TEST_TRUE(decrypted_len == 0u);
    data->secure[MACSEC_TEST_SECTAG_OFFSET + MACSEC_TEST_SECTAG_TCI_AN] = original;

    original = data->secure[MACSEC_TEST_SECTAG_OFFSET + MACSEC_TEST_SECTAG_SL];
    data->secure[MACSEC_TEST_SECTAG_OFFSET + MACSEC_TEST_SECTAG_SL] = (uint8_t) (original + 1u);
    decrypted_len = 123u;
    ret = macsec_frame_decrypt(&data->rx_ctx, data->secure, secure_len, data->decrypted,
                               &decrypted_len, sizeof(data->decrypted));
    TEST_TRUE(ret == MACSEC_ERR_PARAM);
    TEST_TRUE(decrypted_len == 0u);

    macsec_test_frame_crypto_clear_pair(data);
    return 0;
}

static int macsec_test_frame_crypto_limits_and_window_validation(
    macsec_test_frame_crypto_encrypt_decrypt_one_data_t *data, int verbose)
{
    size_t secure_len = 99u;
    size_t decrypted_len = 99u;
    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  Frame crypto size and replay-window limit test\n"));
    }

    macsec_test_fill_sak(&data->sak, 0u, 16u);
    TEST_OK(macsec_test_frame_crypto_init_pair(data, &data->sak, &data->sak, MACSEC_TRUE,
                                               MACSEC_FRAME_MAX_REPLAY_WINDOW + 1u));
    macsec_test_fill_plain_frame(data->plain, 96u, 0x0800u, 0xB5u);
    TEST_OK(macsec_frame_encrypt(&data->tx_ctx, data->plain, 96u, data->secure, &secure_len,
                                 sizeof(data->secure)));

    ret = macsec_frame_decrypt(&data->rx_ctx, data->secure, secure_len, data->decrypted,
                               &decrypted_len, sizeof(data->decrypted));
    TEST_TRUE(ret == MACSEC_ERR_UNSUPPORTED);
    TEST_TRUE(decrypted_len == 0u);

    secure_len = 99u;
    ret = macsec_frame_encrypt(&data->tx_ctx, data->plain, MACSEC_FRAME_MAX_PLAIN_SIZE + 1u,
                               data->secure, &secure_len, sizeof(data->secure));
    TEST_TRUE(ret == MACSEC_ERR_BUFFER);
    TEST_TRUE(secure_len == 0u);

    decrypted_len = 99u;
    ret = macsec_frame_decrypt(&data->rx_ctx, data->secure, MACSEC_FRAME_MAX_SECURE_SIZE + 1u,
                               data->decrypted, &decrypted_len, sizeof(data->decrypted));
    TEST_TRUE(ret == MACSEC_ERR_BUFFER);
    TEST_TRUE(decrypted_len == 0u);

    macsec_test_frame_crypto_clear_pair(data);
    return 0;
}

int macsec_test_frame_crypto(macsec_test_frame_crypto_data_t *data, int verbose)
{
    if (verbose)
    {
        MACSEC_PRINT(("MACsec frame crypto tests\n"));
    }

    TEST_OK(macsec_test_frame_crypto_selftest_wrapper(
        &data->test_frame_crypto_selftest_wrapper_data, verbose));

    TEST_OK(macsec_test_frame_crypto_encrypt_decrypt(
        &data->test_frame_crypto_encrypt_decrypt_one_data, 16u, verbose));
    TEST_OK(macsec_test_frame_crypto_encrypt_decrypt(
        &data->test_frame_crypto_encrypt_decrypt_one_data, 32u, verbose));

    TEST_OK(macsec_test_frame_crypto_bad_icv(&data->test_frame_crypto_encrypt_decrypt_one_data, 16u,
                                             verbose));
    TEST_OK(macsec_test_frame_crypto_bad_icv(&data->test_frame_crypto_encrypt_decrypt_one_data, 32u,
                                             verbose));

    TEST_OK(macsec_test_frame_crypto_wrong_sak(&data->test_frame_crypto_encrypt_decrypt_one_data,
                                               16u, verbose));
    TEST_OK(macsec_test_frame_crypto_wrong_sak(&data->test_frame_crypto_encrypt_decrypt_one_data,
                                               32u, verbose));

    TEST_OK(macsec_test_frame_crypto_tx_pn_increment(
        &data->test_frame_crypto_encrypt_decrypt_one_data, verbose));
    TEST_OK(macsec_test_frame_crypto_tx_error_preserves_pn(
        &data->test_frame_crypto_encrypt_decrypt_one_data, verbose));
    TEST_OK(macsec_test_frame_crypto_tx_pn_exhaustion(
        &data->test_frame_crypto_encrypt_decrypt_one_data, verbose));

    TEST_OK(macsec_test_frame_crypto_an_selection(&data->test_frame_crypto_encrypt_decrypt_one_data,
                                                  verbose));
    TEST_OK(macsec_test_frame_crypto_lengths(&data->test_frame_crypto_encrypt_decrypt_one_data,
                                             verbose));
    TEST_OK(macsec_test_frame_crypto_output_capacity(
        &data->test_frame_crypto_encrypt_decrypt_one_data, verbose));
    TEST_OK(macsec_test_frame_crypto_missing_sak_and_detection(
        &data->test_frame_crypto_encrypt_decrypt_one_data, verbose));

    TEST_OK(macsec_test_frame_crypto_replay_reject(
        &data->test_frame_crypto_encrypt_decrypt_one_data, 16u, verbose));
    TEST_OK(macsec_test_frame_crypto_replay_reject(
        &data->test_frame_crypto_encrypt_decrypt_one_data, 32u, verbose));
    TEST_OK(macsec_test_frame_crypto_bad_icv_preserves_replay_state(
        &data->test_frame_crypto_encrypt_decrypt_one_data, verbose));

    TEST_OK(macsec_test_frame_crypto_replay_window_duplicate(
        &data->test_frame_crypto_encrypt_decrypt_one_data, verbose));
    TEST_OK(macsec_test_frame_crypto_replay_window_ordering(
        &data->test_frame_crypto_encrypt_decrypt_one_data, verbose));
    TEST_OK(macsec_test_frame_crypto_rx_pn_exhaustion(
        &data->test_frame_crypto_encrypt_decrypt_one_data, verbose));

    TEST_OK(macsec_test_frame_crypto_distinct_local_sci(
        &data->test_frame_crypto_encrypt_decrypt_one_data, verbose));
    TEST_OK(macsec_test_frame_crypto_sectag_validation(
        &data->test_frame_crypto_encrypt_decrypt_one_data, verbose));
    TEST_OK(macsec_test_frame_crypto_limits_and_window_validation(
        &data->test_frame_crypto_encrypt_decrypt_one_data, verbose));

    return 0;
}

#endif /* MACSEC_SELF_TEST */
