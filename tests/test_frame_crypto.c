/*
 * test_frame_crypto.c
 *
 * Lightweight MACsec stack
 * Unit tests for MACsec frame protection.
 * This file validates Ethernet frame encryption, decryption, authentication
 * and MACsec frame processing using predefined test vectors.
 *
 * Copyright (c) 2026 Michal Sarnovský
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */

#include <tests/test_frame_crypto.h>
#include <tests/unit_tests.h>

#include <string.h>

#if (MACSEC_SELF_TEST != 0)

static void macsec_test_fill_plain_frame(uint8_t *frame,
                                         size_t len,
                                         uint16_t ethertype,
                                         uint8_t seed)
{
    size_t i;

    macsec_assert(frame != NULL);
    macsec_assert(len >= 14u);

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

    for (i = 14u; i < len; i++)
    {
        frame[i] = (uint8_t)(seed + (uint8_t)i);
    }
}

static void macsec_test_fill_sak(macsec_frame_sak_t *sak,
                                 uint8_t an)
{
    static const uint8_t key[16] =
    {
        0x00u, 0x11u, 0x22u, 0x33u,
        0x44u, 0x55u, 0x66u, 0x77u,
        0x88u, 0x99u, 0xAAu, 0xBBu,
        0xCCu, 0xDDu, 0xEEu, 0xFFu
    };

    macsec_assert(sak != NULL);

    memset(sak, 0, sizeof(*sak));

    memcpy(sak->key, key, sizeof(key));
    sak->key_len = sizeof(key);
    sak->an = an & 0x03u;
    sak->next_pn = 1u;
    sak->lowest_acceptable_pn = 1u;
    sak->valid = MACSEC_TRUE;
}

static int macsec_test_frame_crypto_selftest_wrapper(macsec_test_frame_crypto_selftest_wrapper_data_t *data, int verbose)
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

static int macsec_test_frame_crypto_encrypt_decrypt_one(macsec_test_frame_crypto_encrypt_decrypt_one_data_t *data, int verbose)
{
    size_t plain_len = 96u;
    size_t secure_len = 0u;
    size_t decrypted_len = 0u;

    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  Frame crypto encrypt/decrypt one packet test\n"));
    }

    data->sci.bytes[0] = 0x02u;
    data->sci.bytes[1] = 0x00u;
    data->sci.bytes[2] = 0x00u;
    data->sci.bytes[3] = 0x00u;
    data->sci.bytes[4] = 0x00u;
    data->sci.bytes[5] = 0x02u;
    data->sci.bytes[6] = 0x00u;
    data->sci.bytes[7] = 0x01u;

    macsec_test_fill_sak(&data->sak, 0u);
    macsec_test_fill_plain_frame(data->plain, plain_len, 0x0800u, 0x20u);

    ret = macsec_frame_crypto_init(&data->tx_ctx, &data->sci);
    TEST_OK(ret);

    ret = macsec_frame_crypto_init(&data->rx_ctx, &data->sci);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_frame_crypto_clear(&data->tx_ctx);
        return ret;
    }

    data->tx_ctx.replay_protect = MACSEC_FALSE;
    data->rx_ctx.replay_protect = MACSEC_FALSE;

    ret = macsec_frame_crypto_set_tx_sak(&data->tx_ctx, &data->sak);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_frame_crypto_clear(&data->tx_ctx);
        macsec_frame_crypto_clear(&data->rx_ctx);
        return ret;
    }

    ret = macsec_frame_crypto_set_rx_sak(&data->rx_ctx, &data->sak);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_frame_crypto_clear(&data->tx_ctx);
        macsec_frame_crypto_clear(&data->rx_ctx);
        return ret;
    }

    ret = macsec_frame_encrypt(&data->tx_ctx,
                               data->plain,
                               plain_len,
                               data->secure,
                               &secure_len,
                               sizeof(data->secure));
    if (ret != MACSEC_ERR_OK)
    {
        macsec_frame_crypto_clear(&data->tx_ctx);
        macsec_frame_crypto_clear(&data->rx_ctx);
        return ret;
    }

    TEST_TRUE(macsec_frame_is_macsec(data->secure, secure_len));
    TEST_TRUE(macsec_rd_be16(&data->secure[12]) == MACSEC_FRAME_ETHERTYPE);
    TEST_TRUE((data->secure[14] & 0x03u) == 0u);

    ret = macsec_frame_decrypt(&data->rx_ctx,
                               data->secure,
                               secure_len,
                               data->decrypted,
                               &decrypted_len,
                               sizeof(data->decrypted));
    if (ret != MACSEC_ERR_OK)
    {
        macsec_frame_crypto_clear(&data->tx_ctx);
        macsec_frame_crypto_clear(&data->rx_ctx);
        return ret;
    }

    TEST_TRUE(decrypted_len == plain_len);
    TEST_TRUE(memcmp(data->plain, data->decrypted, plain_len) == 0);

    macsec_frame_crypto_clear(&data->tx_ctx);
    macsec_frame_crypto_clear(&data->rx_ctx);

    return 0;
}

static int macsec_test_frame_crypto_bad_icv(macsec_test_frame_crypto_bad_icv_data_t *data, int verbose)
{
    size_t plain_len = 96u;
    size_t secure_len = 0u;
    size_t decrypted_len = 0u;

    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  Frame crypto bad ICV/auth test\n"));
    }

    data->sci.bytes[0] = 0x02u;
    data->sci.bytes[1] = 0x00u;
    data->sci.bytes[2] = 0x00u;
    data->sci.bytes[3] = 0x00u;
    data->sci.bytes[4] = 0x00u;
    data->sci.bytes[5] = 0x02u;
    data->sci.bytes[6] = 0x00u;
    data->sci.bytes[7] = 0x01u;

    macsec_test_fill_sak(&data->sak, 0u);
    macsec_test_fill_plain_frame(data->plain, plain_len, 0x0800u, 0x30u);

    ret = macsec_frame_crypto_init(&data->tx_ctx, &data->sci);
    TEST_OK(ret);

    ret = macsec_frame_crypto_init(&data->rx_ctx, &data->sci);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_frame_crypto_clear(&data->tx_ctx);
        return ret;
    }

    data->tx_ctx.replay_protect = MACSEC_FALSE;
    data->rx_ctx.replay_protect = MACSEC_FALSE;

    ret = macsec_frame_crypto_set_tx_sak(&data->tx_ctx, &data->sak);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_frame_crypto_clear(&data->tx_ctx);
        macsec_frame_crypto_clear(&data->rx_ctx);
        return ret;
    }

    ret = macsec_frame_crypto_set_rx_sak(&data->rx_ctx, &data->sak);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_frame_crypto_clear(&data->tx_ctx);
        macsec_frame_crypto_clear(&data->rx_ctx);
        return ret;
    }

    ret = macsec_frame_encrypt(&data->tx_ctx,
                               data->plain,
                               plain_len,
                               data->secure,
                               &secure_len,
                               sizeof(data->secure));
    if (ret != MACSEC_ERR_OK)
    {
        macsec_frame_crypto_clear(&data->tx_ctx);
        macsec_frame_crypto_clear(&data->rx_ctx);
        return ret;
    }

    data->secure[secure_len - 1u] ^= 0x01u;

    ret = macsec_frame_decrypt(&data->rx_ctx,
                               data->secure,
                               secure_len,
                               data->decrypted,
                               &decrypted_len,
                               sizeof(data->decrypted));

    if (ret == MACSEC_ERR_OK)
    {
        macsec_frame_crypto_clear(&data->tx_ctx);
        macsec_frame_crypto_clear(&data->rx_ctx);
        return -1;
    }

    macsec_frame_crypto_clear(&data->tx_ctx);
    macsec_frame_crypto_clear(&data->rx_ctx);

    return 0;
}

static int macsec_test_frame_crypto_replay_reject(macsec_test_frame_crypto_replay_reject_data_t *data, int verbose)
{
    size_t plain_len = 96u;
    size_t secure_len = 0u;
    size_t decrypted_len = 0u;

    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  Frame crypto replay reject test\n"));
    }

    data->sci.bytes[0] = 0x02u;
    data->sci.bytes[1] = 0x00u;
    data->sci.bytes[2] = 0x00u;
    data->sci.bytes[3] = 0x00u;
    data->sci.bytes[4] = 0x00u;
    data->sci.bytes[5] = 0x02u;
    data->sci.bytes[6] = 0x00u;
    data->sci.bytes[7] = 0x01u;

    macsec_test_fill_sak(&data->sak, 0u);
    macsec_test_fill_plain_frame(data->plain, plain_len, 0x0800u, 0x40u);

    ret = macsec_frame_crypto_init(&data->tx_ctx, &data->sci);
    TEST_OK(ret);

    ret = macsec_frame_crypto_init(&data->rx_ctx, &data->sci);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_frame_crypto_clear(&data->tx_ctx);
        return ret;
    }

    data->tx_ctx.replay_protect = MACSEC_TRUE;
    data->tx_ctx.replay_window = 0u;
    data->rx_ctx.replay_protect = MACSEC_TRUE;
    data->rx_ctx.replay_window = 0u;

    ret = macsec_frame_crypto_set_tx_sak(&data->tx_ctx, &data->sak);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_frame_crypto_clear(&data->tx_ctx);
        macsec_frame_crypto_clear(&data->rx_ctx);
        return ret;
    }

    ret = macsec_frame_crypto_set_rx_sak(&data->rx_ctx, &data->sak);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_frame_crypto_clear(&data->tx_ctx);
        macsec_frame_crypto_clear(&data->rx_ctx);
        return ret;
    }

    ret = macsec_frame_encrypt(&data->tx_ctx,
                               data->plain,
                               plain_len,
                               data->secure,
                               &secure_len,
                               sizeof(data->secure));
    if (ret != MACSEC_ERR_OK)
    {
        macsec_frame_crypto_clear(&data->tx_ctx);
        macsec_frame_crypto_clear(&data->rx_ctx);
        return ret;
    }

    ret = macsec_frame_decrypt(&data->rx_ctx,
                               data->secure,
                               secure_len,
                               data->decrypted,
                               &decrypted_len,
                               sizeof(data->decrypted));
    if (ret != MACSEC_ERR_OK)
    {
        macsec_frame_crypto_clear(&data->tx_ctx);
        macsec_frame_crypto_clear(&data->rx_ctx);
        return ret;
    }

    decrypted_len = 0u;

    ret = macsec_frame_decrypt(&data->rx_ctx,
                               data->secure,
                               secure_len,
                               data->decrypted,
                               &decrypted_len,
                               sizeof(data->decrypted));

    if (ret != MACSEC_ERR_REPLAY)
    {
        macsec_frame_crypto_clear(&data->tx_ctx);
        macsec_frame_crypto_clear(&data->rx_ctx);
        return -1;
    }

    macsec_frame_crypto_clear(&data->tx_ctx);
    macsec_frame_crypto_clear(&data->rx_ctx);

    return 0;
}

int macsec_test_frame_crypto(macsec_test_frame_crypto_data_t *data, int verbose)
{
    if (verbose)
    {
        MACSEC_PRINT(("MACsec frame crypto tests\n"));
    }

    TEST_OK(macsec_test_frame_crypto_selftest_wrapper(&data->test_frame_crypto_selftest_wrapper_data, verbose));
    TEST_OK(macsec_test_frame_crypto_encrypt_decrypt_one(&data->test_frame_crypto_encrypt_decrypt_one_data, verbose));
    TEST_OK(macsec_test_frame_crypto_bad_icv(&data->test_frame_crypto_bad_icv_data, verbose));
    TEST_OK(macsec_test_frame_crypto_replay_reject(&data->test_frame_crypto_replay_reject_data, verbose));

    return 0;
}

#endif /* MACSEC_SELF_TEST */
