/*
 * test_rekey.c
 *
 * Lightweight MACsec stack
 * Rekeying and key update tests.
 * This file validates Secure Association Key (SAK) replacement, packet
 * number continuity and key transition procedures during MACsec operation.
 *
 * Copyright (c) 2026 Michal Sarnovský
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */

#include <tests/test_rekey.h>
#include <tests/unit_tests.h>

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
    frame[5] = 0x02u;

    frame[6] = 0x02u;
    frame[7] = 0x00u;
    frame[8] = 0x00u;
    frame[9] = 0x00u;
    frame[10] = 0x00u;
    frame[11] = 0x01u;

    macsec_wr_be16(&frame[12], ethertype);

    for (i = 14u; i < len; i++)
    {
        frame[i] = (uint8_t)(seed + (uint8_t)i);
    }
}

static void macsec_test_make_sak(macsec_frame_sak_t *sak,
                                 uint8_t an,
                                 uint8_t seed)
{
    size_t i;

    macsec_assert(sak != NULL);

    memset(sak, 0, sizeof(*sak));

    for (i = 0u; i < 16u; i++)
    {
        sak->key[i] = (uint8_t)(seed + (uint8_t)(i * 7u));
    }

    sak->key_len = 16u;
    sak->an = an & 0x03u;
    sak->next_pn = 1u;
    sak->lowest_acceptable_pn = 1u;
    sak->valid = MACSEC_TRUE;
}

static void macsec_test_make_sci(macsec_frame_sci_t *sci)
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

static int macsec_test_rekey_an_rotation_decrypts_all(macsec_test_rekey_an_rotation_decrypts_all_data_t *data, int verbose)
{
    size_t plain_len = 96u;
    size_t secure_len = 0u;
    size_t decrypted_len = 0u;

    uint8_t an;
    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  Rekey AN rotation decrypts all AN test\n"));
    }

    macsec_test_make_sci(&data->sci);

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

    for (an = 0u; an < MACSEC_FRAME_MAX_SA; an++)
    {
        macsec_test_make_sak(&data->sak, an, (uint8_t)(0x10u + (an * 0x20u)));

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

        macsec_test_fill_plain_frame(data->plain,
                                     plain_len,
                                     0x0800u,
                                     (uint8_t)(0x40u + an));

        secure_len = 0u;
        decrypted_len = 0u;

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

        TEST_TRUE((data->secure[14] & 0x03u) == an);

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
    }

    macsec_frame_crypto_clear(&data->tx_ctx);
    macsec_frame_crypto_clear(&data->rx_ctx);

    return 0;
}

static int macsec_test_rekey_old_rx_sak_still_accepted(macsec_test_rekey_old_rx_sak_still_accepted_data_t *data, int verbose)
{
    size_t plain_len = 96u;
    size_t secure0_len = 0u;
    size_t secure1_len = 0u;
    size_t decrypted_len = 0u;

    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  Rekey old RX SAK still accepted test\n"));
    }

    macsec_test_make_sci(&data->sci);
    macsec_test_make_sak(&data->sak0, 0u, 0x11u);
    macsec_test_make_sak(&data->sak1, 1u, 0x55u);

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

    ret = macsec_frame_crypto_set_tx_sak(&data->tx_ctx, &data->sak0);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_frame_crypto_clear(&data->tx_ctx);
        macsec_frame_crypto_clear(&data->rx_ctx);
        return ret;
    }

    ret = macsec_frame_crypto_set_rx_sak(&data->rx_ctx, &data->sak0);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_frame_crypto_clear(&data->tx_ctx);
        macsec_frame_crypto_clear(&data->rx_ctx);
        return ret;
    }

    macsec_test_fill_plain_frame(data->plain0, plain_len, 0x0800u, 0x21u);

    ret = macsec_frame_encrypt(&data->tx_ctx,
                               data->plain0,
                               plain_len,
                               data->secure0,
                               &secure0_len,
                               sizeof(data->secure0));
    if (ret != MACSEC_ERR_OK)
    {
        macsec_frame_crypto_clear(&data->tx_ctx);
        macsec_frame_crypto_clear(&data->rx_ctx);
        return ret;
    }

    ret = macsec_frame_crypto_set_tx_sak(&data->tx_ctx, &data->sak1);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_frame_crypto_clear(&data->tx_ctx);
        macsec_frame_crypto_clear(&data->rx_ctx);
        return ret;
    }

    ret = macsec_frame_crypto_set_rx_sak(&data->rx_ctx, &data->sak1);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_frame_crypto_clear(&data->tx_ctx);
        macsec_frame_crypto_clear(&data->rx_ctx);
        return ret;
    }

    macsec_test_fill_plain_frame(data->plain1, plain_len, 0x0800u, 0x31u);

    ret = macsec_frame_encrypt(&data->tx_ctx,
                               data->plain1,
                               plain_len,
                               data->secure1,
                               &secure1_len,
                               sizeof(data->secure1));
    if (ret != MACSEC_ERR_OK)
    {
        macsec_frame_crypto_clear(&data->tx_ctx);
        macsec_frame_crypto_clear(&data->rx_ctx);
        return ret;
    }

    TEST_TRUE((data->secure0[14] & 0x03u) == 0u);
    TEST_TRUE((data->secure1[14] & 0x03u) == 1u);

    ret = macsec_frame_decrypt(&data->rx_ctx,
                               data->secure0,
                               secure0_len,
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
    TEST_TRUE(memcmp(data->plain0, data->decrypted, plain_len) == 0);

    decrypted_len = 0u;

    ret = macsec_frame_decrypt(&data->rx_ctx,
                               data->secure1,
                               secure1_len,
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
    TEST_TRUE(memcmp(data->plain1, data->decrypted, plain_len) == 0);

    macsec_frame_crypto_clear(&data->tx_ctx);
    macsec_frame_crypto_clear(&data->rx_ctx);

    return 0;
}

static int macsec_test_rekey_wrong_key_same_an_fails(macsec_test_rekey_wrong_key_same_an_fails_data_t *data, int verbose)
{
    size_t plain_len = 96u;
    size_t secure_len = 0u;
    size_t decrypted_len = 0u;

    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  Rekey wrong key same AN fails test\n"));
    }

    macsec_test_make_sci(&data->sci);
    macsec_test_make_sak(&data->tx_sak, 1u, 0x10u);
    macsec_test_make_sak(&data->wrong_rx_sak, 1u, 0x99u);

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

    ret = macsec_frame_crypto_set_tx_sak(&data->tx_ctx, &data->tx_sak);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_frame_crypto_clear(&data->tx_ctx);
        macsec_frame_crypto_clear(&data->rx_ctx);
        return ret;
    }

    ret = macsec_frame_crypto_set_rx_sak(&data->rx_ctx, &data->wrong_rx_sak);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_frame_crypto_clear(&data->tx_ctx);
        macsec_frame_crypto_clear(&data->rx_ctx);
        return ret;
    }

    macsec_test_fill_plain_frame(data->plain, plain_len, 0x0800u, 0x41u);

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

    macsec_frame_crypto_clear(&data->tx_ctx);
    macsec_frame_crypto_clear(&data->rx_ctx);

    TEST_TRUE(ret != MACSEC_ERR_OK);

    return 0;
}

int macsec_test_rekey(macsec_test_rekey_data_t *data, int verbose)
{
    if (verbose)
    {
        MACSEC_PRINT(("MACsec rekey tests\n"));
    }

    TEST_OK(macsec_test_rekey_an_rotation_decrypts_all(&data->rekey_an_rotation_decrypts_all_data, verbose));
    TEST_OK(macsec_test_rekey_old_rx_sak_still_accepted(&data->rekey_old_rx_sak_still_accepted_data, verbose));
    TEST_OK(macsec_test_rekey_wrong_key_same_an_fails(&data->rekey_wrong_key_same_an_fails_data, verbose));

    return 0;
}

#endif /* MACSEC_SELF_TEST */
