/*
 * test_mka_negative.c
 *
 * Lightweight MACsec stack
 * Negative and robustness tests for the MKA protocol.
 * This file verifies correct handling of malformed, invalid and unexpected
 * MKA messages, ensuring proper error detection and protocol robustness.
 *
 * Copyright (c) 2026 Michal Sarnovský
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */

#include <tests/test_mka_negative.h>
#include <tests/unit_tests.h>

#if (MACSEC_SELF_TEST != 0)

static const uint8_t test_cak[16] =
{
    0x00u, 0x11u, 0x22u, 0x33u,
    0x44u, 0x55u, 0x66u, 0x77u,
    0x88u, 0x99u, 0xAAu, 0xBBu,
    0xCCu, 0xDDu, 0xEEu, 0xFFu
};

static const uint8_t test_ckn[24] =
{
    0x00u, 0x11u, 0x22u, 0x33u,
    0x44u, 0x55u, 0x66u, 0x77u,
    0x88u, 0x99u, 0xAAu, 0xBBu,
    0xCCu, 0xDDu, 0xEEu, 0xFFu,
    0x00u, 0x11u, 0x22u, 0x33u,
    0x44u, 0x55u, 0x66u, 0x77u
};

static const uint8_t test_mac_a[6] =
{
    0x02u, 0x00u, 0x00u, 0x00u, 0x00u, 0x01u
};

static const uint8_t test_mac_b[6] =
{
    0x02u, 0x00u, 0x00u, 0x00u, 0x00u, 0x02u
};

static int macsec_test_mka_negative_bad_ethertype(macsec_test_mka_negative_bad_ethertype_data_t *data, int verbose)
{
    size_t frame_len = 0u;
    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  MKA negative bad EtherType test\n"));
    }

    ret = macsec_mka_init(&data->mka,
                          test_cak,
                          sizeof(test_cak),
                          test_ckn,
                          sizeof(test_ckn),
                          test_mac_a,
                          1u,
                          255u,
                          2000u);
    TEST_OK(ret);

    ret = macsec_mka_get_tx_frame(&data->mka,
                                  data->frame,
                                  &frame_len,
                                  sizeof(data->frame));
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_clear(&data->mka);
        return ret;
    }

    macsec_wr_be16(&data->frame[12], 0x0800u);

    ret = macsec_mka_input(&data->mka,
                           data->frame,
                           frame_len,
                           100u);

    macsec_mka_clear(&data->mka);

    TEST_TRUE(ret != MACSEC_ERR_OK);

    return 0;
}

static int macsec_test_mka_negative_bad_eapol_type(macsec_test_mka_negative_bad_eapol_type_data_t *data, int verbose)
{
    size_t frame_len = 0u;
    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  MKA negative bad EAPOL type test\n"));
    }

    ret = macsec_mka_init(&data->mka,
                          test_cak,
                          sizeof(test_cak),
                          test_ckn,
                          sizeof(test_ckn),
                          test_mac_a,
                          1u,
                          255u,
                          2000u);
    TEST_OK(ret);

    ret = macsec_mka_get_tx_frame(&data->mka,
                                  data->frame,
                                  &frame_len,
                                  sizeof(data->frame));
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_clear(&data->mka);
        return ret;
    }

    data->frame[15] = 0x01u;

    ret = macsec_mka_input(&data->mka,
                           data->frame,
                           frame_len,
                           100u);

    macsec_mka_clear(&data->mka);

    TEST_TRUE(ret != MACSEC_ERR_OK);

    return 0;
}

static int macsec_test_mka_negative_short_frame(macsec_test_mka_negative_short_frame_data_t *data, int verbose)
{
    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  MKA negative short frame test\n"));
    }

    ret = macsec_mka_init(&data->mka,
                          test_cak,
                          sizeof(test_cak),
                          test_ckn,
                          sizeof(test_ckn),
                          test_mac_a,
                          1u,
                          255u,
                          2000u);
    TEST_OK(ret);

    memset(data->frame, 0, sizeof(data->frame));
    macsec_wr_be16(&data->frame[12], MACSEC_MKA_ETHERTYPE_EAPOL);
    data->frame[15] = MACSEC_MKA_EAPOL_TYPE_MKA;

    ret = macsec_mka_input(&data->mka,
                           data->frame,
                           sizeof(data->frame),
                           100u);

    macsec_mka_clear(&data->mka);

    TEST_TRUE(ret != MACSEC_ERR_OK);

    return 0;
}

static int macsec_test_mka_negative_bad_icv(macsec_test_mka_negative_bad_icv_data_t *data, int verbose)
{
    size_t frame_len = 0u;

    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  MKA negative bad ICV test\n"));
    }

    ret = macsec_mka_init(&data->tx,
                          test_cak,
                          sizeof(test_cak),
                          test_ckn,
                          sizeof(test_ckn),
                          test_mac_a,
                          1u,
                          255u,
                          2000u);
    TEST_OK(ret);

    ret = macsec_mka_init(&data->rx,
                          test_cak,
                          sizeof(test_cak),
                          test_ckn,
                          sizeof(test_ckn),
                          test_mac_b,
                          1u,
                          100u,
                          2000u);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_clear(&data->tx);
        return ret;
    }

    ret = macsec_mka_get_tx_frame(&data->tx,
                                  data->frame,
                                  &frame_len,
                                  sizeof(data->frame));
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_clear(&data->tx);
        macsec_mka_clear(&data->rx);
        return ret;
    }

    data->frame[frame_len - 1u] ^= 0x01u;

    ret = macsec_mka_input(&data->rx,
                           data->frame,
                           frame_len,
                           100u);

    macsec_mka_clear(&data->tx);
    macsec_mka_clear(&data->rx);

    TEST_TRUE(ret == MACSEC_ERR_AUTH);

    return 0;
}

static int macsec_test_mka_negative_reflected_own_frame_ignored(macsec_test_mka_negative_reflected_own_frame_ignored_data_t *data, int verbose)
{
    size_t frame_len = 0u;

    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  MKA negative reflected own frame ignored test\n"));
    }

    ret = macsec_mka_init(&data->mka,
                          test_cak,
                          sizeof(test_cak),
                          test_ckn,
                          sizeof(test_ckn),
                          test_mac_a,
                          1u,
                          255u,
                          2000u);
    TEST_OK(ret);

    ret = macsec_mka_get_tx_frame(&data->mka,
                                  data->frame,
                                  &frame_len,
                                  sizeof(data->frame));
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_clear(&data->mka);
        return ret;
    }

    ret = macsec_mka_input(&data->mka,
                           data->frame,
                           frame_len,
                           100u);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_clear(&data->mka);
        return ret;
    }

    TEST_TRUE(!data->mka.peer.valid);
    TEST_TRUE(data->mka.state == MACSEC_MKA_STATE_WAIT_PEER);

    macsec_mka_clear(&data->mka);

    return 0;
}

static int macsec_test_mka_negative_wrong_cak_fails_icv(macsec_test_mka_negative_wrong_cak_fails_icv_data_t *data, int verbose)
{
    static const uint8_t wrong_cak[16] =
    {
        0xFFu, 0x11u, 0x22u, 0x33u,
        0x44u, 0x55u, 0x66u, 0x77u,
        0x88u, 0x99u, 0xAAu, 0xBBu,
        0xCCu, 0xDDu, 0xEEu, 0xFFu
    };

    size_t frame_len = 0u;

    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  MKA negative wrong CAK fails ICV test\n"));
    }

    ret = macsec_mka_init(&data->tx,
                          test_cak,
                          sizeof(test_cak),
                          test_ckn,
                          sizeof(test_ckn),
                          test_mac_a,
                          1u,
                          255u,
                          2000u);
    TEST_OK(ret);

    ret = macsec_mka_init(&data->rx,
                          wrong_cak,
                          sizeof(wrong_cak),
                          test_ckn,
                          sizeof(test_ckn),
                          test_mac_b,
                          1u,
                          100u,
                          2000u);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_clear(&data->tx);
        return ret;
    }

    ret = macsec_mka_get_tx_frame(&data->tx,
                                  data->frame,
                                  &frame_len,
                                  sizeof(data->frame));
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_clear(&data->tx);
        macsec_mka_clear(&data->rx);
        return ret;
    }

    ret = macsec_mka_input(&data->rx,
                           data->frame,
                           frame_len,
                           100u);

    macsec_mka_clear(&data->tx);
    macsec_mka_clear(&data->rx);

    TEST_TRUE(ret == MACSEC_ERR_AUTH);

    return 0;
}

int macsec_test_mka_negative(macsec_test_mka_negative_data_t *data, int verbose)
{
    if (verbose)
    {
        MACSEC_PRINT(("MACsec MKA negative tests\n"));
    }

    TEST_OK(macsec_test_mka_negative_bad_ethertype(&data->test_mka_negative_bad_ethertype_data, verbose));
    TEST_OK(macsec_test_mka_negative_bad_eapol_type(&data->test_mka_negative_bad_eapol_type_data, verbose));
    TEST_OK(macsec_test_mka_negative_short_frame(&data->test_mka_negative_short_frame_data_data, verbose));
    TEST_OK(macsec_test_mka_negative_bad_icv(&data->test_mka_negative_bad_icv_data_data, verbose));
    TEST_OK(macsec_test_mka_negative_wrong_cak_fails_icv(&data->test_mka_negative_wrong_cak_fails_icv_data, verbose));
    TEST_OK(macsec_test_mka_negative_reflected_own_frame_ignored(&data->test_mka_negative_reflected_own_frame_ignored_data, verbose));

    return 0;
}

#endif /* MACSEC_SELF_TEST */
