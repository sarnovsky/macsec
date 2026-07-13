/*
 * test_mka_frames.c
 *
 * Lightweight MACsec stack
 * Unit tests for MKA frame encoding and decoding.
 * This file verifies generation, parsing and validation of MKA protocol
 * frames and their individual parameter sets.
 *
 * Copyright (c) 2026 Michal Sarnovský
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */

#include <tests/test_mka_frames.h>
#include <tests/unit_tests.h>

#if (MACSEC_SELF_TEST != 0)

static const uint8_t s_cak[16] =
{
    0x00u, 0x11u, 0x22u, 0x33u,
    0x44u, 0x55u, 0x66u, 0x77u,
    0x88u, 0x99u, 0xAAu, 0xBBu,
    0xCCu, 0xDDu, 0xEEu, 0xFFu
};

static const uint8_t s_ckn[24] =
{
    0x00u, 0x11u, 0x22u, 0x33u,
    0x44u, 0x55u, 0x66u, 0x77u,
    0x88u, 0x99u, 0xAAu, 0xBBu,
    0xCCu, 0xDDu, 0xEEu, 0xFFu,
    0x00u, 0x11u, 0x22u, 0x33u,
    0x44u, 0x55u, 0x66u, 0x77u
};

static const uint8_t s_mac_a[6] =
{
    0x02u, 0x00u, 0x00u, 0x00u, 0x00u, 0x01u
};

static const uint8_t s_mac_b[6] =
{
    0x02u, 0x00u, 0x00u, 0x00u, 0x00u, 0x02u
};

static int macsec_test_mka_init_ctx(macsec_mka_ctx_t *ctx,
                                    const uint8_t mac[6],
                                    uint8_t priority)
{
    return macsec_mka_init(ctx,
                           s_cak,
                           sizeof(s_cak),
                           s_ckn,
                           sizeof(s_ckn),
                           mac,
                           1u,
                           priority,
                           2000u);
}

static int macsec_test_mka_frames_linux_basic_icv(macsec_test_mka_frames_linux_basic_icv_data_t *data, int verbose)
{
    typedef struct
    {
        const char *frame;
        uint32_t expected_mn;
    } test_frame_t;

    static const test_frame_t frames[] =
    {
        { "0180c2000003dca632d16f96888e0305004801ffe034dca632d16f9600019bdefc3c298c8042829d3a80000000010080c20100112233445566778899aabbccddeeff0011223344556677f4f0a54f2ad4511011cb8ff93182d6e8", 1u },
        { "0180c2000003dca632d16f96888e0305004801ffe034dca632d16f9600019bdefc3c298c8042829d3a80000000020080c20100112233445566778899aabbccddeeff0011223344556677d9f640d97c6730460bb3ef07f2e27688", 2u },
        { "0180c2000003dca632d16f96888e0305004801ffe034dca632d16f9600019bdefc3c298c8042829d3a80000000030080c20100112233445566778899aabbccddeeff0011223344556677c7869886aceb873cea6d67ad18d21274", 3u },
        { "0180c2000003dca632d16f96888e0305004801ffe034dca632d16f9600019bdefc3c298c8042829d3a80000000040080c20100112233445566778899aabbccddeeff001122334455667795c5864fc73f26f12a05ab353ef268db", 4u },
        { "0180c2000003dca632d16f96888e0305004801ffe034dca632d16f9600019bdefc3c298c8042829d3a80000000050080c20100112233445566778899aabbccddeeff0011223344556677e2b7be739735f4142a318a040f951541", 5u }
    };

#define MKA_LINUX_BASIC_FRAME_COUNT (sizeof(frames) / sizeof(frames[0]))

    size_t frame_len;
    size_t i;
    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  MKA frames Linux Basic/ICV test\n"));
    }

    ret = macsec_test_mka_init_ctx(&data->mka, s_mac_a, 100u);
    TEST_OK(ret);

    for (i = 0u; i < MKA_LINUX_BASIC_FRAME_COUNT; i++)
    {
        frame_len = 0u;

        ret = macsec_hex_to_bin(frames[i].frame,
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
                               (uint32_t)(i * 1000u));
        if (ret != MACSEC_ERR_OK)
        {
            macsec_mka_clear(&data->mka);
            return ret;
        }

        if (data->mka.last_basic.actor_mn != frames[i].expected_mn)
        {
            macsec_mka_clear(&data->mka);
            return -1;
        }

        if (!data->mka.last_icv_valid)
        {
            macsec_mka_clear(&data->mka);
            return -1;
        }
    }

    macsec_mka_clear(&data->mka);

    return 0;
}

static int macsec_test_mka_frames_build_parse_basic(macsec_test_mka_frames_build_parse_basic_data_t *data, int verbose)
{
    size_t frame_len;
    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  MKA frame build/parse Basic test\n"));
    }

    ret = macsec_test_mka_init_ctx(&data->mka, s_mac_a, 255u);
    TEST_OK(ret);

    frame_len = 0u;

    ret = macsec_mka_get_tx_frame(&data->mka,
                                  data->frame,
                                  &frame_len,
                                  sizeof(data->frame));
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_clear(&data->mka);
        return ret;
    }

    ret = macsec_mka_parse_basic(data->frame, frame_len, &data->basic);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_clear(&data->mka);
        return ret;
    }

    TEST_EQ_U32(data->basic.eapol_type, MACSEC_MKA_EAPOL_TYPE_MKA);
    TEST_EQ_U32(data->basic.actor_mn, 1u);
    TEST_EQ_U32(data->basic.key_server_priority, 255u);
    TEST_MEM_EQ(data->basic.src_mac, s_mac_a, 6u);
    TEST_MEM_EQ(data->basic.cak_name, s_ckn, sizeof(s_ckn));
    TEST_EQ_U32(data->basic.cak_name_len, sizeof(s_ckn));

    macsec_mka_clear(&data->mka);

    return 0;
}

static int macsec_test_mka_frames_generated_icv_ok(macsec_test_mka_frames_generated_icv_ok_data_t *data, int verbose)
{
    size_t frame_len;
    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  MKA generated frame ICV OK test\n"));
    }

    ret = macsec_test_mka_init_ctx(&data->tx, s_mac_a, 255u);
    TEST_OK(ret);

    ret = macsec_test_mka_init_ctx(&data->rx, s_mac_b, 100u);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_clear(&data->tx);
        return ret;
    }

    frame_len = 0u;

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

    ret = macsec_mka_input(&data->rx, data->frame, frame_len, 1000u);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_clear(&data->tx);
        macsec_mka_clear(&data->rx);
        return ret;
    }

    TEST_TRUE(data->rx.peer.valid);
    TEST_TRUE(data->rx.last_icv_valid);
    TEST_MEM_EQ(data->rx.peer.mac, s_mac_a, 6u);
    TEST_EQ_U32(data->rx.peer.mn, 1u);

    macsec_mka_clear(&data->tx);
    macsec_mka_clear(&data->rx);

    return 0;
}

static int macsec_test_mka_frames_generated_icv_bad(macsec_test_mka_frames_generated_icv_bad_data_t *data, int verbose)
{
    size_t frame_len;
    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  MKA generated frame ICV bad test\n"));
    }

    ret = macsec_test_mka_init_ctx(&data->tx, s_mac_a, 255u);
    TEST_OK(ret);

    ret = macsec_test_mka_init_ctx(&data->rx, s_mac_b, 100u);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_clear(&data->tx);
        return ret;
    }

    frame_len = 0u;

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

    ret = macsec_mka_input(&data->rx, data->frame, frame_len, 1000u);
    if (ret != MACSEC_ERR_AUTH)
    {
        macsec_mka_clear(&data->tx);
        macsec_mka_clear(&data->rx);
        return -1;
    }

    macsec_mka_clear(&data->tx);
    macsec_mka_clear(&data->rx);

    return 0;
}

static int macsec_test_mka_frames_two_peer_exchange(macsec_test_mka_frames_two_peer_exchange_data_t *data, int verbose)
{
    static const uint8_t local_mac_a[6] =
    {
        0x02u, 0x00u, 0x00u, 0x00u, 0x00u, 0x01u
    };

    static const uint8_t local_mac_b[6] =
    {
        0x02u, 0x00u, 0x00u, 0x00u, 0x00u, 0x02u
    };

    static const char cakText[] =
        "00112233445566778899aabbccddeeff";

    static const char cknText[] =
        "00112233445566778899aabbccddeeff"
        "0011223344556677";

    size_t cak_len = 0u;
    size_t ckn_len = 0u;
    size_t frame_len = 0u;

    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  MKA two-peer exchange test\n"));
    }

    ret = macsec_hex_to_bin(cakText, data->cak, &cak_len, sizeof(data->cak));
    TEST_OK(ret);

    ret = macsec_hex_to_bin(cknText, data->ckn, &ckn_len, sizeof(data->ckn));
    TEST_OK(ret);

    ret = macsec_mka_init(&data->a,
                          data->cak,
                          cak_len,
                          data->ckn,
                          ckn_len,
                          local_mac_a,
                          1u,
                          255u,
                          2000u);
    TEST_OK(ret);

    ret = macsec_mka_init(&data->b,
                          data->cak,
                          cak_len,
                          data->ckn,
                          ckn_len,
                          local_mac_b,
                          1u,
                          100u,
                          2000u);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_clear(&data->a);
        return ret;
    }

    frame_len = 0u;
    ret = macsec_mka_get_tx_frame(&data->a, data->frame, &frame_len, sizeof(data->frame));
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_clear(&data->a);
        macsec_mka_clear(&data->b);
        return ret;
    }

    ret = macsec_mka_input(&data->b, data->frame, frame_len, 100u);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_clear(&data->a);
        macsec_mka_clear(&data->b);
        return ret;
    }

    TEST_TRUE(data->b.peer.valid);
    TEST_TRUE(data->b.local_key_server);
    TEST_TRUE(!data->b.peer.live);
    TEST_TRUE(data->b.state == MACSEC_MKA_STATE_PEER_FOUND);

    frame_len = 0u;
    ret = macsec_mka_get_tx_frame(&data->b, data->frame, &frame_len, sizeof(data->frame));
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_clear(&data->a);
        macsec_mka_clear(&data->b);
        return ret;
    }

    ret = macsec_mka_input(&data->a, data->frame, frame_len, 200u);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_clear(&data->a);
        macsec_mka_clear(&data->b);
        return ret;
    }

    TEST_TRUE(data->a.peer.valid);
    TEST_TRUE(!data->a.local_key_server);
    TEST_TRUE(data->a.peer.live);
    TEST_TRUE(data->a.state == MACSEC_MKA_STATE_AUTHENTICATED);

    frame_len = 0u;
    ret = macsec_mka_get_tx_frame(&data->a, data->frame, &frame_len, sizeof(data->frame));
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_clear(&data->a);
        macsec_mka_clear(&data->b);
        return ret;
    }

    ret = macsec_mka_input(&data->b, data->frame, frame_len, 300u);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_clear(&data->a);
        macsec_mka_clear(&data->b);
        return ret;
    }

    TEST_TRUE(data->b.peer.valid);
    TEST_TRUE(data->b.local_key_server);
    TEST_TRUE(data->b.peer.live);
    TEST_TRUE(data->b.state == MACSEC_MKA_STATE_AUTHENTICATED);

    macsec_mka_clear(&data->a);
    macsec_mka_clear(&data->b);

    return 0;
}

static int macsec_test_mka_frames_tx_pending_timing(macsec_test_mka_frames_tx_pending_timing_data_t *data, int verbose)
{
    size_t frame_len;
    int ret;

    if (verbose)
    {
        MACSEC_PRINT(("  MKA tx_pending timing test\n"));
    }

    ret = macsec_test_mka_init_ctx(&data->mka, s_mac_a, 255u);
    TEST_OK(ret);

    frame_len = 0u;

    ret = macsec_mka_get_tx_frame(&data->mka,
                                  data->frame,
                                  &frame_len,
                                  sizeof(data->frame));
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_clear(&data->mka);
        return ret;
    }

    TEST_TRUE(!data->mka.tx_pending);

    ret = macsec_mka_tick(&data->mka, 1000u);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_clear(&data->mka);
        return ret;
    }

    TEST_TRUE(!data->mka.tx_pending);

    ret = macsec_mka_tick(&data->mka, 3000u);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_clear(&data->mka);
        return ret;
    }

    TEST_TRUE(data->mka.tx_pending);

    macsec_mka_clear(&data->mka);

    return 0;
}

static int macsec_test_mka_frames_distributed_sak_layout(macsec_test_mka_frames_distributed_sak_layout_data_t *data, int verbose)
{
    /*
     * This test verifies only the local interpretation of Linux Distributed SAK
     * body header:
     *
     *   body[0..3] = Key Number
     *   AN = (Key Number - 1) & 0x03
     *
     * It protects against the previous bug where AN was decoded from body[0].
     */
    uint8_t body[4];
    uint32_t key_number;
    uint8_t an;

    (void)data;

    if (verbose)
    {
        MACSEC_PRINT(("  MKA Distributed SAK layout test\n"));
    }

    body[0] = 0x00u;
    body[1] = 0x00u;
    body[2] = 0x00u;
    body[3] = 0x01u;

    key_number = macsec_rd_be32(body);
    an = (uint8_t)((key_number - 1u) & 0x03u);

    TEST_EQ_U32(key_number, 1u);
    TEST_EQ_U32(an, 0u);

    body[3] = 0x02u;
    key_number = macsec_rd_be32(body);
    an = (uint8_t)((key_number - 1u) & 0x03u);

    TEST_EQ_U32(key_number, 2u);
    TEST_EQ_U32(an, 1u);

    body[3] = 0x03u;
    key_number = macsec_rd_be32(body);
    an = (uint8_t)((key_number - 1u) & 0x03u);

    TEST_EQ_U32(key_number, 3u);
    TEST_EQ_U32(an, 2u);

    body[3] = 0x04u;
    key_number = macsec_rd_be32(body);
    an = (uint8_t)((key_number - 1u) & 0x03u);

    TEST_EQ_U32(key_number, 4u);
    TEST_EQ_U32(an, 3u);

    return 0;
}

#define TEST_MKA_PARAM_LIVE_PEER_LIST       1u
#define TEST_MKA_PARAM_POTENTIAL_PEER_LIST  2u
#define TEST_MKA_PARAM_SAK_USE              3u
#define TEST_MKA_PARAM_DISTRIBUTED_SAK      4u

static int test_mka_find_param(const uint8_t *frame,
                               size_t frame_len,
                               uint8_t wanted_type,
                               const uint8_t **param,
                               uint16_t *body_len)
{
    uint16_t eapol_len;
    size_t pos;
    size_t end;

    TEST_TRUE(frame != NULL);
    TEST_TRUE(param != NULL);
    TEST_TRUE(body_len != NULL);
    TEST_TRUE(frame_len >= 90u);

    eapol_len = macsec_rd_be16(&frame[16]);
    end = 14u + 4u + eapol_len - MACSEC_MKA_ICV_LEN;

    TEST_TRUE(end <= frame_len);

    pos = 18u;

    while ((pos + 4u) <= end)
    {
        uint8_t type;
        uint16_t len;
        size_t body_pos;
        size_t body_end;

        type = frame[pos];
        len = (uint16_t)(((uint16_t)(frame[pos + 2u] & 0x0Fu) << 8u) |
                         frame[pos + 3u]);

        body_pos = pos + 4u;
        body_end = body_pos + len;

        TEST_TRUE(body_end <= end);

        if ((pos != 18u) && (type == wanted_type))
        {
            *param = &frame[pos];
            *body_len = len;
            return 0;
        }

        pos = body_end;
    }

    return -1;
}

static int test_mka_init_pair(macsec_mka_ctx_t *a,
                              macsec_mka_ctx_t *b)
{
    static const uint8_t cak[16] =
    {
        0x00u, 0x11u, 0x22u, 0x33u,
        0x44u, 0x55u, 0x66u, 0x77u,
        0x88u, 0x99u, 0xAAu, 0xBBu,
        0xCCu, 0xDDu, 0xEEu, 0xFFu
    };

    static const uint8_t ckn[24] =
    {
        0x00u, 0x11u, 0x22u, 0x33u,
        0x44u, 0x55u, 0x66u, 0x77u,
        0x88u, 0x99u, 0xAAu, 0xBBu,
        0xCCu, 0xDDu, 0xEEu, 0xFFu,
        0x00u, 0x11u, 0x22u, 0x33u,
        0x44u, 0x55u, 0x66u, 0x77u
    };

    static const uint8_t mac_a[6] =
    {
        0x2Eu, 0x1Fu, 0xB1u, 0xB9u, 0x68u, 0x27u
    };

    static const uint8_t mac_b[6] =
    {
        0xDCu, 0xA6u, 0x32u, 0xD1u, 0x6Fu, 0x96u
    };

    TEST_OK(macsec_mka_init(a, cak, sizeof(cak), ckn, sizeof(ckn),
                            mac_a, 1u, 10u, 2000u));

    TEST_OK(macsec_mka_init(b, cak, sizeof(cak), ckn, sizeof(ckn),
                            mac_b, 1u, 100u, 2000u));

    return 0;
}

static int test_mka_make_a_key_server_live(macsec_mka_ctx_t *a,
                                           macsec_mka_ctx_t *b,
                                           uint8_t *frame_a,
                                           uint8_t *frame_b,
                                           size_t frame_max,
                                           size_t *frame_a_len)
{
    size_t len_a;
    size_t len_b;

    TEST_OK(test_mka_init_pair(a, b));

    len_a = 0u;
    TEST_OK(macsec_mka_get_tx_frame(a, frame_a, &len_a, frame_max));
    TEST_OK(macsec_mka_input(b, frame_a, len_a, 1000u));

    len_b = 0u;
    TEST_OK(macsec_mka_get_tx_frame(b, frame_b, &len_b, frame_max));
    TEST_OK(macsec_mka_input(a, frame_b, len_b, 2000u));

    TEST_TRUE(a->local_key_server);
    TEST_TRUE(a->peer.valid);
    TEST_TRUE(a->peer.live);

    len_a = 0u;
    TEST_OK(macsec_mka_get_tx_frame(a, frame_a, &len_a, frame_max));

    *frame_a_len = len_a;

    return 0;
}

int macsec_test_mka_frames_stm32_key_server_distributes_sak(macsec_test_mka_frames_stm32_key_server_distributes_sak_data_t *data, int verbose)
{
    size_t frame_a_len;
    const uint8_t *param;
    uint16_t body_len;

    if (verbose)
    {
        MACSEC_PRINT(("  MKA STM32 key-server Distributed SAK test\n"));
    }

    TEST_OK(test_mka_make_a_key_server_live(&data->a,
                                            &data->b,
                                            data->frame_a,
                                            data->frame_b,
                                            sizeof(data->frame_a),
                                            &frame_a_len));

    TEST_TRUE(frame_a_len == 186u);

    TEST_OK(test_mka_find_param(data->frame_a,
                                frame_a_len,
                                TEST_MKA_PARAM_DISTRIBUTED_SAK,
                                &param,
                                &body_len));

    TEST_EQ_U32(body_len, 28u);
    TEST_EQ_U32(macsec_rd_be32(&param[4]), 1u);

    TEST_OK(test_mka_find_param(data->frame_a,
                                frame_a_len,
                                TEST_MKA_PARAM_SAK_USE,
                                &param,
                                &body_len));

    TEST_EQ_U32(body_len, 40u);

    macsec_mka_clear(&data->a);
    macsec_mka_clear(&data->b);

    return 0;
}

int macsec_test_mka_frames_sak_use_key_server_mi(macsec_test_mka_frames_sak_use_key_server_mi_data_t *data, int verbose)
{
    size_t frame_a_len;
    const uint8_t *param;
    uint16_t body_len;

    if (verbose)
    {
        MACSEC_PRINT(("  MKA SAK Use Key Server MI test\n"));
    }

    TEST_OK(test_mka_make_a_key_server_live(&data->a,
                                            &data->b,
                                            data->frame_a,
                                            data->frame_b,
                                            sizeof(data->frame_a),
                                            &frame_a_len));

    TEST_OK(test_mka_find_param(data->frame_a,
                                frame_a_len,
                                TEST_MKA_PARAM_SAK_USE,
                                &param,
                                &body_len));

    TEST_EQ_U32(body_len, 40u);

    /*
     * SAK Use body starts at param + 4.
     * First 12 bytes of body are Key Server MI.
     * Since A is Key Server, it must be A local MI.
     */
    TEST_MEM_EQ(&param[4], data->a.local_mi, MACSEC_MKA_MI_LEN);

    macsec_mka_clear(&data->a);
    macsec_mka_clear(&data->b);

    return 0;
}

int macsec_test_mka_frames_sak_use_tx_rx_flags(macsec_test_mka_frames_sak_use_tx_rx_flags_data_t *data, int verbose)
{
    size_t frame_a_len;
    const uint8_t *param;
    uint16_t body_len;
    uint8_t flags;

    if (verbose)
    {
        MACSEC_PRINT(("  MKA SAK Use Tx/Rx flags test\n"));
    }

    TEST_OK(test_mka_make_a_key_server_live(&data->a,
                                            &data->b,
                                            data->frame_a,
                                            data->frame_b,
                                            sizeof(data->frame_a),
                                            &frame_a_len));

    TEST_OK(test_mka_find_param(data->frame_a,
                                frame_a_len,
                                TEST_MKA_PARAM_SAK_USE,
                                &param,
                                &body_len));

    flags = param[1];

    /*
     * Before data-plane TX activation:
     * AN = 0, Latest Key Tx = 0, Latest Key Rx = 1.
     */
    TEST_EQ_U32((flags >> 6u) & 0x03u, 0u);
    TEST_TRUE((flags & 0x20u) == 0u);
    TEST_TRUE((flags & 0x10u) != 0u);

    macsec_mka_set_latest_key_tx(&data->a, 0u, 1u);

    frame_a_len = 0u;
    TEST_OK(macsec_mka_get_tx_frame(&data->a,
                                    data->frame_a,
                                    &frame_a_len,
                                    sizeof(data->frame_a)));

    TEST_OK(test_mka_find_param(data->frame_a,
                                frame_a_len,
                                TEST_MKA_PARAM_SAK_USE,
                                &param,
                                &body_len));

    flags = param[1];

    /*
     * After TX activation:
     * AN = 0, Latest Key Tx = 1, Latest Key Rx = 1.
     */
    TEST_EQ_U32((flags >> 6u) & 0x03u, 0u);
    TEST_TRUE((flags & 0x20u) != 0u);
    TEST_TRUE((flags & 0x10u) != 0u);

    macsec_mka_clear(&data->a);
    macsec_mka_clear(&data->b);

    return 0;
}

int macsec_test_mka_frames(macsec_test_mka_frames_data_t *data, int verbose)
{
    if (verbose)
    {
        MACSEC_PRINT(("MACsec MKA frame tests\n"));
    }

    TEST_OK(macsec_test_mka_frames_linux_basic_icv(&data->test_mka_frames_linux_basic_icv_data, verbose));
    TEST_OK(macsec_test_mka_frames_build_parse_basic(&data->test_mka_frames_build_parse_basic_data, verbose));
    TEST_OK(macsec_test_mka_frames_generated_icv_ok(&data->test_mka_frames_generated_icv_ok_data, verbose));
    TEST_OK(macsec_test_mka_frames_generated_icv_bad(&data->test_mka_frames_generated_icv_bad_data, verbose));
    TEST_OK(macsec_test_mka_frames_two_peer_exchange(&data->test_mka_frames_two_peer_exchange_data, verbose));
    TEST_OK(macsec_test_mka_frames_tx_pending_timing(&data->test_mka_frames_tx_pending_timing_data, verbose));
    TEST_OK(macsec_test_mka_frames_distributed_sak_layout(&data->test_mka_frames_distributed_sak_layout_data, verbose));
    TEST_OK(macsec_test_mka_frames_stm32_key_server_distributes_sak(&data->test_mka_frames_stm32_key_server_distributes_sak_data, verbose));
    TEST_OK(macsec_test_mka_frames_sak_use_key_server_mi(&data->test_mka_frames_sak_use_key_server_mi_data, verbose));
    TEST_OK(macsec_test_mka_frames_sak_use_tx_rx_flags(&data->test_mka_frames_sak_use_tx_rx_flags_data, verbose));

    if (verbose)
    {
        MACSEC_PRINT(("MACsec MKA frame tests PASSED\n"));
    }

    return 0;
}

#endif /* MACSEC_SELF_TEST */
