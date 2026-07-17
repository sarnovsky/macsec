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

#include <string.h>

#if (MACSEC_SELF_TEST != 0)

static const uint8_t s_cak_16[16] =
{
    0x00u, 0x11u, 0x22u, 0x33u,
    0x44u, 0x55u, 0x66u, 0x77u,
    0x88u, 0x99u, 0xAAu, 0xBBu,
    0xCCu, 0xDDu, 0xEEu, 0xFFu
};

static const uint8_t s_cak_32[32] =
{
    0x00u, 0x11u, 0x22u, 0x33u,
    0x44u, 0x55u, 0x66u, 0x77u,
    0x88u, 0x99u, 0xAAu, 0xBBu,
    0xCCu, 0xDDu, 0xEEu, 0xFFu,

    0x10u, 0x21u, 0x32u, 0x43u,
    0x54u, 0x65u, 0x76u, 0x87u,
    0x98u, 0xA9u, 0xBAu, 0xCBu,
    0xDCu, 0xEDu, 0xFEu, 0x0Fu
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
                                    const uint8_t *cak,
                                    size_t cak_len,
                                    const uint8_t mac[6],
                                    uint8_t priority)
{
    macsec_assert(ctx != NULL);
    macsec_assert(cak != NULL);
    macsec_assert(mac != NULL);
    macsec_assert((cak_len == 16u) || (cak_len == 32u));

    return macsec_mka_init(ctx,
                           cak,
                           cak_len,
                           s_ckn,
                           sizeof(s_ckn),
                           mac,
                           1u,
                           priority,
                           2000u);
}

/*
 * Build an MKA frame and simulate successful transmission.
 *
 * This helper preserves the previous build-and-commit behavior while
 * keeping the new build/notify lifecycle
 * explicit in the tests.
 */
static int macsec_test_mka_build_and_commit_tx(
    macsec_mka_ctx_t *ctx,
    uint8_t *frame,
    size_t *frame_len,
    size_t frame_max_len,
    uint32_t now_ms)
{
    macsec_mka_tx_meta_t tx_meta;
    int ret;

    macsec_assert(ctx != NULL);
    macsec_assert(frame != NULL);
    macsec_assert(frame_len != NULL);

    memset(&tx_meta, 0, sizeof(tx_meta));

    ret = macsec_mka_build_tx_frame(ctx,
                                    frame,
                                    frame_len,
                                    frame_max_len,
                                    &tx_meta);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_zeroize(&tx_meta, sizeof(tx_meta));
        return ret;
    }

    ret = macsec_mka_notify_tx_success(ctx,
                                       &tx_meta,
                                       now_ms);

    macsec_zeroize(&tx_meta, sizeof(tx_meta));

    return ret;
}

static int macsec_test_mka_frames_linux_basic_icv(
    macsec_test_mka_frames_linux_basic_icv_data_t *data,
    int verbose)
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
        MACSEC_PRINT(("  MKA frames Linux Basic/ICV test, 16-byte CAK\n"));
    }

    ret = macsec_test_mka_init_ctx(&data->mka,
                                   s_cak_16,
                                   sizeof(s_cak_16),
                                   s_mac_a,
                                   100u);
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

static int macsec_test_mka_frames_build_parse_basic(
    macsec_test_mka_frames_build_parse_basic_data_t *data,
    const uint8_t *cak,
    size_t cak_len,
    int verbose)
{
    size_t frame_len;
    int ret;

    macsec_assert(cak != NULL);
    macsec_assert((cak_len == 16u) || (cak_len == 32u));

    if (verbose)
    {
        MACSEC_PRINT((
            "  MKA frame build/parse Basic test, %u-byte CAK\n",
            (unsigned int)cak_len));
    }

    ret = macsec_test_mka_init_ctx(&data->mka,
                                   cak,
                                   cak_len,
                                   s_mac_a,
                                   255u);
    TEST_OK(ret);

    frame_len = 0u;

    ret = macsec_test_mka_build_and_commit_tx(&data->mka,
                                               data->frame,
                                               &frame_len,
                                               sizeof(data->frame),
                                               1u);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_clear(&data->mka);
        return ret;
    }

    ret = macsec_mka_parse_basic(data->frame,
                                 frame_len,
                                 &data->basic);
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

static int macsec_test_mka_frames_generated_icv_ok(
    macsec_test_mka_frames_generated_icv_ok_data_t *data,
    const uint8_t *cak,
    size_t cak_len,
    int verbose)
{
    size_t frame_len;
    int ret;

    macsec_assert(cak != NULL);
    macsec_assert((cak_len == 16u) || (cak_len == 32u));

    if (verbose)
    {
        MACSEC_PRINT((
            "  MKA generated frame ICV OK test, %u-byte CAK\n",
            (unsigned int)cak_len));
    }

    ret = macsec_test_mka_init_ctx(&data->tx,
                                   cak,
                                   cak_len,
                                   s_mac_a,
                                   255u);
    TEST_OK(ret);

    ret = macsec_test_mka_init_ctx(&data->rx,
                                   cak,
                                   cak_len,
                                   s_mac_b,
                                   100u);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_clear(&data->tx);
        return ret;
    }

    frame_len = 0u;

    ret = macsec_test_mka_build_and_commit_tx(&data->tx,
                                               data->frame,
                                               &frame_len,
                                               sizeof(data->frame),
                                               1000u);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_clear(&data->tx);
        macsec_mka_clear(&data->rx);
        return ret;
    }

    ret = macsec_mka_input(&data->rx,
                           data->frame,
                           frame_len,
                           1000u);
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

static int macsec_test_mka_frames_generated_icv_bad(
    macsec_test_mka_frames_generated_icv_bad_data_t *data,
    const uint8_t *cak,
    size_t cak_len,
    int verbose)
{
    size_t frame_len;
    int ret;

    macsec_assert(cak != NULL);
    macsec_assert((cak_len == 16u) || (cak_len == 32u));

    if (verbose)
    {
        MACSEC_PRINT((
            "  MKA generated frame ICV bad test, %u-byte CAK\n",
            (unsigned int)cak_len));
    }

    ret = macsec_test_mka_init_ctx(&data->tx,
                                   cak,
                                   cak_len,
                                   s_mac_a,
                                   255u);
    TEST_OK(ret);

    ret = macsec_test_mka_init_ctx(&data->rx,
                                   cak,
                                   cak_len,
                                   s_mac_b,
                                   100u);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_clear(&data->tx);
        return ret;
    }

    frame_len = 0u;

    ret = macsec_test_mka_build_and_commit_tx(&data->tx,
                                               data->frame,
                                               &frame_len,
                                               sizeof(data->frame),
                                               1000u);
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
                           1000u);

    TEST_TRUE(ret == MACSEC_ERR_AUTH);
    TEST_TRUE(!data->rx.last_icv_valid);
    TEST_TRUE(!data->rx.peer.valid);

    macsec_mka_clear(&data->tx);
    macsec_mka_clear(&data->rx);

    return 0;
}

static int macsec_test_mka_frames_two_peer_exchange(
    macsec_test_mka_frames_two_peer_exchange_data_t *data,
    const uint8_t *cak,
    size_t cak_len,
    int verbose)
{
    static const uint8_t local_mac_a[6] =
    {
        0x02u, 0x00u, 0x00u, 0x00u, 0x00u, 0x01u
    };

    static const uint8_t local_mac_b[6] =
    {
        0x02u, 0x00u, 0x00u, 0x00u, 0x00u, 0x02u
    };

    size_t frame_len = 0u;
    int ret;

    macsec_assert(cak != NULL);
    macsec_assert((cak_len == 16u) || (cak_len == 32u));

    if (verbose)
    {
        MACSEC_PRINT((
            "  MKA two-peer exchange test, %u-byte CAK\n",
            (unsigned int)cak_len));
    }

    memset(data->cak, 0, sizeof(data->cak));
    memset(data->ckn, 0, sizeof(data->ckn));

    memcpy(data->cak, cak, cak_len);
    memcpy(data->ckn, s_ckn, sizeof(s_ckn));

    ret = macsec_mka_init(&data->a,
                          data->cak,
                          cak_len,
                          data->ckn,
                          sizeof(s_ckn),
                          local_mac_a,
                          1u,
                          255u,
                          2000u);
    TEST_OK(ret);

    ret = macsec_mka_init(&data->b,
                          data->cak,
                          cak_len,
                          data->ckn,
                          sizeof(s_ckn),
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

    ret = macsec_test_mka_build_and_commit_tx(&data->a,
                                               data->frame,
                                               &frame_len,
                                               sizeof(data->frame),
                                               100u);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_clear(&data->a);
        macsec_mka_clear(&data->b);
        return ret;
    }

    ret = macsec_mka_input(&data->b,
                           data->frame,
                           frame_len,
                           100u);
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

    ret = macsec_test_mka_build_and_commit_tx(&data->b,
                                               data->frame,
                                               &frame_len,
                                               sizeof(data->frame),
                                               200u);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_clear(&data->a);
        macsec_mka_clear(&data->b);
        return ret;
    }

    ret = macsec_mka_input(&data->a,
                           data->frame,
                           frame_len,
                           200u);
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

    ret = macsec_test_mka_build_and_commit_tx(&data->a,
                                               data->frame,
                                               &frame_len,
                                               sizeof(data->frame),
                                               300u);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_clear(&data->a);
        macsec_mka_clear(&data->b);
        return ret;
    }

    ret = macsec_mka_input(&data->b,
                           data->frame,
                           frame_len,
                           300u);
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

static int macsec_test_mka_frames_tx_pending_timing(
    macsec_test_mka_frames_tx_pending_timing_data_t *data,
    const uint8_t *cak,
    size_t cak_len,
    int verbose)
{
    size_t frame_len;
    int ret;

    macsec_assert(cak != NULL);
    macsec_assert((cak_len == 16u) || (cak_len == 32u));

    if (verbose)
    {
        MACSEC_PRINT((
            "  MKA tx_pending timing test, %u-byte CAK\n",
            (unsigned int)cak_len));
    }

    ret = macsec_test_mka_init_ctx(&data->mka,
                                   cak,
                                   cak_len,
                                   s_mac_a,
                                   255u);
    TEST_OK(ret);

    frame_len = 0u;

    ret = macsec_test_mka_build_and_commit_tx(&data->mka,
                                               data->frame,
                                               &frame_len,
                                               sizeof(data->frame),
                                               1000u);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_clear(&data->mka);
        return ret;
    }

    TEST_TRUE(data->mka.tx_reasons == MACSEC_MKA_TX_REASON_NONE);

    /*
     * Only 1000 ms elapsed since the successful transmission.
     */
    ret = macsec_mka_tick(&data->mka, 2000u);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_clear(&data->mka);
        return ret;
    }

    TEST_TRUE(data->mka.tx_reasons == MACSEC_MKA_TX_REASON_NONE);

    /*
     * At 3000 ms, the configured 2000 ms interval has elapsed.
     */
    ret = macsec_mka_tick(&data->mka, 3000u);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_clear(&data->mka);
        return ret;
    }

    TEST_TRUE((data->mka.tx_reasons &
               MACSEC_MKA_TX_REASON_PERIODIC) != 0u);

    macsec_mka_clear(&data->mka);

    return 0;
}

static int macsec_test_mka_frames_distributed_sak_layout(
    macsec_test_mka_frames_distributed_sak_layout_data_t *data,
    int verbose)
{
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
                              macsec_mka_ctx_t *b,
                              const uint8_t *cak,
                              size_t cak_len)
{
    static const uint8_t mac_a[6] =
    {
        0x2Eu, 0x1Fu, 0xB1u, 0xB9u, 0x68u, 0x27u
    };

    static const uint8_t mac_b[6] =
    {
        0xDCu, 0xA6u, 0x32u, 0xD1u, 0x6Fu, 0x96u
    };

    TEST_TRUE(a != NULL);
    TEST_TRUE(b != NULL);
    TEST_TRUE(cak != NULL);
    TEST_TRUE((cak_len == 16u) || (cak_len == 32u));

    TEST_OK(macsec_mka_init(a,
                            cak,
                            cak_len,
                            s_ckn,
                            sizeof(s_ckn),
                            mac_a,
                            1u,
                            10u,
                            2000u));

    TEST_OK(macsec_mka_init(b,
                            cak,
                            cak_len,
                            s_ckn,
                            sizeof(s_ckn),
                            mac_b,
                            1u,
                            100u,
                            2000u));

    return 0;
}

static int test_mka_make_a_key_server_live(macsec_mka_ctx_t *a,
                                           macsec_mka_ctx_t *b,
                                           const uint8_t *cak,
                                           size_t cak_len,
                                           uint8_t *frame_a,
                                           uint8_t *frame_b,
                                           size_t frame_max,
                                           size_t *frame_a_len)
{
    size_t len_a;
    size_t len_b;

    TEST_TRUE(cak != NULL);
    TEST_TRUE((cak_len == 16u) || (cak_len == 32u));

    TEST_OK(test_mka_init_pair(a, b, cak, cak_len));

    len_a = 0u;

    TEST_OK(macsec_test_mka_build_and_commit_tx(a,
                                                       frame_a,
                                                       &len_a,
                                                       frame_max,
                                                       1000u));

    TEST_OK(macsec_mka_input(b,
                             frame_a,
                             len_a,
                             1000u));

    len_b = 0u;

    TEST_OK(macsec_test_mka_build_and_commit_tx(b,
                                                       frame_b,
                                                       &len_b,
                                                       frame_max,
                                                       2000u));

    TEST_OK(macsec_mka_input(a,
                             frame_b,
                             len_b,
                             2000u));

    TEST_TRUE(a->local_key_server);
    TEST_TRUE(a->peer.valid);
    TEST_TRUE(a->peer.live);

    len_a = 0u;

    TEST_OK(macsec_test_mka_build_and_commit_tx(a,
                                                       frame_a,
                                                       &len_a,
                                                       frame_max,
                                                       3000u));

    *frame_a_len = len_a;

    return 0;
}

static int macsec_test_mka_frames_stm32_key_server_distributes_sak(
    macsec_test_mka_frames_stm32_key_server_distributes_sak_data_t *data,
    const uint8_t *cak,
    size_t cak_len,
    int verbose)
{
    size_t frame_a_len;
    const uint8_t *param;
    uint16_t body_len;
    int ret;

    macsec_assert(cak != NULL);
    macsec_assert((cak_len == 16u) || (cak_len == 32u));

    if (verbose)
    {
        MACSEC_PRINT((
            "  MKA STM32 key-server Distributed SAK test, "
            "%u-byte CAK\n",
            (unsigned int)cak_len));
    }

    TEST_OK(test_mka_make_a_key_server_live(
        &data->a,
        &data->b,
        cak,
        cak_len,
        data->frame_a,
        data->frame_b,
        sizeof(data->frame_a),
        &frame_a_len));

    /*
     * Current implementation always generates a 16-byte SAK.
     *
     * AES Key Wrap of a 16-byte SAK produces 24 bytes,
     * independently of whether the KEK is 16 or 32 bytes.
     */
    TEST_EQ_U32(frame_a_len, 186u);

    TEST_OK(test_mka_find_param(
        data->frame_a,
        frame_a_len,
        TEST_MKA_PARAM_DISTRIBUTED_SAK,
        &param,
        &body_len));

    TEST_EQ_U32(body_len, 28u);
    TEST_EQ_U32(macsec_rd_be32(&param[4]), 1u);

    TEST_OK(test_mka_find_param(
        data->frame_a,
        frame_a_len,
        TEST_MKA_PARAM_SAK_USE,
        &param,
        &body_len));

    TEST_EQ_U32(body_len, 40u);

    /*
     * A has generated the SAK and successfully transmitted the frame, so
     * its local SAK is already DISTRIBUTED. B has not processed this final
     * frame yet.
     */
    TEST_TRUE(data->a.latest_sak.valid);
    TEST_EQ_U32(data->a.latest_sak.sak_len, 16u);

    ret = macsec_mka_input(&data->b,
                           data->frame_a,
                           frame_a_len,
                           3000u);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_mka_clear(&data->a);
        macsec_mka_clear(&data->b);
        return ret;
    }

    /*
     * B must now have successfully authenticated the frame,
     * unwrapped the Distributed SAK using KEK-128 or KEK-256
     * and stored the same 16-byte SAK.
     */
    TEST_TRUE(data->b.last_icv_valid);
    TEST_TRUE(data->b.latest_sak.valid);
    TEST_EQ_U32(data->b.latest_sak.sak_len, 16u);

    TEST_MEM_EQ(data->a.latest_sak.sak,
                data->b.latest_sak.sak,
                16u);

    TEST_EQ_U32(data->a.latest_sak.key_number,
                data->b.latest_sak.key_number);

    TEST_EQ_U32(data->a.latest_sak.an,
                data->b.latest_sak.an);

    macsec_mka_clear(&data->a);
    macsec_mka_clear(&data->b);

    return 0;
}

static int macsec_test_mka_frames_sak_use_key_server_mi(
    macsec_test_mka_frames_sak_use_key_server_mi_data_t *data,
    const uint8_t *cak,
    size_t cak_len,
    int verbose)
{
    size_t frame_a_len;
    const uint8_t *param;
    uint16_t body_len;

    macsec_assert(cak != NULL);
    macsec_assert((cak_len == 16u) || (cak_len == 32u));

    if (verbose)
    {
        MACSEC_PRINT((
            "  MKA SAK Use Key Server MI test, %u-byte CAK\n",
            (unsigned int)cak_len));
    }

    TEST_OK(test_mka_make_a_key_server_live(
        &data->a,
        &data->b,
        cak,
        cak_len,
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
    TEST_MEM_EQ(&param[4], data->a.local_mi, MACSEC_MKA_MI_LEN);

    macsec_mka_clear(&data->a);
    macsec_mka_clear(&data->b);

    return 0;
}

static int macsec_test_mka_frames_sak_use_tx_rx_flags(
    macsec_test_mka_frames_sak_use_tx_rx_flags_data_t *data,
    const uint8_t *cak,
    size_t cak_len,
    int verbose)
{
    size_t frame_a_len;
    const uint8_t *param;
    uint16_t body_len;
    uint8_t flags;

    macsec_assert(cak != NULL);
    macsec_assert((cak_len == 16u) || (cak_len == 32u));

    if (verbose)
    {
        MACSEC_PRINT((
            "  MKA SAK Use Tx/Rx flags test, %u-byte CAK\n",
            (unsigned int)cak_len));
    }

    TEST_OK(test_mka_make_a_key_server_live(
        &data->a,
        &data->b,
        cak,
        cak_len,
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

    TEST_EQ_U32((flags >> 6u) & 0x03u, 0u);
    TEST_TRUE((flags & 0x20u) == 0u);
    TEST_TRUE((flags & 0x10u) != 0u);

    macsec_mka_set_latest_key_tx(&data->a, 0u, 1u);

    frame_a_len = 0u;

    TEST_OK(macsec_test_mka_build_and_commit_tx(&data->a,
                                                       data->frame_a,
                                                       &frame_a_len,
                                                       sizeof(data->frame_a),
                                                       4000u));

    TEST_OK(test_mka_find_param(data->frame_a,
                                frame_a_len,
                                TEST_MKA_PARAM_SAK_USE,
                                &param,
                                &body_len));

    flags = param[1];

    TEST_EQ_U32((flags >> 6u) & 0x03u, 0u);
    TEST_TRUE((flags & 0x20u) != 0u);
    TEST_TRUE((flags & 0x10u) != 0u);

    macsec_mka_clear(&data->a);
    macsec_mka_clear(&data->b);

    return 0;
}

int macsec_test_mka_frames(macsec_test_mka_frames_data_t *data,
                           int verbose)
{
    if (verbose)
    {
        MACSEC_PRINT(("MACsec MKA frame tests\n"));
    }

    TEST_OK(macsec_test_mka_frames_linux_basic_icv(
        &data->test_mka_frames_linux_basic_icv_data,
        verbose));

    TEST_OK(macsec_test_mka_frames_build_parse_basic(
        &data->test_mka_frames_build_parse_basic_data,
        s_cak_16,
        sizeof(s_cak_16),
        verbose));

    TEST_OK(macsec_test_mka_frames_build_parse_basic(
        &data->test_mka_frames_build_parse_basic_data,
        s_cak_32,
        sizeof(s_cak_32),
        verbose));

    TEST_OK(macsec_test_mka_frames_generated_icv_ok(
        &data->test_mka_frames_generated_icv_ok_data,
        s_cak_16,
        sizeof(s_cak_16),
        verbose));

    TEST_OK(macsec_test_mka_frames_generated_icv_ok(
        &data->test_mka_frames_generated_icv_ok_data,
        s_cak_32,
        sizeof(s_cak_32),
        verbose));

    TEST_OK(macsec_test_mka_frames_generated_icv_bad(
        &data->test_mka_frames_generated_icv_bad_data,
        s_cak_16,
        sizeof(s_cak_16),
        verbose));

    TEST_OK(macsec_test_mka_frames_generated_icv_bad(
        &data->test_mka_frames_generated_icv_bad_data,
        s_cak_32,
        sizeof(s_cak_32),
        verbose));

    TEST_OK(macsec_test_mka_frames_two_peer_exchange(
        &data->test_mka_frames_two_peer_exchange_data,
        s_cak_16,
        sizeof(s_cak_16),
        verbose));

    TEST_OK(macsec_test_mka_frames_two_peer_exchange(
        &data->test_mka_frames_two_peer_exchange_data,
        s_cak_32,
        sizeof(s_cak_32),
        verbose));

    TEST_OK(macsec_test_mka_frames_tx_pending_timing(
        &data->test_mka_frames_tx_pending_timing_data,
        s_cak_16,
        sizeof(s_cak_16),
        verbose));

    TEST_OK(macsec_test_mka_frames_tx_pending_timing(
        &data->test_mka_frames_tx_pending_timing_data,
        s_cak_32,
        sizeof(s_cak_32),
        verbose));

    TEST_OK(macsec_test_mka_frames_distributed_sak_layout(
        &data->test_mka_frames_distributed_sak_layout_data,
        verbose));

    TEST_OK(macsec_test_mka_frames_stm32_key_server_distributes_sak(
        &data->test_mka_frames_stm32_key_server_distributes_sak_data,
        s_cak_16,
        sizeof(s_cak_16),
        verbose));

    TEST_OK(macsec_test_mka_frames_stm32_key_server_distributes_sak(
        &data->test_mka_frames_stm32_key_server_distributes_sak_data,
        s_cak_32,
        sizeof(s_cak_32),
        verbose));

    TEST_OK(macsec_test_mka_frames_sak_use_key_server_mi(
        &data->test_mka_frames_sak_use_key_server_mi_data,
        s_cak_16,
        sizeof(s_cak_16),
        verbose));

    TEST_OK(macsec_test_mka_frames_sak_use_key_server_mi(
        &data->test_mka_frames_sak_use_key_server_mi_data,
        s_cak_32,
        sizeof(s_cak_32),
        verbose));

    TEST_OK(macsec_test_mka_frames_sak_use_tx_rx_flags(
        &data->test_mka_frames_sak_use_tx_rx_flags_data,
        s_cak_16,
        sizeof(s_cak_16),
        verbose));

    TEST_OK(macsec_test_mka_frames_sak_use_tx_rx_flags(
        &data->test_mka_frames_sak_use_tx_rx_flags_data,
        s_cak_32,
        sizeof(s_cak_32),
        verbose));

    if (verbose)
    {
        MACSEC_PRINT(("MACsec MKA frame tests PASSED\n"));
    }

    return 0;
}

#endif /* MACSEC_SELF_TEST */