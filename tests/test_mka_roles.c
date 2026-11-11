/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Michal Sarnovsky
 * A small independent wire builder acts as the opposite-role peer. It uses
 * an AES-KW known answer, so it does not pull a disabled engine into tests.
 */
#include "tests/test_mka_roles.h"
#include "tests/unit_tests.h"
#if MACSEC_SELF_TEST

static const uint8_t role_cak[16] = {
    0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
static const uint8_t role_ckn[16] = {
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f};
static const uint8_t peer_mi[12] = {0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3a,0x3b,0x3c};
static const uint8_t peer_mac[6] = {2,0,0,0,0,2};
static const uint8_t destination[6] = {1,0x80,0xc2,0,0,3};

static int role_hello(macsec_test_mka_roles_data_t *data, uint32_t mn,
                       uint8_t priority, int old_slot, int distributed, size_t *length)
{
    macsec_ctx_t *ctx = &data->ctx;
    uint8_t *p = data->frame;
    size_t n = 18u;
    const uint8_t *key_mi = MACSEC_MKA_SERVER_SUPPORT ? ctx->mka.local_mi : peer_mi;
    static const uint8_t wrapped[24] = {0x1d,0xfb,0x42,0x01,0x31,0x57,0x9f,0xf7,0x45,0x1c,0xee,0x2e,0xac,0x7e,0xbd,0x9e,0x5f,0x13,0xf5,0xdc,0x00,0x16,0x02,0x09};
    memset(p,0,sizeof(data->frame));
    memcpy(p,destination,6); memcpy(p+6,peer_mac,6);
    macsec_wr_be16(p+12,0x888e); p[14]=3; p[15]=5;
    p[n]=1; p[n+1]=priority; p[n+2]=MACSEC_MKA_SERVER_SUPPORT ? 0x60 : 0xe0;
    p[n+3]=44; memcpy(p+n+4,peer_mac,6); macsec_wr_be16(p+n+10,1);
    memcpy(p+n+12,peer_mi,12); macsec_wr_be32(p+n+24,mn);
    macsec_wr_be32(p+n+28,0x0080c201u); memcpy(p+n+32,role_ckn,16); n+=48;
    p[n]=1; p[n+3]=16; memcpy(p+n+4,ctx->mka.local_mi,12);
    macsec_wr_be32(p+n+16,ctx->mka.local_mn); n+=20;
    if(distributed)
    {
        p[n]=4; p[n+3]=28; macsec_wr_be32(p+n+4,1);
        memcpy(p+n+8,wrapped,24); n+=32;
    }
    if(ctx->mka.latest_sak.lifecycle_state != MACSEC_MKA_SAK_STATE_NONE)
    {
        size_t slot = old_slot ? 20u : 0u;
        p[n]=3; p[n+1]=(uint8_t)((ctx->mka.latest_sak.an << (old_slot ? 2 : 6)) |
                                (old_slot ? 3u : 0x30u));
        p[n+3]=40; memcpy(p+n+4+slot,key_mi,12);
        macsec_wr_be32(p+n+16+slot,ctx->mka.latest_sak.key_number);
        macsec_wr_be32(p+n+20+slot,1); n+=44;
    }
    macsec_wr_be16(p+16,(uint16_t)(n+16-18));
    TEST_OK(macsec_mka_crypto_calc_mic(&ctx->mka.crypto,p,n,p+n));
    *length=n+16; return 0;
}

static int role_receive(macsec_test_mka_roles_data_t *data, size_t n)
{
    size_t out=0; macsec_bool_t pass=MACSEC_FALSE;
    int ret=macsec_input(&data->ctx,data->frame,n,data->output,&out,sizeof(data->output),&pass);
    TEST_TRUE(!pass && out==0u);
    return ret;
}

static int role_case(macsec_test_mka_roles_data_t *data, int old_slot)
{
    macsec_ctx_t *ctx=&data->ctx;
    const uint8_t normal_priority=MACSEC_MKA_SERVER_SUPPORT ? 200u : 50u;
    size_t n, out;
    uint8_t an;
    memset(data,0,sizeof(*data));
    data->cfg.mode=MACSEC_MODE_MKA_PSK;
    data->cfg.local_mac.addr[0]=2; data->cfg.local_mac.addr[5]=1;
    data->cfg.port_id=1; data->cfg.key_server_priority=100;
    data->cfg.cak_len=16; data->cfg.ckn_len=16;
    memcpy(data->cfg.cak,role_cak,16); memcpy(data->cfg.ckn,role_ckn,16);
    data->cfg.replay_protect=MACSEC_TRUE; data->cfg.replay_window=32;
    data->cfg.mka_tx_interval_ms=2000;
    TEST_OK(macsec_init(ctx,&data->cfg));
    TEST_EQ_U32(ctx->mka.local_key_server,MACSEC_MKA_SERVER_SUPPORT);
    TEST_OK(role_hello(data,1,normal_priority,old_slot,!MACSEC_MKA_SERVER_SUPPORT,&n));
    TEST_OK(role_receive(data,n));
    TEST_OK(macsec_build_control_frame(ctx,data->frame,&n,sizeof(data->frame)));
    TEST_EQ_U32(ctx->pending_mka_tx_meta.contains_distributed_sak,MACSEC_MKA_SERVER_SUPPORT);
    TEST_OK(macsec_notify_control_tx_success(ctx,1));
    TEST_TRUE(macsec_is_secured(ctx));
    memset(data->plain,0x45,sizeof(data->plain));
    data->plain[0]=2; data->plain[6]=2; data->plain[12]=8; data->plain[13]=0;
    TEST_OK(macsec_output(ctx,data->plain,sizeof(data->plain),data->output,&out,sizeof(data->output)));
    an=ctx->mka.latest_sak.an;
    data->saved_tx=ctx->frame_crypto.tx_sak;
    data->saved_rx=ctx->frame_crypto.rx_sak[an];
    TEST_OK(macsec_tick(ctx,7000));
    TEST_TRUE(!macsec_is_secured(ctx));
    TEST_OK(role_hello(data,1,normal_priority,old_slot,0,&n));
    TEST_TRUE(role_receive(data,n)==MACSEC_ERR_REPLAY);
    TEST_OK(role_hello(data,2,normal_priority,old_slot,0,&n));
    data->frame[n-1]^=1;
    TEST_TRUE(role_receive(data,n)==MACSEC_ERR_AUTH);
    TEST_TRUE(!macsec_is_secured(ctx));
    data->frame[n-1]^=1;
    TEST_OK(role_receive(data,n));
    TEST_TRUE(macsec_is_secured(ctx));
    TEST_MEM_EQ(&data->saved_tx,&ctx->frame_crypto.tx_sak,sizeof(data->saved_tx));
    TEST_MEM_EQ(&data->saved_rx,&ctx->frame_crypto.rx_sak[an],sizeof(data->saved_rx));

#if !MACSEC_MKA_SERVER_SUPPORT || !MACSEC_MKA_CLIENT_SUPPORT
    /* A bad ICV cannot close the port; an authenticated role conflict can. */
    TEST_OK(role_hello(data,4,MACSEC_MKA_SERVER_SUPPORT ? 50u : 200u,old_slot,0,&n));
    data->frame[n-1]^=1;
    TEST_TRUE(role_receive(data,n)==MACSEC_ERR_AUTH);
    TEST_TRUE(macsec_is_secured(ctx));
    data->frame[n-1]^=1;
    TEST_TRUE(role_receive(data,n)==MACSEC_ERR_UNSUPPORTED);
    TEST_TRUE(!macsec_is_secured(ctx));
    TEST_EQ_U32(ctx->state,MACSEC_STATE_WAIT_MKA);
    TEST_TRUE(!ctx->mka.local_key_server);
    TEST_MEM_EQ(&data->saved_tx,&ctx->frame_crypto.tx_sak,sizeof(data->saved_tx));
    TEST_MEM_EQ(&data->saved_rx,&ctx->frame_crypto.rx_sak[an],sizeof(data->saved_rx));
    TEST_OK(role_hello(data,3,normal_priority,old_slot,0,&n));
    TEST_TRUE(role_receive(data,n)==MACSEC_ERR_REPLAY);
    TEST_TRUE(!macsec_is_secured(ctx));
    TEST_OK(role_hello(data,5,normal_priority,old_slot,0,&n));
    TEST_OK(role_receive(data,n));
    TEST_TRUE(macsec_is_secured(ctx));
    TEST_MEM_EQ(&data->saved_tx,&ctx->frame_crypto.tx_sak,sizeof(data->saved_tx));
#endif
#if MACSEC_MKA_SERVER_SUPPORT && !MACSEC_MKA_CLIENT_SUPPORT
    TEST_OK(role_hello(data,6,normal_priority,old_slot,1,&n));
    TEST_TRUE(role_receive(data,n)==MACSEC_ERR_UNSUPPORTED);
    TEST_TRUE(macsec_is_secured(ctx));
    TEST_MEM_EQ(&data->saved_tx,&ctx->frame_crypto.tx_sak,sizeof(data->saved_tx));
#endif
#if !MACSEC_MKA_SERVER_SUPPORT
    TEST_TRUE(macsec_mka_request_rekey(&ctx->mka)==MACSEC_ERR_UNSUPPORTED);
#endif
    macsec_clear(ctx);
    return 0;
}

int macsec_test_mka_roles(macsec_test_mka_roles_data_t *data, int verbose)
{
    if(verbose) { MACSEC_PRINT(("MKA role profile server=%u client=%u: wire, timeout, PN and conflict tests\n",
                              MACSEC_MKA_SERVER_SUPPORT,MACSEC_MKA_CLIENT_SUPPORT)); }
    TEST_OK(role_case(data,0));
    TEST_OK(role_case(data,1));
    return 0;
}
#endif
