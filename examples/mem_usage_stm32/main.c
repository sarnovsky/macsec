/*
 * main.c
 *
 * Lightweight MACsec stack
 * STM32 memory-footprint measurement harness.
 *
 * This program is intended for linking and size measurement only.
 * It is not a functional application.
 */

#define MEMUSAGE_PROFILE_MINIMAL 1
#define MEMUSAGE_PROFILE_FULL 2
#define MEMUSAGE_PROFILE_FULL_DEBUG 3
#define MEMUSAGE_PROFILE_FULL_SELFTEST 4

#ifndef MEMUSAGE_PROFILE
#define MEMUSAGE_PROFILE MEMUSAGE_PROFILE_FULL
#endif

#include <macsec/frame_crypto.h>
#include <macsec/macsec_common.h>

#if (MEMUSAGE_PROFILE != MEMUSAGE_PROFILE_MINIMAL)
#include <macsec/macsec.h>
#include <macsec/mka.h>
#include <macsec/mka_crypto.h>
#endif

#if (MEMUSAGE_PROFILE == MEMUSAGE_PROFILE_FULL_SELFTEST)
#include <tests/unit_tests.h>
#endif

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/*
 * Volatile result prevents the compiler from removing calls whose return
 * values would otherwise be unused.
 */
static volatile int g_memusage_result;

/*
 * The context is static so its complete size is included in .bss.
 */
#if (MEMUSAGE_PROFILE == MEMUSAGE_PROFILE_MINIMAL)

static macsec_frame_crypto_ctx_t g_frame_ctx;

#elif (MEMUSAGE_PROFILE == MEMUSAGE_PROFILE_FULL_SELFTEST)

/*
 * Self-test working context is included only in the self-test profile.
 * This means the reported RAM for that profile includes the test workspace.
 */
static macsec_test_data_t g_test_ctx;

#else

static macsec_ctx_t g_macsec_ctx;
static macsec_config_t g_macsec_cfg;

#endif

#if (MEMUSAGE_PROFILE != MEMUSAGE_PROFILE_FULL_SELFTEST)

/*
 * Small but valid Ethernet frame buffers.
 *
 * These buffers are intentionally much smaller than full-size Ethernet
 * application buffers. The benchmark is intended to measure the library
 * rather than a particular networking integration.
 */
static uint8_t g_plain_frame[64];

#define MEMUSAGE_WORK_BUFFER_SIZE 512u
static union
{
    uint8_t control[MEMUSAGE_WORK_BUFFER_SIZE];
    uint8_t secure[128];
    uint8_t decrypted[64];
} g_work;

static void memusage_fill_plain_frame(uint8_t *frame, size_t *frame_len)
{
    size_t i;

    /*
     * Destination MAC.
     */
    frame[0] = 0x02u;
    frame[1] = 0x00u;
    frame[2] = 0x00u;
    frame[3] = 0x00u;
    frame[4] = 0x00u;
    frame[5] = 0x02u;

    /*
     * Source MAC.
     */
    frame[6] = 0x02u;
    frame[7] = 0x00u;
    frame[8] = 0x00u;
    frame[9] = 0x00u;
    frame[10] = 0x00u;
    frame[11] = 0x01u;

    /*
     * IPv4 EtherType.
     */
    frame[12] = 0x08u;
    frame[13] = 0x00u;

    for (i = 14u; i < 64u; i++)
    {
        frame[i] = (uint8_t) i;
    }

    *frame_len = 64u;
}

#endif

#if (MEMUSAGE_PROFILE == MEMUSAGE_PROFILE_MINIMAL)

static int memusage_run_minimal(void)
{
    static const uint8_t sci_bytes[8] = {0x02u, 0x00u, 0x00u, 0x00u, 0x00u, 0x01u, 0x00u, 0x01u};

    static const uint8_t key[16] = {0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u,
                                    0x88u, 0x99u, 0xAAu, 0xBBu, 0xCCu, 0xDDu, 0xEEu, 0xFFu};

    macsec_frame_sci_t sci;
    macsec_frame_sak_t sak;
    size_t plain_len;
    size_t secure_len;
    size_t decrypted_len;
    int ret;

    memset(&sci, 0, sizeof(sci));
    memcpy(sci.bytes, sci_bytes, sizeof(sci_bytes));

    memset(&sak, 0, sizeof(sak));

    memcpy(sak.key, key, sizeof(key));
    sak.key_len = (uint8_t) sizeof(key);
    sak.an = 0u;
    sak.next_pn = 1u;
    sak.lowest_acceptable_pn = 1u;
    sak.valid = MACSEC_TRUE;

    memusage_fill_plain_frame(g_plain_frame, &plain_len);

    ret = macsec_frame_crypto_init(&g_frame_ctx, &sci);
    if (ret != MACSEC_ERR_OK)
    {
        return ret;
    }

    ret = macsec_frame_crypto_set_tx_sak(&g_frame_ctx, &sak);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_frame_crypto_clear(&g_frame_ctx);
        return ret;
    }

    ret = macsec_frame_crypto_set_rx_sak(&g_frame_ctx, &sak);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_frame_crypto_clear(&g_frame_ctx);
        return ret;
    }

    secure_len = 0u;

    ret = macsec_frame_encrypt(&g_frame_ctx, g_plain_frame, plain_len, g_work.secure, &secure_len,
                               sizeof(g_work.secure));

    if (ret != MACSEC_ERR_OK)
    {
        macsec_frame_crypto_clear(&g_frame_ctx);
        return ret;
    }

    decrypted_len = 0u;

    ret = macsec_frame_decrypt(&g_frame_ctx, g_work.secure, secure_len, g_work.decrypted,
                               &decrypted_len, sizeof(g_work.decrypted));

    macsec_frame_crypto_clear(&g_frame_ctx);

    return ret;
}

#elif (MEMUSAGE_PROFILE == MEMUSAGE_PROFILE_FULL) ||                                               \
    (MEMUSAGE_PROFILE == MEMUSAGE_PROFILE_FULL_DEBUG)

static void memusage_prepare_config(macsec_config_t *cfg)
{
    static const uint8_t cak[32] = {0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u,
                                    0x88u, 0x99u, 0xAAu, 0xBBu, 0xCCu, 0xDDu, 0xEEu, 0xFFu,
                                    0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u,
                                    0x88u, 0x99u, 0xAAu, 0xBBu, 0xCCu, 0xDDu, 0xEEu, 0xFFu};

    static const uint8_t ckn[24] = {0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u,
                                    0x88u, 0x99u, 0xAAu, 0xBBu, 0xCCu, 0xDDu, 0xEEu, 0xFFu,
                                    0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u};

    memset(cfg, 0, sizeof(*cfg));

    cfg->mode = MACSEC_MODE_MKA_PSK;

    cfg->local_mac.addr[0] = 0x02u;
    cfg->local_mac.addr[1] = 0x00u;
    cfg->local_mac.addr[2] = 0x00u;
    cfg->local_mac.addr[3] = 0x00u;
    cfg->local_mac.addr[4] = 0x00u;
    cfg->local_mac.addr[5] = 0x01u;

    cfg->port_id = 1u;

    memcpy(cfg->cak, cak, sizeof(cak));
    cfg->cak_len = (uint8_t) sizeof(cak);

    memcpy(cfg->ckn, ckn, sizeof(ckn));
    cfg->ckn_len = (uint8_t) sizeof(ckn);

    cfg->replay_protect = MACSEC_TRUE;
    cfg->replay_window = 0u;

    cfg->key_server_priority = 10u;
    cfg->mka_tx_interval_ms = 2000u;
}

static int memusage_run_full(void)
{
    size_t plain_len;
    size_t output_len;
    macsec_bool_t pass_to_stack;
    int ret;

    memusage_prepare_config(&g_macsec_cfg);
    memusage_fill_plain_frame(g_plain_frame, &plain_len);

    ret = macsec_init(&g_macsec_ctx, &g_macsec_cfg);
    if (ret != MACSEC_ERR_OK)
    {
        return ret;
    }

    ret = macsec_tick(&g_macsec_ctx, 2000u);
    if (ret != MACSEC_ERR_OK)
    {
        macsec_clear(&g_macsec_ctx);
        return ret;
    }

    output_len = 0u;

    /*
     * Pull an MKA control frame. This keeps the complete TX MKA path,
     * including MIC calculation, in the linked image.
     */
    ret = macsec_get_control_frame(&g_macsec_ctx, g_work.control, &output_len,
                                   sizeof(g_work.control));

    if ((ret != MACSEC_ERR_OK) && (ret != MACSEC_ERR_NOT_READY))
    {
        macsec_clear(&g_macsec_ctx);
        return ret;
    }

    /*
     * Reference top-level input and output paths as well.
     * The calls need not succeed for the memory-footprint harness.
     */
    output_len = 0u;
    pass_to_stack = MACSEC_FALSE;

    ret = macsec_input(&g_macsec_ctx, g_plain_frame, plain_len, g_work.decrypted, &output_len,
                       sizeof(g_work.decrypted), &pass_to_stack);

    g_memusage_result += ret;

    output_len = 0u;

    ret = macsec_output(&g_macsec_ctx, g_plain_frame, plain_len, g_work.secure, &output_len,
                        sizeof(g_work.secure));

    g_memusage_result += ret;

    macsec_clear(&g_macsec_ctx);

    return MACSEC_ERR_OK;
}

#endif

int main(void)
{
#if (MEMUSAGE_PROFILE == MEMUSAGE_PROFILE_MINIMAL)

    g_memusage_result = memusage_run_minimal();

#elif (MEMUSAGE_PROFILE == MEMUSAGE_PROFILE_FULL) ||                                               \
    (MEMUSAGE_PROFILE == MEMUSAGE_PROFILE_FULL_DEBUG)

    g_memusage_result = memusage_run_full();

#elif (MEMUSAGE_PROFILE == MEMUSAGE_PROFILE_FULL_SELFTEST)

#if (MACSEC_SELF_TEST != 0)
    g_memusage_result = macsec_test_all(&g_test_ctx, 0);
#else
#error "FULL_SELFTEST profile requires MACSEC_SELF_TEST != 0"
#endif

#else
#error "Unsupported MEMUSAGE_PROFILE"
#endif

    /*
     * The footprint image is not intended to return or run on hardware.
     */
    for (;;)
    {
        /*
         * Keep the result observable.
         */
        if (g_memusage_result == 0x7FFFFFFF)
        {
            g_memusage_result = 0;
        }
    }
}