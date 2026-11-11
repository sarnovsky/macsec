/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Michal Sarnovsky
 * Compile-time role and authenticated peer-recovery regression tests.
 */
#ifndef MACSEC_TEST_MKA_ROLES_H
#define MACSEC_TEST_MKA_ROLES_H
#include "macsec.h"
#if MACSEC_SELF_TEST
typedef struct
{
    macsec_ctx_t ctx;
    macsec_config_t cfg;
    macsec_frame_sak_t saved_tx;
    macsec_frame_sak_t saved_rx;
    uint8_t frame[512];
    uint8_t output[512];
    uint8_t plain[60];
} macsec_test_mka_roles_data_t;
int macsec_test_mka_roles(macsec_test_mka_roles_data_t *data, int verbose);
#endif
#endif
