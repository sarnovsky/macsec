/*
 * test_common.h
 *
 * Lightweight MACsec stack
 * Unit tests for common utility functions.
 * This file verifies the behavior of shared helper routines, including
 * byte-order conversion, buffer manipulation and other common utilities.
 *
 * Copyright (c) 2026 Michal Sarnovský
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */

#ifndef MACSEC_TEST_COMMON_H
#define MACSEC_TEST_COMMON_H

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

#if (MACSEC_SELF_TEST != 0)
int macsec_test_common(int verbose);
#endif

#ifdef __cplusplus
}
#endif

#endif
