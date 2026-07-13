/*
 * port.h
 *
 * Lightweight MACsec stack
 * Platform abstraction layer.
 * This file provides the platform-dependent services required by the
 * MACsec stack, such as memory allocation, debug output, timing and
 * other operating system or hardware specific functionality.
 *
 * Copyright (c) 2026 Michal Sarnovský
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */

#ifndef MACSEC_PORT_H
#define MACSEC_PORT_H

#ifdef __cplusplus
extern "C" {
#endif

#include "common.h"

/* Panic */
void macsec_sysPanic(void);

/* Printf */
#if (MACSEC_DEBUG_LEVEL > 0)
void macsec_printf(const char *format, ...);
#endif

/* Random */
void macsec_randomInit(uint32_t seed);
void macsec_random(uint8_t *bytes, size_t count);

#ifdef __cplusplus
}
#endif

#endif /* MACSEC_PORT_H */

