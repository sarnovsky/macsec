/*
 * port.c
 *
 * Lightweight MACsec stack
 * Minimal platform abstraction used by the STM32 memory-footprint harness.
 *
 * This port is intended only for compilation, linking and static memory
 * measurement. It does not provide production-quality random generation
 * or actual debug output.
 *
 * Copyright (c) 2026 Michal Sarnovsky
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */

#include "port/port.h"

#if (MACSEC_DEBUG_LEVEL > 0)
#include <stdarg.h>
#endif

void macsec_sysPanic(void)
{
    for (;;)
    {
    }
}

/* ------------------------------------------------------------------------- */
/* Debug output                                                              */
/* ------------------------------------------------------------------------- */

#if (MACSEC_DEBUG_LEVEL > 0)

void macsec_printf(const char *format, ...)
{
    va_list args;

    va_start(args, format);
    va_end(args);

    /*
     * Deliberately discard all output.
     *
     * The calls and format strings remain referenced by the linked image,
     * but no UART driver or formatting library is included.
     */
    (void) format;
}

#endif

/* ------------------------------------------------------------------------- */
/* Deterministic pseudo-random generator                                     */
/* ------------------------------------------------------------------------- */

static uint32_t g_macsec_random_seed = 0x12345678u;

void macsec_randomInit(uint32_t seed)
{
    if (seed == 0u)
    {
        seed = 0x12345678u;
    }

    g_macsec_random_seed = seed;
}

void macsec_random(uint8_t *bytes, size_t count)
{
    uint32_t lfsr;

    macsec_assert(bytes != NULL);

    lfsr = g_macsec_random_seed;

    while (count-- > 0u)
    {
        if (lfsr == 0u)
        {
            lfsr = 1u;
        }

        if ((lfsr & 1u) != 0u)
        {
            lfsr >>= 1;
            lfsr ^= 0xD0000001u;
        }
        else
        {
            lfsr >>= 1;
        }

        *bytes++ = (uint8_t) ((lfsr >> 24u) ^ (lfsr >> 16u) ^ (lfsr >> 8u) ^ lfsr);
    }

    g_macsec_random_seed = lfsr;
}