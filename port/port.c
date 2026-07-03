/*
 * port.c
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

#include <macsec/port/port.h>

#include <string.h>

#if (MACSEC_DEBUG_LEVEL > 0)
#include <stdarg.h>
#include "xprintf.h"
#endif


void macsec_sysPanic(void) {
	while(1);
}


//--------------------------------------------------------------------


#if (MACSEC_DEBUG_LEVEL > 0)

#define macsec_PRINTFBUFFER_SIZE 800

static char macsec_printfBuffer[macsec_PRINTFBUFFER_SIZE];

void macsec_printf(const char *format, ...)
{
    va_list arp;
    struct xprintPar par;

    par.out = macsec_printfBuffer;
    par.outFunc = NULL;
    par.maxCount = macsec_PRINTFBUFFER_SIZE - 1u;
    par.count = 0;

    va_start(arp, format);
    xvprintf(&par, format, arp);
    va_end(arp);

    macsec_printfBuffer[par.count] = 0;

    xprintf("%s", macsec_printfBuffer);
}

#endif


//--------------------------------------------------------------------


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

        *bytes++ = (uint8_t)((lfsr >> 24) ^
                             (lfsr >> 16) ^
                             (lfsr >> 8)  ^
                              lfsr);
    }

    g_macsec_random_seed = lfsr;
}

