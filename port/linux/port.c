/*
 * port.c
 *
 * Lightweight MACsec stack
 * Linux platform abstraction layer.
 *
 * This file provides the Linux-dependent services required by the
 * MACsec stack, such as debug output, panic handling and random data.
 *
 * Copyright (c) 2026 Michal Sarnovsky
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */

#include "port/port.h"

#include <errno.h>
#include <stdlib.h>
#include <sys/random.h>

#if (MACSEC_DEBUG_LEVEL > 0)
#include <stdarg.h>
#include <stdio.h>
#endif

void macsec_sysPanic(void)
{
#if (MACSEC_DEBUG_LEVEL > 0)
    fputs("MACsec panic\n", stderr);
    fflush(stderr);
#endif

    abort();
}

//--------------------------------------------------------------------

#if (MACSEC_DEBUG_LEVEL > 0)

void macsec_printf(const char *format, ...)
{
    va_list args;

    if (format == NULL)
    {
        return;
    }

    va_start(args, format);
    vprintf(format, args);
    va_end(args);

    fflush(stdout);
}

#endif

//--------------------------------------------------------------------

void macsec_randomInit(uint32_t seed)
{
    /*
     * Linux uses the kernel cryptographic random number generator.
     * The supplied seed is therefore not needed.
     */
    (void) seed;
}

void macsec_random(uint8_t *bytes, size_t count)
{
    size_t offset = 0u;

    macsec_assert(bytes != NULL);

    while (offset < count)
    {
        ssize_t ret;

        ret = getrandom(bytes + offset, count - offset, 0);

        if (ret > 0)
        {
            offset += (size_t) ret;
            continue;
        }

        if ((ret < 0) && (errno == EINTR))
        {
            continue;
        }

        /*
         * Random data are security-critical for MKA. Do not silently use
         * rand() or a deterministic fallback if the kernel RNG fails.
         */
        macsec_sysPanic();
    }
}
