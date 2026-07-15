/*
 * common.c
 *
 * Lightweight MACsec stack
 * Common utility functions shared by the MACsec modules.
 * This file contains small helper routines for byte-order conversion,
 * buffer handling, debug output and other low-level operations that are
 * not specific to a single protocol layer.
 *
 * Copyright (c) 2026 Michal Sarnovský
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */
 
#include "macsec_common.h"

/* =========================================================================
 * Helpers
 * ========================================================================= */

uint16_t macsec_rd_be16(const uint8_t *p)
{
    macsec_assert(p != NULL);

    return (uint16_t)(((uint16_t)p[0] << 8) |
                       (uint16_t)p[1]);
}

uint32_t macsec_rd_be32(const uint8_t *p)
{
    macsec_assert(p != NULL);

    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |
           ((uint32_t)p[3]);
}

uint64_t macsec_rd_be64(const uint8_t *p)
{
    macsec_assert(p != NULL);

    return ((uint64_t)p[0] << 56) |
           ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) |
           ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) |
           ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8)  |
           ((uint64_t)p[7]);
}

void macsec_wr_be16(uint8_t *p, uint16_t v)
{
    macsec_assert(p != NULL);

    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v);
}

void macsec_wr_be32(uint8_t *p, uint32_t v)
{
    macsec_assert(p != NULL);

    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v);
}

void macsec_wr_be64(uint8_t *p, uint64_t v)
{
    macsec_assert(p != NULL);

    p[0] = (uint8_t)(v >> 56);
    p[1] = (uint8_t)(v >> 48);
    p[2] = (uint8_t)(v >> 40);
    p[3] = (uint8_t)(v >> 32);
    p[4] = (uint8_t)(v >> 24);
    p[5] = (uint8_t)(v >> 16);
    p[6] = (uint8_t)(v >> 8);
    p[7] = (uint8_t)(v);
}

void macsec_zeroize(void *buf, size_t len)
{
    macsec_assert(buf != NULL);
    memset(buf, 0, len);
}

#if (MACSEC_DEBUG_LEVEL > 0)

void macsec_printHex(const char *label, const uint8_t *buf, int len)
{
    int i;

    macsec_assert(label != NULL);
    macsec_assert(buf != NULL);

    macsec_printf("%s (%d B):\n", label, len);

    for (i = 1; i <= len; i++)
    {
        if (((i - 1) % 16) == 0)
        {
            macsec_printf("  ");
        }

        macsec_printf("%02X", buf[i - 1]);

        if ((i % 16) == 0)
        {
            macsec_printf("\n");
        }
        else if ((i % 2) == 0)
        {
            macsec_printf(" ");
        }
    }

    if ((len % 16) != 0)
    {
        macsec_printf("\n");
    }
}

#endif

static int macsec_hex_value(char c)
{
    if ((c >= '0') && (c <= '9'))
        return c - '0';

    if ((c >= 'a') && (c <= 'f'))
        return c - 'a' + 10;

    if ((c >= 'A') && (c <= 'F'))
        return c - 'A' + 10;

    return -1;
}

int macsec_hex_to_bin(const char *hex,
                      uint8_t *out,
                      size_t *out_len,
                      size_t out_max_len)
{
    size_t count = 0u;
    int hi = -1;
    int lo;
    char c;

    macsec_assert(hex != NULL);
    macsec_assert(out != NULL);
    macsec_assert(out_len != NULL);

    while (*hex != '\0')
    {
        c = *hex++;

        if ((c == ' ') || (c == '\n') || (c == '\r') || (c == '\t') || (c == ':'))
            continue;

        lo = macsec_hex_value(c);
        macsec_check(lo >= 0, MACSEC_ERR_PARAM);

        if (hi < 0)
        {
            hi = lo;
        }
        else
        {
            macsec_check(count < out_max_len, MACSEC_ERR_BUFFER);
            out[count++] = (uint8_t)((hi << 4) | lo);
            hi = -1;
        }
    }

    macsec_check(hi < 0, MACSEC_ERR_PARAM);

    *out_len = count;
    return MACSEC_ERR_OK;
}

