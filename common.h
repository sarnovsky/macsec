/*
 * common.h
 *
 * Lightweight MACsec stack
 * Common utility functions shared by the MACsec modules.
 * This file contains small helper routines for byte-order conversion,
 * buffer handling, debug output and other low-level operations that are
 * not specific to a single protocol layer.
 *
 * Copyright (c) 2026 Michal Sarnovsk 
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */
 
#ifndef MACSEC_COMMON_H
#define MACSEC_COMMON_H

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <inttypes.h>

typedef uint8_t macsec_bool_t;
#define MACSEC_TRUE                   1
#define MACSEC_FALSE                  0

/* =========================================================================
 * Configuration
 * ========================================================================= */

#define MACSEC_SELF_TEST              1

/*
 * Debug level:
 *
 *   0 = no debug prints compiled in
 *   1 = errors only
 *   2 = medium / important protocol events
 *   3 = info / detailed packet-level debug
 */
#define MACSEC_DEBUG_LEVEL            1

#define MACSEC_DEBUG_LEVEL_ERROR      1u
#define MACSEC_DEBUG_LEVEL_MEDIUM     2u
#define MACSEC_DEBUG_LEVEL_INFO       3u

/* =========================================================================
 * Return codes
 * ========================================================================= */

#define MACSEC_ERR_OK                 0
#define MACSEC_ERR_PARAM             -1
#define MACSEC_ERR_BUFFER            -2
#define MACSEC_ERR_CRYPTO            -3
#define MACSEC_ERR_STATE             -4
#define MACSEC_ERR_REPLAY            -5
#define MACSEC_ERR_UNSUPPORTED       -6
#define MACSEC_ERR_AUTH              -7
#define MACSEC_ERR_TIMEOUT           -8
#define MACSEC_ERR_NOT_READY         -9

/* =========================================================================
 * Port functions
 * ========================================================================= */

#if (MACSEC_DEBUG_LEVEL > 0)
void macsec_printf(const char *format, ...);
void macsec_printHex(const char *label, const uint8_t *buf, int len);
#else
#define macsec_printf(...)                 ((void)0)
#define macsec_printHex(label, buf, len)   ((void)0)
#endif

void macsec_sysPanic(void);

/* =========================================================================
 * Debug macros
 * ========================================================================= */

#if (MACSEC_DEBUG_LEVEL > 0)
#define MACSEC_PRINT(MSG) \
    do { macsec_printf MSG; } while (0)

#define MACSEC_PRINT_HEX(MSG) \
    do { macsec_printHex MSG; } while (0)
#else
#define MACSEC_PRINT(MSG)                  ((void)0)
#define MACSEC_PRINT_HEX(MSG)              ((void)0)
#endif

#if (MACSEC_DEBUG_LEVEL >= MACSEC_DEBUG_LEVEL_ERROR)
#define MACSEC_ERROR(MSG) \
    do { macsec_printf MSG; } while (0)

#define MACSEC_ERROR_HEX(MSG) \
    do { macsec_printHex MSG; } while (0)
#else
#define MACSEC_ERROR(MSG)                  ((void)0)
#define MACSEC_ERROR_HEX(MSG)              ((void)0)
#endif

#if (MACSEC_DEBUG_LEVEL >= MACSEC_DEBUG_LEVEL_MEDIUM)
#define MACSEC_MEDIUM(MSG) \
    do { macsec_printf MSG; } while (0)

#define MACSEC_MEDIUM_HEX(MSG) \
    do { macsec_printHex MSG; } while (0)
#else
#define MACSEC_MEDIUM(MSG)                 ((void)0)
#define MACSEC_MEDIUM_HEX(MSG)             ((void)0)
#endif

#if (MACSEC_DEBUG_LEVEL >= MACSEC_DEBUG_LEVEL_INFO)
#define MACSEC_INFO(MSG) \
    do { macsec_printf MSG; } while (0)

#define MACSEC_INFO_HEX(MSG) \
    do { macsec_printHex MSG; } while (0)
#else
#define MACSEC_INFO(MSG)                   ((void)0)
#define MACSEC_INFO_HEX(MSG)               ((void)0)
#endif

/* =========================================================================
 * Assert and checks
 * ========================================================================= */

#define macsec_assert(X) \
    do { \
        if (!(X)) { \
            MACSEC_ERROR(("MACsec failed assertion (%s:%d): '%s'\n", __FILE__, __LINE__, #X)); \
            macsec_sysPanic(); \
        } \
    } while (0)

#define macsec_check(X, RET) \
    do { \
        if (!(X)) { \
            MACSEC_ERROR(("MACsec failure (%d) (%s:%d): '%s'\n", (RET), __FILE__, __LINE__, #X)); \
            return (RET); \
        } \
    } while (0)

#define macsec_check_void(X) \
    do { \
        if (!(X)) { \
            MACSEC_ERROR(("MACsec failure (%s:%d): '%s'\n", __FILE__, __LINE__, #X)); \
            return; \
        } \
    } while (0)

/* =========================================================================
 * Helpers
 * ========================================================================= */

uint16_t macsec_rd_be16(const uint8_t *p);
uint32_t macsec_rd_be32(const uint8_t *p);
uint64_t macsec_rd_be64(const uint8_t *p);

void macsec_wr_be16(uint8_t *p, uint16_t v);
void macsec_wr_be32(uint8_t *p, uint32_t v);
void macsec_wr_be64(uint8_t *p, uint64_t v);

void macsec_zeroize(void *buf, size_t len);

int macsec_hex_to_bin(const char *hex,
                      uint8_t *out,
                      size_t *out_len,
                      size_t out_max_len);

#endif /* MACSEC_COMMON_H */
