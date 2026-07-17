/*
 * macsec_common.h
 *
 * Lightweight MACsec stack
 * Common types, macros and utility functions.
 *
 * This file contains common definitions shared by the MACsec modules,
 * including return codes, debug helpers, parameter checks, byte-order
 * conversion helpers and secure memory handling.
 *
 * Copyright (c) 2026 Michal Sarnovský
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */

#ifndef MACSEC_COMMON_H
#define MACSEC_COMMON_H

#include "macsec_config.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif


/* =========================================================================
 * Common types
 * ========================================================================= */

typedef uint8_t macsec_bool_t;

#define MACSEC_FALSE                  ((macsec_bool_t)0u)
#define MACSEC_TRUE                   ((macsec_bool_t)1u)


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
#define MACSEC_ERR_BUSY              -10

/* =========================================================================
 * Platform functions
 * ========================================================================= */

/*
 * Enter a non-returning platform-specific panic state.
 *
 * The integrating platform must provide this function.
 */
void macsec_sysPanic(void);


/*
 * Debug output is provided by the platform only when debug output is enabled.
 */
#if (MACSEC_DEBUG_LEVEL > MACSEC_DEBUG_LEVEL_NONE)

void macsec_printf(const char *format, ...);

void macsec_printHex(const char *label,
                     const uint8_t *buf,
                     int len);

#else

#define macsec_printf(...) \
    ((void)0)

#define macsec_printHex(label, buf, len) \
    ((void)0)

#endif


/* =========================================================================
 * General debug macros
 * ========================================================================= */

/*
 * MACSEC_PRINT is intended primarily for optional test and diagnostic output.
 * It is enabled whenever any debug output is enabled.
 */
#if (MACSEC_DEBUG_LEVEL > MACSEC_DEBUG_LEVEL_NONE)

#define MACSEC_PRINT(MSG) \
    do \
    { \
        macsec_printf MSG; \
    } while (0)

#define MACSEC_PRINT_HEX(MSG) \
    do \
    { \
        macsec_printHex MSG; \
    } while (0)

#else

#define MACSEC_PRINT(MSG) \
    ((void)0)

#define MACSEC_PRINT_HEX(MSG) \
    ((void)0)

#endif


/* =========================================================================
 * Error-level debug macros
 * ========================================================================= */

#if (MACSEC_DEBUG_LEVEL >= MACSEC_DEBUG_LEVEL_ERROR)

#define MACSEC_ERROR(MSG) \
    do \
    { \
        macsec_printf MSG; \
    } while (0)

#define MACSEC_ERROR_HEX(MSG) \
    do \
    { \
        macsec_printHex MSG; \
    } while (0)

#else

#define MACSEC_ERROR(MSG) \
    ((void)0)

#define MACSEC_ERROR_HEX(MSG) \
    ((void)0)

#endif


/* =========================================================================
 * Medium-level debug macros
 * ========================================================================= */

#if (MACSEC_DEBUG_LEVEL >= MACSEC_DEBUG_LEVEL_MEDIUM)

#define MACSEC_MEDIUM(MSG) \
    do \
    { \
        macsec_printf MSG; \
    } while (0)

#define MACSEC_MEDIUM_HEX(MSG) \
    do \
    { \
        macsec_printHex MSG; \
    } while (0)

#else

#define MACSEC_MEDIUM(MSG) \
    ((void)0)

#define MACSEC_MEDIUM_HEX(MSG) \
    ((void)0)

#endif


/* =========================================================================
 * Information-level debug macros
 * ========================================================================= */

#if (MACSEC_DEBUG_LEVEL >= MACSEC_DEBUG_LEVEL_INFO)

#define MACSEC_INFO(MSG) \
    do \
    { \
        macsec_printf MSG; \
    } while (0)

#define MACSEC_INFO_HEX(MSG) \
    do \
    { \
        macsec_printHex MSG; \
    } while (0)

#else

#define MACSEC_INFO(MSG) \
    ((void)0)

#define MACSEC_INFO_HEX(MSG) \
    ((void)0)

#endif


/* =========================================================================
 * Assertions and parameter checks
 * ========================================================================= */

/*
 * Assert an internal invariant.
 *
 * A failed assertion always enters macsec_sysPanic(). When debug output is
 * disabled, the diagnostic message is removed but the assertion remains
 * active.
 */
#define macsec_assert(X) \
    do \
    { \
        if (!(X)) \
        { \
            MACSEC_ERROR(("MACsec failed assertion (%s:%d): '%s'\n", \
                          __FILE__, \
                          __LINE__, \
                          #X)); \
            macsec_sysPanic(); \
        } \
    } while (0)


/*
 * Check a condition in a function returning an error code.
 */
#define macsec_check(X, RET) \
    do \
    { \
        if (!(X)) \
        { \
            MACSEC_ERROR(("MACsec failure (%d) (%s:%d): '%s'\n", \
                          (RET), \
                          __FILE__, \
                          __LINE__, \
                          #X)); \
            return (RET); \
        } \
    } while (0)


/*
 * Check a condition in a function returning void.
 */
#define macsec_check_void(X) \
    do \
    { \
        if (!(X)) \
        { \
            MACSEC_ERROR(("MACsec failure (%s:%d): '%s'\n", \
                          __FILE__, \
                          __LINE__, \
                          #X)); \
            return; \
        } \
    } while (0)


/* =========================================================================
 * Byte-order helpers
 * ========================================================================= */

uint16_t macsec_rd_be16(const uint8_t *p);

uint32_t macsec_rd_be32(const uint8_t *p);

uint64_t macsec_rd_be64(const uint8_t *p);


void macsec_wr_be16(uint8_t *p, uint16_t value);

void macsec_wr_be32(uint8_t *p, uint32_t value);

void macsec_wr_be64(uint8_t *p, uint64_t value);


/* =========================================================================
 * Buffer helpers
 * ========================================================================= */

/*
 * Securely erase a memory region.
 *
 * The implementation must prevent the compiler from removing the writes as
 * dead stores.
 */
void macsec_zeroize(void *buf, size_t len);


/*
 * Convert a hexadecimal text string to binary data.
 *
 * @param hex
 *        Input hexadecimal string.
 *
 * @param out
 *        Output binary buffer.
 *
 * @param out_len
 *        Receives the number of decoded bytes.
 *
 * @param out_max_len
 *        Capacity of the output buffer.
 *
 * @return
 *        MACSEC_ERR_OK on success or another MACSEC_ERR_* value on failure.
 */
int macsec_hex_to_bin(const char *hex,
                      uint8_t *out,
                      size_t *out_len,
                      size_t out_max_len);


#ifdef __cplusplus
}
#endif

#endif /* MACSEC_COMMON_H */