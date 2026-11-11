/*
 * macsec_config.h
 *
 * Lightweight MACsec stack
 * Compile-time configuration.
 *
 * This file contains the compile-time options used to configure the
 * lightweight MACsec stack. Configuration values may be changed here or
 * overridden by definitions supplied by the integrating build system.
 *
 * Copyright (c) 2026 Michal Sarnovsky
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */

#ifndef MACSEC_CONFIG_H
#define MACSEC_CONFIG_H

/* =========================================================================
 * MKA roles (numeric 0/1 switches)
 * ========================================================================= */

/* Defaults retain automatic Key Server election and both roles.
 * A single-role build still requires compatible peer priorities: it rejects
 * an authenticated election selecting the unavailable role. These switches
 * do not restrict MACsec data TX/RX or static-SAK mode.
 * This stack's inverse AES is needed only by the MKA client (AES-KW unwrap).
 * Keep CLIENT_SUPPORT=1 if another user of math/aes needs inverse AES.
 */
#ifndef MACSEC_MKA_SERVER_SUPPORT
#define MACSEC_MKA_SERVER_SUPPORT 1
#endif
#ifndef MACSEC_MKA_CLIENT_SUPPORT
#define MACSEC_MKA_CLIENT_SUPPORT 1
#endif

/* =========================================================================
 * AES lookup-table configuration
 * ========================================================================= */

/*
 * The AES implementation supports four lookup-table configurations.
 *
 * The following presence macros may be defined by the integrating project
 * or build system:
 *
 *   MATH_AES_ROM_TABLES
 *       Store AES lookup tables as constant read-only tables.
 *
 *       If this macro is not defined, the lookup tables are generated at
 *       runtime and stored in writable static RAM.
 *
 *   MATH_AES_FEWER_TABLES
 *       Store or generate only one forward and one reverse lookup table.
 *       The remaining table values are derived using word rotations.
 *
 * Supported combinations:
 *
 *   Neither macro defined:
 *       Runtime-generated full lookup tables.
 *       Lowest FLASH usage, highest static RAM usage.
 *
 *   MATH_AES_FEWER_TABLES:
 *       Runtime-generated reduced lookup tables.
 *       Low FLASH usage, reduced static RAM usage.
 *
 *   MATH_AES_ROM_TABLES:
 *       Full constant lookup tables stored in FLASH.
 *       Highest FLASH usage, minimum static RAM usage.
 *
 *   MATH_AES_ROM_TABLES + MATH_AES_FEWER_TABLES:
 *       Reduced constant lookup tables stored in FLASH.
 *       Good balance between FLASH and static RAM usage.
 *
 * No AES lookup-table mode is selected by default in this file.
 *
 * Example build-system definitions:
 *
 *   -DMATH_AES_ROM_TABLES
 *   -DMATH_AES_FEWER_TABLES
 */

/* =========================================================================
 * Self-test configuration
 * ========================================================================= */

/*
 * Enable or disable cryptographic and MACsec self-test code.
 *
 *   0 = self-test code disabled
 *   1 = self-test code enabled
 *
 * The value may be overridden from the compiler command line:
 *
 *   -DMACSEC_SELF_TEST=0
 *   -DMACSEC_SELF_TEST=1
 */
#ifndef MACSEC_SELF_TEST
#define MACSEC_SELF_TEST 1
#endif

/* =========================================================================
 * Debug configuration
 * ========================================================================= */

/*
 * Debug level:
 *
 *   0 = no debug output compiled in
 *   1 = error messages only
 *   2 = error messages and important protocol events
 *   3 = detailed packet-level and protocol debug output
 *
 * The value may be overridden from the compiler command line:
 *
 *   -DMACSEC_DEBUG_LEVEL=0
 *   -DMACSEC_DEBUG_LEVEL=1
 *   -DMACSEC_DEBUG_LEVEL=2
 *   -DMACSEC_DEBUG_LEVEL=3
 */
#ifndef MACSEC_DEBUG_LEVEL
#define MACSEC_DEBUG_LEVEL 1
#endif

/* Key material stays hidden even in verbose diagnostics unless explicitly
 * enabled for a controlled test build. Never enable this with real keys. */
#ifndef MACSEC_DEBUG_SECRETS
#define MACSEC_DEBUG_SECRETS 0
#endif

/* Start MKA key-server rollover with one million packet numbers remaining. */
#ifndef MACSEC_REKEY_PN_THRESHOLD
#define MACSEC_REKEY_PN_THRESHOLD 0xFFF00000u
#endif

#define MACSEC_DEBUG_LEVEL_NONE 0u
#define MACSEC_DEBUG_LEVEL_ERROR 1u
#define MACSEC_DEBUG_LEVEL_MEDIUM 2u
#define MACSEC_DEBUG_LEVEL_INFO 3u

/* =========================================================================
 * Configuration validation
 * ========================================================================= */

#if (MACSEC_MKA_SERVER_SUPPORT != 0) && (MACSEC_MKA_SERVER_SUPPORT != 1)
#error "MACSEC_MKA_SERVER_SUPPORT must be 0 or 1"
#endif
#if (MACSEC_MKA_CLIENT_SUPPORT != 0) && (MACSEC_MKA_CLIENT_SUPPORT != 1)
#error "MACSEC_MKA_CLIENT_SUPPORT must be 0 or 1"
#endif
#if !MACSEC_MKA_SERVER_SUPPORT && !MACSEC_MKA_CLIENT_SUPPORT
#error "At least one MKA role must be enabled"
#endif

#if (MACSEC_SELF_TEST != 0) && (MACSEC_SELF_TEST != 1)
#error "MACSEC_SELF_TEST must be 0 or 1"
#endif

#if (MACSEC_DEBUG_LEVEL < MACSEC_DEBUG_LEVEL_NONE) || (MACSEC_DEBUG_LEVEL > MACSEC_DEBUG_LEVEL_INFO)
#error "MACSEC_DEBUG_LEVEL must be in range 0..3"
#endif

#endif /* MACSEC_CONFIG_H */
