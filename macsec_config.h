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

#define MACSEC_DEBUG_LEVEL_NONE 0u
#define MACSEC_DEBUG_LEVEL_ERROR 1u
#define MACSEC_DEBUG_LEVEL_MEDIUM 2u
#define MACSEC_DEBUG_LEVEL_INFO 3u

/* =========================================================================
 * Configuration validation
 * ========================================================================= */

#if (MACSEC_SELF_TEST != 0) && (MACSEC_SELF_TEST != 1)
#error "MACSEC_SELF_TEST must be 0 or 1"
#endif

#if (MACSEC_DEBUG_LEVEL < MACSEC_DEBUG_LEVEL_NONE) || (MACSEC_DEBUG_LEVEL > MACSEC_DEBUG_LEVEL_INFO)
#error "MACSEC_DEBUG_LEVEL must be in range 0..3"
#endif

#endif /* MACSEC_CONFIG_H */