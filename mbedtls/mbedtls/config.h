#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

#include <macsec/common.h>

/* Algorithms */
#define MBEDTLS_AES_ROM_TABLES
#define MBEDTLS_AES_C
#define MBEDTLS_CMAC_C
#define MBEDTLS_GCM_C

/* Self tests - disable in final release if not needed */
#if (MACSEC_SELF_TEST != 0)

#if (MACSEC_DEBUG_LEVEL > 0)
extern void macsec_printf(const char *format, ...);
#define mbedtls_printf macsec_printf
#else
#define mbedtls_printf(...)                 ((void)0)
#endif

#define MBEDTLS_SELF_TEST
#endif

#endif /* MBEDTLS_CONFIG_H */
