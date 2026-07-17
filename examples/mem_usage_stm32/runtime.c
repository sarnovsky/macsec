/*
 * runtime.c
 *
 * Minimal C runtime functions for the STM32 memory-footprint harness.
 */

#include <stddef.h>
#include <stdint.h>

void *memset(void *destination, int value, size_t length)
{
    uint8_t *dst;

    dst = (uint8_t *) destination;

    while (length-- > 0u)
    {
        *dst++ = (uint8_t) value;
    }

    return destination;
}

void *memcpy(void *destination, const void *source, size_t length)
{
    uint8_t *dst;
    const uint8_t *src;

    dst = (uint8_t *) destination;
    src = (const uint8_t *) source;

    while (length-- > 0u)
    {
        *dst++ = *src++;
    }

    return destination;
}

int memcmp(const void *a, const void *b, size_t length)
{
    const uint8_t *pa;
    const uint8_t *pb;

    pa = (const uint8_t *) a;
    pb = (const uint8_t *) b;

    while (length-- > 0u)
    {
        if (*pa != *pb)
        {
            return (*pa < *pb) ? -1 : 1;
        }

        pa++;
        pb++;
    }

    return 0;
}

void SystemInit(void)
{
    /*
     * No clock or peripheral initialization is required by the
     * memory-footprint harness.
     */
}

void __libc_init_array(void)
{
    /*
     * The footprint harness contains no C++ constructors or other
     * initialization arrays.
     */
}

void _init(void) {}

void _fini(void) {}
