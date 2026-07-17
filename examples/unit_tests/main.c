#include "macsec_common.h"
#include "tests/unit_tests.h"

#include "xprintf.h"

#include <stdio.h>

void DEBUGCONSOLE_writeChar(uint8_t c) { putchar(c); }

uint8_t DEBUGCONSOLE_readChar(void) { return 0; }

int main(int argc, char *argv[])
{
    int verbose = 1;
    int ret;
    static macsec_test_data_t test_data;

    (void) argc;
    (void) argv;

    xdev_out(DEBUGCONSOLE_writeChar);
    xdev_in(DEBUGCONSOLE_readChar);

    ret = macsec_test_all(&test_data, verbose);
    if (ret != 0)
    {
        xprintf("ALL TESTS FAILED ret=%d\n", ret);
        return ret;
    }

    xprintf("ALL TESTS OK\n");

    xprintf("========================================\n");

    xprintf("sizeof(macsec_ctx_t) = %u bytes\n", (unsigned) sizeof(macsec_ctx_t));
    xprintf("sizeof(macsec_mka_ctx_t) = %u bytes\n", (unsigned) sizeof(macsec_mka_ctx_t));
    xprintf("sizeof(macsec_test_data_t) = %u bytes\n", (unsigned) sizeof(macsec_test_data_t));

    return 0;
}
