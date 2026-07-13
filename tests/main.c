#include "common.h"
#include "tests/unit_tests.h"

#include "xprintf.h"

void DEBUGCONSOLE_writeChar(uint8_t c)
{
    putchar(c);
}

uint8_t DEBUGCONSOLE_readChar(void)
{
    return 0;
}

int main(int argc, char *argv[])
{
    int verbose = 1;
    int ret;
    static macsec_test_data_t test_data;

    (void)argc;
    (void)argv;

    xdev_out(DEBUGCONSOLE_writeChar);
    xdev_in(DEBUGCONSOLE_readChar);

    ret = macsec_test_all(&test_data, verbose);
    if (ret != 0)
    {
        MACSEC_PRINT(("ALL TESTS FAILED ret=%d\n", ret));
        return ret;
    }

    MACSEC_PRINT(("ALL TESTS OK\n"));

    MACSEC_PRINT(("========================================\n"));

    MACSEC_PRINT(("sizeof(macsec_ctx_t) = %u bytes\n",
                  (unsigned)sizeof(macsec_ctx_t)));

    MACSEC_PRINT(("sizeof(macsec_mka_ctx_t) = %u bytes\n",
                  (unsigned)sizeof(macsec_mka_ctx_t)));

    MACSEC_PRINT(("sizeof(macsec_test_data_t) = %u bytes\n",
                  (unsigned)sizeof(macsec_test_data_t)));

    return 0;
}

