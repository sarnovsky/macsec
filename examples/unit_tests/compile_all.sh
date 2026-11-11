#!/usr/bin/env bash

set -u

echo "============================================"
echo "MACsec unit test regression"
echo "============================================"

run_tests()
{
    self_test="$1"
    debug="$2"
    rom="$3"
    fewer="$4"

    echo
    echo "============================================"
    echo "SELF_TEST=$self_test DEBUG=$debug ROM=$rom FEWER=$fewer SERVER=$mka_server CLIENT=$mka_client"
    echo "============================================"

    make clean || configuration_failed \
        "$self_test" "$debug" "$rom" "$fewer"

    make tests -j \
        MACSEC_SELF_TEST="$self_test" \
        MACSEC_MKA_SERVER_SUPPORT="$mka_server" \
        MACSEC_MKA_CLIENT_SUPPORT="$mka_client" \
        MACSEC_DEBUG_LEVEL="$debug" \
        MATH_AES_ROM_TABLES="$rom" \
        MATH_AES_FEWER_TABLES="$fewer" \
        || configuration_failed \
            "$self_test" "$debug" "$rom" "$fewer"

    echo "Running tests..."
    ./build/macsec_tests || configuration_failed \
        "$self_test" "$debug" "$rom" "$fewer"

    echo "Configuration passed."
}

build_only()
{
    self_test="$1"
    debug="$2"
    rom="$3"
    fewer="$4"

    echo
    echo "============================================"
    echo "SELF_TEST=$self_test DEBUG=$debug ROM=$rom FEWER=$fewer SERVER=$mka_server CLIENT=$mka_client"
    echo "BUILD ONLY"
    echo "============================================"

    make clean || configuration_failed \
        "$self_test" "$debug" "$rom" "$fewer"

    make tests -j \
        MACSEC_SELF_TEST="$self_test" \
        MACSEC_MKA_SERVER_SUPPORT="$mka_server" \
        MACSEC_MKA_CLIENT_SUPPORT="$mka_client" \
        MACSEC_DEBUG_LEVEL="$debug" \
        MATH_AES_ROM_TABLES="$rom" \
        MATH_AES_FEWER_TABLES="$fewer" \
        || configuration_failed \
            "$self_test" "$debug" "$rom" "$fewer"

    echo "Configuration built successfully."
}

configuration_failed()
{
    self_test="$1"
    debug="$2"
    rom="$3"
    fewer="$4"

    echo
    echo "============================================"
    echo "CONFIGURATION FAILED"
    echo "SELF_TEST=$self_test DEBUG=$debug ROM=$rom FEWER=$fewer SERVER=$mka_server CLIENT=$mka_client"
    echo "============================================"

    exit 1
}

for role_profile in both server client; do
    case "$role_profile" in
        both)   mka_server=1; mka_client=1 ;;
        server) mka_server=1; mka_client=0 ;;
        client) mka_server=0; mka_client=1 ;;
    esac
    run_tests 1 0 0 0
    run_tests 1 3 0 0

    run_tests 1 0 0 1
    run_tests 1 3 0 1

    run_tests 1 0 1 0
    run_tests 1 3 1 0

    run_tests 1 0 1 1
    run_tests 1 3 1 1

    build_only 0 0 0 0
done

echo
echo "============================================"
echo "ALL CONFIGURATIONS PASSED"
echo "============================================"

exit 0
