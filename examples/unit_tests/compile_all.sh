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
    echo "SELF_TEST=$self_test DEBUG=$debug ROM=$rom FEWER=$fewer"
    echo "============================================"

    make clean || configuration_failed \
        "$self_test" "$debug" "$rom" "$fewer"

    make tests -j \
        MACSEC_SELF_TEST="$self_test" \
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
    echo "SELF_TEST=$self_test DEBUG=$debug ROM=$rom FEWER=$fewer"
    echo "BUILD ONLY"
    echo "============================================"

    make clean || configuration_failed \
        "$self_test" "$debug" "$rom" "$fewer"

    make tests -j \
        MACSEC_SELF_TEST="$self_test" \
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
    echo "SELF_TEST=$self_test DEBUG=$debug ROM=$rom FEWER=$fewer"
    echo "============================================"

    exit 1
}

run_tests 1 0 0 0
run_tests 1 3 0 0

run_tests 1 0 0 1
run_tests 1 3 0 1

run_tests 1 0 1 0
run_tests 1 3 1 0

run_tests 1 0 1 1
run_tests 1 3 1 1

build_only 0 0 0 0

echo
echo "============================================"
echo "ALL CONFIGURATIONS PASSED"
echo "============================================"

exit 0
