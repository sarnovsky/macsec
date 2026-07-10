###############################################################################
# MACsec library
###############################################################################

CC      := gcc

CFLAGS  := -std=c99
CFLAGS  += -Wall
CFLAGS  += -Wextra
CFLAGS  += -O2

INCLUDES := \
    -I. \
    -Imath \
    -Iport \
    -Itests

BUILD_DIR := build

###############################################################################
# Library sources
###############################################################################

LIB_SRCS := \
    common.c \
    frame_crypto.c \
    macsec.c \
    mka.c \
    mka_crypto.c \
    math/aes.c \
    math/cmac.c \
    math/gcm.c \
    port/port.c

###############################################################################
# Test sources
###############################################################################

TEST_SRCS := \
    tests/xprintf.c \
    tests/main.c \
    tests/test_common.c \
    tests/test_frame_crypto.c \
    tests/test_integration.c \
    tests/test_macsec_flow.c \
    tests/test_math_selftest.c \
    tests/test_mka_crypto.c \
    tests/test_mka_frames.c \
    tests/test_mka_negative.c \
    tests/test_rekey.c \
    tests/unit_tests.c

###############################################################################

.PHONY: all tests clean

all: tests

tests:
	mkdir -p $(BUILD_DIR)
	$(CC) \
	    $(CFLAGS) \
	    $(INCLUDES) \
	    $(LIB_SRCS) \
	    $(TEST_SRCS) \
	    -o $(BUILD_DIR)/macsec_tests

clean:
	rm -rf $(BUILD_DIR)