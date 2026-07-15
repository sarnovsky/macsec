###############################################################################
# Makefile
#
# Lightweight MACsec stack
# Build script for the unit test application.
#
# This Makefile builds the complete MACsec unit test suite together with
# the embedded platform abstraction layer and the local console interface.
#
# Copyright (c) 2026 Michal Sarnovský
#
# SPDX-License-Identifier: MIT
#
# This file is part of the lightweight MACsec stack.
# See LICENSE file in the project root for full license text.
###############################################################################

###############################################################################
# Lightweight MACsec stack - unit tests
#
# Usage:
#
#   make
#   make tests
#   make clean
#   make tests MACSEC_DEBUG_LEVEL=2
###############################################################################

CC := gcc

PROJECT_ROOT := ../..

BUILD_DIR := build
OBJ_DIR   := $(BUILD_DIR)/obj

###############################################################################
# Host-dependent executable suffix
###############################################################################

ifeq ($(OS),Windows_NT)
EXE_EXT := .exe
else
EXE_EXT :=
endif

TARGET := $(BUILD_DIR)/macsec_tests$(EXE_EXT)

###############################################################################
# Configurable MACsec options
###############################################################################

MACSEC_DEBUG_LEVEL ?= 1
MACSEC_SELF_TEST   ?= 1

MATH_AES_ROM_TABLES   ?= 1
MATH_AES_FEWER_TABLES ?= 0

ifeq ($(MATH_AES_ROM_TABLES),1)
ifeq ($(MATH_AES_FEWER_TABLES),1)
$(error MATH_AES_ROM_TABLES and MATH_AES_FEWER_TABLES cannot both be enabled)
endif
endif

###############################################################################
# Compiler options
###############################################################################

CPPFLAGS := \
	-DMACSEC_DEBUG_LEVEL=$(MACSEC_DEBUG_LEVEL) \
	-DMACSEC_SELF_TEST=$(MACSEC_SELF_TEST) \
	-DMATH_AES_ROM_TABLES=$(MATH_AES_ROM_TABLES) \
	-DMATH_AES_FEWER_TABLES=$(MATH_AES_FEWER_TABLES)

CFLAGS := \
	-std=c99 \
	-Wall \
	-Wextra \
	-O2 \
	-MMD \
	-MP

INCLUDES := \
	-I. \
	-I$(PROJECT_ROOT) \
	-I$(PROJECT_ROOT)/math \
	-I$(PROJECT_ROOT)/port \
	-I$(PROJECT_ROOT)/tests

LDFLAGS :=

###############################################################################
# MACsec library sources
#
# Paths are relative to PROJECT_ROOT.
###############################################################################

LIB_SRCS := \
	macsec_common.c \
	frame_crypto.c \
	macsec.c \
	mka.c \
	mka_crypto.c \
	math/aes.c \
	math/cmac.c \
	math/gcm.c

###############################################################################
# Embedded example port
###############################################################################

PORT_SRCS := \
	port/embedded/port.c

###############################################################################
# Unit-test framework sources
#
# Paths are relative to PROJECT_ROOT.
###############################################################################

TEST_SRCS := \
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
# Sources local to examples/unit_tests
###############################################################################

LOCAL_SRCS := \
	main.c \
	xprintf.c

###############################################################################
# Object files
#
# Everything remains inside examples/unit_tests/build/.
###############################################################################

LIB_OBJS := \
	$(LIB_SRCS:%.c=$(OBJ_DIR)/library/%.o)

PORT_OBJS := \
	$(PORT_SRCS:%.c=$(OBJ_DIR)/platform/%.o)

TEST_OBJS := \
	$(TEST_SRCS:%.c=$(OBJ_DIR)/framework/%.o)

LOCAL_OBJS := \
	$(LOCAL_SRCS:%.c=$(OBJ_DIR)/local/%.o)

OBJS := \
	$(LIB_OBJS) \
	$(PORT_OBJS) \
	$(TEST_OBJS) \
	$(LOCAL_OBJS)

DEPS := $(OBJS:.o=.d)

###############################################################################
# Targets
###############################################################################

.PHONY: all
.PHONY: tests
.PHONY: run
.PHONY: clean
.PHONY: rebuild
.PHONY: config

all: tests

tests: $(TARGET)

###############################################################################
# Link
###############################################################################

$(TARGET): $(OBJS)
	@echo "  LD    $@"
	@mkdir -p $(dir $@)
	@$(CC) $(OBJS) $(LDFLAGS) -o $@
	@echo "  Built $@"

###############################################################################
# Compile MACsec library
###############################################################################

$(OBJ_DIR)/library/%.o: $(PROJECT_ROOT)/%.c
	@echo "  CC    $<"
	@mkdir -p $(dir $@)
	@$(CC) $(CPPFLAGS) $(CFLAGS) $(INCLUDES) -c $< -o $@

###############################################################################
# Compile platform port
###############################################################################

$(OBJ_DIR)/platform/%.o: $(PROJECT_ROOT)/%.c
	@echo "  CC    $<"
	@mkdir -p $(dir $@)
	@$(CC) $(CPPFLAGS) $(CFLAGS) $(INCLUDES) -c $< -o $@

###############################################################################
# Compile unit-test framework
###############################################################################

$(OBJ_DIR)/framework/%.o: $(PROJECT_ROOT)/%.c
	@echo "  CC    $<"
	@mkdir -p $(dir $@)
	@$(CC) $(CPPFLAGS) $(CFLAGS) $(INCLUDES) -c $< -o $@

###############################################################################
# Compile local example sources
###############################################################################

$(OBJ_DIR)/local/%.o: %.c
	@echo "  CC    $<"
	@mkdir -p $(dir $@)
	@$(CC) $(CPPFLAGS) $(CFLAGS) $(INCLUDES) -c $< -o $@

###############################################################################
# Commands
###############################################################################

run: tests
	@echo "  RUN   $(TARGET)"
	@./$(TARGET)

config:
	@echo "TARGET                    = $(TARGET)"
	@echo "MACSEC_DEBUG_LEVEL        = $(MACSEC_DEBUG_LEVEL)"
	@echo "MACSEC_SELF_TEST          = $(MACSEC_SELF_TEST)"
	@echo "MATH_AES_ROM_TABLES       = $(MATH_AES_ROM_TABLES)"
	@echo "MATH_AES_FEWER_TABLES     = $(MATH_AES_FEWER_TABLES)"

clean:
	@echo "  CLEAN $(BUILD_DIR)"
	@rm -rf $(BUILD_DIR)

rebuild: clean tests

-include $(DEPS)