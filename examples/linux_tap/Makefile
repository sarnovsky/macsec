###############################################################################
# Makefile
#
# Lightweight MACsec stack
# Build script for the Linux TAP example.
#
# This Makefile builds the userspace Linux TAP demonstration application,
# including the MACsec library, Linux platform abstraction layer and the
# TAP/AF_PACKET helper modules.
#
# Copyright (c) 2026 Michal Sarnovský
#
# SPDX-License-Identifier: MIT
#
# This file is part of the lightweight MACsec stack.
# See LICENSE file in the project root for full license text.
###############################################################################

###############################################################################
# Lightweight MACsec stack - Linux TAP example
#
# Usage:
#
#   make
#   make linux_tap
#   make clean
#   make linux_tap MACSEC_DEBUG_LEVEL=2
###############################################################################

CC := gcc

PROJECT_ROOT := ../..

BUILD_DIR := build
OBJ_DIR   := $(BUILD_DIR)/obj
TARGET    := $(BUILD_DIR)/macsec_linux_tap


###############################################################################
# Configurable MACsec options
###############################################################################

MACSEC_DEBUG_LEVEL ?= 1

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
	-D_GNU_SOURCE \
	-DMACSEC_DEBUG_LEVEL=$(MACSEC_DEBUG_LEVEL) \
	-DMACSEC_SELF_TEST=0 \
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
	-I$(PROJECT_ROOT)/port

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
# Linux platform port
#
# Paths are relative to PROJECT_ROOT.
###############################################################################

PORT_SRCS := \
	port/linux/port.c


###############################################################################
# Local Linux TAP application sources
###############################################################################

LOCAL_SRCS := \
	main.c \
	tap.c \
	raw_socket.c


###############################################################################
# Object files
#
# Everything remains inside examples/linux_tap/build/.
###############################################################################

LIB_OBJS := \
	$(LIB_SRCS:%.c=$(OBJ_DIR)/library/%.o)

PORT_OBJS := \
	$(PORT_SRCS:%.c=$(OBJ_DIR)/platform/%.o)

LOCAL_OBJS := \
	$(LOCAL_SRCS:%.c=$(OBJ_DIR)/local/%.o)

OBJS := \
	$(LIB_OBJS) \
	$(PORT_OBJS) \
	$(LOCAL_OBJS)

DEPS := $(OBJS:.o=.d)


###############################################################################
# Targets
###############################################################################

.PHONY: all
.PHONY: linux_tap
.PHONY: run
.PHONY: clean
.PHONY: rebuild
.PHONY: config

all: linux_tap

linux_tap: $(TARGET)


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
# Compile Linux platform port
###############################################################################

$(OBJ_DIR)/platform/%.o: $(PROJECT_ROOT)/%.c
	@echo "  CC    $<"
	@mkdir -p $(dir $@)
	@$(CC) $(CPPFLAGS) $(CFLAGS) $(INCLUDES) -c $< -o $@


###############################################################################
# Compile local Linux TAP sources
###############################################################################

$(OBJ_DIR)/local/%.o: %.c
	@echo "  CC    $<"
	@mkdir -p $(dir $@)
	@$(CC) $(CPPFLAGS) $(CFLAGS) $(INCLUDES) -c $< -o $@


###############################################################################
# Commands
###############################################################################

run: linux_tap
	@echo "Linux TAP example requires root privileges."
	@echo
	@echo "Run manually, for example:"
	@echo "  sudo ./$(TARGET) eth0 tap0"

config:
	@echo "TARGET                    = $(TARGET)"
	@echo "MACSEC_DEBUG_LEVEL        = $(MACSEC_DEBUG_LEVEL)"
	@echo "MACSEC_SELF_TEST          = 0"
	@echo "MATH_AES_ROM_TABLES       = $(MATH_AES_ROM_TABLES)"
	@echo "MATH_AES_FEWER_TABLES     = $(MATH_AES_FEWER_TABLES)"

clean:
	@echo "  CLEAN $(BUILD_DIR)"
	@rm -rf $(BUILD_DIR)

rebuild: clean linux_tap

-include $(DEPS)