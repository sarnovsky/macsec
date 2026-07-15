###############################################################################
# Lightweight MACsec stack
# STM32 memory-footprint measurement project
###############################################################################

PROJECT_ROOT := ../..
PROJECT_PARENT := $(PROJECT_ROOT)/..

TARGET ?= macsec_memusage

BUILD_DIR ?= build/default

PROFILE ?= full
OPT ?= -Os
DEBUG_LEVEL ?= 0
SELF_TEST ?= 0
AES_TABLE_MODE ?= rom_fewer
MACSEC_HEAP_SIZE ?= 4096

TOOLCHAIN ?=
PREFIX ?= arm-none-eabi-

CC      := $(TOOLCHAIN)$(PREFIX)gcc
OBJCOPY := $(TOOLCHAIN)$(PREFIX)objcopy
SIZE    := $(TOOLCHAIN)$(PREFIX)size
NM      := $(TOOLCHAIN)$(PREFIX)nm

LDSCRIPT ?= stm32f4_flash.ld
STARTUP ?= startup_stm32f4xx.s


###############################################################################
# Profile selection
###############################################################################

MEMUSAGE_PROFILE_MINIMAL       := 1
MEMUSAGE_PROFILE_FULL          := 2
MEMUSAGE_PROFILE_FULL_DEBUG    := 3
MEMUSAGE_PROFILE_FULL_SELFTEST := 4

ifeq ($(PROFILE),minimal)
PROFILE_ID := $(MEMUSAGE_PROFILE_MINIMAL)
PROFILE_SELF_TEST := 0
else ifeq ($(PROFILE),full)
PROFILE_ID := $(MEMUSAGE_PROFILE_FULL)
PROFILE_SELF_TEST := 0
else ifeq ($(PROFILE),full_debug)
PROFILE_ID := $(MEMUSAGE_PROFILE_FULL_DEBUG)
PROFILE_SELF_TEST := 0
else ifeq ($(PROFILE),full_selftest)
PROFILE_ID := $(MEMUSAGE_PROFILE_FULL_SELFTEST)
PROFILE_SELF_TEST := 1
else
$(error Unsupported PROFILE '$(PROFILE)')
endif

# Explicit command-line SELF_TEST=1 may enable tests for other experiments,
# but full_selftest always enables them.
ifeq ($(PROFILE_SELF_TEST),1)
EFFECTIVE_SELF_TEST := 1
else
EFFECTIVE_SELF_TEST := $(SELF_TEST)
endif


###############################################################################
# AES table configuration
###############################################################################

AES_DEFINES :=

ifeq ($(AES_TABLE_MODE),runtime_full)
# No table-related defines.
else ifeq ($(AES_TABLE_MODE),runtime_fewer)
AES_DEFINES += -DMATH_AES_FEWER_TABLES
else ifeq ($(AES_TABLE_MODE),rom_full)
AES_DEFINES += -DMATH_AES_ROM_TABLES
else ifeq ($(AES_TABLE_MODE),rom_fewer)
AES_DEFINES += -DMATH_AES_ROM_TABLES
AES_DEFINES += -DMATH_AES_FEWER_TABLES
else
$(error Unsupported AES_TABLE_MODE '$(AES_TABLE_MODE)')
endif


###############################################################################
# Compiler and linker flags
###############################################################################

CPU_FLAGS := -mthumb -mcpu=cortex-m4
CPU_FLAGS += -mfloat-abi=softfp -mfpu=fpv4-sp-d16

COMMON_FLAGS := $(CPU_FLAGS)
COMMON_FLAGS += -std=gnu90
COMMON_FLAGS += -ffunction-sections
COMMON_FLAGS += -fdata-sections
COMMON_FLAGS += -fno-builtin
COMMON_FLAGS += -Wall
COMMON_FLAGS += -Wextra
COMMON_FLAGS += -Wno-unused-parameter
COMMON_FLAGS += -MMD
COMMON_FLAGS += -MP
COMMON_FLAGS += $(OPT)

DEFINES := -DMEMUSAGE_PROFILE=$(PROFILE_ID)
DEFINES += -DMACSEC_SELF_TEST=$(EFFECTIVE_SELF_TEST)
DEFINES += -DMACSEC_DEBUG_LEVEL=$(DEBUG_LEVEL)
DEFINES += -DMACSEC_HEAP_SIZE=$(MACSEC_HEAP_SIZE)
DEFINES += $(AES_DEFINES)

INCLUDES := -I.
INCLUDES += -I$(PROJECT_PARENT)
INCLUDES += -I$(PROJECT_ROOT)
INCLUDES += -I$(PROJECT_ROOT)/math
INCLUDES += -I$(PROJECT_ROOT)/tests

CFLAGS := $(COMMON_FLAGS) $(DEFINES) $(INCLUDES)

ASFLAGS := $(CPU_FLAGS)
ASFLAGS += -x assembler-with-cpp
ASFLAGS += -Wa,--warn

LDFLAGS := $(CPU_FLAGS)
LDFLAGS += -T$(LDSCRIPT)
LDFLAGS += -nostartfiles
LDFLAGS += -nostdlib
LDFLAGS += -static
LDFLAGS += -Wl,--gc-sections
LDFLAGS += -Wl,-Map=$(BUILD_DIR)/$(TARGET).map
LDFLAGS += -Wl,-cref
LDFLAGS += -Wl,-u,Reset_Handler
LDFLAGS += -Wl,--start-group
LDFLAGS += -lgcc
LDFLAGS += -Wl,--end-group


###############################################################################
# Sources
###############################################################################

LOCAL_SOURCES := main.c
LOCAL_SOURCES += port.c
LOCAL_SOURCES += runtime.c

MINIMAL_SOURCES := $(PROJECT_ROOT)/macsec_common.c
MINIMAL_SOURCES += $(PROJECT_ROOT)/frame_crypto.c
MINIMAL_SOURCES += $(PROJECT_ROOT)/math/aes.c
MINIMAL_SOURCES += $(PROJECT_ROOT)/math/gcm.c

FULL_SOURCES := $(MINIMAL_SOURCES)
FULL_SOURCES += $(PROJECT_ROOT)/macsec.c
FULL_SOURCES += $(PROJECT_ROOT)/mka.c
FULL_SOURCES += $(PROJECT_ROOT)/mka_crypto.c
FULL_SOURCES += $(PROJECT_ROOT)/math/cmac.c

TEST_SOURCES := $(PROJECT_ROOT)/tests/unit_tests.c
TEST_SOURCES += $(PROJECT_ROOT)/tests/test_common.c
TEST_SOURCES += $(PROJECT_ROOT)/tests/test_math_selftest.c
TEST_SOURCES += $(PROJECT_ROOT)/tests/test_mka_crypto.c
TEST_SOURCES += $(PROJECT_ROOT)/tests/test_mka_frames.c
TEST_SOURCES += $(PROJECT_ROOT)/tests/test_frame_crypto.c
TEST_SOURCES += $(PROJECT_ROOT)/tests/test_integration.c
TEST_SOURCES += $(PROJECT_ROOT)/tests/test_mka_negative.c
TEST_SOURCES += $(PROJECT_ROOT)/tests/test_rekey.c
TEST_SOURCES += $(PROJECT_ROOT)/tests/test_macsec_flow.c

ifeq ($(PROFILE),minimal)
C_SOURCES := $(LOCAL_SOURCES) $(MINIMAL_SOURCES)
else ifeq ($(PROFILE),full_selftest)
C_SOURCES := $(LOCAL_SOURCES) $(FULL_SOURCES) $(TEST_SOURCES)
else
C_SOURCES := $(LOCAL_SOURCES) $(FULL_SOURCES)
endif


###############################################################################
# Object path conversion
###############################################################################

# Convert source paths to safe names below BUILD_DIR/obj.
#
# ../../math/aes.c -> build/.../obj/math/aes.o
define source_to_object
$(BUILD_DIR)/obj/$(subst ../,,$(basename $(1))).o
endef

C_OBJECTS := $(foreach SRC,$(C_SOURCES),$(call source_to_object,$(SRC)))
STARTUP_OBJECT := $(BUILD_DIR)/obj/startup_stm32f4xx.o

DEPENDENCIES := $(C_OBJECTS:.o=.d)

-include $(DEPENDENCIES)

ELF := $(BUILD_DIR)/$(TARGET).elf
BIN := $(BUILD_DIR)/$(TARGET).bin
HEX := $(BUILD_DIR)/$(TARGET).hex
SIZE_TXT := $(BUILD_DIR)/size.txt
SECTIONS_TXT := $(BUILD_DIR)/sections.txt
SYMBOLS_TXT := $(BUILD_DIR)/symbols.txt


###############################################################################
# Targets
###############################################################################

all: $(ELF) $(BIN) $(HEX) reports

$(ELF): $(C_OBJECTS) $(STARTUP_OBJECT)
	@mkdir -p $(@D)
	@echo "  LD      $@"
	@$(CC) $(C_OBJECTS) $(STARTUP_OBJECT) $(LDFLAGS) -o $@
	@echo "  SIZE    $@"
	@$(SIZE) $@

$(BIN): $(ELF)
	@echo "  OBJCOPY $@"
	@$(OBJCOPY) -O binary $< $@

$(HEX): $(ELF)
	@echo "  OBJCOPY $@"
	@$(OBJCOPY) -O ihex $< $@

reports: $(ELF)
	@echo "  REPORT  $(SIZE_TXT)"
	@$(SIZE) $(ELF) > $(SIZE_TXT)
	@$(SIZE) -A $(ELF) > $(SECTIONS_TXT)
	@$(NM) --print-size --size-sort --radix=d $(ELF) > $(SYMBOLS_TXT)

$(STARTUP_OBJECT): $(STARTUP)
	@mkdir -p $(@D)
	@echo "  AS      $<"
	@$(CC) $(ASFLAGS) -c $< -o $@

# Rule for local sources.
$(BUILD_DIR)/obj/%.o: %.c
	@mkdir -p $(@D)
	@echo "  CC      $<"
	@$(CC) $(CFLAGS) -c $< -o $@

# Rule for ../../ sources after ../ removal.
$(BUILD_DIR)/obj/%.o: $(PROJECT_ROOT)/%.c
	@mkdir -p $(@D)
	@echo "  CC      $<"
	@$(CC) $(CFLAGS) -c $< -o $@

print-config:
	@echo "PROFILE=$(PROFILE)"
	@echo "PROFILE_ID=$(PROFILE_ID)"
	@echo "OPT=$(OPT)"
	@echo "DEBUG_LEVEL=$(DEBUG_LEVEL)"
	@echo "SELF_TEST=$(EFFECTIVE_SELF_TEST)"
	@echo "AES_TABLE_MODE=$(AES_TABLE_MODE)"
	@echo "MACSEC_HEAP_SIZE=$(MACSEC_HEAP_SIZE)"
	@echo "BUILD_DIR=$(BUILD_DIR)"

size: $(ELF)
	@$(SIZE) $(ELF)

sections: $(ELF)
	@$(SIZE) -A $(ELF)

clean:
	@echo "Removing $(BUILD_DIR)"
	@rm -rf $(BUILD_DIR)

mrproper:
	@echo "Removing all footprint builds and results"
	@rm -rf build
	@rm -rf results

.PHONY: all reports print-config size sections clean mrproper