CC := gcc

BUILD_DIR := build
OBJ_DIR   := $(BUILD_DIR)/obj

TEST_TARGET      := $(BUILD_DIR)/macsec_tests
LINUX_TAP_TARGET := $(BUILD_DIR)/macsec_linux_tap

CFLAGS := \
    -std=c99 \
    -Wall \
    -Wextra \
#    -Wpedantic \
    -O2

INCLUDES := \
    -I. \
    -Imath \
    -Iport \
    -Itests \
    -Iexamples/linux_tap

LDFLAGS :=

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

LINUX_TAP_SRCS := \
    examples/linux_tap/main.c \
    examples/linux_tap/tap.c \
    examples/linux_tap/raw_socket.c

LIB_OBJS := $(LIB_SRCS:%.c=$(OBJ_DIR)/%.o)

TEST_OBJS := $(TEST_SRCS:%.c=$(OBJ_DIR)/%.o)

LINUX_TAP_OBJS := $(LINUX_TAP_SRCS:%.c=$(OBJ_DIR)/%.o)

.PHONY: all
.PHONY: tests
.PHONY: linux_tap
.PHONY: run
.PHONY: run_linux_tap
.PHONY: clean
.PHONY: rebuild

all: tests linux_tap

tests: $(TEST_TARGET)

linux_tap: $(LINUX_TAP_TARGET)

$(TEST_TARGET): $(LIB_OBJS) $(TEST_OBJS)
	@echo "  LD    $@"
	@mkdir -p $(dir $@)
	@$(CC) $(LIB_OBJS) $(TEST_OBJS) $(LDFLAGS) -o $@
	@echo "  Built $@"

$(LINUX_TAP_TARGET): $(LIB_OBJS) $(LINUX_TAP_OBJS)
	@echo "  LD    $@"
	@mkdir -p $(dir $@)
	@$(CC) $(LIB_OBJS) $(LINUX_TAP_OBJS) $(LDFLAGS) -o $@
	@echo "  Built $@"

$(OBJ_DIR)/%.o: %.c
	@echo "  CC    $<"
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

run: tests
	@echo "  RUN   $(TEST_TARGET)"
	@./$(TEST_TARGET)

run_linux_tap: linux_tap
	@echo "Linux TAP example requires root privileges."
	@echo
	@echo "Run manually, for example:"
	@echo "  sudo ./$(LINUX_TAP_TARGET) eth0 tap0"

clean:
	@echo "  CLEAN $(BUILD_DIR)"
	@rm -rf $(BUILD_DIR)

rebuild: clean all