/*
 * tap.h
 *
 * Linux TAP helper for the lightweight MACsec stack example.
 *
 * Copyright (c) 2026 Michal Sarnovsky
 * SPDX-License-Identifier: MIT
 */

#ifndef MACSEC_EXAMPLE_LINUX_TAP_H
#define MACSEC_EXAMPLE_LINUX_TAP_H

#include <stddef.h>
#include <stdint.h>

#define LINUX_TAP_NAME_MAX 16u

int linux_tap_open(char *name, size_t name_size);
int linux_tap_set_mac(const char *name, const uint8_t mac[6]);
int linux_tap_set_mtu(const char *name, int mtu);
int linux_tap_set_up(const char *name);
int linux_tap_read(int fd, uint8_t *frame, size_t frame_capacity);
int linux_tap_write(int fd, const uint8_t *frame, size_t frame_len);

#endif
