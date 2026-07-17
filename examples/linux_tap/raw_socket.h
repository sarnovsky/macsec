/*
 * raw_socket.h
 *
 * Linux AF_PACKET helper for the lightweight MACsec stack example.
 *
 * Copyright (c) 2026 Michal Sarnovsky
 * SPDX-License-Identifier: MIT
 */

#ifndef MACSEC_EXAMPLE_LINUX_RAW_SOCKET_H
#define MACSEC_EXAMPLE_LINUX_RAW_SOCKET_H

#include <stddef.h>
#include <stdint.h>

typedef struct
{
    int fd;
    int ifindex;
    uint8_t mac[6];
} linux_raw_socket_t;

int linux_raw_open(linux_raw_socket_t *raw, const char *ifname);
void linux_raw_close(linux_raw_socket_t *raw);

int linux_raw_receive(linux_raw_socket_t *raw, uint8_t *frame, size_t frame_capacity);

int linux_raw_send(linux_raw_socket_t *raw, const uint8_t *frame, size_t frame_len);

#endif
