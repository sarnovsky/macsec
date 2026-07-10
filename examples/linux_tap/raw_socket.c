/*
 * raw_socket.c
 *
 * Linux AF_PACKET helper for the lightweight MACsec stack example.
 *
 * Copyright (c) 2026 Michal Sarnovský
 * SPDX-License-Identifier: MIT
 */

#include "raw_socket.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef ETH_P_MACSEC
#define ETH_P_MACSEC 0x88E5u
#endif

static int linux_raw_get_interface(int fd,
                                   const char *ifname,
                                   int *ifindex,
                                   uint8_t mac[6])
{
    struct ifreq ifr;
    size_t len;

    if ((ifname == NULL) || (ifindex == NULL) || (mac == NULL))
    {
        errno = EINVAL;
        return -1;
    }

    len = strlen(ifname);
    if (len >= IFNAMSIZ)
    {
        errno = ENAMETOOLONG;
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.ifr_name, ifname, len + 1u);

    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0)
    {
        return -1;
    }

    *ifindex = ifr.ifr_ifindex;

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0)
    {
        return -1;
    }

    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6u);

    return 0;
}

int linux_raw_open(linux_raw_socket_t *raw, const char *ifname)
{
    struct sockaddr_ll address;
    int one = 1;
    int fd;

    if ((raw == NULL) || (ifname == NULL))
    {
        errno = EINVAL;
        return -1;
    }

    memset(raw, 0, sizeof(*raw));
    raw->fd = -1;

    fd = socket(AF_PACKET,
                SOCK_RAW | SOCK_CLOEXEC,
                htons((uint16_t)ETH_P_MACSEC));
    if (fd < 0)
    {
        return -1;
    }

    if (linux_raw_get_interface(fd, ifname, &raw->ifindex, raw->mac) < 0)
    {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }

#ifdef PACKET_IGNORE_OUTGOING
    /*
     * Prevent frames sent by this socket from being delivered back to it.
     * Older kernels may not support the option; ENOPROTOOPT is harmless.
     */
    if (setsockopt(fd,
                   SOL_PACKET,
                   PACKET_IGNORE_OUTGOING,
                   &one,
                   sizeof(one)) < 0)
    {
        if (errno != ENOPROTOOPT)
        {
            int saved_errno = errno;
            close(fd);
            errno = saved_errno;
            return -1;
        }
    }
#endif

    memset(&address, 0, sizeof(address));
    address.sll_family = AF_PACKET;
    address.sll_protocol = htons((uint16_t)ETH_P_MACSEC);
    address.sll_ifindex = raw->ifindex;

    if (bind(fd, (const struct sockaddr *)&address, sizeof(address)) < 0)
    {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }

    raw->fd = fd;

    return 0;
}

void linux_raw_close(linux_raw_socket_t *raw)
{
    if (raw == NULL)
    {
        return;
    }

    if (raw->fd >= 0)
    {
        close(raw->fd);
    }

    memset(raw, 0, sizeof(*raw));
    raw->fd = -1;
}

int linux_raw_receive(linux_raw_socket_t *raw,
                      uint8_t *frame,
                      size_t frame_capacity)
{
    struct sockaddr_ll source;
    socklen_t source_len = sizeof(source);
    ssize_t ret;

    if ((raw == NULL) ||
        (raw->fd < 0) ||
        (frame == NULL) ||
        (frame_capacity == 0u))
    {
        errno = EINVAL;
        return -1;
    }

    for (;;)
    {
        memset(&source, 0, sizeof(source));

        ret = recvfrom(raw->fd,
                       frame,
                       frame_capacity,
                       0,
                       (struct sockaddr *)&source,
                       &source_len);

        if ((ret < 0) && (errno == EINTR))
        {
            continue;
        }

        if (ret < 0)
        {
            return -1;
        }

        if (source.sll_pkttype == PACKET_OUTGOING)
        {
            continue;
        }

        if (ret > INT32_MAX)
        {
            errno = EOVERFLOW;
            return -1;
        }

        return (int)ret;
    }
}

int linux_raw_send(linux_raw_socket_t *raw,
                   const uint8_t *frame,
                   size_t frame_len)
{
    struct sockaddr_ll destination;
    ssize_t ret;

    if ((raw == NULL) ||
        (raw->fd < 0) ||
        (frame == NULL) ||
        (frame_len < ETH_HLEN))
    {
        errno = EINVAL;
        return -1;
    }

    memset(&destination, 0, sizeof(destination));
    destination.sll_family = AF_PACKET;
    destination.sll_protocol = htons((uint16_t)ETH_P_MACSEC);
    destination.sll_ifindex = raw->ifindex;
    destination.sll_halen = ETH_ALEN;
    memcpy(destination.sll_addr, frame, ETH_ALEN);

    do
    {
        ret = sendto(raw->fd,
                     frame,
                     frame_len,
                     0,
                     (const struct sockaddr *)&destination,
                     sizeof(destination));
    }
    while ((ret < 0) && (errno == EINTR));

    if (ret < 0)
    {
        return -1;
    }

    if ((size_t)ret != frame_len)
    {
        errno = EIO;
        return -1;
    }

    return (int)ret;
}
