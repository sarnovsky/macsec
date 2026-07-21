/*
 * raw_socket.c
 *
 * Linux AF_PACKET helper for the lightweight MACsec stack example.
 *
 * Copyright (c) 2026 Michal Sarnovsky
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

static int linux_raw_get_interface(int fd, const char *ifname, int *ifindex, uint8_t mac[6])
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

    /*
     * Non-blocking I/O is required because the example uses one event loop
     * for both TAP and AF_PACKET. A full socket queue must never prevent the
     * process from observing SIGINT/SIGTERM.
     */
    fd = socket(AF_PACKET,
                SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK,
                htons(ETH_P_ALL));
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
     * Prevent locally transmitted frames from being delivered back to this
     * packet socket. The receive path also checks PACKET_OUTGOING as a
     * fallback for kernels that do not support this socket option.
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
    address.sll_protocol = htons(ETH_P_ALL);
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

static uint16_t linux_raw_get_ethertype(const uint8_t *frame, size_t frame_len)
{
    if ((frame == NULL) || (frame_len < ETH_HLEN))
    {
        return 0u;
    }

    return ((uint16_t)frame[12] << 8) | (uint16_t)frame[13];
}

int linux_raw_receive(linux_raw_socket_t *raw,
                      uint8_t *frame,
                      size_t frame_capacity)
{
    struct sockaddr_ll source;
    socklen_t source_len;
    ssize_t ret;
    uint16_t ether_type;

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
        source_len = sizeof(source);

        ret = recvfrom(raw->fd,
                       frame,
                       frame_capacity,
                       0,
                       (struct sockaddr *)&source,
                       &source_len);

        if (ret < 0)
        {
            if ((errno == EAGAIN) || (errno == EWOULDBLOCK) ||
                (errno == EINTR))
            {
                return 0;
            }

            return -1;
        }

        /*
         * Fallback protection against the AF_PACKET socket receiving frames
         * emitted by this host. Feeding such a frame into TAP would create:
         *
         *   TAP -> encrypt -> AF_PACKET -> decrypt -> TAP -> ...
         */
        if (source.sll_pkttype == PACKET_OUTGOING)
        {
            continue;
        }

        if (ret > INT32_MAX)
        {
            errno = EOVERFLOW;
            return -1;
        }

        ether_type = linux_raw_get_ethertype(frame, (size_t)ret);

        /*
         * The userspace MACsec endpoint consumes only protected MACsec data
         * and EAPOL/MKA control traffic. Ignore all other physical traffic.
         */
        if ((ether_type != ETH_P_MACSEC) &&
            (ether_type != ETH_P_PAE))
        {
            continue;
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
    uint16_t ether_type;

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

    ether_type = linux_raw_get_ethertype(frame, frame_len);

    destination.sll_protocol = htons(ether_type);
    destination.sll_ifindex = raw->ifindex;
    destination.sll_halen = ETH_ALEN;

    memcpy(destination.sll_addr, frame, ETH_ALEN);

    ret = sendto(raw->fd,
                 frame,
                 frame_len,
                 0,
                 (const struct sockaddr *)&destination,
                 sizeof(destination));

    if (ret < 0)
    {
        if ((errno == EAGAIN) || (errno == EWOULDBLOCK) ||
            (errno == EINTR))
        {
            /*
             * The frame was not queued. This is a temporary condition, not
             * a fatal socket error.
             */
            return 0;
        }

        return -1;
    }

    /*
     * AF_PACKET sends one complete Ethernet frame per call. A short send is
     * therefore treated as an I/O error rather than retried as a byte stream.
     */
    if ((size_t)ret != frame_len)
    {
        errno = EIO;
        return -1;
    }

    return (int)ret;
}
