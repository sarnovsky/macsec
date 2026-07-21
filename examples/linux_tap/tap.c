/*
 * tap.c
 *
 * Linux TAP helper for the lightweight MACsec stack example.
 *
 * Copyright (c) 2026 Michal Sarnovsky
 * SPDX-License-Identifier: MIT
 */

#include "tap.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <net/if_arp.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

static int linux_tap_copy_name(struct ifreq *ifr, const char *name)
{
    size_t len;

    if ((ifr == NULL) || (name == NULL))
    {
        errno = EINVAL;
        return -1;
    }

    len = strlen(name);
    if (len >= IFNAMSIZ)
    {
        errno = ENAMETOOLONG;
        return -1;
    }

    memset(ifr, 0, sizeof(*ifr));
    memcpy(ifr->ifr_name, name, len + 1u);

    return 0;
}

int linux_tap_open(char *name, size_t name_size)
{
    struct ifreq ifr;
    int fd;

    if ((name == NULL) || (name_size == 0u))
    {
        errno = EINVAL;
        return -1;
    }

    if (strlen(name) >= IFNAMSIZ)
    {
        errno = ENAMETOOLONG;
        return -1;
    }

    /*
     * Non-blocking mode prevents a full TAP queue from trapping the event
     * loop inside read() or write(), which would also delay Ctrl+C handling.
     */
    fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0)
    {
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = (short) (IFF_TAP | IFF_NO_PI);

    if (name[0] != '\0')
    {
        memcpy(ifr.ifr_name, name, strlen(name) + 1u);
    }

    if (ioctl(fd, TUNSETIFF, &ifr) < 0)
    {
        int saved_errno = errno;

        close(fd);
        errno = saved_errno;
        return -1;
    }

    if (strlen(ifr.ifr_name) + 1u > name_size)
    {
        close(fd);
        errno = ENOSPC;
        return -1;
    }

    memcpy(name, ifr.ifr_name, strlen(ifr.ifr_name) + 1u);

    return fd;
}

int linux_tap_set_mac(const char *name, const uint8_t mac[6])
{
    struct ifreq ifr;
    int fd;
    int ret;
    int saved_errno;

    if ((name == NULL) || (mac == NULL))
    {
        errno = EINVAL;
        return -1;
    }

    fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
    {
        return -1;
    }

    if (linux_tap_copy_name(&ifr, name) < 0)
    {
        saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }

    ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
    memcpy(ifr.ifr_hwaddr.sa_data, mac, 6u);

    ret = ioctl(fd, SIOCSIFHWADDR, &ifr);
    saved_errno = errno;

    close(fd);
    errno = saved_errno;

    return ret;
}

int linux_tap_set_mtu(const char *name, int mtu)
{
    struct ifreq ifr;
    int fd;
    int ret;
    int saved_errno;

    if ((name == NULL) || (mtu <= 0))
    {
        errno = EINVAL;
        return -1;
    }

    fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
    {
        return -1;
    }

    if (linux_tap_copy_name(&ifr, name) < 0)
    {
        saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }

    ifr.ifr_mtu = mtu;

    ret = ioctl(fd, SIOCSIFMTU, &ifr);

    saved_errno = errno;
    close(fd);
    errno = saved_errno;

    return ret;
}

int linux_tap_set_up(const char *name)
{
    struct ifreq ifr;
    int fd;
    int ret;
    int saved_errno;

    if (name == NULL)
    {
        errno = EINVAL;
        return -1;
    }

    fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
    {
        return -1;
    }

    if (linux_tap_copy_name(&ifr, name) < 0)
    {
        saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }

    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0)
    {
        saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }

    ifr.ifr_flags = (short) (ifr.ifr_flags | IFF_UP | IFF_RUNNING);

    ret = ioctl(fd, SIOCSIFFLAGS, &ifr);
    saved_errno = errno;

    close(fd);
    errno = saved_errno;

    return ret;
}

int linux_tap_read(int fd, uint8_t *frame, size_t frame_capacity)
{
    ssize_t ret;

    if ((fd < 0) || (frame == NULL) || (frame_capacity == 0u))
    {
        errno = EINVAL;
        return -1;
    }

    ret = read(fd, frame, frame_capacity);

    if (ret < 0)
    {
        if ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR))
        {
            return 0;
        }

        return -1;
    }

    if (ret > INT32_MAX)
    {
        errno = EOVERFLOW;
        return -1;
    }

    return (int) ret;
}

int linux_tap_write(int fd, const uint8_t *frame, size_t frame_len)
{
    ssize_t ret;

    if ((fd < 0) || (frame == NULL) || (frame_len == 0u))
    {
        errno = EINVAL;
        return -1;
    }

    /*
     * TAP preserves Ethernet frame boundaries. Do not retry a partial write
     * as a byte stream because that could create a malformed second frame.
     */
    ret = write(fd, frame, frame_len);

    if (ret < 0)
    {
        if ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR))
        {
            return 0;
        }

        return -1;
    }

    if ((size_t) ret != frame_len)
    {
        errno = EIO;
        return -1;
    }

    return (int) ret;
}
