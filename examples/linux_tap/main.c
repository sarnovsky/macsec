/*
 * main.c
 *
 * Linux TAP <-> userspace MACsec <-> AF_PACKET example.
 *
 * The first version intentionally uses a fixed static SAK. Its purpose is to
 * verify the Linux data path, AES-GCM protection/recovery and ping traffic.
 *
 * Copyright (c) 2026 Michal Sarnovský
 * SPDX-License-Identifier: MIT
 */

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <macsec/macsec.h>

#include "raw_socket.h"
#include "tap.h"

#define LINUX_TAP_FRAME_MAX 2048u

static volatile sig_atomic_t linux_tap_running = 1;

static const uint8_t linux_tap_static_sak[16] =
{
    0x00u, 0x11u, 0x22u, 0x33u,
    0x44u, 0x55u, 0x66u, 0x77u,
    0x88u, 0x99u, 0xAAu, 0xBBu,
    0xCCu, 0xDDu, 0xEEu, 0xFFu
};

typedef struct
{
    uint64_t tap_rx;
    uint64_t raw_tx;
    uint64_t raw_rx;
    uint64_t tap_tx;
    uint64_t encrypt_errors;
    uint64_t decrypt_errors;
} linux_tap_stats_t;

static void linux_tap_signal_handler(int signal_number)
{
    (void)signal_number;
    linux_tap_running = 0;
}

static void linux_tap_print_mac(const uint8_t mac[6])
{
    printf("%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2],
           mac[3], mac[4], mac[5]);
}

static void linux_tap_usage(const char *program)
{
    fprintf(stderr,
            "Usage: sudo %s <physical-interface> [tap-name]\n"
            "\n"
            "Example:\n"
            "  sudo %s eth0 tap0\n"
            "\n"
            "After the program starts, configure an IP address in another shell:\n"
            "  sudo ip addr add 10.0.0.1/24 dev tap0\n",
            program,
            program);
}

static int linux_tap_init_macsec(macsec_ctx_t *ctx, const uint8_t local_mac[6])
{
    macsec_config_t cfg;

    memset(&cfg, 0, sizeof(cfg));

    cfg.mode = MACSEC_MODE_STATIC_SAK;
    memcpy(cfg.local_mac.addr, local_mac, 6u);
    cfg.port_id = 1u;

    memcpy(cfg.static_sak,
           linux_tap_static_sak,
           sizeof(linux_tap_static_sak));

    cfg.static_sak_len = sizeof(linux_tap_static_sak);
    cfg.static_an = 0u;

    /*
     * Replay protection is useful for the real test. Each program start resets
     * PN to 1, so both peers should normally be restarted together.
     */
    cfg.replay_protect = MACSEC_TRUE;
    cfg.replay_window = 0u;

    return macsec_init(ctx, &cfg);
}

static int linux_tap_process_plain(macsec_ctx_t *macsec,
                                   linux_raw_socket_t *raw,
                                   int tap_fd,
                                   linux_tap_stats_t *stats)
{
    uint8_t plain[LINUX_TAP_FRAME_MAX];
    uint8_t secure[LINUX_TAP_FRAME_MAX];
    size_t secure_len = 0u;
    int plain_len;
    int ret;

    plain_len = linux_tap_read(tap_fd, plain, sizeof(plain));
    if (plain_len < 0)
    {
        perror("read(tap)");
        return -1;
    }

    if (plain_len == 0)
    {
        return 0;
    }

    stats->tap_rx++;

    ret = macsec_output(macsec,
                        plain,
                        (size_t)plain_len,
                        secure,
                        &secure_len,
                        sizeof(secure));
    if (ret != MACSEC_ERR_OK)
    {
        stats->encrypt_errors++;
        fprintf(stderr,
                "MACsec encrypt failed: ret=%d plain_len=%d\n",
                ret,
                plain_len);
        return 0;
    }

    if (linux_raw_send(raw, secure, secure_len) < 0)
    {
        perror("sendto(AF_PACKET)");
        return -1;
    }

    stats->raw_tx++;

    printf("TX plain=%d secure=%zu PN=%lu\n",
           plain_len,
           secure_len,
           (unsigned long)macsec->frame_crypto.tx_sak.next_pn - 1ul);

    return 0;
}

static int linux_tap_process_secure(macsec_ctx_t *macsec,
                                    linux_raw_socket_t *raw,
                                    int tap_fd,
                                    linux_tap_stats_t *stats)
{
    uint8_t secure[LINUX_TAP_FRAME_MAX];
    uint8_t plain[LINUX_TAP_FRAME_MAX];
    size_t plain_len = 0u;
    macsec_bool_t pass_to_stack = MACSEC_FALSE;
    int secure_len;
    int ret;

    secure_len = linux_raw_receive(raw, secure, sizeof(secure));
    if (secure_len < 0)
    {
        perror("recvfrom(AF_PACKET)");
        return -1;
    }

    stats->raw_rx++;

    ret = macsec_input(macsec,
                       secure,
                       (size_t)secure_len,
                       plain,
                       &plain_len,
                       sizeof(plain),
                       &pass_to_stack);
    if (ret != MACSEC_ERR_OK)
    {
        stats->decrypt_errors++;
        fprintf(stderr,
                "MACsec decrypt failed: ret=%d secure_len=%d\n",
                ret,
                secure_len);
        return 0;
    }

    if (!pass_to_stack)
    {
        return 0;
    }

    if (linux_tap_write(tap_fd, plain, plain_len) < 0)
    {
        perror("write(tap)");
        return -1;
    }

    stats->tap_tx++;

    printf("RX secure=%d plain=%zu\n", secure_len, plain_len);

    return 0;
}

static void linux_tap_print_stats(const linux_tap_stats_t *stats)
{
    printf("\nStatistics:\n");
    printf("  TAP -> stack : %lu\n", (unsigned long)stats->tap_rx);
    printf("  encrypted TX : %lu\n", (unsigned long)stats->raw_tx);
    printf("  encrypted RX : %lu\n", (unsigned long)stats->raw_rx);
    printf("  stack -> TAP : %lu\n", (unsigned long)stats->tap_tx);
    printf("  encrypt errors: %lu\n", (unsigned long)stats->encrypt_errors);
    printf("  decrypt errors: %lu\n", (unsigned long)stats->decrypt_errors);
}

int main(int argc, char *argv[])
{
    linux_raw_socket_t raw;
    linux_tap_stats_t stats;
    macsec_ctx_t macsec;
    struct pollfd poll_fds[2];
    char tap_name[LINUX_TAP_NAME_MAX] = "tap0";
    const char *physical_name;
    int tap_fd = -1;
    int ret;
    int exit_code = EXIT_FAILURE;

    memset(&raw, 0, sizeof(raw));
    raw.fd = -1;
    memset(&stats, 0, sizeof(stats));
    memset(&macsec, 0, sizeof(macsec));

    if ((argc < 2) || (argc > 3))
    {
        linux_tap_usage(argv[0]);
        return EXIT_FAILURE;
    }

    physical_name = argv[1];

    if (argc == 3)
    {
        if (strlen(argv[2]) >= sizeof(tap_name))
        {
            fprintf(stderr, "TAP name is too long\n");
            return EXIT_FAILURE;
        }

        memcpy(tap_name, argv[2], strlen(argv[2]) + 1u);
    }

    signal(SIGINT, linux_tap_signal_handler);
    signal(SIGTERM, linux_tap_signal_handler);

    if (linux_raw_open(&raw, physical_name) < 0)
    {
        perror("linux_raw_open");
        goto cleanup;
    }

    tap_fd = linux_tap_open(tap_name, sizeof(tap_name));
    if (tap_fd < 0)
    {
        perror("linux_tap_open");
        goto cleanup;
    }

    /*
     * The protected Ethernet frame keeps the original destination/source MAC.
     * Giving TAP the physical NIC MAC makes peer unicast frames acceptable to
     * the physical NIC and keeps SCI/source addressing consistent.
     */
    if (linux_tap_set_mac(tap_name, raw.mac) < 0)
    {
        perror("linux_tap_set_mac");
        goto cleanup;
    }

    if (linux_tap_set_up(tap_name) < 0)
    {
        perror("linux_tap_set_up");
        goto cleanup;
    }

    ret = linux_tap_init_macsec(&macsec, raw.mac);
    if (ret != MACSEC_ERR_OK)
    {
        fprintf(stderr, "macsec_init failed: ret=%d\n", ret);
        goto cleanup;
    }

    printf("Linux userspace MACsec example started\n");
    printf("  physical: %s\n", physical_name);
    printf("  TAP     : %s\n", tap_name);
    printf("  MAC     : ");
    linux_tap_print_mac(raw.mac);
    printf("\n");
    printf("  mode    : static SAK, AN=0, replay protection enabled\n");
    printf("\nConfigure the TAP address in another shell, for example:\n");
    printf("  sudo ip addr add 10.0.0.1/24 dev %s\n", tap_name);
    printf("\nPress Ctrl+C to stop.\n\n");

    memset(poll_fds, 0, sizeof(poll_fds));

    poll_fds[0].fd = tap_fd;
    poll_fds[0].events = POLLIN;

    poll_fds[1].fd = raw.fd;
    poll_fds[1].events = POLLIN;

    exit_code = EXIT_SUCCESS;

    while (linux_tap_running)
    {
        ret = poll(poll_fds, 2u, 1000);
        if (ret < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }

            perror("poll");
            exit_code = EXIT_FAILURE;
            break;
        }

        if (ret == 0)
        {
            continue;
        }

        if ((poll_fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0)
        {
            fprintf(stderr, "TAP poll error: revents=0x%X\n",
                    poll_fds[0].revents);
            exit_code = EXIT_FAILURE;
            break;
        }

        if ((poll_fds[1].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0)
        {
            fprintf(stderr, "AF_PACKET poll error: revents=0x%X\n",
                    poll_fds[1].revents);
            exit_code = EXIT_FAILURE;
            break;
        }

        if ((poll_fds[0].revents & POLLIN) != 0)
        {
            if (linux_tap_process_plain(&macsec,
                                        &raw,
                                        tap_fd,
                                        &stats) < 0)
            {
                exit_code = EXIT_FAILURE;
                break;
            }
        }

        if ((poll_fds[1].revents & POLLIN) != 0)
        {
            if (linux_tap_process_secure(&macsec,
                                         &raw,
                                         tap_fd,
                                         &stats) < 0)
            {
                exit_code = EXIT_FAILURE;
                break;
            }
        }
    }

cleanup:
    linux_tap_print_stats(&stats);
    macsec_clear(&macsec);

    if (tap_fd >= 0)
    {
        close(tap_fd);
    }

    linux_raw_close(&raw);

    return exit_code;
}
