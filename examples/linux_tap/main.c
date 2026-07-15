/*
 * main.c
 *
 * Linux TAP <-> userspace MACsec <-> AF_PACKET example.
 *
 * The application supports MACsec with either a statically configured SAK
 * or MKA using a pre-shared CAK/CKN pair.
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

#include <time.h>

#include <ctype.h>

#include <macsec.h>

#include "raw_socket.h"
#include "tap.h"

#define LINUX_TAP_FRAME_MAX 2048u

static volatile sig_atomic_t linux_tap_running = 1;

#define LINUX_TAP_CONFIG_DEFAULT "linux_tap.conf"

#define LINUX_TAP_CONFIG_LINE_MAX 512u
#define LINUX_TAP_CAK_MAX_LEN 32u
#define LINUX_TAP_CKN_MAX_LEN 32u

#define LINUX_TAP_STATIC_SAK_PREFIX "STATIC_SAK="

typedef enum
{
    LINUX_TAP_MODE_MKA_PSK = 0,
    LINUX_TAP_MODE_STATIC_SAK
} linux_tap_mode_t;

typedef struct
{
    linux_tap_mode_t mode;

    uint8_t cak[LINUX_TAP_CAK_MAX_LEN];
    size_t cak_len;

    uint8_t ckn[LINUX_TAP_CKN_MAX_LEN];
    size_t ckn_len;

    uint8_t mka_priority;

    uint8_t static_sak[32];
    size_t static_sak_len;

    macsec_bool_t cak_set;
    macsec_bool_t ckn_set;
    macsec_bool_t priority_set;
} linux_tap_config_t;

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
            "Usage:\n"
            "  sudo %s <physical-interface> [tap-name] [config-file]\n"
            "  sudo %s <physical-interface> [tap-name] STATIC_SAK=<hex>\n"
            "\n"
            "MKA example:\n"
            "  sudo %s eth0 tap0 linux_tap.conf\n"
            "\n"
            "Static SAK example:\n"
            "  sudo %s eth0 tap0 "
            "STATIC_SAK=00112233445566778899aabbccddeeff\n"
            "\n"
            "Defaults:\n"
            "  TAP interface : tap0\n"
            "  configuration : linux_tap.conf\n"
            "\n"
            "After the program starts, configure an IP address:\n"
            "  sudo ip addr add 10.0.0.1/24 dev tap0\n",
            program,
            program,
            program,
            program);
}

static char *linux_tap_trim(char *text)
{
    char *end;

    if (text == NULL)
    {
        return NULL;
    }

    while (isspace((unsigned char)*text))
    {
        text++;
    }

    if (*text == '\0')
    {
        return text;
    }

    end = text + strlen(text);

    while ((end > text) && isspace((unsigned char)end[-1]))
    {
        end--;
    }

    *end = '\0';

    return text;
}

static int linux_tap_hex_value(char c)
{
    if ((c >= '0') && (c <= '9'))
    {
        return c - '0';
    }

    if ((c >= 'a') && (c <= 'f'))
    {
        return 10 + (c - 'a');
    }

    if ((c >= 'A') && (c <= 'F'))
    {
        return 10 + (c - 'A');
    }

    return -1;
}

static int linux_tap_parse_hex(const char *text,
                               uint8_t *output,
                               size_t output_capacity,
                               size_t *output_len)
{
    size_t text_len;
    size_t byte_count;
    size_t i;

    if ((text == NULL) ||
        (output == NULL) ||
        (output_len == NULL))
    {
        return -1;
    }

    text_len = strlen(text);

    if ((text_len == 0u) || ((text_len & 1u) != 0u))
    {
        return -1;
    }

    byte_count = text_len / 2u;

    if (byte_count > output_capacity)
    {
        return -1;
    }

    for (i = 0u; i < byte_count; i++)
    {
        int high;
        int low;

        high = linux_tap_hex_value(text[i * 2u]);
        low = linux_tap_hex_value(text[i * 2u + 1u]);

        if ((high < 0) || (low < 0))
        {
            return -1;
        }

        output[i] = (uint8_t)(((unsigned)high << 4) |
                              (unsigned)low);
    }

    *output_len = byte_count;

    return 0;
}

static int linux_tap_parse_priority(const char *text,
                                    uint8_t *priority)
{
    char *end;
    unsigned long value;

    if ((text == NULL) || (priority == NULL))
    {
        return -1;
    }

    errno = 0;
    end = NULL;

    value = strtoul(text, &end, 10);

    if ((errno != 0) ||
        (end == text) ||
        (*end != '\0') ||
        (value > 255ul))
    {
        return -1;
    }

    *priority = (uint8_t)value;

    return 0;
}

static int linux_tap_load_config(const char *path,
                                 linux_tap_config_t *config)
{
    FILE *file;
    char line[LINUX_TAP_CONFIG_LINE_MAX];
    unsigned long line_number = 0ul;

    if ((path == NULL) || (config == NULL))
    {
        errno = EINVAL;
        return -1;
    }

    memset(config, 0, sizeof(*config));
    config->mode = LINUX_TAP_MODE_MKA_PSK;

    file = fopen(path, "r");
    if (file == NULL)
    {
        fprintf(stderr,
                "Cannot open configuration file '%s': %s\n",
                path,
                strerror(errno));
        return -1;
    }

    while (fgets(line, sizeof(line), file) != NULL)
    {
        char *text;
        char *comment;

        line_number++;

        if ((strchr(line, '\n') == NULL) && !feof(file))
        {
            fprintf(stderr,
                    "%s:%lu: configuration line is too long\n",
                    path,
                    line_number);

            fclose(file);
            return -1;
        }

        /*
         * Remove comments and surrounding whitespace.
         */
        comment = strchr(line, '#');
        if (comment != NULL)
        {
            *comment = '\0';
        }

        text = linux_tap_trim(line);

        if (*text == '\0')
        {
            continue;
        }

        if (strncmp(text, "mka_cak=", 8u) == 0)
        {
            const char *value = linux_tap_trim(text + 8u);

            if (config->cak_set)
            {
                fprintf(stderr,
                        "%s:%lu: duplicate mka_cak\n",
                        path,
                        line_number);
                fclose(file);
                return -1;
            }

            if (linux_tap_parse_hex(value,
                                    config->cak,
                                    sizeof(config->cak),
                                    &config->cak_len) < 0)
            {
                fprintf(stderr,
                        "%s:%lu: invalid mka_cak\n",
                        path,
                        line_number);
                fclose(file);
                return -1;
            }

            if ((config->cak_len != 16u) &&
                (config->cak_len != 32u))
            {
                fprintf(stderr,
                        "%s:%lu: mka_cak must contain 16 or 32 bytes\n",
                        path,
                        line_number);
                fclose(file);
                return -1;
            }

            config->cak_set = MACSEC_TRUE;
        }
        else if (strncmp(text, "mka_ckn=", 8u) == 0)
        {
            const char *value = linux_tap_trim(text + 8u);

            if (config->ckn_set)
            {
                fprintf(stderr,
                        "%s:%lu: duplicate mka_ckn\n",
                        path,
                        line_number);
                fclose(file);
                return -1;
            }

            if (linux_tap_parse_hex(value,
                                    config->ckn,
                                    sizeof(config->ckn),
                                    &config->ckn_len) < 0)
            {
                fprintf(stderr,
                        "%s:%lu: invalid mka_ckn\n",
                        path,
                        line_number);
                fclose(file);
                return -1;
            }

            if ((config->ckn_len == 0u) ||
                (config->ckn_len > LINUX_TAP_CKN_MAX_LEN))
            {
                fprintf(stderr,
                        "%s:%lu: mka_ckn must contain 1 to 32 bytes\n",
                        path,
                        line_number);
                fclose(file);
                return -1;
            }

            config->ckn_set = MACSEC_TRUE;
        }
        else if (strncmp(text, "mka_priority=", 13u) == 0)
        {
            const char *value = linux_tap_trim(text + 13u);

            if (config->priority_set)
            {
                fprintf(stderr,
                        "%s:%lu: duplicate mka_priority\n",
                        path,
                        line_number);
                fclose(file);
                return -1;
            }

            if (linux_tap_parse_priority(value,
                                         &config->mka_priority) < 0)
            {
                fprintf(stderr,
                        "%s:%lu: invalid mka_priority\n",
                        path,
                        line_number);
                fclose(file);
                return -1;
            }

            config->priority_set = MACSEC_TRUE;
        }
        else
        {
            /*
             * Ignore all unrelated wpa_supplicant options,
             * network braces and comments.
             */
        }
    }

    if (ferror(file))
    {
        fprintf(stderr,
                "Cannot read configuration file '%s'\n",
                path);
        fclose(file);
        return -1;
    }

    fclose(file);

    if (!config->cak_set)
    {
        fprintf(stderr, "%s: missing mka_cak\n", path);
        return -1;
    }

    if (!config->ckn_set)
    {
        fprintf(stderr, "%s: missing mka_ckn\n", path);
        return -1;
    }

    if (!config->priority_set)
    {
        fprintf(stderr, "%s: missing mka_priority\n", path);
        return -1;
    }

    return 0;
}

static int linux_tap_parse_static_sak(const char *argument,
                                      linux_tap_config_t *config)
{
    const char *value;

    if ((argument == NULL) || (config == NULL))
    {
        return -1;
    }

    if (strncmp(argument,
                LINUX_TAP_STATIC_SAK_PREFIX,
                strlen(LINUX_TAP_STATIC_SAK_PREFIX)) != 0)
    {
        return -1;
    }

    value = argument + strlen(LINUX_TAP_STATIC_SAK_PREFIX);

    memset(config, 0, sizeof(*config));
    config->mode = LINUX_TAP_MODE_STATIC_SAK;

    if (linux_tap_parse_hex(value,
                            config->static_sak,
                            sizeof(config->static_sak),
                            &config->static_sak_len) < 0)
    {
        fprintf(stderr, "Invalid STATIC_SAK hexadecimal value\n");
        return -1;
    }

    if ((config->static_sak_len != 16u) &&
        (config->static_sak_len != 32u))
    {
        fprintf(stderr,
                "STATIC_SAK must contain 16 or 32 bytes\n");
        return -1;
    }

    return 0;
}

static int linux_tap_init_macsec(macsec_ctx_t *ctx,
                                 const uint8_t local_mac[6],
                                 const linux_tap_config_t *config)
{
    macsec_config_t cfg;

    if ((ctx == NULL) ||
        (local_mac == NULL) ||
        (config == NULL))
    {
        return -1;
    }

    memset(&cfg, 0, sizeof(cfg));

    memcpy(cfg.local_mac.addr, local_mac, 6u);
    cfg.port_id = 1u;

    cfg.replay_protect = MACSEC_FALSE;
    cfg.replay_window = 0u;

    if (config->mode == LINUX_TAP_MODE_STATIC_SAK)
    {
        cfg.mode = MACSEC_MODE_STATIC_SAK;

        memcpy(cfg.static_sak,
               config->static_sak,
               config->static_sak_len);

        cfg.static_sak_len = config->static_sak_len;
        cfg.static_an = 0u;
    }
    else
    {
        cfg.mode = MACSEC_MODE_MKA_PSK;

        memcpy(cfg.cak, config->cak, config->cak_len);
        cfg.cak_len = config->cak_len;

        memcpy(cfg.ckn, config->ckn, config->ckn_len);
        cfg.ckn_len = config->ckn_len;

        cfg.key_server_priority = config->mka_priority;
        cfg.mka_tx_interval_ms = 2000u;
    }

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

        if (macsec->state != MACSEC_STATE_SECURED)
        {
            printf("TX plaintext deferred: MACsec state=%u\n",
                   (unsigned)macsec->state);
        }
        else
        {
            fprintf(stderr,
                    "MACsec encrypt failed: ret=%d plain_len=%d\n",
                    ret,
                    plain_len);
        }

        return 0;
    }

    if (linux_raw_send(raw, secure, secure_len) < 0)
    {
        perror("sendto(AF_PACKET)");
        return -1;
    }

    stats->raw_tx++;

    /* printf("TX plain=%d secure=%zu PN=%lu\n",
           plain_len,
           secure_len,
           (unsigned long)macsec->frame_crypto.tx_sak.next_pn - 1ul); */

    return 0;
}

static int linux_tap_process_physical(macsec_ctx_t *macsec,
                                      linux_raw_socket_t *raw,
                                      int tap_fd,
                                      linux_tap_stats_t *stats)
{
    uint8_t input[LINUX_TAP_FRAME_MAX];
    uint8_t plain[LINUX_TAP_FRAME_MAX];
    size_t plain_len = 0u;
    macsec_bool_t pass_to_stack = MACSEC_FALSE;
    uint16_t ether_type;
    int input_len;
    int ret;

    input_len = linux_raw_receive(raw, input, sizeof(input));
    if (input_len < 0)
    {
        perror("recvfrom(AF_PACKET)");
        return -1;
    }

    if (input_len < 14)
    {
        fprintf(stderr,
                "Received Ethernet frame is too short: len=%d\n",
                input_len);
        return 0;
    }

    ether_type = ((uint16_t)input[12] << 8) |
                  (uint16_t)input[13];

    stats->raw_rx++;

    if (ether_type == 0x888Eu)
    {
        printf("RX MKA len=%d state=%u\n",
               input_len,
               (unsigned)macsec->state);
    }

    ret = macsec_input(macsec,
                       input,
                       (size_t)input_len,
                       plain,
                       &plain_len,
                       sizeof(plain),
                       &pass_to_stack);

    if (ret != MACSEC_ERR_OK)
    {
        stats->decrypt_errors++;

        fprintf(stderr,
                "macsec_input failed: ret=%d type=0x%04X len=%d\n",
                ret,
                ether_type,
                input_len);

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

    printf("RX MACsec secure=%d plain=%zu\n",
           input_len,
           plain_len);

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

static uint32_t linux_tap_get_time_ms(void)
{
    struct timespec ts;
    uint64_t milliseconds;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
    {
        return 0u;
    }

    milliseconds = ((uint64_t)ts.tv_sec * 1000u) +
                   ((uint64_t)ts.tv_nsec / 1000000u);

    return (uint32_t)milliseconds;
}

static int linux_tap_macsec_control_service(macsec_ctx_t *macsec,
                                            linux_raw_socket_t *raw)
{
    uint8_t frame[MACSEC_MKA_MAX_FRAME_LEN];
    size_t frame_len = 0u;
    uint32_t now_ms;
    int ret;

    now_ms = linux_tap_get_time_ms();

    ret = macsec_tick(macsec, now_ms);
    if (ret != MACSEC_ERR_OK)
    {
        fprintf(stderr, "macsec_tick failed: ret=%d\n", ret);
        return -1;
    }

    ret = macsec_get_control_frame(macsec,
                                   frame,
                                   &frame_len,
                                   sizeof(frame));

    if (ret == MACSEC_ERR_OK)
    {
        if (linux_raw_send(raw, frame, frame_len) < 0)
        {
            perror("send MKA");
            return -1;
        }

        printf("TX MKA len=%zu state=%u\n",
               frame_len,
               (unsigned)macsec->state);
    }

    /*
     * not ready is not error, return code depends on API
     */
    return 0;
}

int main(int argc, char *argv[])
{
    linux_raw_socket_t raw;
    linux_tap_stats_t stats;
    linux_tap_config_t config;
    macsec_ctx_t macsec;
    struct pollfd poll_fds[2];

    char tap_name[LINUX_TAP_NAME_MAX] = "tap0";

    const char *physical_name;
    const char *config_path = LINUX_TAP_CONFIG_DEFAULT;

    macsec_bool_t macsec_initialized = MACSEC_FALSE;

    int tap_fd = -1;
    int ret;
    int exit_code = EXIT_FAILURE;

    memset(&raw, 0, sizeof(raw));
    raw.fd = -1;

    memset(&stats, 0, sizeof(stats));
    memset(&config, 0, sizeof(config));
    memset(&macsec, 0, sizeof(macsec));

    if ((argc < 2) || (argc > 4))
    {
        linux_tap_usage(argv[0]);
        return EXIT_FAILURE;
    }

    physical_name = argv[1];

    if (argc >= 3)
    {
        if (strlen(argv[2]) >= sizeof(tap_name))
        {
            fprintf(stderr, "TAP name is too long\n");
            return EXIT_FAILURE;
        }

        memcpy(tap_name, argv[2], strlen(argv[2]) + 1u);
    }

    if (argc >= 4)
    {
        config_path = argv[3];
    }

    if (strncmp(config_path,
                LINUX_TAP_STATIC_SAK_PREFIX,
                strlen(LINUX_TAP_STATIC_SAK_PREFIX)) == 0)
    {
        if (linux_tap_parse_static_sak(config_path, &config) < 0)
        {
            return EXIT_FAILURE;
        }
    }
    else
    {
        if (linux_tap_load_config(config_path, &config) < 0)
        {
            return EXIT_FAILURE;
        }
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

    ret = linux_tap_init_macsec(&macsec,
                                raw.mac,
                                &config);
    if (ret != MACSEC_ERR_OK)
    {
        fprintf(stderr, "macsec_init failed: ret=%d\n", ret);
        goto cleanup;
    }

    macsec_initialized = MACSEC_TRUE;

    printf("Linux userspace MACsec example started\n");
    printf("  physical: %s\n", physical_name);
    printf("  TAP     : %s\n", tap_name);
    printf("  MAC     : ");
    linux_tap_print_mac(raw.mac);
    printf("\n");
    if (config.mode == LINUX_TAP_MODE_STATIC_SAK)
    {
        printf("  mode    : static SAK\n");
        printf("  SAK     : %zu bytes\n", config.static_sak_len);
        printf("  AN      : 0\n");
    }
    else
    {
        printf("  mode    : MKA PSK\n");
        printf("  config  : %s\n", config_path);
        printf("  CAK     : %zu bytes\n", config.cak_len);
        printf("  CKN     : %zu bytes\n", config.ckn_len);
        printf("  priority: %u\n",
               (unsigned)config.mka_priority);
    }
    printf("  replay  : disabled\n");

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
        ret = poll(poll_fds, 2u, 100);
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

        if (config.mode == LINUX_TAP_MODE_MKA_PSK)
        {
            if (linux_tap_macsec_control_service(&macsec, &raw) < 0)
            {
                exit_code = EXIT_FAILURE;
                break;
            }
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
            if (linux_tap_process_physical(&macsec,
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

    if (macsec_initialized)
    {
        macsec_clear(&macsec);
    }

    if (tap_fd >= 0)
    {
        close(tap_fd);
    }

    linux_raw_close(&raw);

    return exit_code;
}
