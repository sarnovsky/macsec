# Lightweight MACsec Stack

Lightweight experimental implementation of IEEE 802.1AE (MACsec) and IEEE 802.1X
MACsec Key Agreement (MKA) written in C for embedded systems.

The project focuses on portability, readability and low resource usage while
remaining independent of any operating system or network stack. It is intended
primarily for embedded development, experimentation and educational purposes.

---

# Status

Experimental / proof of concept.

The implementation has **not** been independently security audited and should
not be used in production or safety/security-critical systems without
additional review and validation.

---

# Features

## MACsec

- IEEE 802.1AE frame protection
- AES-GCM authenticated encryption
- SecTAG generation and parsing
- ICV generation and verification
- SCI support
- Packet Number (PN) handling
- Replay protection
- Static Secure Association Keys (SAK)
- 128-bit and 256-bit SAK support

## MKA

- IEEE 802.1X MACsec Key Agreement (MKA)
- Pre-Shared Key (PSK) mode
- CAK lengths:
  - 128-bit (16-byte)
  - 256-bit (32-byte)
- CKN lengths up to 32 bytes
- ICK / KEK derivation
- Distributed SAK generation
- Key Server election
- Rekey support
- MKA frame encoding and decoding
- MIC generation and verification (AES-CMAC)

## Cryptography

- Embedded AES implementation
- AES-GCM
- AES-CMAC
- Runtime or ROM lookup tables
- Reduced lookup-table configuration for lower Flash usage

## Testing

- Unit tests
- Integration tests
- Negative tests
- Rekey tests
- Cryptographic self-tests
- Linux interoperability testing with wpa_supplicant

---

# Design goals

- Small Flash footprint
- Small RAM footprint
- Portable ANSI C implementation
- No operating system required
- Easy integration into existing Ethernet drivers
- Readable implementation suitable for learning

---

# Requirements

- C compiler
- Standard C library
- `<stdint.h>`
- `<stddef.h>`

No operating system is required.

The library is self-contained and does not depend on lwIP, FreeRTOS or any
particular Ethernet controller.

---

# Directory structure

```text
macsec/
    common.[ch]
    frame_crypto.[ch]
    macsec.[ch]
    mka.[ch]
    mka_crypto.[ch]

math/
    aes.[ch]
    gcm.[ch]
    cmac.[ch]

tests/
    Unit tests
    Integration tests
    Negative tests
    Rekey tests

examples/
    Linux TAP example
    STM32 memory footprint measurement
    Platform examples

port/
    Linux platform
    Embedded platform
```

---

# Memory footprint

The repository contains a dedicated STM32 memory-footprint measurement project
located in:

```text
examples/mem_usage_stm32
```

Measurements are performed automatically using:

- STM32F411
- Cortex-M4
- Thumb instruction set
- arm-none-eabi-gcc

Several build configurations are evaluated automatically, including:

- compiler optimization (`-O0`, `-O2`, `-Os`)
- debug levels
- self-test support
- AES lookup-table implementations

Typical production (`PROFILE=full`, `SELF_TEST=0`, `DEBUG_LEVEL=0`, `-Os`)
results are:

| AES mode | FLASH | RAM |
|-----------|------:|----:|
| runtime_fewer | **13.85 KiB** | 8.80 KiB |
| rom_fewer | 15.93 KiB | **4.26 KiB** |

This demonstrates the configurable Flash/RAM trade-off available for embedded
systems.

---

# Examples

The repository contains example integrations for:

- Linux userspace (TAP interface)
- STM32 memory-footprint measurement

The examples are intended as reference implementations and starting points for
porting the stack to other embedded platforms.

---

# Current capabilities

Current development includes:

- MACsec frame encryption/decryption
- MKA over PSK
- 16-byte and 32-byte CAK support
- Automatic key derivation (ICK / KEK)
- Rekey support
- Linux interoperability testing
- Extensive automated test suite

Further work will continue toward improving interoperability, documentation and
embedded platform support.

---

# License

MIT License.