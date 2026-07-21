# Lightweight MACsec Stack

<p align="center">
    <img src="doc/images/architecture.svg"
         alt="Lightweight MACsec Stack Architecture"
         width="900">
</p>

A lightweight, portable implementation of **IEEE 802.1AE (MACsec)** and **IEEE 802.1X MACsec Key Agreement (MKA)** written in C for embedded systems.

The project focuses on portability, readability and low resource usage while remaining independent of any operating system or networking stack. It is intended for embedded development, experimentation, education and as a reference implementation for integrating MACsec into resource-constrained devices.

> **Detailed architecture, integration guidance and protocol walkthrough are available in [`doc/README.md`](doc/README.md).**

---

# Status

> **Experimental / Proof of Concept**

The implementation is under active development.

Although the library includes an extensive automated test suite and has been validated against the Linux MACsec implementation using `wpa_supplicant`, it has **not** undergone an independent security audit and should **not** be used in production or safety/security-critical systems without additional review and validation.

---

# Highlights

* IEEE 802.1AE MACsec implementation
* IEEE 802.1X MKA in PSK mode
* Portable ANSI C implementation
* No operating system required
* Small platform adaptation layer
* Small Flash and RAM footprint
* Embedded-oriented design
* Linux interoperability testing
* Comprehensive automated test suite
* MIT licensed

---

# Features

## MACsec

* IEEE 802.1AE frame protection
* AES-GCM authenticated encryption
* SecTAG generation and parsing
* Integrity Check Value (ICV) generation and verification
* Secure Channel Identifier (SCI) support
* Packet Number (PN) management
* Replay protection
* Static Secure Association Keys (SAK)
* 128-bit and 256-bit SAK support
* MACsec frame encryption and decryption

## MKA

* IEEE 802.1X MACsec Key Agreement
* Pre-Shared Key (PSK) mode
* Connectivity Association Key (CAK)

  * 128-bit (16-byte)
  * 256-bit (32-byte)
* Connectivity Association Key Name (CKN) up to 32 bytes
* ICK and KEK derivation
* Distributed SAK generation and installation
* Key Server election
* Automatic rekey support
* MKPDU encoding and decoding
* AES-CMAC MIC generation and verification

## Cryptography

* Embedded AES implementation
* AES-GCM
* AES-CMAC
* Runtime or ROM lookup tables
* Configurable Flash/RAM trade-offs

## Testing and interoperability

* Unit tests
* Integration tests
* Negative tests
* Rekey tests
* Cryptographic self-tests
* Linux interoperability testing with `wpa_supplicant`

---

# Design Goals

* Small Flash footprint
* Small RAM footprint
* Portable ANSI C implementation
* Deterministic behavior
* No operating system dependency
* Easy integration into existing Ethernet drivers
* Readable source code suitable for learning
* Clear separation between protocol logic and platform-specific code

---

# Requirements

* C compiler
* Standard C library
* `<stdint.h>`
* `<stddef.h>`

No operating system is required.

The library is self-contained and does not depend on:

* FreeRTOS
* lwIP
* Linux
* POSIX
* any particular Ethernet controller

Only a small platform adaptation layer must be provided for the target system.

---

# Memory Footprint

The repository contains a dedicated STM32 memory-footprint measurement project located in:

```text
examples/mem_usage_stm32
```

Measurements are performed automatically using:

* STM32F411
* Cortex-M4
* Thumb instruction set
* `arm-none-eabi-gcc`

Several build configurations can be evaluated, including:

* compiler optimization (`-O0`, `-O2`, `-Os`)
* debug levels
* self-test support
* AES lookup-table implementations

Typical production configuration:

* `PROFILE=full`
* `SELF_TEST=0`
* `DEBUG_LEVEL=0`
* `-Os`

| AES implementation       |         FLASH |          RAM |
| ------------------------ | ------------: | -----------: |
| Runtime tables (reduced) | **14.71 KiB** |     8.39 KiB |
| ROM tables (reduced)     |     16.84 KiB | **4.35 KiB** |

This demonstrates the configurable Flash/RAM trade-off available for different embedded targets.

---

# Testing

The project includes an automated test suite covering:

* protocol and utility functions
* MACsec encryption and decryption
* MKA cryptographic operations
* frame encoding and decoding
* invalid and unauthenticated frames
* Secure Association rekeying
* complete MACsec communication flows
* AES, GCM and CMAC self-tests

The stack has also been tested for interoperability with the Linux MACsec implementation and `wpa_supplicant`.

---

# Examples

The repository contains example integrations for:

* Linux userspace using a TAP interface
* STM32 memory-footprint measurement
* platform adaptation implementations

The examples are intended as reference implementations and starting points for porting the stack to other embedded platforms.

---

# Documentation

Detailed documentation is available in [`doc/README.md`](doc/README.md), including:

* learning path
* architecture overview
* packet journey
* library integration
* MACsec lifecycle
* transmit and receive paths
* MKA control flow
* configuration overview
* porting guide
* current limitations

---

# License

This project is released under the **MIT License**.

See the [`LICENSE`](LICENSE) file for the complete license text.
