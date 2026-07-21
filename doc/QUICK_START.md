# Quick Start Guide

This guide provides the shortest path to building and trying the Lightweight MACsec Stack.

It covers:

* running the automated test suite,
* testing different build configurations,
* creating a MACsec-protected Linux TAP interface,
* measuring the STM32 memory footprint.

For architecture and integration details, see [`README.md`](README.md).

---

# 1. Run the Unit Tests

The unit test application builds the complete stack for the host system and runs the automated test suite.

## Linux

From the repository root:

```bash
cd examples/unit_tests

make clean
make tests -j
./build/macsec_tests
```

## Windows

A GCC-compatible toolchain is required. For example, when using the MinGW compiler installed with Dev-C++:

```bat
set "PATH=%PATH%;C:\Program Files (x86)\Dev-Cpp\MinGW64\bin"
```

Then build and run the tests:

```bat
cd examples\unit_tests

make clean
make tests -j
build\macsec_tests.exe
```

A successful run executes the unit, integration, negative, rekey and cryptographic self-tests.

---

# 2. Build Without Self-Tests or Debug Logging

To build the stack without the built-in self-tests and debug output:

```bash
make clean
make tests -j MACSEC_SELF_TEST=0 MACSEC_DEBUG_LEVEL=0
```

With `MACSEC_SELF_TEST=0`, the test application may contain no executable test cases. This configuration is useful primarily for verifying that a production-oriented library configuration compiles successfully.

---

# 3. Test AES Configurations

The AES implementation supports lookup tables generated at runtime or stored in ROM. Full or reduced lookup-table variants can be selected using compile-time options.

The two relevant macros are:

| Macro                   | Value | Meaning                                     |
| ----------------------- | ----: | ------------------------------------------- |
| `MATH_AES_ROM_TABLES`   |   `0` | Generate lookup tables at runtime           |
| `MATH_AES_ROM_TABLES`   |   `1` | Store lookup tables in Flash/ROM            |
| `MATH_AES_FEWER_TABLES` |   `0` | Use the full lookup-table implementation    |
| `MATH_AES_FEWER_TABLES` |   `1` | Use the reduced lookup-table implementation |

## Runtime, full tables

```bash
make clean
make tests -j \
    MACSEC_DEBUG_LEVEL=0 \
    MATH_AES_ROM_TABLES=0 \
    MATH_AES_FEWER_TABLES=0
```

Verbose build:

```bash
make clean
make tests -j \
    MACSEC_DEBUG_LEVEL=3 \
    MATH_AES_ROM_TABLES=0 \
    MATH_AES_FEWER_TABLES=0
```

## Runtime, reduced tables

```bash
make clean
make tests -j \
    MACSEC_DEBUG_LEVEL=0 \
    MATH_AES_ROM_TABLES=0 \
    MATH_AES_FEWER_TABLES=1
```

Verbose build:

```bash
make clean
make tests -j \
    MACSEC_DEBUG_LEVEL=3 \
    MATH_AES_ROM_TABLES=0 \
    MATH_AES_FEWER_TABLES=1
```

## ROM, full tables

```bash
make clean
make tests -j \
    MACSEC_DEBUG_LEVEL=0 \
    MATH_AES_ROM_TABLES=1 \
    MATH_AES_FEWER_TABLES=0
```

Verbose build:

```bash
make clean
make tests -j \
    MACSEC_DEBUG_LEVEL=3 \
    MATH_AES_ROM_TABLES=1 \
    MATH_AES_FEWER_TABLES=0
```

## ROM, reduced tables

```bash
make clean
make tests -j \
    MACSEC_DEBUG_LEVEL=0 \
    MATH_AES_ROM_TABLES=1 \
    MATH_AES_FEWER_TABLES=1
```

Verbose build:

```bash
make clean
make tests -j \
    MACSEC_DEBUG_LEVEL=3 \
    MATH_AES_ROM_TABLES=1 \
    MATH_AES_FEWER_TABLES=1
```

The reduced ROM configuration is normally the best choice when RAM usage is the primary constraint.

The reduced runtime configuration is normally the best choice when Flash usage is the primary constraint.

---

# 4. Run the Linux TAP Example

The Linux TAP example connects the userspace MACsec stack to a physical Ethernet interface and exposes the unprotected side as a virtual TAP interface.

The application requires administrator privileges because it creates and configures a TAP interface and accesses raw Ethernet frames.

## Build

```bash
cd examples/linux_tap

make clean
make linux_tap -j
```

The debug level can be selected at build time:

```bash
make clean
make linux_tap -j MACSEC_DEBUG_LEVEL=0
```

```bash
make clean
make linux_tap -j MACSEC_DEBUG_LEVEL=1
```

```bash
make clean
make linux_tap -j MACSEC_DEBUG_LEVEL=2
```

```bash
make clean
make linux_tap -j MACSEC_DEBUG_LEVEL=3
```

Debug levels:

| Level | Output                                  |
| ----: | --------------------------------------- |
|   `0` | Logging disabled                        |
|   `1` | Errors only                             |
|   `2` | Protocol events and verbose diagnostics |
|   `3` | Detailed packet-level logging           |

Level `3` produces a large amount of output and should normally be used only for troubleshooting.

---

# 5. Static SAK Example

The fastest way to try MACsec frame protection is Static SAK mode.

Replace `eth0` with the physical Ethernet interface connected to the remote MACsec device:

```bash
sudo ./build/macsec_linux_tap \
    eth0 \
    tap0 \
    STATIC_SAK=00112233445566778899aabbccddeeff
```

This command:

* opens the physical interface `eth0`,
* creates the virtual TAP interface `tap0`,
* uses the supplied 128-bit static SAK,
* enables MACsec frame encryption and decryption,
* does not run MKA key negotiation.

After the application starts, configure an IP address on the TAP interface:

```bash
sudo ip link set tap0 up
sudo ip address add 10.0.0.1/24 dev tap0
```

The remote peer must use:

* the same SAK,
* the corresponding transmit and receive Secure Associations,
* compatible SCI and Association Number settings.

Traffic sent through `tap0` is protected and transmitted through `eth0`.

Received MACsec traffic is authenticated, decrypted and delivered through `tap0`.

---

# 6. MKA PSK Example

To run the complete stack with MKA, start the application without the `STATIC_SAK` argument:

```bash
sudo ./build/macsec_linux_tap eth0 tap0
```

The application reads its MKA configuration from:

```text
linux_tap.conf
```

The configuration includes values such as:

* `mka_cak`,
* `mka_ckn`,
* `mka_priority`.

The local and remote participants must use the same CAK and CKN.

During startup, the MKA participants:

1. exchange MKPDUs,
2. authenticate each other,
3. elect a Key Server,
4. derive the ICK and KEK,
5. generate and distribute a SAK,
6. install the Secure Association,
7. enable protected data traffic.

Once the connection reaches the secured state, traffic sent through `tap0` is protected automatically.

---

# 7. Test a 256-Bit CAK

MKA supports both 128-bit and 256-bit Connectivity Association Keys.

To test a 32-byte CAK, configure `mka_cak` in `linux_tap.conf` as 64 hexadecimal characters.

Example:

```ini
mka_cak=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
```

The remote MKA participant must be configured with the identical CAK and CKN.

For Linux interoperability testing, `wpa_supplicant` can be configured with the same 32-byte CAK.

---

# 8. Rekey Testing

The stack supports replacing an active Secure Association Key while communication is running.

Rekey behavior is covered by the automated rekey tests:

```bash
cd examples/unit_tests

make clean
make tests -j
./build/macsec_tests
```

The test output contains a dedicated MACsec rekey test group.

Possible application-level rekey policies include:

* rekey after a configured time interval,
* rekey after a configured amount of transmitted data,
* rekey before Packet Number exhaustion,
* rekey after a security or administrative event.

The policy deciding when to initiate a rekey is separate from the mechanism that distributes and installs the new SAK.

---

# 9. Measure STM32 Memory Usage

The STM32 measurement example builds multiple library configurations and extracts their Flash and RAM usage.

From the measurement example directory:

```bash
cd examples/mem_usage_stm32
```

Example invocation on Windows:

```bash
python3 measure.py \
    --toolchain "C:/Users/<user>/Sourcery_CodeBench_Lite_for_ARM_EABI/bin/"
```

Generated reports are stored in:

```text
results/
    memory.csv
    memory.md
```

The reports compare:

* optimization levels,
* protocol profiles,
* debug levels,
* self-test support,
* AES lookup-table configurations.

See [`../examples/mem_usage_stm32/README.md`](../examples/mem_usage_stm32/README.md) for a complete explanation of the measurement process.

---

# Common Problems

## `gcc` or `make` Is Not Found

Verify that the compiler and GNU Make directories are present in `PATH`.

On Windows, the GCC path may be added temporarily using:

```bat
set "PATH=%PATH%;C:\Program Files (x86)\Dev-Cpp\MinGW64\bin"
```

## TAP Interface Cannot Be Created

Run the Linux TAP example with `sudo`:

```bash
sudo ./build/macsec_linux_tap eth0 tap0
```

Also verify that the kernel supports TAP interfaces:

```bash
ls -l /dev/net/tun
```

## Physical Interface Is Already in Use

The physical interface used by the example should not simultaneously carry ordinary IP traffic managed by NetworkManager or another network service.

The interface may need to be disconnected from NetworkManager before starting the example.

## MKA Does Not Reach the Secured State

Verify that both participants use identical:

* CAK,
* CKN,
* cipher suite settings.

Increase the debug level to inspect the MKA exchange:

```bash
make clean
make linux_tap -j MACSEC_DEBUG_LEVEL=2
```

Use debug level `3` only when packet-level diagnostics are required.

---

# Next Steps

After completing this guide, continue with the full documentation:

* [`README.md`](README.md) — architecture and protocol overview
* [`../README.md`](../README.md) — project overview
* [`../examples/mem_usage_stm32/README.md`](../examples/mem_usage_stm32/README.md) — memory measurement guide
