# STM32 Memory Footprint Measurement

This example measures the Flash and RAM footprint of the Lightweight MACsec Stack across multiple build configurations.

The purpose is not to benchmark execution performance, but to compare the memory impact of:

* compiler optimization level,
* enabled protocol components,
* debug logging,
* built-in self-tests,
* AES lookup-table implementation.

The measurement script automatically builds multiple firmware variants, extracts memory usage from the generated ELF files and stores the results in CSV and Markdown reports.

---

# Requirements

The measurement project requires:

* Python 3,
* GNU Arm Embedded Toolchain,
* `arm-none-eabi-gcc`,
* `arm-none-eabi-size`,
* GNU Make.

The current project configuration targets:

* STM32F411,
* Arm Cortex-M4,
* Thumb instruction set.

---

# Running the Measurement

Run the measurement script from the example directory.

Example on Windows:

```bash
python3 measure.py \
    --toolchain "C:/Users/<user>/Sourcery_CodeBench_Lite_for_ARM_EABI/bin/"
```

The toolchain path must contain the required Arm compiler and binary utilities.

After all configurations have been processed, the generated reports are stored in:

```text
results/
    memory.csv
    memory.md
```

The existing report files are replaced whenever the measurement script is run again.

---

# Configuration Groups

The measurements are divided into two groups:

1. **Profiles**
2. **Production configurations**

The profile group compares major library configurations, while the production group provides a more detailed comparison of settings relevant to deployed firmware.

---

# Profiles

The **profiles** group compares complete firmware configurations.

| Profile         | Description                                          |
| --------------- | ---------------------------------------------------- |
| `minimal`       | MACsec frame encryption and decryption using AES-GCM |
| `full`          | Complete MACsec stack including MKA                  |
| `full_debug`    | Complete stack with maximum debug logging            |
| `full_selftest` | Complete stack including all built-in self-tests     |

Each profile is measured using the following compiler optimization levels:

* `-O0`
* `-O2`
* `-Os`

The profile measurements use the default embedded AES configuration:

```text
rom_fewer
```

This group provides a high-level overview of the memory required by individual library capabilities.

---

# Production Configurations

The **production** group measures configurations representative of practical firmware deployments.

The complete MACsec and MKA stack is enabled while varying:

* compiler optimization level,
* debug level,
* AES lookup-table implementation.

The following optimization levels are measured:

* `-O0`
* `-O2`
* `-Os`

The following debug levels are measured:

* `0`
* `1`
* `2`
* `3`

Built-in self-tests are disabled in this group because they would normally be excluded from production firmware.

---

# AES Lookup-Table Modes

Four AES lookup-table configurations are available.

| Mode            |          Flash usage |  RAM usage | Description                                                  |
| --------------- | -------------------: | ---------: | ------------------------------------------------------------ |
| `runtime_full`  |                  Low |    Highest | Full lookup tables generated in RAM during initialization    |
| `runtime_fewer` | **Lowest practical** |     Medium | Reduced lookup tables generated in RAM during initialization |
| `rom_full`      |              Highest |        Low | Full lookup tables stored in Flash                           |
| `rom_fewer`     |               Medium | **Lowest** | Reduced lookup tables stored in Flash                        |

The runtime configurations generate lookup tables during startup. This reduces Flash consumption but requires writable RAM for the generated tables.

The ROM configurations store constant lookup tables in Flash. This increases Flash consumption but substantially reduces RAM usage.

---

# Typical Production Results

For a production-oriented build using:

```text
PROFILE=full
SELF_TEST=0
DEBUG_LEVEL=0
OPTIMIZATION=-Os
```

the measured memory usage is approximately:

| AES implementation |         Flash |          RAM |
| ------------------ | ------------: | -----------: |
| `runtime_fewer`    | **14.71 KiB** |     8.39 KiB |
| `rom_fewer`        |     16.84 KiB | **4.35 KiB** |

These configurations demonstrate the primary Flash/RAM trade-off:

* **`runtime_fewer`** minimizes Flash usage by generating reduced AES lookup tables during initialization.
* **`rom_fewer`** minimizes RAM usage by storing the reduced lookup tables in Flash.

The remaining modes, `runtime_full` and `rom_full`, are included primarily for comparison and evaluation.

Actual values may differ depending on the compiler version, linker version, configuration macros and changes made to the library.

---

# Optimization Levels

Measurements are generated for three compiler optimization levels.

| Option | Description                                                 |
| ------ | ----------------------------------------------------------- |
| `-O0`  | Disables optimization and is primarily useful for debugging |
| `-O2`  | Optimizes primarily for execution performance               |
| `-Os`  | Optimizes primarily for code size                           |

For resource-constrained production firmware, `-Os` will usually provide the smallest Flash footprint.

However, the most suitable optimization level depends on the target platform, timing requirements and compiler version.

---

# Debug Levels

The production matrix also measures the effect of debug logging.

| Level | Description                       |
| ----: | --------------------------------- |
|   `0` | Debug output disabled             |
|   `1` | Error messages                    |
|   `2` | Protocol events                   |
|   `3` | Detailed packet-level diagnostics |

Increasing the debug level primarily increases Flash usage because additional logging code and format strings are included in the firmware image.

Depending on the platform implementation, debug output may also affect execution timing and stack usage.

Production firmware should normally use:

```text
DEBUG_LEVEL=0
```

---

# Self-Tests

Built-in cryptographic and protocol self-tests can be included in the firmware when required.

The `full_selftest` profile measures the additional memory needed for:

* AES self-tests,
* AES-GCM self-tests,
* AES-CMAC self-tests,
* MACsec protocol self-tests,
* MKA cryptographic self-tests.

Self-tests are useful during development, validation and platform bring-up, but are normally disabled in production firmware to reduce Flash usage.

---

# Generated Reports

The measurement script generates two report formats.

## CSV Report

```text
results/memory.csv
```

The CSV file is suitable for:

* automated processing,
* spreadsheet analysis,
* regression tracking,
* plotting memory usage over time.

## Markdown Report

```text
results/memory.md
```

The Markdown report provides a human-readable summary that can be viewed directly on GitHub.

Each report contains:

* configuration group,
* profile,
* optimization level,
* debug level,
* self-test setting,
* AES implementation,
* Flash usage,
* RAM usage,
* build status.

---

# Memory Accounting

Flash usage is calculated from sections stored in the firmware image, primarily:

* `.text`
* `.rodata`
* initialized data stored in Flash.

RAM usage includes statically allocated runtime sections, primarily:

* `.data`
* `.bss`.

The reported RAM value does not necessarily represent the maximum runtime memory consumption of the complete application. Depending on the target integration, additional memory may be required for:

* task stacks,
* interrupt stacks,
* Ethernet frame buffers,
* driver buffers,
* dynamically allocated memory,
* application-specific data.

The measurements are therefore intended primarily for comparing library configurations under identical build conditions.

---

# Purpose

This example makes it possible to evaluate the cost of individual MACsec features and select an appropriate configuration for a specific embedded target.

In particular, it helps determine:

* whether Flash or RAM should be prioritized,
* which AES implementation is most suitable,
* how much memory debug logging consumes,
* how much memory is added by MKA,
* how much memory is added by built-in self-tests,
* which compiler optimization level provides the best result.
