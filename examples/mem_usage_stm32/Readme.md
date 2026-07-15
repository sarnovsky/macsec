\# STM32 Memory Footprint Measurement



This example measures the Flash and RAM footprint of the lightweight MACsec stack

for a number of different build configurations.



The goal is not to benchmark performance, but to compare the impact of:



\- compiler optimization level,

\- enabled protocol components,

\- debug logging,

\- self-tests,

\- AES lookup-table implementation.



The project automatically builds multiple firmware variants, extracts their

memory usage from the generated ELF files and stores the results as CSV and

Markdown reports.



\---



\# Running



Example:



```bash

python3 measure.py --toolchain "C:/Users/<user>/Sourcery\_CodeBench\_Lite\_for\_ARM\_EABI/bin/"

```



Generated reports:



```

results/

&#x20;   memory.csv

&#x20;   memory.md

```



\---



\# Configuration groups



The measurements are divided into two groups.



\## Profiles



The \*\*profiles\*\* group compares complete firmware configurations.



| Profile | Description |

|---------|-------------|

| minimal | Frame encryption/decryption only (AES-GCM) |

| full | Complete MACsec stack including MKA |

| full\_debug | Complete stack with maximum debug logging |

| full\_selftest | Complete stack including all built-in self-tests |



Each profile is measured for:



\- `-O0`

\- `-O2`

\- `-Os`



using the default embedded AES configuration (`rom\_fewer`).



\---



\## Production



The \*\*production\*\* group measures practical deployment configurations.



The complete MACsec stack is always enabled while varying only:



\- compiler optimization (`-O0`, `-O2`, `-Os`)

\- debug level (`0...3`)

\- AES lookup-table implementation



Self-tests are disabled because they are not included in production firmware.



\---



\# AES lookup-table modes



Four AES implementations are available.



| Mode | Flash | RAM | Description |

|------|------:|----:|-------------|

| runtime\_full | lowest | highest | Tables generated at runtime |

| runtime\_fewer | \*\*lowest practical Flash\*\* | medium | Reduced runtime tables |

| rom\_full | highest | lowest | Full lookup tables stored in Flash |

| rom\_fewer | good compromise | \*\*lowest RAM\*\* | Reduced ROM lookup tables |



\---



\# Typical production configurations



For a production build (`PROFILE=full`, `SELF\_TEST=0`, `DEBUG\_LEVEL=0`,

`-Os`) the measured memory usage is approximately:



| AES mode | Flash | RAM |

|----------|------:|----:|

| runtime\_fewer | \*\*13.85 KiB\*\* | 8.80 KiB |

| rom\_fewer | 15.93 KiB | \*\*4.26 KiB\*\* |



This demonstrates the main trade-off:



\- \*\*runtime\_fewer\*\* minimizes Flash usage by generating AES lookup tables at startup.

\- \*\*rom\_fewer\*\* minimizes RAM usage by storing the lookup tables in Flash.



The remaining modes (`runtime\_full` and `rom\_full`) are included mainly for

comparison and performance evaluation.



\---



\# Optimization levels



Measurements are generated for three compiler optimization levels.



| Option | Description |

|---------|-------------|

| `-O0` | No optimization (debugging) |

| `-O2` | Performance optimization |

| `-Os` | Size optimization |



For embedded production firmware, `-Os` is generally the recommended choice.



\---



\# Debug levels



The production matrix also measures the effect of debug logging.



| Level | Description |

|------:|-------------|

| 0 | Debug disabled |

| 1 | Errors only |

| 2 | Protocol events |

| 3 | Detailed packet-level logging |



Increasing the debug level primarily increases Flash usage due to additional

format strings and logging code.



\---



\# Output



The generated reports provide:



\- Flash usage

\- RAM usage

\- build status

\- complete build configuration



making it easy to compare memory consumption across different compiler and

library configurations.

