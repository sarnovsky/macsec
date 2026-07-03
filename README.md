# Lightweight MACsec Stack



Lightweight experimental MACsec-related stack written in C for embedded systems.



The project contains helper code for MACsec frame encryption/decryption and related

test code. It is intended mainly for learning, prototyping and embedded experiments.



## Status



Experimental / proof of concept.



This project has not been security audited and should not be used in production

or safety/security-critical systems without independent review.



## Features



- MACsec frame encryption/decryption helpers

- AES-GCM based frame protection using mbedTLS

- SecTAG / ICV handling

- Basic unit-test support

- Embedded-oriented C code



## Requirements



- C compiler

- mbedTLS

- Standard integer types from `<stdint.h>`

- Project-specific platform glue for logging / memory / integration



## Directory structure

```text

include/macsec/    Public headers

src/               Source files

tests/             Tests and self-tests

examples/          Example integration code

```

## Memory footprint

Measured on STM32F411 using arm-none-eabi-gcc, Cortex-M4, Thumb mode.

| Configuration | Optimization | Debug prints | mbedTLS self-tests | FLASH | Static RAM | MACsec context | MACsec heap |
|---|---:|---:|---:|---:|---:|---:|---:|
| Minimal frame crypto only | -Os | off | off | TBD | TBD | sizeof(macsec_ctx_t) | MACSEC_HEAP_SIZE |
| Full MACsec + MKA | -Os | off | off | TBD | TBD | sizeof(macsec_ctx_t) | MACSEC_HEAP_SIZE |
| Full MACsec + MKA + debug | -Og | on | off | TBD | TBD | sizeof(macsec_ctx_t) | MACSEC_HEAP_SIZE |
| Full tests | -Og | on | on | TBD | TBD | sizeof(macsec_ctx_t) | MACSEC_HEAP_SIZE |
