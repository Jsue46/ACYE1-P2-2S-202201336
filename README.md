# Pure AArch64 Assembly AES-128 Cryptographic Engine

Academic project developed for the **Computer Architecture and Assemblers 1** course at the Universidad de San Carlos de Guatemala (Second Semester 2025).

This repository contains a full implementation of the **AES-128 (Advanced Encryption Standard)** symmetric cipher written entirely in 64-bit ARM assembly language (AArch64), operating without the C standard library (`libc`) and performing all I/O through raw Linux kernel system calls.

---

## Overview

The engine executes the standard 10-round AES-128 transformation pipeline from scratch. Key expansion, SubBytes (using a software S-Box), ShiftRows, MixColumns (Galois field arithmetic), and AddRoundKey are explicitly coded in assembly instructions. Memory state matrices are tracked in column-major order, and execution times are measured with microsecond precision using the `clock_gettime` syscall.

---

## Technical Specifications

- **Architecture:** ARM64 (AArch64 / ARMv8-A)
- **Zero External Dependencies:** Built without `libc`; all terminal I/O is handled via raw Linux system calls (`sys_read`, `sys_write`, `sys_clock_gettime`).
- **State Representation:** 4x4 byte matrix held in memory and processed in column-major order.
- **Key Expansion:** Automated Key Schedule computing 11 round keys (176 bytes) dynamically using the Rcon table and S-Box substitution.
- **Round Trace Output:** Optional stage-by-stage matrix dumping (SubBytes, ShiftRows, MixColumns, AddRoundKey) across all 10 rounds for didactic verification against NIST Known Answer Tests (KAT).
- **Execution Timing:** Benchmarked using `clock_gettime` (syscall 113) reporting execution latency in milliseconds with 3 decimal places.

---

## Build and Execution Guide

### Prerequisites
- GNU Assembler and Linker for AArch64 (`aarch64-linux-gnu-as`, `aarch64-linux-gnu-ld`)
- QEMU User Space Emulator (`qemu-aarch64`) or physical ARM64 hardware
- GNU Make

### Building the Binary

```bash
# Assemble and link without standard libraries
make
```

### Running under QEMU

```bash
make run
# Or directly:
qemu-aarch64 ./aes
```

---

## NIST Vector Verification

The engine is verified against the official NIST AES-128 test vector:

```text
Key: 000102030405060708090A0B0C0D0E0F
PT : 00112233445566778899AABBCCDDEEFF
CT : 69C4E0D86A7B0430D8CDB78070B4C55A
```

---

## Repository Structure

```
ACYE1-P2-2S-202201336/
├── aes_main.s       # Main assembly source (menu, cipher engine, I/O syscalls)
├── constants.s      # Substitution Box (S-Box) and Rcon constants
├── Makefile         # Build and execution targets
├── docs/            # Technical reports and test logs
└── README.md
```

---

## Academic Context

| Field       | Detail                                                 |
|-------------|--------------------------------------------------------|
| Course      | Computer Architecture and Assemblers 1 (ACYE1)         |
| Institution | Universidad de San Carlos de Guatemala                 |
| Semester    | Second Semester 2025                                   |
| Author      | Estuardo Josue Vaquiax Reyes (202201336)               |
