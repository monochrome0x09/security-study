# Computer Architecture Fundamentals for Security Analysis

> Source topic: Layer7 reverse-engineering session 1 — computer architecture
> Category: Reverse Engineering — Foundations

## Concept

Computer architecture studies how a program is actually carried out at the machine level, and how hardware and software components interact during execution. For reverse engineering and binary exploitation specifically, this is foundational: both disciplines operate at the register/memory level, and finding a vulnerability or recovering program logic from a disassembly requires an accurate mental model of what the CPU and memory subsystem are actually doing underneath the source-level abstraction.

## Why it matters for security analysis

Every technique covered elsewhere in this portfolio — stack layout analysis, canary mechanics, ROP gadget chaining, calling-convention-aware argument recovery — depends on this baseline. Without it, a disassembly is just unfamiliar syntax; with it, the same disassembly is a precise, debuggable model of program state.

## Key technical details

### Instruction Set Architecture (ISA)

An ISA is the contract that defines which instructions, registers, and addressing modes a given CPU family understands. Different hardware families (ARM, x86, x86-64) implement different ISAs, which is why the same source code compiles to entirely different byte sequences depending on target.

ISAs fall into two broad design philosophies:

- **CISC (Complex Instruction Set Computer)** — used in general-purpose/high-performance hardware. A single instruction can perform multiple sub-operations, at the cost of higher power draw and heat. x86 and x86-64 are CISC.
- **RISC (Reduced Instruction Set Computer)** — used in mobile/embedded hardware. Instructions are simple and each performs exactly one operation, trading lower power consumption for needing more instructions to express complex operations. ARM is the canonical example.

### Memory hierarchy

**Primary storage** is what the CPU directly operates on:
- **RAM** (Random Access Memory) — volatile, fast, holds the OS and running applications while powered.
- **ROM** (Read Only Memory) — non-volatile, read-only, retains data without power.

**Secondary storage** is slower but persists without power:
- **HDD** — physical magnetic disk; mechanically fragile and audible.
- **SSD** — electrically addressed, no moving parts; faster and silent.

**Virtual memory** lets the OS back part of a process's address space with disk space, allowing programs to keep running even when physical RAM is exhausted.

### CPU internals

The CPU is the component that fetches, decodes, and executes instructions. Its major sub-units:

- **Registers** — tiny, extremely fast storage built directly into the CPU, used because even the fastest RAM/SSD cannot keep up with CPU-internal operation speed.
- **ALU (Arithmetic Logic Unit)** — performs arithmetic and logical operations.
- **CU (Control Unit)** — issues control signals that sequence the other components correctly.
- **Internal bus** — the pathway instructions, data, and signals travel along.

**General-purpose registers** (illustrated via the x86 32-bit naming convention, where sub-registers are addressable at multiple widths — e.g. `RAX`/`EAX`/`AX`/`AH`/`AL` for 64/32/16/high-8/low-8 bits respectively):

| Register | Name | Conventional role |
|---|---|---|
| RAX/EAX | Accumulator | Arithmetic/logic results; holds a function's return value |
| RBX/EBX | Base | General-purpose; often a memory-address base |
| RCX/ECX | Count | Loop counters; decremented each iteration until zero |
| RDX/EDX | Data | Auxiliary arithmetic/data storage |
| RSI/ESI | Source Index | Source address in data-movement operations |
| RDI/EDI | Destination Index | Destination address in data-movement operations |
| RSP/ESP | Stack Pointer | Address of the top of the stack |
| RBP/EBP | Base Pointer | Anchors a function's stack frame for local-variable/argument access |
| RIP/EIP | Instruction Pointer | Address of the next instruction to execute |

These roles are conventions enforced by compilers and calling conventions, not hardware restrictions — any general-purpose register can technically be repurposed, which is exactly why reverse engineers must verify actual usage in a given binary rather than assuming textbook roles always hold.

**Flags register** — holds condition outcomes from the most recent arithmetic/logic operation:

- **ZF (Zero Flag)** — set when a result is zero.
- **SF (Sign Flag)** — reflects the result's sign bit.
- **CF (Carry Flag)** — set on unsigned carry/borrow.
- **OF (Overflow Flag)** — set on signed overflow.
- **IF (Interrupt Flag)** — whether interrupts are currently enabled.
- **Supervisor Flag** — distinguishes kernel mode from user mode.

Conditional branches (`je`, `jg`, `jl`, `jne`, ...) consume these flags, which is why recovering the preceding `cmp`/`test` instruction is always the first step in reconstructing a high-level conditional from disassembly.

### Byte ordering (endianness)

- **Big-endian**: most-significant byte stored first (matches how humans write numbers).
- **Little-endian**: least-significant byte stored first — the convention used by x86/x86-64, and the reason raw hex literals in shellcode/ROP payloads must often be byte-reversed by hand when manually constructing them.

Only byte order changes between the two — bit order within each byte is unaffected.

### Encoding vs. encryption

Both transform data, but for different purposes. **Encoding** (ASCII, UTF-8, Base64, URL-encoding) converts data into another representation for compatibility, compression, or safe transmission, and is always reversible by anyone without a secret. **Encryption** uses a key to make data unintelligible to anyone without that key; without it, recovering the plaintext is computationally infeasible. Confusing the two is a common and serious misstep — e.g. mistaking Base64 for a security control.

### Operating systems and the kernel

The **kernel** is the core OS layer that mediates between hardware and software, responsible for process management, memory management, device management, filesystem access, and exposing system calls as the user-mode-to-kernel-mode gateway. The **shell** (bash, zsh, sh) is the user-facing program that translates typed commands into kernel requests, since the kernel itself provides no direct interactive interface.

## Practical reference

Recognizing CISC-vs-RISC, register conventions, flag semantics, and little-endian byte layout is assumed baseline knowledge throughout every disassembly-driven write-up in the rest of this collection — particularly the GDB, IDA, and CTF reverse-engineering write-ups that follow.
