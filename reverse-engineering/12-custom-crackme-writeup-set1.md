# Custom Crackme Write-up Set 1: Ghidra Scripting for Data Extraction

> Source topic: Layer7 reverse-engineering session 7 (Custom2, Custom3 — Ghidra Jython scripting)
> Category: Reverse Engineering — CTF Write-up / Tooling

## Overview

Both challenges in this set are small quadratic/XOR ciphers whose reference data is embedded directly in the binary's data segment as raw bytes. Rather than manually transcribing dozens of hex bytes by hand from the decompiler's display — slow and error-prone — this write-up solves them using Ghidra's built-in scripting console (Jython, Python 2-based in this Ghidra version) to programmatically read memory and compute the inversion in one step.

## `Custom2` — quadratic difference cipher

### Transform Analysis

```c
// Reconstructed:
// while (true):
//     flag[lVar5] = cVar4 - lVar5*lVar5
//     cVar4 = enc2.0[lVar5 + 1]     (next reference byte becomes the new base)
//     lVar5 += 1
```

### Ghidra Script (data extraction + inversion in one pass)

```python
# -*- coding: utf-8 -*-
#@category _NEW_
#@runtime Jython

program = getCurrentProgram()
memory = program.getMemory()

address = toAddr(0x00102040)
buffer_size = 65
byte_array = getBytes(address, buffer_size)

unsigned_byte_array = [b & 0xFF for b in byte_array]

cvar4 = 76
var5 = 0
flag = [0] * 65

while True:
    flag[var5] = cvar4 - (var5 * var5) & 0xFF
    var5 += 1
    if var5 == 64:
        break
    cvar4 = int(hex(unsigned_byte_array[var5]), 16)

print "\nflag: ",
for c in flag:
    print chr(c),
```

The key technical point of this approach: `getBytes(address, size)` returns **signed** Java bytes, so any value ≥ 0x80 would otherwise read as negative in subsequent arithmetic — masking with `& 0xFF` immediately after the read is mandatory, mirroring the same C `BYTE`-vs-Python-`int` truncation issue seen throughout this collection's other write-ups, just manifesting here as a signed/unsigned issue instead.

## `Custom3` — indirect function-pointer dispatch with XOR core

### Transform Analysis

`main` allocates a 152-byte `flag` buffer (deliberately oversized to absorb several subsequent local variables as well, so the "real" data spans multiple nominally-separate stack variables) and then dispatches through a computed function-pointer table:

```c
(*(code *)(&PTR_FUN_001040a0)[sVar4 % 11])(&flag);
```

Rather than computing `sVar4 % 11` to determine exactly which function is invoked, inspection shows only **one** function among the eleven candidates actually takes a parameter — every other entry is parameterless, so the real transformation function is identified by elimination rather than by fully resolving the dispatch index.

### Transform

```c
// Reconstructed core loop inside the one parameterized function:
// flag[i] = dat[i % 16] XOR flag[i]
```

### Ghidra Script

```python
program = getCurrentProgram()

address = toAddr(0x00104020)
byte_count = 8 * 14 + 4
raw_bytes = getBytes(address, byte_count)
unsigned_bytes = [b & 0xFF for b in raw_bytes]

dat_address = toAddr(0x00102010)
dat_bytes = getBytes(dat_address, 16)
unsigned_dat = [b & 0xFF for b in dat_bytes]

for i in range(116):
    unsigned_bytes[i] = (unsigned_dat[i % 16] ^ unsigned_bytes[i]) & 0xFF

for b in unsigned_bytes:
    print chr(b),
```

## Why this matters for security analysis

Two reusable skills stand out: (1) **when a disassembly routes through indirect/computed function dispatch** (a jump table, a function-pointer array indexed by a runtime value), resolving the exact branch taken is not always necessary — comparing candidate functions' signatures or side effects can identify the relevant one faster than fully tracing the dispatch index; (2) **automating data extraction directly inside the analysis tool** (via Ghidra's or IDA's scripting console) scales far better than manual transcription once reference data exceeds a handful of bytes, and eliminates transcription errors as a source of "my inversion script doesn't work" bugs.
