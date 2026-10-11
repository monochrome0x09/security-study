# CTFd Practice Write-up Set 1: PicoCTF Warm-ups and Custom Ciphers

> Source topic: Layer7 reverse-engineering session 5 CTFd write-ups (PicoCTF file-run1/2, Merong, Custom1, Custom2)
> Category: Reverse Engineering — CTF Write-up

## Overview

A mixed set of challenges ranging from trivial (flag stored in plain sight) to moderate custom bit-rotation ciphers, demonstrating the full spectrum of effort a reversing challenge can require — and the importance of checking the easy cases (string search, direct data-segment inspection) before reaching for heavier analysis.

## PicoCTF `file-run1` / `file-run2` — flags stored without obfuscation

Both challenges decompile to trivial logic with the flag either directly visible in a buffer inspected via the decompiled `main`, or placed verbatim in the data segment with no encoding applied at all. The practical lesson: **always check the data segment / string listing before writing any transformation-inversion logic** — a meaningful fraction of CTF reversing challenges (especially introductory ones) require no cryptanalysis whatsoever.

## `Merong` — direct string comparison, flag format easily missed

The target compares user input against a hardcoded string (`aEae41779bdf799`) and, on match, echoes the input back — meaning the matching string literal *is* the flag. The only real pitfall here was procedural rather than technical: recognizing that the platform's required flag wrapper (`FLAG{...}`) still needed to be applied around the recovered string before submission — a reminder that CTF platforms often impose a submission format independent of whatever the binary itself outputs.

## `Custom1` — byte-indexed XOR with a shifting key

### Vulnerability / Transform Analysis

The validation routine XORs each input byte against a rotating high-byte value derived from a loop counter, iterating 33 times:

```c
// Reconstructed: cipher[i] = HIBYTE(v5) ^ input[i], with HIBYTE(v5) fixed at 0x42 ('B')
```

### Exploitation (inversion)

```python
v10 = [  # data-segment bytes, reconstructed in little-endian order
    0x0E, 0x23, 0x3B, 0x27, 0x30, 0x75, 0x39, 0x31,
    0x36, 0x23, 0x30, 0x27, 0x1D, 0x2E, 0x2B, 0x29,
    0x27, 0x1D, 0x35, 0x23, 0x36, 0x21, 0x2A, 0x2B,
    0x2C, 0x25, 0x1D, 0x31, 0x36, 0x23, 0x30, 0x31
]
hibyte_v5 = 66   # 0x42
for b in v10:
    print(chr(hibyte_v5 ^ b), end="")
```

The key pitfall encountered: when reading an 8-byte literal straight out of the decompiler's hex-constant view, the bytes are presented in the CPU's native little-endian storage order — reconstructing the "obvious" byte order (as written left-to-right in the hex literal) instead of accounting for the reversal cost significant debugging time before the correct byte ordering was identified.

## `Custom2` — rotate-then-add cipher

### Vulnerability / Transform Analysis

```c
// Reconstructed: cipher[i] = rol(input[i], (i % 8) + 1) + 5
```

where `rol(a1, a2)` is a standard 8-bit left-rotate: `(a1 << a2) | (a1 >> (8 - a2))`.

### Exploitation (inversion)

```python
def reversed_rol(a1, a2):
    return ((a1 >> a2) | (a1 << (8 - a2))) & 0xFF

v3 = [0x9D, 0x8A, 0xD0, 0x5B, ...]   # 56 bytes, reconstructed little-endian

for i, byte in enumerate(v3):
    temp = (byte - 5) & 0xFF
    original = reversed_rol(temp, (i % 8) + 1)
    print(chr(original), end="")
```

Deriving the inverse requires two careful steps: first subtract the constant additive term (`5`) *before* attempting to undo the rotation, since the operations were applied in a specific order (`rol` then `+5`) and must be undone in exactly the reverse order (`-5` then un-rotate); second, mask every intermediate result with `& 0xFF`, since neither the subtraction nor the rotate naturally stays within an 8-bit range in Python's arbitrary-precision integers the way the original C `BYTE`-typed computation implicitly did.

## Why this matters for security analysis

This set reinforces two complementary lessons: (1) always rule out the trivial case first (plaintext storage, simple string comparison) before investing in cryptanalysis, and (2) when a transform genuinely is a composition of multiple operations (rotate + add, as in `Custom2`), the inverse must undo each stage in **exactly the reverse order** of the forward transform, with careful attention to bit-width truncation at every intermediate step — a mismatch at either point silently produces plausible-looking but incorrect output rather than an obvious error.
