# rev-basic Series CTF Write-up: Reversing Custom Encoding Schemes

> Source topic: Layer7 "rev-basic-0" through "rev-basic-6" write-ups
> Category: Reverse Engineering — CTF Write-up

## Overview

The `rev-basic` series is a structured progression of crackme-style challenges, each gating a flag behind a different transformation applied to user input and compared against a hardcoded reference. Solving each one follows the same methodology: decompile, identify the comparison function, extract the hardcoded reference data, algebraically invert the transformation, and recover the input. This write-up documents that methodology across the series.

## Methodology (applied throughout)

1. Decompile `main` and locate the call to the custom validation routine; confirm the program treats a non-zero/true return as success.
2. Decompile the validation routine itself and identify the exact per-character or per-byte transformation applied to user input before comparison.
3. Dump the hardcoded comparison array/string from the data segment.
4. Algebraically invert the transformation (self-inverse operations like XOR are trivial; others, like bit-rotation or modular arithmetic, require deriving and implementing the explicit inverse).
5. Reconstruct the required input in a short Python script and submit it.

## Challenge-by-Challenge Notes

### rev-basic-0 (Windows PE target)

Demonstrates reading an unnamed/auto-generated function (`sub_140001190`-style naming, characteristic of PE binaries without symbol information, unlike the ELF case where original names often survive) and tracing argument usage to infer that a given subroutine is really `scanf`, purely from its calling pattern and position in the control flow — illustrating that function identity can often be inferred from *usage context* even without symbol names.

### rev-basic-1 — direct character-by-character comparison

The validation function walks the input one byte at a time, comparing each against a fixed ASCII value (`0x43`, `'C'`, for the first character, then incrementing through a hardcoded sequence). Reconstructing each comparison in order directly spells out the flag: `"Compar3_the_ch4ract3r"`.

### rev-basic-2 — array-vs-array comparison

The reference data is a 4-byte-strided array in the data segment (`aC`), compared element-by-element against the input (`*aC[4*i]` vs. `*(a1+i)`). Reading the referenced array directly from the data segment yields the flag with no arithmetic inversion needed at all: `"Comp4re_the_arr4y"`.

### rev-basic-3 — additive + XOR + index-dependent cipher

```c
// forward transform (reconstructed from disassembly):
// cipher[i] = (i ^ input[i]) + 2*i
```

```python
converted_lst = [73, 96, 103, 116, 99, 103, 66, 102, 128, 120, 105, 105,
                  123, 153, 109, 136, 104, 148, 159, 141, 77, 165, 157, 69]
i = 0
for item in converted_lst:
    a1 = (item - (2 * i)) ^ i
    print(chr(a1), end="")
    i += 1
```

The inversion simply undoes the two operations in reverse order: subtract the index-dependent additive term, then XOR with the index again (self-inverse).

### rev-basic-4 — bit-rotation (ROL) cipher

```c
// forward transform: cipher[i] = (input[i] << 4) | (input[i] >> 4)   [an 8-bit rotate by 4]
```

```python
converted_lst = [36, 39, 19, 198, 198, 19, 22, 230, ...]
for item in converted_lst:
    a1 = ((item << 4) | (item >> 4)) & 0xFF
    print(chr(a1), end="")
```

A rotate-by-4 on an 8-bit value is its own inverse (rotating by half the bit width twice returns to the original), so the same operation, re-applied, recovers the plaintext. The `& 0xFF` mask is essential in Python, since Python integers don't natively truncate to 8 bits the way a `BYTE`-typed C variable does — omitting it silently produces incorrect, oversized values.

### rev-basic-5 — chained-difference cipher with brute-forced seed

```c
// forward transform: cipher[i] = input[i] + input[i+1]
```

Because each ciphertext byte depends on *two* adjacent plaintext bytes, the first plaintext byte (`a[0]`) cannot be derived directly — it must be **brute-forced** across all 255 possible byte values, computing the full resulting string for each guess and visually identifying which one produces a meaningful ASCII string:

```python
def calculate(seed):
    a1 = [0] * 24
    a1[0] = seed
    for i in range(len(a1) - 1):
        a1[i + 1] = by140[i] - a1[i]
    return a1

for seed in range(255):
    a1 = calculate(seed)
    try:
        print(f"{seed}. " + "".join(chr(c) for c in a1))
    except Exception:
        pass
```

This is a useful general technique: when an inversion is under-determined (depends on an unknown seed/initial value with a small search space), brute-force the seed and filter for printable/meaningful output rather than trying to solve the system analytically.

### rev-basic-6 — substitution-box (S-box) lookup, inverted by search

```c
// forward transform: cipher[input[i]] == reference[i]  (i.e. input[i] is used as an INDEX into an S-box)
```

Here the "input" is not transformed directly — it is used as an *index* into a substitution table, and the resulting values are what's compared against the reference. Inverting therefore means: for each reference byte, scan the S-box for the matching value and report its *index* as the recovered plaintext byte.

```python
for item in reference_values:
    for index in range(len(sbox)):
        if sbox[index] == item:
            print(chr(index), end="")
            break
```

## Why this matters for security analysis

This series demonstrates that the overwhelming majority of "custom crypto" found in CTF-style crackmes and, by extension, in real-world malware/DRM obfuscation, falls into a small number of reversible categories: direct comparison, positional XOR/additive ciphers, bit rotation, chained/dependent transforms requiring a brute-forced seed, and substitution tables. Recognizing which category a given transform belongs to is usually sufficient to write an inversion script in minutes, without needing to understand *why* the original author chose that particular scheme.

## Defensive remediation note

None of these schemes constitute cryptographically sound protection — XOR, rotation, and small S-boxes with no keying material are all trivially reversible given only the algorithm and the ciphertext (Kerckhoffs's-principle violation: security here depends entirely on the algorithm staying secret, which a reverse engineer defeats by definition). Any real license-check or anti-tamper mechanism should rely on actual cryptographic primitives (HMAC, AEAD ciphers with a securely-provisioned key) rather than ad-hoc bit manipulation, and should assume the attacker has full access to the binary.
