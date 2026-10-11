# CTFd Practice Write-up Set 2: Positional Ciphers and Brute-Forced S-box Recovery

> Source topic: Layer7 reverse-engineering session 6 CTFd write-ups (Custom1, Custom2, Custom3)
> Category: Reverse Engineering — CTF Write-up

## Overview

A second set of custom-cipher crackmes, increasing in structural complexity: a positional additive/XOR cipher with an evolving key across iterations, a rotate-then-XOR cipher with a positional key component, and a permutation/substitution-table cipher solved via brute-force rather than direct algebraic inversion.

## `Custom1` — chained, position-dependent additive/XOR cipher

### Transform Analysis

```c
// Reconstructed per-iteration relationship (v2 = index/counter, v1 += 93 each step):
// a1[v2] = v3 + (v1 ^ 0xA6) + 4*v2    (mod 256), where v3 is the previous reference byte
```

The reference data (`v5`) is stored as 16-byte hex blocks that must first be converted to little-endian byte order and flattened into a single one-dimensional array before the per-index relationship can be evaluated.

### Exploitation

```python
v5_little, all_of_v5 = [], []
for chunk in v5:
    v5_little.append(list(chunk.to_bytes(16, "little")))
for block in v5_little:
    all_of_v5.extend(block)

a1 = [0] * 81
v1, v2, v3 = 0, 0, -90
while True:
    a1[v2] = (v3 + (v1 ^ 166) + 4 * v2) & 0xFF
    v2 += 1
    v1 += 93
    if v2 == 80:
        break
    v3 = all_of_v5[v2]

if a1[80] == 0:
    print("".join(chr(c) for c in a1 if c != 0))
```

Two implementation details were essential: converting the 2D little-endian byte blocks into a flat 1D array *before* indexing (working directly with the nested structure makes the index arithmetic error-prone), and masking every computed byte with `& 0xFF` since Python integers don't truncate the way a C `BYTE` cast implicitly does.

## `Custom2` — rotate (ROL) combined with a positional XOR key

### Transform Analysis

```c
// Reconstructed: cipher[i] = rol((3*i) ^ ((input[i] + i) & 0xFF), (i % 7) + 1)
```

### Exploitation

```python
def reversed_rol(a1, a2):
    return ((a1 >> a2) | (a1 << (8 - a2))) & 0xFF

a1 = [0] * 169
for i in range(168):
    a1[i] = (reversed_rol(all_of_v3[i] & 0xFF, (i % 7) + 1) ^ (3 * i)) & 0xFF
```

Deriving this inversion required working the forward equation backward algebraically, step by step:

```
rol(a1+i, (i%7)+1) + 5  = v3[i]          (forward, as reconstructed from disassembly)
=> v3[i] >> a2 | v3[i] << (8-a2)  = a1   (un-rotate first)
=> (that result) ^ (3*i) & 0xFF  = a1 + i (then undo the positional XOR)
```

As with the previous challenge, every intermediate value is masked with `& 0xFF`, since the source routine operates on genuine 8-bit (`BYTE`) values and Python has no native equivalent truncation.

## `Custom3` — permutation + substitution table solved by index search

### Transform Analysis

The target maintains three parallel structures — an S-box, a permutation table (`perm`), and ciphertext (`enc3`) — and iterates exactly 101 times:

```c
// Reconstructed:
// for v1 in 0..100:
//     a1[v3] = index of v2 within sbox   (v3 = perm[v1], v2 = enc3[v1])
```

Here, unlike the earlier positional ciphers, the plaintext byte at a given index is not computable via a closed-form algebraic inverse — it is **the index at which a specific value occurs within the S-box**, which must be found by linear search rather than arithmetic.

### Exploitation

```python
def solve_a1():
    a1 = [0] * 101
    v1, v2, v3 = 0, -125, 42
    while True:
        found = False
        for i in range(256):
            if sbox[i] == v2 & 0xFF:
                a1[v3] = i
                found = True
                break
        if not found:
            return None
        v1 += 1
        if v1 == 100:
            break
        v3 = perm[v1]
        v2 = enc3[v1]
    return "".join(chr(c) for c in a1 if c != 0)

print(solve_a1())
```

## Why this matters for security analysis

This set illustrates the limits of pure algebraic inversion: as soon as a cipher routes data through a lookup table (an S-box) rather than a reversible bitwise/arithmetic operation, the "inverse" is no longer a formula — it is a search over the table's domain. Recognizing this distinction early (does the transform apply an *operation* to the input, or does it use the input as an *index* into a table?) determines whether the correct next step is "derive the algebraic inverse" or "brute-force/search the table," and attempting the wrong approach on a table-based cipher wastes significant analysis time.
