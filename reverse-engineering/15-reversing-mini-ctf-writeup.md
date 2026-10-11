# Custom Cipher Crackme Write-up: Mini-CTF Series

> Source topic: Layer7 "Reversing Mini CTF" write-up (One by One, YEKROX, Secret Present, XORING, What's real?)
> Category: Reverse Engineering — CTF Write-up

## Overview

This mini-CTF set covers five challenges ranging from a trivial plaintext-in-memory case, through positional XOR ciphers with evolving keys, an image-decryption challenge requiring key identification among several candidates, and a struct-overrun comparison trick, up to a three-stage composite cipher (repeating-key XOR + chained addition + bit rotation) that required careful, ordered inversion.

## `One by One` — flag visible via string search

The program only appears to Base64-encode user input, but the flag is present verbatim in the binary's string table — found immediately via Ghidra's **String Search** feature rather than any analysis of the program's actual logic. As emphasized throughout this collection: always check for the trivial case before investing in cryptanalysis.

## `YEKROX` — evolving-key positional XOR

### Transform Analysis

```c
// Reconstructed: flag[i] = (i + 0x42) ^ key_byte, where key_byte starts at 0xe
//                and is replaced each iteration by the PREVIOUS reference byte
```

### Exploitation

```python
dat = [...]  # bytes at 0x00402041
loc8 = [0] * len(dat)
lvar2, bvar5 = 0, 0xe
while True:
    loc8[lvar2] = ((lvar2 + 0x42) ^ bvar5) & 0xFF
    if lvar2 + 1 == 0x24:
        break
    bvar5 = dat[lvar2]
    lvar2 += 1

for c in loc8:
    if 0x20 <= c <= 0x90:   # filter to printable range
        print(chr(c), end="")
```

An alternate implementation noted in the source: since the key array's logical starting value happens to coincide with the first element of the *adjacent* data symbol (`DAT_00402040`), the initial key constant could equivalently be read directly from memory rather than hardcoded — a useful cross-check when two independently-derived values should agree.

## `Secret Present` — key identification among multiple candidates, then XOR+offset inversion

### Overview

The challenge supplies an encrypted image and several numbered candidate key images (`0.png` … `N.png`); only one is the correct key, and the binary itself determines (and would apply) the correct one at runtime via a dedicated key-selection function.

### Exploitation Methodology

Rather than reverse-engineering *why* a particular key is selected, the selection function (`FUN_00101209`) is simply **executed forward** (mentally or by re-tracing the logic directly) to determine its return value — which turns out to be `3`, identifying `3.png` as the correct key without needing to understand the selection criteria in depth.

```c
// Reconstructed: original[i] = (encrypted[i] ^ key[i]) ^ (i + 39)
```

```python
key = open("3.png", "rb").read()
encrypted = open("Encrypted.png", "rb").read()

original = bytearray()
for i in range(len(encrypted)):   # bounded by the SHORTER of the two buffers
    original.append(((encrypted[i] ^ key[i]) & 0xFF) ^ ((i + 39) & 0xFF))

open("Original.png", "wb").write(original)
```

A key implementation detail: the key and encrypted image files differ in size, so the reconstruction loop must iterate only up to the length of the **shorter** buffer, or it will index out of bounds against the key.

## `XORING` — struct-overrun comparison exploited for recovery, not corruption

### Overview

The validation function compares a transformed version of the user's input against a local variable, `local_88`, using `memcmp` with a length (31 bytes) that **exceeds `local_88`'s own declared size** — meaning the comparison silently reads into whatever stack-adjacent local variables happen to follow it.

### Exploitation Methodology

Rather than treating this as something to *fix* (it's the target binary's own logic, not the analyst's), the overrun is used to the analyst's advantage: by inspecting the full chain of locally-declared variables that follow `local_88` in the stack frame (`uStack_80`, `local_78`, `local_70`, `local_6c`, `local_6a`), their combined bytes reconstruct the *entire* 31-byte comparison value that `memcmp` actually reads, even though no single declared variable is that large on its own.

```python
loc88_1 = list((0x30394420d02f2206).to_bytes(8, 'little'))
loc88_2 = list((0x1a7365126463672b).to_bytes(8, 'little'))
loc88_3 = list((0x855fab87a0587272).to_bytes(8, 'little'))
loc88_4 = list((0xec8d9781).to_bytes(4, 'little'))
loc88_5 = list((0xecec).to_bytes(2, 'little'))
loc88_6 = list((0xef).to_bytes(1, 'little'))
b = loc88_1 + loc88_2 + loc88_3 + loc88_4 + loc88_5 + loc88_6   # 31 bytes total

inputed_value = [0] * 31
lvar3, bvar2 = 0x1f, 220
while lvar3 >= 0:
    lvar3 -= 1
    bvar1 = ((b[lvar3] ^ 0x5a) & 0xFF) - 0xd
    bvar2 -= 7
    inputed_value[lvar3] = (bvar1 ^ bvar2) & 0xFF

print("".join(chr(c) for c in inputed_value))
```

## `What's real?` — three-stage composite cipher, inverted in reverse order

### Overview

The hardest challenge in this set: `main` itself is not the program's actual entry point as displayed by default (a String Search was again needed to locate it), and the validating function applies **three distinct transformations in sequence**: a repeating-key XOR (key: the literal string `"We_Hack_The_Universe"`), an index-dependent chained addition (each byte derived from itself plus the *next* byte), and finally a fixed 3-bit rotation applied uniformly across all bytes.

### Exploitation Methodology — inverting a multi-stage pipeline

The correct approach, as with any multi-stage transform, is to invert each stage **in the reverse order they were originally applied** (last-applied stage undone first):

```python
# Stage 1 (undo the LAST-applied transform first): un-rotate
after_rol = bytearray(size)
for i in range(size):
    byte = encrypted_data[i]
    after_rol[i] = ((byte << 3) | (byte >> 5)) & 0xFF

# Stage 2: undo the chained addition, working backward from the last byte
after_sub = bytearray(size)
after_sub[size - 1] = after_rol[size - 1]
for i in range(size - 2, -1, -1):
    after_sub[i] = (after_rol[i] - after_sub[i + 1] + 256) & 0xFF

# Stage 3: undo the repeating-key XOR
key_string = "We_Hack_The_Universe"
flag_bytes = bytearray(size)
flag_bytes[0] = ord('W') ^ after_sub[0]
for i in range(1, size):
    flag_bytes[i] = ord(key_string[i % len(key_string)]) ^ after_sub[i]

print("".join(chr(b) for b in flag_bytes))
```

The chained-addition stage is the trickiest to invert correctly: because each ciphertext byte depends on the *following* plaintext byte (`cipher[i] = plain[i] + plain[i+1]`), the only byte that can be recovered directly is the **last** one (which has no following byte and is therefore left untouched by this stage); every preceding byte must then be derived working **backward** from the end of the buffer, using the just-recovered next byte to isolate the current one — attempting a forward pass instead would have no valid starting point.

## Why this matters for security analysis

The `What's real?` challenge is the clearest illustration in this collection of a general multi-stage-cipher principle: **composing transforms is easy to apply forward but requires exact order-reversal and per-stage inversion logic to undo**, and getting either the stage order or an individual stage's inversion direction wrong (as with the chained-addition stage here, which can only be solved backward) produces output that looks like noise rather than a recognizable error — making careful, stage-by-stage verification (printing intermediate results after each undo step, as the original write-up does) essential rather than optional.
