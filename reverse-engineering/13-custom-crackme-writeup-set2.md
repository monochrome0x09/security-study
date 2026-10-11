# Custom Crackme Write-up Set 2: pyhidra Automation and Binary Patching

> Source topic: Layer7 reverse-engineering session 8 (CTFd Custom1/Custom2, Dreamhack Recover & legacyopt)
> Category: Reverse Engineering — CTF Write-up / Tooling

## Overview

This set demonstrates two tooling upgrades over the previous write-up: driving Ghidra from standalone Python 3 scripts via `pyhidra` (rather than Ghidra's built-in Jython console), and, where recovering an algorithm is impractical, directly **patching** a binary's control flow to make it do the work for the analyst.

## `Custom1` — positional XOR/additive cipher via pyhidra automation

### Transform Analysis

```c
// Reconstructed:
// compared[i] = ((bVar5 ^ 0x55) + i*2) ^ bVar6
// bVar6 = enc1.0[i+1]; bVar5 += 51   (each iteration)
```

### pyhidra Script

```python
import pyhidra
from pyhidra import open_program
pyhidra.start()

with open_program("<path>/r8_custom1", analyze=True) as api:
    enc = api.getBytes(api.toAddr("0x00102040"), 64)
    modified_enc = [b & 0xFF for b in enc]

    compared = [0] * 64
    lvar2, bvar5, bvar6 = 0, 0, 25
    while True:
        compared[lvar2] = (((bvar5 ^ 85) & 0xFF) + (0xFF & lvar2) * 2 ^ bvar6) & 0xFF
        if lvar2 + 1 == 64:
            break
        bvar6 = modified_enc[lvar2 + 1]
        lvar2 += 1
        bvar5 += 51

    print("".join(chr(c) for c in compared))
```

`pyhidra` exposes Ghidra's `FlatProgramAPI` to an ordinary Python 3 interpreter (`open_program` loads the target and runs Ghidra's own auto-analysis before handing back an API object), which is a significant ergonomic upgrade over Ghidra's embedded Jython-2 console: standard Python 3 syntax, normal tooling/IDE support, and no need to keep the Ghidra GUI open during scripting.

## `Custom2` — recovering logic via binary patching instead of re-implementation

### Overview

`main` contains no flag-related logic at all; a `print_flag` function exists elsewhere in the binary (discoverable by browsing the `functions` list) but is never called from the normal execution path — it is dead code from the program's perspective, reachable only by force.

### Exploitation Methodology

Rather than reverse-engineering `print_flag`'s internal logic and reimplementing it in a script, the binary itself is **patched**: the call site that would normally invoke `validate_input` is redirected to call `print_flag` instead, and the patched binary is then simply executed to print the flag directly.

A critical caution emphasized in the source material: the patch must replace a call site, not be inserted at an arbitrary address — inserting a call anywhere unrelated to proper calling-convention setup risks corrupting adjacent code or stack state and crashing with a segmentation fault instead of producing useful output. This is a direct application of calling-convention awareness (covered elsewhere in this collection): a patched call still needs correct argument setup and a valid return path, exactly like any legitimate call site.

## `Recover` (Dreamhack) — image-file decryption via reconstructed byte-stream transform

### Transform Analysis

```c
// Reconstructed: encrypted[i] = (plaintext[i] - 0x13) XOR key[i % 4]
```

### Exploitation

```python
with open('encrypted', 'rb') as f:
    encrypted_data = f.read()

decrypted_data = bytearray()
with open_program('<path>/chall') as api:
    loc28 = [b & 0xFF for b in api.getBytes(api.toAddr(0x00102004), 4)]
    for i, byte in enumerate(encrypted_data):
        decrypted = ((byte - 0x13) & 0xFF) ^ (loc28[i % 4] & 0xFF)
        decrypted_data.append(decrypted & 0xFF)

with open('decrypted.png', 'wb') as f:
    f.write(decrypted_data)
```

Here the "plaintext" being recovered is an entire PNG image, not a text flag — a reminder that reverse-engineering inversion techniques apply equally to arbitrary binary payloads, not just ASCII strings; the recovered bytes are written straight to a `.png` file and opened as an image to view the flag.

## `legacyopt` (Dreamhack) — per-position XOR table with a modular switch-based dispatch

### Transform Analysis

The transformation function uses a **Duff's-device-style fallthrough switch** keyed on `input_length % 8`, applying a different fixed XOR byte at each position in a repeating 8-byte cycle (`0x88, 0x66, 0x44, 0x11, 0x77, 0x55, 0x22, 0x33`), then looping for `(length + 7) >> 3` repetitions of the full cycle:

```c
switch (inputed_length % 8) {
  case 0: do {
      *out = *in ^ 0x88; in++; out++;
  switchD_caseD_7:
      *out = *in ^ 0x66; in++; out++;
  // ... (falls through each case label in sequence)
  } while (0 < local_c);
  break;
  case 1: goto switchD_caseD_1;
  // ...
}
```

### Exploitation

Rather than implementing the full switch/goto structure, the write-up directly reasons about which XOR byte applies at which position, given the known total input length (39, derived from the challenge's provided `output.txt`) and reconstructs the sequence in reverse, applying each XOR key to the ciphertext bytes from the *end* of the buffer backward (matching the forward loop's increment-then-decrement bookkeeping):

```python
ptr_arr = bytearray((0x220c6a33...).to_bytes(39, 'big'))
localc = 39
for i in range(5):
    for key in (0x33, 0x22, 0x55, 0x77, 0x11, 0x44, 0x66):
        localc -= 1
        ptr_arr[localc] ^= key
    if i != 4:
        localc -= 1
        ptr_arr[localc] ^= 0x88

print("".join(chr(b) for b in ptr_arr))
```

## Why this matters for security analysis

This set highlights a pragmatic principle: **not every reversing problem needs to be solved by fully re-deriving the algorithm from first principles**. When a target binary contains working logic that is merely unreachable (dead code, like `print_flag`), patching the control flow to reach it is faster and less error-prone than reimplementing equivalent logic externally — provided the patch respects the same calling-convention and stack-integrity constraints that govern the rest of the binary's control flow.
