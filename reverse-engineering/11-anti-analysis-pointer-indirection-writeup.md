# Anti-Analysis Techniques: Manual Flag Search and Pointer Indirection

> Source topic: Layer7 reverse-engineering session 6 ("please, please, please" and "fake" write-ups)
> Category: Reverse Engineering — CTF Write-up / Anti-Analysis

## Overview

This note covers two short challenges that each illustrate a different anti-analysis friction point: a flag deliberately scattered across many functions requiring manual traversal, and a double-pointer-indirection scheme used to obscure an array shuffle.

## `please, please, please` — manual traversal as the actual obstacle

### Overview

The challenge presents no algorithmic puzzle at all — the only "difficulty" is that the flag-bearing buffer is reachable only by manually following a chain of function calls from `main` down into a nested helper and the data it references, with no shortcuts or patterns to exploit.

### Why this matters

Not every reversing obstacle is cryptographic. Some challenges (and, more importantly, some real-world obfuscated malware) simply rely on **control-flow sprawl** — spreading logic across many small functions — to slow down an analyst through sheer traversal effort rather than through any genuinely hard transformation. The correct response is systematic, patient call-graph traversal (following each call from `main` outward, inspecting referenced buffers at each stop) rather than searching for a clever shortcut that doesn't exist.

## `fake` — double-pointer indirection concealing an array shuffle

### Transform Analysis

A helper function (`sub_140B`) constructs a doubly-indirected pointer structure: `ptr[1]` stores a count (`23`), and `ptr[0]` points to an array populated from an 8-byte hex literal reconstructed in little-endian order. Several other functions in the binary only *read* through this pointer structure, but one (`sub_1521`, via a nested helper `sub_12C5`) actually **mutates** the underlying array — and is therefore the function that matters for recovering the final data.

Inside `sub_12C5`:

```c
// Reconstructed: result = ptr[1] >> 1   (~11 iterations)
// loop body: swaps array[i] with array[ptr[1] - i - 1]
```

This is a standard **in-place array reversal** pattern (swap element `i` with element `count - i - 1`, iterating only through the first half of the array), just expressed through an extra layer of pointer indirection that obscures the fact that it's a reversal at all until the indirection is unwound.

A further helper (`sub_123F`) uses the same `ptr[1]` count (`23`) as a loop bound, confirming that `23` is the array's true element count rather than an unrelated constant — cross-referencing how a value is used across multiple functions is often the fastest way to confirm its semantic role when no variable names survive.

### Why this matters for security analysis

Pointer indirection (storing data behind one or more extra levels of pointer dereference, as opposed to a flat array) is a common, lightweight anti-analysis technique: it doesn't change *what* the code does, but it forces a reverse engineer to explicitly trace each dereference by hand rather than recognizing the operation at a glance from the disassembly. The defensive takeaway for legitimate software: indirection of this kind offers essentially no real protection against a determined analyst — if genuine code-confidentiality matters, cryptographic sealing or server-side validation of sensitive logic is required instead of obfuscation through pointer layout alone.
