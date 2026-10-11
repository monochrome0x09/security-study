# IDA Pro / IDA Free: Introduction and First Decompilation

> Source topic: Layer7 reverse-engineering session 5 — IDA introduction and simple-operation walkthrough
> Category: Reverse Engineering — Tooling

## Concept

IDA (Interactive DisAssembler) is a disassembler/decompiler developed by Hex-Rays, widely regarded as one of the most capable static-analysis tools available due to its broad file-format support and strong decompilation accuracy. This note covers its UI model and demonstrates a first full reverse-engineering pass against a small "guess the number" style challenge, recovering the solution algebraically from the decompiled logic.

## Why it matters for security analysis

A decompiler that reliably turns machine code back into readable C-like pseudocode dramatically accelerates vulnerability discovery and CTF-style challenge solving, especially against medium-to-large binaries where hand-tracing raw assembly (as in the companion GDB-handraying note) would be impractical. Understanding its UI and output conventions is a prerequisite for every later write-up in this collection that references IDA-derived pseudocode.

## Key technical details

### Supported formats (IDA Pro)

MS-DOS EXE, New/Linear Executable, Windows dump files, JVM/Dalvik/MSIL bytecode, JAR files, Linux ELF, Windows PE, Nintendo N64, Intel HEX, macOS/iOS binaries, PlayStation PSX files, ZIP archives, and more. IDA Free supports a reduced but still substantial subset sufficient for most CTF-style ELF/PE analysis, and is the edition used throughout this collection given IDA Pro's cost.

### UI model

- **Graph View** — the disassembled instructions rendered as a control-flow graph, splitting into tree-like branches at each conditional jump, with named basic blocks for readability.
- **Hex View** — the same code region rendered as raw hexadecimal bytes.
- **Function View** — a list of both user-defined and externally-linked (imported) functions (e.g. `main`, a custom `generate_key`, or `printf`).

### Decompilation

Selecting a function in Function View and pressing **F5** in Graph View invokes the Hex-Rays decompiler, producing C-like pseudocode from the disassembly — IDA's single most valuable capability, and the reason variable/function names in decompiled output can match the original source almost exactly when the binary retains its ELF symbol table (see the companion GDB/ELF note for why symbols survive in unstripped binaries).

## Challenge Walkthrough: `simple-operation`

### Overview

A Dreamhack challenge: the program generates a random number, reads a user-supplied integer, XORs the two together, formats the result as an 8-digit hex string, reverses that string, and checks it against a hardcoded value.

### Decompiled logic (annotated)

```c
rand_num = 0;
get_rand_num(&rand_num);
printf("Random number: %#x\n", rand_num);
printf("Input? ");
scanf("%d", &v7);

v11 = rand_num ^ v7;
snprintf(s, 9, "%08x", rand_num ^ v7);   // 8-digit hex string of the XOR result

for (i = 0; i <= 7; ++i)
    s1[i] = s[7 - i];                    // reverse the 8-character string

printf("Result: %s\n", s1);

if (!strcmp(s1, "a0b4c1d7")) {
    puts("Congrats!");
    puts(buf);                           // flag
} else {
    puts("Try again");
}
```

Note the disassembly contains dead/unused intermediate variables (`v11`, `s2`) that IDA still names and tracks even though they play no further role — a common artifact of decompiler output on non-optimized builds, and something a reverse engineer must learn to recognize and set aside rather than over-interpret.

### Algebraic solution

Working backward from the success condition: `s1` must equal `"a0b4c1d7"`; since `s1` is `s` reversed, `s` must be `"7d1c4b0a"`; since `s` is the hex representation of `rand_num ^ v7`, converting that hex string back to its integer value and then XOR-ing it with the (now-known) displayed `rand_num` recovers the required input `v7` — because XOR is self-inverse (`a ^ b ^ b = a`), re-applying it undoes the original operation exactly.

```python
rand_num = int(input(), 16)        # the program discloses this value directly
reversed_hex = int("7d1c4b0a", 16)
print(rand_num ^ reversed_hex)      # the value to submit
```

## Practical reference

This "work backward from the success condition, exploiting a self-inverse operation like XOR" pattern recurs throughout the custom-cipher and crackme write-ups elsewhere in this collection — recognizing XOR, bit-rotation, and additive ciphers as reversible operations (given the output and the transformation) is the single most reusable reverse-engineering skill demonstrated across the CTF-style challenges in this portfolio.
