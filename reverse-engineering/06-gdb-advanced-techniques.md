# GDB Advanced Techniques: Assembly-Level "Handraying"

> Source topic: Layer7 reverse-engineering session 4 — GDB handraying
> Category: Reverse Engineering — Tooling

## Concept

"Handraying" (hand-deriving/tracing) with GDB refers to the practice of reading raw assembly directly off a live debugger and mentally reconstructing the equivalent C-level logic, without relying on an automated decompiler. This note is a condensed reference of the instruction semantics and stack-offset heuristics needed to do that reliably.

## Why it matters for security analysis

Decompilers (IDA's Hex-Rays, Ghidra) are powerful but not infallible — they can produce misleading output on obfuscated, optimized, or unusually structured code. Being able to fall back to manual assembly tracing is what separates confident vulnerability analysis from blindly trusting a decompiler's guess. The benefits of this approach: source-level-equivalent debugging confidence even without a decompiler, direct register-state verification of control flow, visibility into local/global/heap/stack state at any point, and the ability to pinpoint exactly which instruction triggers an error down to the assembly level.

## Key technical details

### Instruction reference

| Instruction | Semantics | C equivalent |
|---|---|---|
| `add a, b` | `a = a + b` | `a += b` |
| `mov a, b` | `a = b` | `a = b` |
| `lea a, [b]` | `a` = the computed address `b`, not the value at it | `a = &b` (pointer arithmetic) |
| `cmp a, b` | Computes `a - b`, setting flags only (ZF set if equal) | `a == b` / `a < b` / etc. (the *comparison*, not the subtraction) |
| `sub a, b` | `a = a - b` | `a -= b` |
| `imul a, b` | Signed multiply, result in `a` | `a *= b` (signed) |
| `mul b` | Unsigned multiply: `EAX * b` → `EAX` (high bits to `EDX` on overflow) | unsigned `a *= b` |
| `idiv a` | Signed divide: `EAX / a` → quotient in `EAX`, remainder in `EDX` | signed `/`, `%` |
| `div a` | Unsigned divide, same register layout as `idiv` | unsigned `/`, `%` |
| `xor a, b` | Bitwise XOR | `a ^= b` |
| `xor a, a` | Zeroes `a` (XOR of identical operands is always 0) | `a = 0` (common zeroing idiom) |
| `and a, b` / `or a, b` | Bitwise AND / OR | `a &= b` / `a \|= b` |
| `inc a` / `dec a` | `a += 1` / `a -= 1` | `a++` / `a--` |
| `je`/`jz` | Jump if ZF=1 (operands equal / result zero) | `if (a == b)` |
| `jne`/`jnz` | Jump if ZF=0 | `if (a != b)` |
| `call` | Invoke a procedure, pushing a return address first | function call |
| `jmp` | Unconditional jump, **no** return-address push | `goto` |

### Stack-offset heuristics ("handray tips")

- **`[ebp + 8]` and beyond → function arguments.** Because arguments are pushed by the caller *before* the call (per the calling convention), and the prologue then pushes the return address and old `ebp`, anything at a positive offset past the saved `ebp`/return address is caller-supplied data.
- **`[ebp - 4]`, `[esp + 8]` and similar → local variables.** `ebp` holds the previous frame's base address; moving just past it (on the 32-bit-width side) reaches the current function's own locally declared data.
- **Numerically larger negative offsets were declared earlier.** Because the stack grows from high addresses to low, the first local variable declared sits at the "highest" (least negative) offset, with each subsequent declaration pushed further down (more negative).
- **`mov x, y` reads as `x = y`; `lea x, [y]` reads as `x = &y`.** Keeping this distinction straight when hand-translating to C-like pseudocode avoids conflating a value with its address.
- **`BYTE`/`WORD`/`DWORD`/`QWORD` = 1/2/4/8 bytes.** Explicit size directives disambiguate memory operands when the operation itself doesn't make the width obvious.
- **A `sub` immediately following the prologue indicates total local-variable/frame space reserved.** The subtracted amount is exactly how much of the stack the compiler decided this function's locals require — useful for sanity-checking a reconstructed variable layout against the actual reserved size.

## Practical reference

The combination of "offset sign and magnitude tells you argument-vs-local, and relative-declaration-order" plus "a handful of instruction idioms map directly onto C operators" is sufficient to hand-trace the overwhelming majority of straightforward CTF-style reversing targets without ever opening a decompiler — a skill repeatedly exercised in this collection's IDA- and Ghidra-based write-ups whenever decompiled output needed independent verification.
