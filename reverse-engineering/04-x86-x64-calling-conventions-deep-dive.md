# x86/x64 Calling Conventions Deep Dive: MSVC vs. SysV

> Source topic: Layer7 reverse-engineering session 2 — calling conventions
> Category: Reverse Engineering — Foundations

## Concept

Building on the baseline calling-convention material elsewhere in this collection, this note focuses on the practical differences a reverse engineer encounters between **Windows (MSVC)** and **Linux/macOS (SysV)** x86-64 conventions, plus the x86-era conventions (`cdecl`, `stdcall`, `fastcall`) that remain relevant when analyzing legacy or cross-compiled 32-bit binaries.

## Why it matters for security analysis

Getting the calling convention wrong when reading a disassembly produces a cascade of misidentified arguments — a reverse engineer who assumes SysV register ordering while actually looking at an MSVC binary will systematically swap or miss function arguments. Since Windows malware/PE analysis and Linux ELF analysis both appear throughout real-world reverse-engineering work, recognizing which convention is in play from the binary's target platform (and confirming it against the actual disassembly) is a basic but essential discipline.

## Key technical details

### Caller / Callee terminology

**Caller** is the routine that invokes a function; **Callee** is the invoked function itself. Every calling convention is, fundamentally, an answer to two questions: who places the arguments (and where), and who cleans the stack up afterward.

### x86 conventions, revisited with their trade-offs

- **cdecl** — caller pushes arguments **right-to-left** and cleans up afterward (`add esp, N`). This caller-side cleanup is precisely what makes variadic functions like `printf` possible, since only the caller knows exactly how many arguments were actually passed.
- **stdcall** — used throughout the Win32 API; the *callee* cleans up via `ret N`. Benefits include slightly more compact call sites (no per-call-site cleanup instruction) and **name mangling** that encodes the argument byte-count into the decorated symbol name, letting a linker or disassembler recover size information straight from the symbol table.
- **fastcall** — first two arguments in `ECX`/`EDX`, remainder on the stack, callee cleans up. The benefit is raw performance from using on-die registers instead of memory for the hot-path arguments.

### x86-64 conventions

With far more general-purpose registers available in 64-bit mode, nearly all practical x86-64 calling conventions are fastcall-style by default — the open question is only *which* registers and *in what order*, and this differs by **operating system**, not by architecture:

**MSVC (Windows x86-64)**
- Integer/pointer arguments: `RCX, RDX, R8, R9`, in order (only 4 register slots, versus SysV's 6).
- Floating-point arguments: `XMM0L–XMM3L`.
- Remaining arguments: stack.
- Return value: `RAX` (integer), `XMM0` (floating-point).
- Distinctive requirement: the caller must reserve **shadow space** — a fixed block of stack space the callee can use to spill its register-passed arguments into, even though the arguments were never stack-passed to begin with.

**SysV (Linux/macOS x86-64)**
- Integer/pointer arguments: `RDI, RSI, RDX, RCX, R8, R9`, in order (6 register slots).
- Floating-point arguments: `XMM0` through `XMM7` (8 slots).
- Remaining arguments: stack.
- Return value: `RAX`; for 128-bit return values, the upper 64 bits land in `RDX`.
- No shadow-space requirement.

The practical consequence for a reverse engineer: the *same* 5-argument C function compiles to visibly different argument-loading sequences on Windows (`rcx, rdx, r8, r9`, then stack) versus Linux (`rdi, rsi, rdx, rcx, r8`, then stack) — recognizing which OS/ABI a binary targets before mapping register reads to source-level arguments avoids systematic misattribution.

### Prologue/epilogue

Prologue and epilogue construction follows the same `push rbp / mov rbp, rsp` (setup) and `mov rsp, rbp / pop rbp` (teardown) pattern across both conventions and both bit-widths — see the companion note on stack frame construction in this collection for the full mechanical breakdown.

## Practical reference

When disassembling an unfamiliar binary, the fastest confirmation of which convention is in play is simply checking the target platform (PE vs. ELF header) and then verifying the first few argument-loading instructions against the tables above — e.g. seeing `mov [rsp+8], rcx` immediately after a function's entry strongly suggests MSVC's shadow-space-spill pattern, which has no SysV equivalent.
