# Calling Conventions and Stack Frame Construction (x86 / x86-64)

> Source topic: Layer7 x86/x64 calling convention, prologue, and epilogue notes
> Category: Reverse Engineering — Foundations

## Concept

A calling convention is the agreed-upon contract between a caller and a callee for how arguments are passed, how the return value comes back, and which side is responsible for cleaning up the stack afterward. The convention in use directly determines the shape of a function's **prologue** (frame setup) and **epilogue** (frame teardown), which are the first things a reverse engineer must recognize when locating function boundaries in a disassembly.

## Why it matters for security analysis

Stack-frame structure is the substrate every stack-based exploitation technique in this collection operates on: offsets to a buffer, the saved frame pointer, the saved return address, and any canary are all defined by prologue/epilogue behavior. Misreading which convention a binary uses (or confusing 32-bit and 64-bit frame geometry) is one of the most common sources of off-by-N errors when calculating overflow offsets.

## Key technical details

### Stack frame mechanics (x86)

A stack frame holds a function's locals, saved return address, and other bookkeeping, created on call and destroyed on return. Construction (the **prologue**) proceeds as: push the caller's `EBP` (preserving it for later restoration), then copy the current `ESP` into `EBP` (anchoring the new frame at a fixed base so locals can be addressed via constant offsets even as `ESP` itself moves during the function body), then push or register-pass arguments as the convention dictates. Teardown (the **epilogue**) reverses this: `ESP` is restored to `EBP`'s value, then `EBP` is popped back to the caller's saved value.

### x86 conventions

**cdecl** — C's default convention. The *caller* pushes arguments right-to-left and cleans the stack afterward with an explicit `add esp, N`.

```asm
push 3          ; third argument
push 2          ; second argument
push 1          ; first argument
call func
add esp, 12     ; caller cleans up
```

**stdcall** — used by the Win32 API. Arguments are still stack-pushed, but the *callee* cleans up, via `ret N`.

```asm
func:
    push ebp
    ...
    ret 12      ; pops 12 bytes of arguments on return
```

**fastcall** — the first two arguments travel in `ECX`/`EDX` registers rather than the stack; remaining arguments still use the stack. Using registers for the common case improves performance.

```asm
mov ecx, 1      ; first argument
mov edx, 2      ; second argument
push 4          ; fourth argument
push 3          ; third argument
call func
```

### x86-64 stack frames

Conceptually identical to x86, with `R`-prefixed 64-bit registers (`RSP`, `RBP`) replacing their `E`-prefixed 32-bit counterparts. `RSP` tracks the top of the stack and is adjusted automatically by `push`/`pop`/`call`/`ret` and explicit local-variable allocation; `RBP` anchors the frame's start, giving fixed-offset access to locals and parameters regardless of further stack movement within the function body.

### x86-64 calling convention: SysV (Linux/macOS)

Unlike x86's multiple competing conventions, x86-64 effectively standardizes on a single fastcall-style convention — simply because the much larger x86-64 register file makes register-passing universally preferable. Under **SysV** (the Linux/macOS ABI):
- Integer/pointer arguments: `RDI, RSI, RDX, RCX, R8, R9`, in that order; any further arguments spill to the stack.
- Return value: `RAX` (and, for very large/structured return types, potentially paired with `RDX`).

This is the exact convention assumed by every syscall table and shellcode example in this collection's binary-exploitation folder.

## Practical reference

When first opening a function in a disassembler, locating the prologue (`push rbp; mov rbp, rsp; sub rsp, N`) immediately establishes: the frame's base (`rbp`), the amount of local-variable space reserved (`N`), and — by extension — the fixed offsets at which every subsequent `[rbp-X]`/`[rbp+X]` reference in the function body can be interpreted (negative offsets are typically locals; positive offsets starting at `rbp+0x10` on x86-64, after the saved `rbp` and return address, are typically stack-passed arguments or caller-visible data).
