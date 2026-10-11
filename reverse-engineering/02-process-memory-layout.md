# Process Memory Layout and the Compilation Pipeline

> Source topic: Layer7 reverse-engineering session 1 (part 2) — memory structure, compilers vs. interpreters
> Category: Reverse Engineering — Foundations

## Concept

This note covers how a running process's address space is organized into distinct regions (code, data, heap, stack), and how source code becomes that running process in the first place — via either a compiler or an interpreter. Both are prerequisites for reading a disassembly or a debugger's memory view with any confidence about *why* a given value lives where it does.

## Why it matters for security analysis

Nearly every exploitation technique in this portfolio is really a statement about memory layout: a stack buffer overflow only works because adjacent stack slots hold a return address; a GOT overwrite only works because the data segment holds a writable function-pointer table; a heap-based bug depends on allocator-specific layout assumptions. Internalizing *why* the layout is organized the way it is (not just memorizing "stack grows down") is what lets an analyst predict adjacency and offsets in an unfamiliar binary.

## Key technical details

### The four core memory regions

**Code (Text) segment** — holds the loaded machine code. It persists unchanged for the program's entire lifetime and sits at the **lowest** address specifically so the dynamically-growing heap and stack regions have room to expand without colliding with it. It is marked **read-only** (and executable) for a direct security reason: if code were writable, malware or a code-injection exploit could rewrite instructions in place.

**Data segment** — holds global variables, static variables, and string literals.
```c
char *str = "Hello, world";
printf("%p\n", str);
printf("%p\n", "literal");   // even an unassigned literal lives in the data segment
```
String literals are **read-only** data-segment entries; attempting to modify one through a pointer is undefined behavior precisely because it violates this read-only property.

The data segment is further split by initialization status:
- **BSS (Block Started by Symbol)** — uninitialized (or explicitly zero/NULL-initialized) globals/statics. Only a *size* is recorded in the binary, not actual stored zero bytes, saving file space; the loader zero-fills this region at load time. This is also why an uninitialized local variable contains garbage, but an uninitialized global/static variable reliably reads as zero.
- **GVAR** — initialized global variables, stored with their actual initial value directly in the file.

**Stack segment** — holds local variables, function parameters, and return addresses; sized at compile time. Operates strictly **LIFO** (last-in, first-out) via `push`/`pop`, and grows from high addresses toward low addresses. A **stack frame** is the per-call bookkeeping region (return address, saved frame pointer, locals, parameters) that exists only for the duration of one subroutine call and is discarded when that call returns. Critically, **the stack is per-thread**, unlike code/data/heap which are shared across all threads in a process — this isolation prevents concurrent function calls on different threads from corrupting each other's local state. **Stack overflow** (the OS-level condition, distinct from *stack buffer* overflow) occurs when this region's compile-time-sized allocation is exhausted, most commonly via unbounded recursion continually pushing new return addresses and frames.

**Heap segment** — sized and managed entirely at runtime by the program itself (allocated/freed explicitly), growing from low addresses toward high addresses specifically to avoid colliding with the downward-growing stack. Operates FIFO conceptually (first allocated tends to be first reclaimed in simple allocator designs) but access is slower than the stack because free space must be located dynamically rather than being a fixed compile-time offset. The heap is preferred over the stack when: an object's lifetime must outlive the function that created it, an object is too large to safely fit in a stack frame, or the number/size of allocations can't be known until runtime.

| | Stack | Heap |
|---|---|---|
| Layout | Contiguous | Potentially fragmented |
| Managed by | Compiler | Programmer (explicit alloc/free) |
| Cost | Low | Higher |
| Access speed | Fast | Slower |
| Primary failure mode | Memory exhaustion (stack overflow) | Fragmentation |
| Sizing | Fixed at compile time | Dynamic at runtime |

### Compilers vs. interpreters

**Compiled languages** (e.g. C, via GCC): source and header macros are expanded in a **pre-processing** step; the result is checked and transformed through multiple passes into assembly; an assembler converts the assembly into a machine-code object file; a linker combines that object file with any required libraries into a final executable.

```bash
gcc -S file.c     # -> assembly (.s), AT&T syntax by default on Linux
gcc -c file.c     # -> object file (.o): machine code + metadata, not yet linked/runnable
gcc file.c -o out  # -> fully linked, runnable executable
```

Compiled output executes directly as machine code, which is fast, but the result is tied to a specific ISA (a binary compiled for x86-64 will not run on ARM) — a portability/compatibility trade-off. Syntax errors are caught at compile time, before the program ever runs.

**Interpreted languages** (e.g. Python) execute by re-interpreting source one statement at a time, typically through:
1. **Lexer** — breaks source text into tokens (identifiers, operators, constants). E.g. `x = 23 + 5 * 10` → `'x', '=', '23', '+', '5', '*', '10'`.
2. **Parser** — assembles tokens into an **Abstract Syntax Tree (AST)** reflecting operator precedence and structure.

```python
import ast
tree = ast.parse("x = 23 + 5 * 10")
print(ast.dump(tree))
# Module(body=[Assign(targets=[Name(id='x', ...)], value=BinOp(left=Constant(23), op=Add(), right=BinOp(...)))])
```

3. The AST is then translated and executed line by line at runtime.

Interpreted execution is slower (translation happens during execution rather than once ahead of time) but is inherently **portable**, since the same source can run anywhere a compatible interpreter exists, with no fixed machine-code target to tie it to a specific architecture.

## Practical reference

When reading a disassembly or a Ghidra/IDA decompilation, always ask: *which segment does this address belong to?* An address near the binary's low end and marked executable is code; a fixed address referenced without any preceding allocation call is almost certainly BSS/data; an address computed relative to `rbp`/`rsp` with a negative offset is stack; and an address obtained from a `malloc`-family call (or passed around as an opaque pointer with no compile-time-fixed value) is heap. This single question resolves most "where does this value actually live" ambiguities encountered throughout the CTF write-ups in this collection.
