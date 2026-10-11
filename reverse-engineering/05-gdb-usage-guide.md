# GDB Usage Guide for Security Analysis

> Source topic: Layer7 reverse-engineering session 3 — GDB and the ELF format
> Category: Reverse Engineering — Tooling

## Concept

GDB (GNU Debugger) is the primary dynamic-analysis tool used throughout this portfolio. This note covers its setup and the command surface needed to inspect breakpoints, registers, memory, and stack frames, plus the ELF file format it operates on — the standard executable/object format on Unix-like systems.

## Why it matters for security analysis

Static analysis (reading a disassembly or decompilation) can only take an analyst so far; confirming runtime behavior — actual register contents, actual memory layout, actual branch outcomes — requires a debugger. GDB is also the tool used throughout this collection to manually force program state (e.g. overriding a flag to force an "unreachable" branch) during wargame-style exercises, and to single-step through hand-built exploit payloads during development.

## Key technical details

### Setup

```bash
sudo apt update
sudo apt install gdb
gcc -g main.c -o main   # -g embeds debug symbols
gdb ./main
```

### Breakpoints

| Command | Effect |
|---|---|
| `b <func>` | Break at a function's entry |
| `b 10` | Break at line 10 |
| `b *<addr>` | Break at a specific address |
| `tb <...>` | One-shot breakpoint (auto-removed after first hit) |
| `info b` | List current breakpoints |
| `b <file>:<func>` / `b <file>:<line>` | Break at a specific file+location |
| `b +N` / `b -N` | Break N lines forward/backward from current position |
| `cl` / `d` | Clear all breakpoints |
| `cl <line>` / `cl <file>:<line>` | Clear a specific breakpoint |

### Viewing source

`list` (around `main`), `list <line>`, `list <func>`, `list -` (previous block), `list <file>:<func>`, `list <file>:<line>`.

### Execution control

| Command | Effect |
|---|---|
| `run` (`r`) | Start execution |
| `kill` (`k`) | Terminate the running program |
| `step` (`s`) | Execute current line; steps *into* called functions |
| `next` (`n`) | Execute current line; steps *over* called functions |
| `u` | Exit the current loop |
| `continue` (`c`) [n] | Run to the next breakpoint, optionally skipping n hits |
| `finish` | Run until the current function returns |
| `return [value]` | Force an immediate return, optionally with a given value |
| `si` / `ni` | Instruction-level step/next (assembly granularity) |

### Watchpoints

`watch <var>` breaks execution whenever the named variable's value changes, printing both the old and new value — invaluable for locating exactly where an unexpected write occurs.

### Inspecting variables and registers

- `info locals` — all local variables in the current frame.
- `info variables` — all global variables.
- `p <var>` — print a value (for pointers, prints the address; `*ptr` prints the pointed-to value).
- `p $<reg>` — print a register's value.
- `p /<fmt> <var>` — print in a specific format: `t` binary, `o` octal, `d` signed decimal, `u` unsigned decimal, `x` hex, `c` first byte as a character, `f` float, `a` as a symbol+offset.
- `p (<cast>) <var>` — print with an explicit type cast.
- `p <ptr_or_array>+<N>` — print a computed address/offset.
- `p <var> = <value>` — directly assign a new value to a variable at runtime (used throughout this collection's wargame write-ups to force otherwise-unreachable branches).
- `info registers` — dump the full register set.
- `display <var>` / `undisplay <N>` — auto-print a variable at every stop / remove that auto-print.

### Stack inspection

| Command | Effect |
|---|---|
| `info f` | Current stack frame details |
| `info args` | Current function's arguments |
| `info locals` | Current function's locals |
| `bt` | Full backtrace (call stack) |
| `frame <N>` | Jump to a specific frame |
| `up [N]` / `down [N]` | Move toward caller / callee frames |

### Memory inspection

```
x/<count><format><size> <address-or-symbol>
```
- Size: `b` (1 byte), `h` (2), `w` (4), `g` (8).
- Format: `t`/`o`/`d`/`u`/`x`/`c`/`f`/`a`/`s` (string)/`i` (disassembly).

```
x/10i main    # disassemble the first 10 instructions of main
```

### Miscellaneous

- `disas <func>` / `disas <addr> <addr>` — disassemble a function or address range.
- `jump *<addr>` / `jump <func>` — force execution to an arbitrary location.
- `info signals` — list recognized signals.
- `set {<type>}<addr> = <value>` — directly write a typed value into memory.
- `set prompt <text>` — cosmetic prompt customization.

## The ELF file format

ELF (Executable and Linkable Format) is the standard binary format on Unix-like systems, used for four distinct purposes: executables, shared libraries (dynamically linked at runtime), relocatable object files (pre-linking), and core dumps (a process's memory snapshot at crash time).

### ELF Header (selected fields)

| Field | Size | Purpose |
|---|---|---|
| `e_ident[EI_MAG0..3]` | 4 | Magic bytes identifying the file as ELF |
| `e_ident[EI_CLASS]` | 1 | 1 = 32-bit, 2 = 64-bit |
| `e_ident[EI_DATA]` | 1 | 1 = little-endian, 2 = big-endian |
| `e_ident[EI_OSABI]` | 1 | OS/ABI identifier (e.g. 3 = Linux) |
| `e_type` | 2 | File type (exec, shared object, etc.) |
| `e_machine` | 2 | Target ISA |
| `e_entry` | 4/8 | Entry point's virtual address |
| `e_phoff` / `e_shoff` | 4/8 | Offsets of the Program/Section Header Tables |
| `e_phnum` / `e_shnum` | 2 | Number of entries in each table |

```bash
readelf -h file   # ELF header
readelf -l file   # program headers
readelf -s file   # symbol table
readelf -S file   # section headers
readelf -a file   # everything
```

### Program Header Table

Describes **segments** — groupings of sections by memory-permission and loading behavior, used by the OS loader. Key segment types:

| Type | Purpose |
|---|---|
| `PT_LOAD` | Memory-mapped at load time (covers both code and data segments) |
| `PT_DYNAMIC` | Dynamic-linking metadata (shared library dependencies) |
| `PT_INTERP` | Path to the dynamic linker/interpreter to use |
| `PT_NOTE` | Vendor/OS-specific auxiliary information |
| `PT_PHDR` | Location of the Program Header Table itself at runtime |
| `PT_TLS` | Thread-local storage template |
| `PT_GNU_STACK` | Whether the stack segment is executable — directly relevant to NX/DEP analysis |

### Section Header Table

Describes **sections** — compiler-generated groupings of code/data by purpose:

| Section | Purpose |
|---|---|
| `.text` | Executable machine code (read+execute) |
| `.plt` | Procedure Linkage Table — jump stubs for external function calls |
| `.data` | Initialized global/static variables (read+write) |
| `.bss` | Uninitialized global/static variables (read+write, zero-filled) |
| `.rodata` | String constants, `const` data, jump tables (read-only) |
| `.symtab` | Full symbol table |
| `.init` / `.fini` | Startup / teardown code |
| `.got` | Global Offset Table — resolved addresses of external functions/variables |
| `.got.plt` | The PLT-linked portion of the GOT, holding dynamically-resolved function addresses |
| `.dynsym` | Runtime-relevant symbol subset |
| `.strtab` / `.dynstr` | Symbol-name string storage (static / dynamic) |
| `.dynamic` | Dynamic-linking metadata (library list, symbol/string table locations) |
| `.hash` | Symbol lookup hash table |
| `.interp` | Dynamic linker path |
| `.comment` | Compiler version metadata |

## Practical reference

The GOT/PLT distinction here directly underpins the GOT-overwrite exploitation technique covered in this collection's binary-exploitation write-ups: `.got.plt` is the writable table an attacker targets, and `.plt` is the stub code every external call passes through on its way to (or around) that table.
