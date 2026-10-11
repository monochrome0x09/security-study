# Linux Kernel Fundamentals for Security Analysis

> Source topic: KOCW "Linux Kernel Programming" course notes
> Category: Reverse Engineering — Kernel / OS Internals

## Concept

This note summarizes the historical and architectural background of Unix/Linux kernels that underpins kernel-level exploitation and analysis work elsewhere in this portfolio (notably the kernel syscall-table hijack covered in the binary-exploitation folder). Understanding *why* the kernel is structured the way it is — dual-mode execution, the syscall boundary, module loading — is what makes kernel-level vulnerabilities and their exploitation intelligible rather than a memorized sequence of steps.

## Why it matters for security analysis

Kernel-level vulnerabilities (privilege escalation via a vulnerable syscall or driver, container/namespace escapes, race conditions in kernel data structures) all operate against the same dual-mode boundary described here. Recognizing the user/kernel split, and precisely what a system call does and does not grant, is the conceptual prerequisite for the LPE technique documented in this collection's `syscall` pwnable write-up.

## Key technical details

### Unix lineage

Unix was developed at Bell Labs by Dennis Ritchie and Ken Thompson, originally growing out of work on the Multics project; it split into two major lineages — **System V** (AT&T's commercially-licensed, source-portable branch, sold to vendors like IBM, HP, SGI, and Sun to port across the era's fragmented hardware landscape) and **BSD** (developed at UC Berkeley, where Thompson and his students substantially extended the original system). Linux and Minix are notable as independent reimplementations rather than direct descendants of either branch.

Unix's enduring design advantages: a small number of system calls, the "everything is a file" abstraction (allowing most device interaction to go through a handful of calls — open/close/read/write — rather than requiring bespoke interfaces per device), simple inter-process communication (IPC), and broad environment portability.

### Linux's origin and the GNU Project

Linux, strictly speaking, refers only to the **kernel**, created by Linus Torvalds (originally posted publicly to a Usenet newsgroup, which drove its early adoption and the proliferation of today's distributions — Debian, RedHat, Fedora, Ubuntu, Arch, and others). The surrounding operating system is substantially composed of the **GNU Project**'s userland tools (GCC, Emacs, and much more), founded by Richard Stallman on the principle that software should be a shared commons. Because GNU's own kernel effort stalled, Stallman adopted the newly-announced Linux kernel to complete the GNU system — which is why the kernel itself is not GPL-licensed even though most of the surrounding userland is: different components of a modern Linux distribution can carry different licenses depending on their origin.

The **GNU GPL** specifically exists to prevent exactly this kind of commons from being silently appropriated for closed commercial redistribution — the Free Software Foundation can compel license compliance or source disclosure from violators.

Linux's real-world reach is often underestimated from a desktop-centric view: Android (Linux-kernel-based) accounts for roughly 56% of all device operating systems; Linux holds only ~1.54% desktop share, but 35.9% of the top 10 million web servers, 95.8% of the top 1 million, and roughly 99% of supercomputers.

### Dual-mode execution

The kernel is the core component responsible for interrupt handling, scheduling, memory management, and I/O — essentially the control-and-allocation core of the broader "operating system" process. To prevent one process from corrupting another's memory, the kernel enforces **dual mode**: **user space**, where ordinary application code executes with restricted hardware access, and **kernel space**, where direct hardware access is permitted. A user-space program that needs a hardware-level service must cross this boundary via a **system call**.

This yields three distinct execution states:
1. User-space execution of ordinary application code.
2. Kernel-space execution of code on behalf of a process, triggered by that process's own system call.
3. Kernel-space execution handling a hardware interrupt.

States 2 and 3 both run in kernel space, but differ in origin: state 2 is tied to a specific process's own request, while state 3 is driven by the CPU/hardware asynchronously and is not associated with servicing any particular process's system call.

The kernel and device drivers are deliberately kept **separate** — there is no direct call path between them; interaction happens only through dedicated shared data structures, a design detail that matters when analyzing driver-level vulnerabilities.

### Idle state

Most operating systems implement idle time via a dedicated **idle process** that simply loops on a `halt` instruction — consuming the CPU's attention but no significant power. Because other components may continue drawing power even while the CPU is halted, modern idle implementations escalate through additional system calls as idle time extends: first reducing peripheral power draw (disk spin-down, display blanking), and eventually powering off components entirely if idle persists — which is why the modern idle process has grown substantially more complex than a bare `halt` loop.

### Linux vs. traditional Unix kernels

**Shared traits**: both are monolithic static binaries, both use a Memory Management Unit (MMU), and both support Symmetric Multiprocessing (SMP).

**Differences**: Linux supports **dynamic module loading** (code is loaded into the running kernel only when actually needed, rather than being compiled monolithically into a single static image in the traditional sense); Linux is a **preemptive kernel** (kernel-mode execution itself can be interrupted and rescheduled, improving responsiveness); and Linux treats threads and processes largely identically at the kernel level — rather than maintaining a separate lightweight "thread" kernel object, creating a thread in Linux effectively creates a full process-like `task_struct`, with shared-resource semantics (address space, file descriptors) configured via flags rather than a fundamentally different underlying primitive.

## Practical reference

The dual-mode boundary and the syscall-as-gateway model described here is exactly what the `syscall` kernel-module LPE challenge in this collection's binary-exploitation folder exploits: a custom, insufficiently-validated syscall (`sys_upper`) is used as an arbitrary kernel-mode write primitive to hijack the syscall table itself and escalate privileges — a direct, practical application of the concepts summarized above.
