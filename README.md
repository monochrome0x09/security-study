# Security Study Portfolio

A curated, English-language portfolio of security wargame and CTF write-ups and technical study notes, originally authored in Korean on a personal security-research blog ("Lambda's Notebook") and reorganized by topic for review purposes. The material spans binary exploitation, reverse engineering, web exploitation, and miscellaneous CTF challenges spanning infrastructure and AI/LLM security.

## Contents

| Folder | Scope | Skills demonstrated |
|---|---|---|
| [`binary-exploitation/`](binary-exploitation/) | Pwnable/binary exploitation: x86/x86-64 architecture and shellcode fundamentals, stack buffer overflows, stack canary leak/bypass, return-to-libc, and ROP-based (GOT overwrite, ret2main) exploitation chains. | Vulnerability root-cause analysis (CWE-mapped), exploit development with `pwntools`, mitigation-bypass reasoning (NX, ASLR/PIE, RELRO, canaries, seccomp), defensive remediation design. |
| [`reverse-engineering/`](reverse-engineering/) | Computer architecture and process memory layout, calling conventions, GDB and IDA Pro/Ghidra tooling, and a large set of CTF crackme write-ups (custom ciphers, S-box recovery, anti-analysis techniques, kernel fundamentals). | Static and dynamic analysis methodology, disassembly-level reasoning, cipher/transform inversion, tool-assisted automation (Ghidra/pyhidra scripting), binary patching. |
| [`web-exploitation/`](web-exploitation/) | Web application security: Server-Side Template Injection, SQL injection (including WAF/denylist bypass), Server-Side Request Forgery, and OS command injection across several Flask-based CTF targets. | Source-to-sink vulnerability tracing, exploit chaining across multiple bug classes, secure-coding remediation (parameterized queries, safe templating APIs, resolved-IP allow-listing). |
| [`misc-ctf/`](misc-ctf/) | Challenges that don't fit a single category: infrastructure information disclosure, LLM prompt-injection/jailbreak, and a Python `eval()` sandbox escape. | Adjacent/emerging security domains — AI/LLM security reasoning, language-level sandbox-escape analysis, operational-security hygiene. |

Each write-up follows a consistent structure — **Overview → Vulnerability Analysis → Exploitation Methodology → Defensive Remediation** (foundational/reference-style notes instead follow **Concept → Why it matters → Key technical details → Practical reference**) — so that root-cause identification, proof-of-concept reasoning, and mitigation design are each clearly separable for review.

## Scope & Disclaimer

All work in this repository was performed against **intentionally vulnerable wargame and CTF targets** — including Dreamhack, pwnable.tw, pwnable.kr, Layer7 CTF, and self-hosted CTFd instances — for educational purposes in authorized training environments. No production systems, third-party infrastructure, or real-world targets were accessed or tested at any point. Flag values, credentials, and challenge-specific secrets appearing in source code excerpts are either already public (part of published wargame materials) or have been redacted where the original source material redacted them.
