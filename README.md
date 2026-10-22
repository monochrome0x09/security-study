# Security Study Portfolio

A curated, English-language collection of cybersecurity studies, authorized wargame/CTF write-ups, and defensive engineering experience. The original Korean notes were published over time on [Lambda's Notebook](https://lambda-c.tistory.com/); this GitHub repository was subsequently reorganized for easier technical review.

The material covers binary exploitation, reverse engineering, web security, AI/LLM security, a separate collaborative OpenSSH-log analysis tool, and original responsible-disclosure research against published WordPress plugins. **The CTF/wargame training challenges are not presented as independently discovered real-world vulnerabilities; the `responsible-disclosure/` material is.**

## Source chronology and verification

The English collection was initially committed on **2026-10-11**, but the Korean source notes predate that consolidation. Representative dated posts include:

- [2025-08-05 — Web CTF analyses](https://lambda-c.tistory.com/31)
- [2025-08-12 — Return to Library](https://lambda-c.tistory.com/32)
- [2025-10-26 — Shellcode/ORW training](https://lambda-c.tistory.com/37)
- [2025-11-05 — Stack canary exercises](https://lambda-c.tistory.com/40)
- [2025-11-16 — Mixed CTF and LLM-security exercises](https://lambda-c.tistory.com/41)
- [2025-11-17 — ROP training](https://lambda-c.tistory.com/42)

These blog posts document the **earlier study chronology**; the English documents are edited and reorganized versions, not new vulnerability discoveries dated to October 2026.

## Selected case studies

The following five case studies emphasize **root-cause reasoning and defensive remediation** rather than the number of challenges solved. Expanded summaries and evidence links are in [CASE_STUDIES.md](CASE_STUDIES.md).

| Case | English technical analysis | Defensive takeaway | Dated original |
|---|---|---|---|
| Web vulnerability chains | [SSTI, SQLi, SSRF and injection analysis](web-exploitation/01-web-ctf-writeup.md) | Treat user input as data; parameterize queries and enforce outbound network restrictions | [2025-08-05](https://lambda-c.tistory.com/31) |
| Stack canary and data disclosure | [Stack canary and memory-error exercises](binary-exploitation/08-stack-canary-leak-and-bypass.md) | Use bounded I/O and complementary memory mitigations; disclose incomplete results | [2025-11-05](https://lambda-c.tistory.com/40) |
| Return-to-libc | [Memory-safety root cause under NX](binary-exploitation/09-return-to-libc-ret2libc.md) | Correct the underlying buffer overflow; combine PIE/ASLR and control-flow protections | [2025-08-12](https://lambda-c.tistory.com/32) |
| ROP and GOT hardening | [ROP, ret2main and GOT behavior](binary-exploitation/10-rop-ret2libc-and-ret2main.md) | Understand RELRO, NX and defense-in-depth | [2025-11-17](https://lambda-c.tistory.com/42) |
| LLM and Python evaluator security | [Prompt security and expression-evaluation challenges](misc-ctf/01-ctf-writeup-misc-challenges.md) | Do not treat prompts or string filters as robust security boundaries | [2025-11-16](https://lambda-c.tistory.com/41) |

## Responsible disclosure — real WordPress plugin vulnerabilities

Separate from the CTF case studies above, [`responsible-disclosure/01-wordpress-plugin-vulnerability-disclosures.md`](responsible-disclosure/01-wordpress-plugin-vulnerability-disclosures.md) documents **original vulnerability research against two currently-published WordPress plugins**: a CAPTCHA-validation bypass in reCAPTCHA for MW WP Form (CWE-290) and a broken-access-control bug in Under Construction (CWE-862). Both were discovered by manual source review, reproduced end-to-end in a local, self-hosted lab against a real lower-privileged request flow, and submitted through WPScan's official vulnerability submission form. The write-up includes the full technical analysis, PoC methodology, and WPScan's own confirmation emails (submissions **#56579** and **#56580**) as evidence that both were genuinely reported.

## Defensive engineering — SSH Log Analyzer (collaborative)

**SSH Log Analyzer** is a separate, privately developed Python defensive tool for interpreting OpenSSH authentication events and flagging potentially suspicious repeated authentication failures or account-guessing patterns. It was a **two-person project**, distinct from the training write-ups in this repository.

**My contribution:** implementation and verification of the authentication-event parser and analyzer; IPv4/IPv6 and password/public-key log handling; IP/account aggregation; configurable time-window analysis; CLI, console/JSON/CSV outputs, input/output safeguards; automated regression tests, package build, and Ubuntu deployment checks.

**Teammate's contribution:** an authorized Ubuntu cloud test environment; anonymized real-log experiments; time-of-day and detection-threshold comparisons; charts, performance measurements, and assessment of detection limitations.

**Evidence and status:** In the reviewed August 2026 project records, the core analyzer had a **139-test passing regression baseline**, was installed and verified in an authorized Ubuntu/OpenSSH environment, and produced console, JSON, and CSV results from an actual 90-line journal sample. These are historical recorded results **not independently re-run for this publication**. Some unusual OpenSSH log variants were not reproduced during live tests; a later experimental-results integration had not yet been completed in the last reviewed status. Without labeled ground truth, no measured general detection accuracy or false-positive rate is claimed.

The project's GitHub source and internal records remain private. No raw authentication logs, identifying IP addresses, hostnames, credentials, private documentation URLs, or teammate personal information are published here. This project represents **defensive implementation and testing**, not a CVE or a production-vulnerability disclosure.

## Contents

| Folder | Scope | Skills demonstrated |
|---|---|---|
| [`binary-exploitation/`](binary-exploitation/) | Pwnable/binary exploitation: x86/x86-64 architecture and shellcode fundamentals, stack buffer overflows, stack canary leak/bypass, return-to-libc, and ROP-based (GOT overwrite, ret2main) exploitation chains. | Vulnerability root-cause analysis (CWE-mapped), exploit development with `pwntools`, mitigation-bypass reasoning (NX, ASLR/PIE, RELRO, canaries, seccomp), defensive remediation design. |
| [`reverse-engineering/`](reverse-engineering/) | Computer architecture and process memory layout, calling conventions, GDB and IDA Pro/Ghidra tooling, and a large set of CTF crackme write-ups (custom ciphers, S-box recovery, anti-analysis techniques, kernel fundamentals). | Static and dynamic analysis methodology, disassembly-level reasoning, cipher/transform inversion, tool-assisted automation (Ghidra/pyhidra scripting), binary patching. |
| [`web-exploitation/`](web-exploitation/) | Web application security: Server-Side Template Injection, SQL injection (including WAF/denylist bypass), Server-Side Request Forgery, and OS command injection across several Flask-based CTF targets. | Source-to-sink vulnerability tracing, exploit chaining across multiple bug classes, secure-coding remediation (parameterized queries, safe templating APIs, resolved-IP allow-listing). |
| [`misc-ctf/`](misc-ctf/) | Challenges that don't fit a single category: infrastructure information disclosure, LLM prompt-injection/jailbreak, and a Python `eval()` sandbox escape. | Adjacent/emerging security domains — AI/LLM security reasoning, language-level sandbox-escape analysis, operational-security hygiene. |
| [`responsible-disclosure/`](responsible-disclosure/) | Original vulnerability research against real, published WordPress plugins: a CAPTCHA-bypass and an access-control bypass, both submitted to WPScan. | End-to-end vulnerability research — low-noise target discovery, manual source audit, real-invocation-path PoC reproduction, CVSS scoring, and coordinated disclosure through a vendor-neutral VDB. |

Each write-up follows a consistent structure — **Overview → Vulnerability Analysis → Exploitation Methodology → Defensive Remediation** (foundational/reference-style notes instead follow **Concept → Why it matters → Key technical details → Practical reference**) — so that root-cause identification, proof-of-concept reasoning, and mitigation design are each clearly separable for review.

## Scope & Disclaimer

The four CTF-oriented topic directories (`binary-exploitation/`, `reverse-engineering/`, `web-exploitation/`, `misc-ctf/`) document **intentionally vulnerable wargame and CTF targets**, including Dreamhack, pwnable.tw, pwnable.kr, Layer7 CTF, and self-hosted CTFd instances. They are educational analyses in authorized training environments and do **not** represent independently discovered production vulnerabilities. The separately described SSH Log Analyzer project involved legitimate defensive log analysis in an authorized server environment, rather than vulnerability discovery or offensive testing of third-party infrastructure. Flag values, credentials, and challenge-specific secrets in source excerpts are public training data or have been redacted where appropriate.

The `responsible-disclosure/` directory is different in kind: it documents **original, independently discovered vulnerabilities in real, currently-published WordPress plugins**, reviewed only in a local, self-hosted lab never exposed to or run against any third party's infrastructure, and reported through WPScan's official coordinated-disclosure process rather than disclosed publicly here first.