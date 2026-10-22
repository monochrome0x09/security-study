# Selected Security Case Studies

The cases below were selected for methodological clarity, root-cause analysis, and defensive conclusions. Cases 1–5 concern intentionally vulnerable **authorized training targets**. Case 6 is different: it documents **original, independently discovered vulnerabilities in real, published WordPress plugins**, reported through WPScan's coordinated-disclosure process.

## 1. Web applications: dangerous sinks and trust boundaries

- **Technical write-up:** [Web CTF: SSTI, SQLi, SSRF and injection](web-exploitation/01-web-ctf-writeup.md)
- **Original Korean record:** [2025-08-05](https://lambda-c.tistory.com/31)
- **Analysis:** Several Flask training problems illustrate what happens when untrusted input reaches template evaluation, interpolated SQL, command execution, or internal HTTP requests. The analysis distinguishes the injection's root cause from the weaknesses in blacklists or denylist filters.
- **Defensive lessons:** Render untrusted content as template data, parameterize SQL, avoid shell interpolation, validate resolved network destinations, and apply egress controls.

## 2. Stack canaries: distinguish bypass from a separate vulnerability

- **Technical write-up:** [Stack Canary Leak and Bypass](binary-exploitation/08-stack-canary-leak-and-bypass.md)
- **Original Korean record:** [2025-11-05](https://lambda-c.tistory.com/40)
- **Analysis:** Training binaries combine out-of-bounds memory operations, information disclosure, and protection settings. The write-up makes clear that a leaked canary alone does not guarantee a complete exploit chain.
- **Defensive lessons:** Fix unsafe input bounds; use NX, PIE/ASLR and RELRO as complementary mitigations. The unsuccessful final chain in HSPACE Chall 6 is preserved as an explicit partial result.

## 3. Return-to-libc: NX is not a substitute for memory safety

- **Technical write-up:** [Return-to-libc (ret2libc)](binary-exploitation/09-return-to-libc-ret2libc.md)
- **Original Korean record:** [2025-08-12](https://lambda-c.tistory.com/32)
- **Analysis:** A fixed-size stack buffer and an overlong read are the underlying defect. The case is used to distinguish the memory-safety failure from the exploitation path in a binary with specific mitigation settings.
- **Defensive lessons:** Enforce input length at the source and add platform-appropriate protections such as PIE/ASLR, control-flow integrity, and shadow stacks where available.

## 4. ROP and GOT: evaluate how protections interact

- **Technical write-up:** [ROP Techniques](binary-exploitation/10-rop-ret2libc-and-ret2main.md)
- **Original Korean record:** [2025-11-17](https://lambda-c.tistory.com/42)
- **Analysis:** The training cases relate information disclosure, address-space layout and writable dynamic-linkage state to the effects of runtime mitigations.
- **Defensive lessons:** Full RELRO addresses writable-GOT risks, while NX alone does not remove all code-reuse risks; source-level removal of memory corruption remains essential.

## 5. LLM and Python security: unreliable behavioral or lexical boundaries

- **Technical write-up:** [Mixed CTF: LLM security and Python evaluator](misc-ctf/01-ctf-writeup-misc-challenges.md)
- **Original Korean record:** [2025-11-16](https://lambda-c.tistory.com/41)
- **Analysis:** Training challenges illustrate why prompt text is not a dependable authorization boundary and why a restricted character set is not equivalent to a restricted interpreter. The original chatbot record explicitly notes that an observed result was not reliably repeatable.
- **Defensive lessons:** Keep secrets outside model-visible untrusted contexts; do not execute untrusted Python expressions via `eval()`; choose narrowly scoped parsers with explicit allowed grammars.

## 6. Real-world responsible disclosure: WordPress plugin vulnerabilities

- **Technical write-up:** [Two WordPress plugin vulnerabilities submitted to WPScan](responsible-disclosure/01-wordpress-plugin-vulnerability-disclosures.md)
- **Targets:** reCAPTCHA for MW WP Form (CAPTCHA bypass, WPScan submission #56579) and Under Construction (role-restriction bypass, WPScan submission #56580) — both currently-published WordPress.org plugins, reviewed only in a local, self-hosted lab.
- **Analysis:** A `isset()`-vs-truthiness mismatch between two code paths that read the same POST field lets an attacker skip Google reCAPTCHA verification with one extra, falsy field. Separately, a role-restriction feature is wired to the wrong WordPress action hooks, so it never actually gates the front-end request path it is meant to protect.
- **Verification standard:** both findings were reproduced against the plugin's real front-end invocation path at the privilege level claimed, not via `wp eval`/direct database manipulation — the exact standard that caused an earlier, unrelated candidate finding in this research pass to be retracted before submission.
- **Evidence:** WPScan's own confirmation emails (submission IDs, titles, and triage priority) are quoted in the write-up.
- **Defensive lessons:** Never let a client-supplied field skip a security check by presence alone — check it the same way the rest of the application does; make sure every access-control check is wired onto the request path it is actually meant to protect.

## Separate defensive engineering project: SSH Log Analyzer

The **SSH Log Analyzer** is a private **collaborative Python project**, not one of the CTF case studies above.

- **Purpose:** Structure OpenSSH authentication logs, aggregate failures by source and account, and identify repeated-failure patterns for human review.
- **My responsibilities:** Core parser and analysis engine, CLI and output formats, validation, regression tests, packaging, and deployment verification.
- **Collaborator's responsibilities:** Authorized cloud test environment, anonymized-log collection and experiments, threshold/time-of-day comparisons, visualizations, and performance/limitations study.
- **Historical verification:** August 2026 project notes record 139 passing regression tests, authorized Ubuntu/OpenSSH cloud checks, and analysis/output verification using a 90-line journal sample. These results were not re-run for this write-up.
- **Limitations:** Some live log variants were not reproduced; experimental result integration was still pending in the last recorded status. No measured accuracy/false-positive-rate claim is made without labeled ground truth.
- **Privacy:** The source repository and internal coordination records are private; this public summary omits source links, raw logs, host/IP identifiers, credentials, and the collaborator's identity.

## Scope statement

The dated Korean source posts establish an activity timeline; this English collection is a later editorial consolidation. CTF/wargame solutions demonstrate security reasoning **in intentionally vulnerable learning environments**, while SSH Log Analyzer demonstrates **defensive software construction and testing in an authorized environment**. The responsible-disclosure case (Case 6) is the exception to both: it is original vulnerability research against real, published software, submitted to WPScan as described in that write-up's evidence section.