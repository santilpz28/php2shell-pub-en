# PHP2Shell — Publication Notes

**Repository:** https://github.com/santilpz28/php2shell-pub-en
**Article:** [`BLOG.md`](BLOG.md) · **Logbook:** [`NOTES-alloc-trace.md`](NOTES-alloc-trace.md)

---

## Repo description (copy into GitHub → Settings → General)

```
Anatomy of CVE-2026-109618 / CVE-2026-109619: a use-after-free in PHP's
session layer (CVSS 9.2). Chain-Cortex research with a reproducible Docker
lab, an exposure detector, and the real mechanism verified against the
PHP 8.2.34 source.
```

## Topics (GitHub → Settings → Topics)

```
php security cve rce use-after-free vulnerability-research heap chain-cortex
```

---

## Social

### LinkedIn (long post)

**Title:** PHP2Shell: two 9.2 CVEs in the PHP core. And why "update PHP" is not always the answer.

**Body:**

> On October 21, the PHP project published an emergency release that fixed two critical vulnerabilities in the **core** of the language:
>
> | CVE | Effect |
> |---|---|
> | **CVE-2026-109619** | RCE + memory disclosure (use-after-free in `session.upload_progress`) |
> | **CVE-2026-109618** | RCE + memory disclosure (corruption via OOM) |
>
> CVSS v4.0: **9.2** for both.
>
> What makes this not "just another bug":
>
> **1. It is not an application bug.** It is in the interpreter. Any endpoint that accepts a multipart upload is vulnerable, even if your code is impeccable.
>
> **2. No authentication.** There is no login to bypass.
>
> **3. Vulnerable default configuration.** `session.upload_progress.enabled=On` has been the factory default since PHP 5.
>
> **4. PHP 7.4, 8.0 and 8.1 are out of the regular cycle.** PHP published minimal source-code backports, but not the regular release cycle: updating depends on your distro.
>
> CISA, Cisco, Akamai, Vercel, Laravel, Autodesk, IC3 and CERT-EU published advisories the same day. There are indications of active exploitation.
>
> **Patched versions:** 8.2.35 · 8.3.36 · 8.4.27 · 8.5.12
>
> ---
>
> What kept us busy: **the real mechanism is not the one described by most of the literature.**
>
> We set up a lab with the vulnerable and the patched build, instrumented PHP itself and measured.
>
> **The finding:** the chain does not start with a use-after-free. It starts with a **memory exhaustion**.
>
> ```
> Request A → 1.500 empty nested uploads → ~536 KB HTTP body
>           → exhausts PHP's 32 MB heap
>           → zend_bailout() / longjmp() SKIPS cleanup
>           → the heap is freed, the worker survives with dangling pointers
>
> Request B → multipart with PHP_SESSION_UPLOAD_PROGRESS and NO file part
>           → MULTIPART_EVENT_END → php_session_rfc1867_cleanup()
>           → php_session_initialize() → zend_hash_del() over freed memory
>           → USE-AFTER-FREE
> ```
>
> Three consequences that do not show up in the writeups:
>
> **① The attack has no rhythm.** The first description —"a network pause of more than one second for `session.upload_progress.min_freq` to expire"— was **incorrect**, and experimentation ruled it out. The chain is deterministic. **WAFs and rate limiting that look at the cadence do not see this attack**, because there is no cadence to look at. Neither does one that limits the *body size*: ~536 KB is enough. One that limits the **number of nested files**, yes.
>
> **② Instrumenting the binary is what turns the hypothesis into proof.** We inserted two traces in `ext/session/session.c` and Request B turned out to operate on **exactly** the `zend_array` that Request A freed — same address, with the refcount and flags already corrupted. Not inferred: measured.
>
> **③ Why the public PoCs fail.** `sizeof(zend_array) = 56 bytes` → **bin 6** of the Zend MM allocator. The 288-byte blob the writeups use lives in **bin 68**. Two bins never share blocks. It is not timing, it is not precision, it is not ASLR: it is **size class**. Instrumenting the allocator we saw that the bin 6 pool is a contiguous progression with a 0x38 step — the slot is predictable — and that the LIFO allocation hits **28.4 %** of the time per attempt.
>
> And this last point validates the entire body of work: the official PHP advisory (`GHSA-6wmf-4rv5-p3rp`) describes exactly this abstract model —*"global state retained by a worker but pointing to memory owned by one request"*, *"a fatal error, including one caused by memory exhaustion"*, producer and consumer in different requests of the same worker. The session branch we measured is a concretization of that model. The vendor and the lab reached the same place by different paths.
>
> **What was NOT achieved, and we say so:** full RCE. We failed to reclaim the freed slot with a forged `zend_array`. What we did establish is that the remaining blocker is **allocator control**, not timing — and why the classic spray cannot work. It is all documented, with the evidence.
>
> We publish the complete lab: reproducible Docker, the idempotent patches that instrument PHP itself, an exposure detector that discriminates vulnerable from patched **without running exploits and without needing offsets**, and the technical article with the A/B controls and the disassembly.
>
> → https://github.com/santilpz28/php2shell-pub
>
> ---
>
> **And one note that came out of the public debate: "update PHP" is not always the answer.**
>
> The instinctive reaction to a 9.2 CVE is "upgrade to the latest version". But in real fleets that collides with compiled PECL extensions, with platform dependencies and with years of customisation. And there is a fourth route almost nobody mentions: **patching the code while keeping the version**.
>
> We tested it. The official patch is a *commit* —"Avoid state corruption via bailout"— available as source code, not as a binary. Applied on top of 8.2.34, on a build that "still says 8.2.34" and with the same compiled extensions:
>
> - The upstream commit on the 8.2 branch touches **423 files** and rewrites the Zend MM allocator: it is not cherry-pickable, it conflicts in the core of the engine.
> - The EOL branches (7.4, 8.0, 8.1) carry **the same fix reduced to its minimal form** (23 files). That one does apply on top of 8.2.34 with only 3 code conflicts, all trivial.
> - One of those conflicts is a **function redefinition that `git apply` does not detect** and that only shows up at compile time. We documented it entirely, with the detail of what was resolved and why.
>
> Measured result, three targets, six rounds each:
>
> | Target | `php -v` | OOM | UAF | Verdict |
> |---|---|---|---|---|
> | A | 8.2.34 | 6/6 | 6/6 | VULNERABLE |
> | B | 8.2.35 | 0/6 | 0/6 | PATCHED |
> | C | **8.2.34** | 0/6 | 0/6 | **PATCHED** |
>
> Same version number, same extensions, same ABI. Only the code changed.
>
> The golden rule: *patch, do not rewrite*. And if you can neither update nor patch: `session.upload_progress.enabled=0`, bounded `max_multipart_body_parts` and `max_file_uploads`, and blocking `multipart/form-data` at the web server.
>
> ⚠️ With honesty: the EOL branch backport is a **minimal mitigation**, not the full upstream fix. It permanently disables the `session.upload_progress` callback — it cuts the chain, but it also turns off upload progress tracking. That is the trade-off of patching when you cannot update.
>
> If your fleet runs PHP 7.4/8.0/8.1, or you cannot update within 48 h, let's talk: we build an exposure inventory with that differential test. →
>
> #cybersecurity #php #securityresearch #vulnerability #CVE #RCE #pentesting #appsec #infosec #chaincortex

---

### Twitter / X (thread)

```
1/ PHP2Shell: two 9.2 CVEs in the PHP core (CVE-2026-109618 / -109619).
RCE without authentication on any endpoint that accepts multipart uploads.
Your code can be perfect and still be vulnerable. 🧵

2/ The interesting part: the real mechanism is NOT the one described by most
of the literature. The chain does not start with a UAF, it starts with an OOM.

Request A → 1.500 empty nested uploads → ~536 KB → exhausts the 32 MB PHP heap
→ zend_bailout() skips cleanup → heap freed, worker stays alive

3/ Request B → multipart with PHP_SESSION_UPLOAD_PROGRESS and NO file part
→ MULTIPART_EVENT_END → php_session_rfc1867_cleanup() → php_session_initialize()
→ zend_hash_del() over already freed memory → USE-AFTER-FREE

4/ Practical consequence: the attack has NO rhythm. It is deterministic.
WAFs that look at request cadence do not see it.
Neither does one that limits the body size: 536 KB is enough.
One that limits the NUMBER of nested files, yes.

5/ We instrumented PHP itself (idempotent patches over session.c).
Request B operates on EXACTLY the zend_array that Request A freed.
Same address, refcount and flags already corrupted. Not inferred: measured.

6/ Why the public PoCs fail: sizeof(zend_array) = 56 B → bin 6 of the
allocator. The 288 B blob from the writeups lives in bin 68. Two bins never
share blocks. It is not timing, nor precision, nor ASLR: it is size class.

7/ Instrumenting the allocator: the bin 6 pool is a contiguous progression
with a 0x38 step → the slot is predictable. LIFO allocation: 28,4 % hit rate
per attempt. The remaining blocker is allocator control, not timing.

8/ What we did NOT achieve: full RCE. We could not reclaim the slot with a
forged zend_array. It is documented as such, with the evidence.

9/ The vendor and the lab reached the same place by different paths:
the official advisory (GHSA-6wmf-4rv5-p3rp) describes exactly this abstract
model — producer and consumer, different requests, same worker.

10/ And one note from the public debate: "update PHP" is not always the
answer. The official patch is a SOURCE COMMIT, not a binary → it can be
applied keeping version, extensions and ABI.

11/ The upstream 8.2 commit touches 423 files and is not cherry-pickable.
The EOL branches (7.4/8.0/8.1) carry the SAME fix in 23 files → that one
does apply on 8.2.34 with only 3 conflicts, all trivial.

12/ Measured, 3 targets × 6 rounds:
A: 8.2.34 → OOM 6/6, UAF 6/6 → VULNERABLE
B: 8.2.35 → OOM 0/6, UAF 0/6 → PATCHED
C: 8.2.34 → OOM 0/6, UAF 0/6 → PATCHED

Same `php -v` on A and C. Only the code changed.

13/ One of the 3 conflicts is a FUNCTION REDEFINITION that `git apply` does
NOT detect: the failure only appears at compile time. We documented it all.

Golden rule: patch, do not rewrite.

14/ Complete lab: reproducible Docker, exposure detector that discriminates
vulnerable from patched WITHOUT running exploits or needing offsets.

https://github.com/santilpz28/php2shell-pub
```

---

## Newsletter (option B)

**Subject:** PHP2Shell — urgent exposure audit for PHP

**Body:**

> On October 21, 2026, PHP published an emergency release fixing two critical vulnerabilities (CVSS 9.2) in the **core** of the language: CVE-2026-109619 (use-after-free) and CVE-2026-109618 (memory corruption via exhaustion). Both allow remote code execution **without authentication**.
>
> What matters for your organization:
>
> - **The flaw is in PHP, not in your application.** Your code can be correct and the server still be exploitable. A code audit does not cover this.
> - **A default requirement.** `session.upload_progress.enabled=On` ships enabled out of the box. All you need is an endpoint that accepts uploads.
> - **Double impact:** command execution and reading of process memory, which can expose data of other users sharing the worker (Heartbleed pattern).
> - **PHP 7.4 / 8.0 / 8.1 are out of the regular cycle.** PHP published minimal source-code backports, but without periodic releases: updating depends on your distro.
> - **A WAF that looks at the pace or the body size will not stop it.** The chain is deterministic; what does limit it is the number of nested files.
> - **If you cannot update the version, you can patch while keeping it.** The official patch is a source commit, not a binary: it can be applied on your build keeping version, extensions and ABI. We verified it (6/6 UAF unpatched, 0/6 patched, identical `php -v`).
>
> **What to do:**
>
> 1. Inventory the actual PHP version in use (not the package version).
> 2. Update to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 and restart all workers.
> 3. For 7.4 / 8.0 / 8.1: plan a migration or apply the PHP backport.
> 4. If you cannot update immediately: `session.upload_progress.enabled=0` (the official PHP mitigation, with partial coverage) and bounded `max_multipart_body_parts` / `max_file_uploads`.
> 5. If you can neither update nor patch: block `multipart/form-data` at the web server.
> 6. Review logs looking for `PHP_SESSION_UPLOAD_PROGRESS` in multipart requests and anomalous activity in `session.save_path`.
>
> **Chain-Cortex proposal:** PHP2Shell exposure audit for your fleet — version inventory, exposure verification with a differential test over non-intrusive services, and remediation validation. The detector we use distinguishes vulnerable from patched without needing to run exploits or know binary offsets.
>
> Full technical detail, with reproducible lab:
> https://github.com/santilpz28/php2shell-pub
>
> —
> *Chain-Cortex · Smart Contract Auditors and Web 2.5 Security Architects*

---

## Publication checklist

- [x] Public repository created: `santilpz28/php2shell-pub-en`
- [x] Full article in `BLOG.md` (sections 1-11 + appendices)
- [x] README as landing page with status, tools and remedies
- [x] `CITATION.cff` + BibTeX block
- [x] `NOTES-alloc-trace.md` with the instrumentation logbook
- [x] Idempotent patches (`patches/`) and instrumented target (`Dockerfile.trace`)
- [x] Exposure detector (`check_exposure.sh`, `behavioural_diff.py`)
- [ ] **Repo description** (Settings → General) — text above
- [ ] **Topics** (Settings → Topics) — list above
- [ ] **LinkedIn post** published
- [ ] **Twitter/X thread** published
- [ ] **Newsletter** sent
- [ ] **Add the repo to `chainguard-pages` / CV** with link
- [ ] **Next milestone: escalate to RCE** (allocator control over the bin 6 slot)

---

## Precision note (important for future posts)

An earlier version of this material claimed that **"PHP 7.4 is EOL and unpatched,
vulnerable forever"**. **That is incorrect** and it has been corrected in the
README and the BLOG on 27-Oct-2026 at 23:20: the PHP project published minimal
source-code backports for 7.4, 8.0 and 8.1 (verified against the NCSC-NL
advisory and `GHSA-6wmf-4rv5-p3rp`). What is true is that those branches do
not receive the regular release cycle.

Before publishing any claim about the support status of a version, verify it
against the primary source. In a public article, a strong and wrong claim
costs more credibility than it adds.
