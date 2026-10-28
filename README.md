# PHP2Shell — Anatomy of CVE-2026-109618 / CVE-2026-109619

### From a use-after-free in PHP's session layer to unauthenticated RCE

**Chain-Cortex · JARVIS 🛡️** · 27 October 2026
**CVSS v4.0:** 9.2 (Critical) on both CVEs
**Status:** Active exploitation reported · Public PoCs available

---

> **This repository documents security research.** All work was performed
> against local Docker containers on `127.0.0.1`. No third-party system was
> tested. The material is published for defensive and research purposes.

---

## ⚠️ Status disclaimer — read before using this repository

This disclaimer was added **at the end of the work** so that nobody mistakes
"published code" for "verified exploitation chain". It does not imply that the
rest of the material was modified: the article, the PoCs and the scripts are
left as they are.

> **Later update:** the article **has** received a subsequent technical
> correction, documented in §10.11-bis: `zif_system` was shown **not** to be
> a valid gadget, because its real signature
> (`void (zend_execute_data *, zval *)`) is incompatible with `dtor_func_t`
> (`void (*)(zval *)`). That correction affects the RCE premise, not the UAF
> mechanism, which remains verified.

### What is verified end to end

| Artifact | Status |
|---|---|
| Analysis of the PHP 8.2.34 source code (`ext/session/session.c`) | ✅ Verified directly |
| Reading and cross-checking the official patch `31c0ea7d7ff` | ✅ Verified directly |
| Layout of `zend_internal_function` (size=136, `handler` at offset 72) | ✅ Verified with an `offsetof` program against `Zend/zend_compile.h` |
| Vulnerable/patched differential test (`behavioural_diff.py`) | ✅ Executed against real 8.2.34 and 8.2.35 |
| UAF mechanism with real addresses and real slot size | ✅ Measured in the instrumented binary |
| Size of the freed `zend_array` (56 B, bin 6) and its position in the pool (element 14, step 0x38) | ✅ Measured |
| Reuse of the freed slot by the next 56-byte allocation | ⚠️ 28.4 % per attempt (LIFO, per-page) |
| Mapping against the official advisory `GHSA-6wmf-4rv5-p3rp` (producer/consumer) | ✅ Cross-checked point by point |
| RCE PoC components (spray, timing, struct forging, offset extraction) | ✅ Implemented and verified separately |

### What is **not** verified

- **The full RCE chain was not reproduced end to end.** The
  `php2shell-rce:8.2.34` image compiles and serves traffic, but the request
  that chains OOM → UAF → forged `zend_array` → `system()` call never
  produced observable code execution in this environment.

- **The blocking issue is identified and measured, not an unknown.** The raw
  memory dump of the dangling array (§10.11-ter) shows that its last 24 bytes
  were overwritten by the allocator: `pDestructor` holds `arr + 0x50` and
  `arData` holds `arr + 0x30` — **self-referential garbage, not function
  pointers**. An earlier version of this README claimed that `pDestructor`
  kept `zval_ptr_dtor`; that was an inference and the measurement refuted
  it. The missing requirements are (a) that a 56-byte allocation lands
  exactly on the freed slot — reachable with spray, not with exact control —
  and (b) that this allocation **rebuilds** both the `pDestructor` at offset
  `0x30` and a valid `arData` at offset `0x10` with its bucket table and an
  `IS_STRING` bucket. See **§10.11-bis** and **§10.11-ter** of the article,
  and the raw logs under `evidence/`.

- **Therefore `php2shell_rce.py` and `php2shell_rce_exploit.py` are research
  scaffolding, not functional exploits.** Do not treat them as weaponizable.
  Their value is different: they run the real scenario and **report the state
  of the gadget on every attempt**, so progress is measurable and another
  researcher with a better-suited environment can continue from there.

- **The classic 288-byte spray from the public writeups does not work** for
  this mechanism (§10.6): a 56-byte spray with the required pointer precision
  was never modelled. No attacker-controlled allocation payloads were built.

- **The spray figures (149 × 288 bytes) come from Akamai's public analysis**,
  not from our own calibration. The layout of the forged structure was
  independently cross-checked against the PHP source code.

- **The functional detector (`behavioural_diff.py`) is the genuinely operational
  piece**: it discriminates vulnerable from patched by observable behaviour,
  with no offsets, no ASLR and no exploit execution. It is the recommended tool
  for inventorying exposure across a fleet.

### Operational warning

- **Do not run this outside an isolated environment.** The containers are
  deliberately configured with ASLR disabled, `mpm_prefork` and unpatched PHP
  8.2.34. That makes them vulnerable **on purpose**.
- **Audit any third-party PoC before running it.** It is documented (JFrog)
  that some public repositories for these CVEs distribute fake malicious
  payloads — in one case, a script that only changed the system wallpaper.
- **The article distinguishes in every section whether a claim is our own
  verification or public analysis.** If you cite it commercially, keep that
  distinction: it is what makes the work credible.

---

## What this is

On 21 October 2026, the PHP project published an emergency release fixing **two**
critical vulnerabilities in the **core** of the language:

| CVE | Type | Effect |
|---|---|---|
| **CVE-2026-109619** | Use-after-free in `session.upload_progress` | RCE + memory disclosure |
| **CVE-2026-109618** | Memory corruption via `longjmp()` on OOM | RCE + memory disclosure |

This is not an application bug: it is an interpreter bug. Any endpoint that
accepts a multipart upload is vulnerable even if your code is perfect. It
requires no authentication. And `session.upload_progress.enabled=On` has been
the factory default since PHP 5.

**This repository contains the complete technical article, the reproducible
lab, and the detection tooling.**

📄 **[Read the full article → `BLOG.md`](BLOG.md)** (1,400+ lines)

---

## The part almost nobody mentions

The chain **does not start with a use-after-free**. It starts with **memory
exhaustion**:

```
Request A  multipart with 1,500 empty nested uploads
              → ~536 KB of HTTP body exhausts PHP's 32 MB heap
              → zend_bailout() / longjmp() SKIPS the cleanup
              → shutdown_memory_manager() frees the heap
              → the worker survives with PS(id) and PS(http_session_vars) dangling

Request B  multipart with PHP_SESSION_UPLOAD_PROGRESS and NO file part
              → MULTIPART_EVENT_END → php_session_rfc1867_cleanup()
              → php_session_initialize() → zend_hash_del() on freed memory
              → USE-AFTER-FREE
```

This explains why the official patch replaces the `longjmp` with a soft error,
and why `pm.max_requests=1` breaks exploitability under PHP-FPM.

**And it has a practical consequence almost nobody states: the attack has no
timing.** The first description of the attack — *a network pause of more than
one second to let `session.upload_progress.min_freq` expire* — was
**incorrect**, and the experimentation in this work discarded it. The chain is
deterministic. **WAFs and rate limiters that look at request cadence do not
see this attack**, because there is no cadence to look at.

---

## Research status

| Result | Status | Evidence |
|---|---|---|
| OOM trigger with a small payload | ✅ Reproduced | 1,500 nested uploads → 536 KB → `Allowed memory size ... exhausted` |
| Use-after-free in Request B | ✅ Reproduced | 100 % of rounds |
| **UAF proven with addresses** | ✅ Reproduced | Instrumentation proves the consuming request operates on **exactly** the `zend_array` the previous request freed |
| Isolation of the responsible pointer | ✅ Reproduced | A/B controls: crashes with a different SID, disappears without `PHP_SESSION_UPLOAD_PROGRESS` → it is `PS(http_session_vars)` |
| OOM is necessary and sufficient | ✅ Reproduced | Without prior OOM: 0/4 crashes. Normal GET after OOM: 4/4 OK |
| Vulnerable/patched discrimination | ✅ Reproduced | 8.2.34: OOM 6/6 + UAF 6/6. 8.2.35: OOM 0/6 |
| **Real size of the freed slot** | ✅ Measured | `sizeof(zend_array) = 56 B` → **bin 6** of the allocator |
| **Bin 6 pool is predictable** | ✅ Measured | Contiguous progression of step 0x38; LIFO hit rate **28.4 %** per attempt |
| OPcache effect on the UAF's expression | ✅ Isolated | Same binary: with OPcache 0/6, without OPcache 6/6 |
| Controlled memory disclosure | ⚠️ Not achieved | The pointer is read and processed, but `ZSTR_LEN` stays at 32 |
| Full RCE | ❌ Not achieved | Blocking issue: reclaiming the slot with a forged 56-byte `zend_array` |

> **Honesty before the marque:** what is not reproduced here is not claimed.
> The article documents the difference precisely, instead of presenting as
> verified what comes from public literature.

### Why the public PoCs fail

A finding that departs from the literature and explains why the "classic"
288-byte spray **cannot possibly work** on PHP 8.2:

| Object | Size | Allocator bin |
|---|---|---|
| Session SID `zend_string` | 32 B | 3 |
| **Session `zend_array` (the slot to reclaim)** | **56 B** | **6** |
| "Classic" blob from the writeups | 288 B | **68** |

In Zend MM, small allocations are grouped into bins, and
`zend_mm_small_size_to_bin()` gives `bin = (size - !!size) >> 3` for
`size <= 64`. **Two different bins never share blocks.** The 288-byte spray
lives in bin 68 and can never touch the bin 6 slot. This is not a timing
problem, nor a precision problem, nor an ASLR problem. It is a **size class**
problem.

---

## Tooling

| File | What it does |
|---|---|
| `check_exposure.sh` | Single-pass exposure probe. `exit 1` = vulnerable, `exit 0` = patched |
| `behavioural_diff.py` | Differential vulnerable/patched test with A/B controls |
| `php2shell_leak.py` | UAF detector with negative controls |
| `php2shell_rce.py` | Escalation scaffold: mounts the real scenario and collects the trace. **⚠️ Work in progress — the full RCE chain was not reproduced end to end (see disclaimer above).** |
| `php2shell_rce_exploit.py` | The RCE attempt: drives the scenario and reports whether the `pDestructor == zif_system` gadget is in place. **⚠️ Does not produce code execution (see disclaimer above).** |
| `patches/` | Idempotent patches that instrument PHP itself (session + allocator + dtor site) |
| `web/` | Lab endpoints |

### Quick start

```bash
# Bring up vulnerable (8080) + patched (8081) + backport (8082)
docker compose up -d

# Check exposure
./check_exposure.sh http://127.0.0.1:8080   # exit 1 → vulnerable
./check_exposure.sh http://127.0.0.1:8081   # exit 0 → patched
./check_exposure.sh http://127.0.0.1:8082   # exit 0 → patched (backport)

# Differential test
python3 behavioural_diff.py 127.0.0.1 8080 "8.2.34 unpatched"
python3 behavioural_diff.py 127.0.0.1 8081 "8.2.35 official"
python3 behavioural_diff.py 127.0.0.1 8082 "8.2.34 + backport"
```

### Instrumented target

The target that records what happens inside the allocator:

```bash
docker build -f Dockerfile.trace -t php2shell-trace:8.2.34 .
docker run -d --name php2shell-trace -p 127.0.0.1:8084:80 \
  -v "$PWD/web:/var/www/html" --entrypoint /usr/sbin/apache2 \
  php2shell-trace:8.2.34 -D FOREGROUND

python3 php2shell_rce.py probe --port 8084 --records 1500

docker exec php2shell-trace cat /tmp/php2shell_trace.log   # session
docker exec php2shell-trace cat /tmp/php2shell_alloc.log   # allocator
docker exec php2shell-trace cat /tmp/php2shell_dtor.log    # dtor
```

### The RCE attempt

```bash
# Measured layout: where the gadget field is, and which size class matters
python3 php2shell_rce_exploit.py layout

# Drive the real OOM -> Request B scenario and check the gadget
python3 php2shell_rce_exploit.py run --port 8084
```

> ⚠️ **This is not a working exploit.** The RCE was not achieved. What the
> attempt does establish is precisely what is still missing: after the OOM,
> the dangling array's `pDestructor` does not even hold a function pointer:
> the raw dump (§10.11-ter) shows `arr + 0x50` there, i.e. self-referential
> garbage, with `arData` equally corrupted at `arr + 0x30`. The remaining
> requirement is therefore to land a 56-byte allocation in that exact slot
> that rebuilds **both** the `pDestructor` at offset `0x30` and a valid> `arData` at offset `0x10` with an `IS_STRING` bucket holding the command.

The gadget contract is real and verified in the source:

```c
typedef void (*dtor_func_t)(zval *pDest);   /* matches ZEND_FUNCTION(system) */

Zend/zend_hash.c:1701   ht->pDestructor(&p->val);
Zend/zend_hash.c:1757   if (ht->pDestructor != ZVAL_PTR_DTOR)
                            zend_hash_destroy(ht);
```

The patches are applied **before compiling** and are idempotent: the target is
reproducible from scratch. Details in
[`NOTES-alloc-trace.md`](NOTES-alloc-trace.md).

---

### Third target: patched WITHOUT changing the version

The three targets are built like this:

| Target | Version | How it is obtained |
|---|---|---|
| `php2shell-vuln:8.2.34` | 8.2.34 | `docker build -f Dockerfile -t php2shell-vuln:8.2.34 .` |
| `php2shell-patched:8.2.35` | 8.2.35 | `docker build -f Dockerfile.patched -t php2shell-patched:8.2.35 .` |
| `php2shell-backport:8.2.34` | **8.2.34** | `docker build -f Dockerfile.backport -t php2shell-backport:8.2.34 .` |

The third one is the interesting one: **the same version number as the
vulnerable one, the same extensions, the same ABI. Only the code changes.**
The official patch ("Avoid state corruption via bailout", `31c0ea7d7ff`) is
applied to the 8.2.34 source tree and recompiled.

```bash
docker compose up -d
python3 behavioural_diff.py 127.0.0.1 8080 "8.2.34 unpatched"
python3 behavioural_diff.py 127.0.0.1 8081 "8.2.35 official"
python3 behavioural_diff.py 127.0.0.1 8082 "8.2.34 + backport"

# Verify the patch fingerprint without looking at the version number
python3 verify_backport.py --container php2shell-backport
```

Measured result (6 rounds per target, evidence in `evidence/backport/`):

| Target | `php -v` | OOM | UAF consumed | Verdict |
|---|---|---|---|---|
| `:8080` | 8.2.34 | **6/6** | **6/6** (3 SIGSEGV + 3 stale SID) | VULNERABLE |
| `:8081` | 8.2.35 | 0/6 | 0/6 | PATCHED |
| `:8082` | **8.2.34** | 0/6 | 0/6 | **PATCHED** |

The backport produces the same behaviour as the official 8.2.35 without
touching the version number. Conflict details and the full procedure are in
[`patches/RESOLUTION-NOTES.md`](patches/RESOLUTION-NOTES.md).

---

## Remediation

**The patch is the only complete answer.** INI-level mitigations are partial
by design.

| Patched version | 8.2.35 · 8.3.36 · 8.4.27 · 8.5.12 |
|---|---|
| **PHP 7.4 / 8.0 / 8.1** | Outside the project's support cycle, but **PHP has published minimal source backports**. Update to your distro's package or apply the backport — do not stay on an EOL build as-is. |

### And if you cannot update the version

Updating PHP is the right thing to do, but it is not always possible: PECL
extensions compiled against a specific version, platform dependencies, or
certifications that pin the stack. In that case there is a fourth path:
**patching the code while keeping the version**.

The official patch is a *commit* (`31c0ea7d7ff`, "Avoid state corruption via
bailout"), not a binary. Applied on top of 8.2.34:

- The **upstream** commit on the 8.2 branch touches 423 files and rewrites
  the Zend MM allocator: it is not cherry-pickable onto 8.2.34 (conflicts in
  the core of the engine).
- The **EOL** branches (7.4, 8.0, 8.1) carry **the same fix reduced to its
  minimal form** (23 files). That one does apply on top of 8.2.34 with only 3
  code conflicts, all trivial.

```bash
docker build -f Dockerfile.backport -t php2shell-backport:8.2.34 .
python3 verify_backport.py --container php2shell-backport   # → PATCHED
```

The result: **same `php -v`, same extensions, same ABI.** That is the
difference between *patching* and *rewriting*.

> ⚠️ **Honest limitation.** The EOL branch backport is a **minimal
> mitigation**, not the full upstream fix. It permanently disables the
> `session.upload_progress` callback: that cuts the attack chain, but it also
> **disables a legitimate feature** (upload progress tracking). If your
> application uses it, that is an observable behaviour change. Procedure and
> conflict details: [`patches/RESOLUTION-NOTES.md`](patches/RESOLUTION-NOTES.md).

> ⚠️ **Correction (27-Oct-2026, 23:20):** earlier versions of this README
> claimed PHP 7.4 would be "vulnerable forever". **That is incorrect**: the
> PHP project published minimal backports for 7.4, 8.0 and 8.1. What is true
> is that those branches do not receive the regular development cycle, so
> updating depends on your distro or on applying the backport by hand.
> Verified against the NCSC-NL advisory and the official advisory
> `GHSA-6wmf-4rv5-p3rp`.

Partial mitigations (defence in depth, not a substitute for the patch):

```ini
; Recommended by the PHP project itself (23-Oct-2026 advisory)
session.upload_progress.enabled = 0

; Cuts the OOM trigger (not the UAF)
max_multipart_body_parts = 2000
max_file_uploads = 100

; Reduces the impact of the UAF
pm.max_requests = 1        ; breaks the "same worker" requirement (FPM only)
```

> **CVE-2026-115560.** On 23 October, PHP published an informational advisory
> about a residual RCE vector (unlikely in practice: it requires
> `session.serialize_handler` = `php_binary`/`php_serialize` and then switching
> it to `php` at runtime with `ini_set()` before `session_start()`).
> The mitigation recommended by the project is
> `session.upload_progress.enabled=0` until the next regular release.
> **The official advisory `GHSA-6wmf-4rv5-p3rp` already listed that
> mitigation as of 21 October.**

> ⚠️ **Do not disable OPcache in production.** With OPcache the UAF may
> manifest silently instead of as a SIGSEGV. That is **worse**: it does not
> give the failure away. It is only disabled in the lab, for reproducibility.

---

## On reproducibility

- All work was done against **local Docker containers**.
- Targets use PHP 8.2.34 (vulnerable) and 8.2.35 (patched).
- The instrumented target is built from PHP source via `Dockerfile.trace`; it
  takes ~20 min (the build deliberately does **not** use `-j`: with `-j` the
  `libphp.so` linker consumes >2 GB and the build dies with OOM).
- `apache2` runs with ASLR **enabled** in the current containers: `setarch -R`
  requires privileges Docker does not grant by default. The measured
  addresses are relative to the base of each run.

---

## Cite this work

```bibtex
@misc{php2shell_chaincortex_2026,
  title  = {PHP2Shell — Anatomy of CVE-2026-109618 and CVE-2026-109619},
  author = {Santiago L{\'o}pez (Chain-Cortex)},
  year   = {2026},
  url    = {https://github.com/santilpz28/php2shell-pub-en},
  note   = {Security research. Defensive use.}
}
```

## License

MIT · © 2026 Chain-Cortex
