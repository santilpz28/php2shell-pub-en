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
| `php2shell_rce.py` | Escalation scaffold: mounts the real scenario and collects the trace |
| `patches/` | Idempotent patches that instrument PHP itself (session + allocator + dtor) |
| `web/` | Lab endpoints |

### Quick start

```bash
# Bring up vulnerable (8080) + patched (8081)
bash lab.sh

# Check exposure
./check_exposure.sh http://127.0.0.1:8080   # exit 1 → vulnerable
./check_exposure.sh http://127.0.0.1:8081   # exit 0 → patched

# Differential test
python3 behavioural_diff.py --url http://127.0.0.1:8080
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

The patches are applied **before compiling** and are idempotent: the target is
reproducible from scratch. Details in
[`NOTES-alloc-trace.md`](NOTES-alloc-trace.md).

---

## Remediation

**The patch is the only complete answer.** INI-level mitigations are partial
by design.

| Patched version | 8.2.35 · 8.3.36 · 8.4.27 · 8.5.12 |
|---|---|
| **PHP 7.4 / 8.0 / 8.1** | Outside the project's support cycle, but **PHP has published minimal source backports**. Update to your distro's package or apply the backport — do not stay on an EOL build as-is. |

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
