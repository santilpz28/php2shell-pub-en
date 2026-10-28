# Backport resolution notes — PHP2Shell on PHP 8.2.34

Reference document for the backport process of the official
"Avoid state corruption via bailout" patch onto **PHP 8.2.34**, without
changing the version. Everything below is empirically verified (see
"Reproduction" at the end).

---

## 1. Which commits exist

| Commit | Branch | Files | What it is |
|---|---|---|---|
| `31c0ea7d7ff1d1fccb6492e52dab544011628065` | `PHP-8.2` (upstream) | **423** | Full fix. Rewrites the Zend MM allocator. Tagged `php-8.2.35`. |
| `01a40e89fb…` | `PHP-8.2.35` | — | Cherry-pick of the above onto the release tag. |
| `3c832b523e…` | `PHP-8.3.36` | — | Same for 8.3. |
| `506e87fa7d…` | `PHP-8.4.27` | — | Same for 8.4. |
| `3584a98bda…` | `PHP-8.3`/`8.4`/`8.5` | — | Backport of the full fix onto the development branches. |
| `1d7dec178a094e6e75b229ce22754045f8c6070a` | `PHP-8.1-CVE-2026-109618-109619` | **23** | **Minimal mitigation for EOL version.** |
| `82f8f31b16a035c1b67cc253e79f7cc288f4cc20` | `PHP-8.0-CVE-2026-109618-109619` | 23 | Same. |
| `712e60f9edfd03f0960fc4fc3c2c375f42b90aa2` | `PHP-7.4-CVE-2026-109618-109619` | 23 | Same. |

All commits carry the same message and the same references:

```
Avoid state corruption via bailout

Fix GHSA-w8hw-w9fx-j79w (CVE-2026-109618)
Fix GHSA-6wmf-4rv5-p3rp (CVE-2026-109619)
```

**Beware of an easy false positive:** the commit `ed70b1ea`
("Fix GHSA-www2-q4fc-65wf") and `8b801151` ("Fix GHSA-h96m-rvf9-jgm2") also
appear in those branches, but they are **not** the PHP2Shell CVEs (they are
DNS rebinding and an array null-deref). The one we want is `1d7dec17`.

## 2. Why the upstream 8.2 commit is NOT used

The commit `31c0ea7d7ff` rewrites the Zend MM allocator: `Zend/zend_alloc.c`
undergoes 651 lines of changes, and it touches `zend_hash.c`,
`zend_string.c`, `zend_operators.c`, the VM, OPcache, and a dozen extensions.

Tested with `git cherry-pick --no-commit 31c0ea7d7ff` on top of the
`php-8.2.34` tag: **content conflicts in the core of the engine**, among
others:

```
CONFLICT (content): Merge conflict in Zend/zend.c
CONFLICT (content): Merge conflict in Zend/zend_alloc.c
CONFLICT (content): Merge conflict in Zend/zend_alloc.h
CONFLICT (content): Merge conflict in Zend/zend_attributes.c
CONFLICT (content): Merge conflict in Zend/zend_builtin_functions.c
CONFLICT (content): Merge conflict in Zend/zend_execute.c
CONFLICT (content): Merge conflict in Zend/zend_hash.c
...
```

It is not a "drop-in" patch. Resolving it by hand on a production build is
exactly the kind of operation you do not want to attempt on a Friday.

## 3. Why the EOL branch commit IS used

The `1d7dec17` commit on the 8.1 branch is **the same fix reduced to its
minimal form**, written explicitly for the unsupported branches. It touches
23 files, of which **5 are code** and 18 are `.phpt` tests.

Applied on top of `php-8.2.34` with `git cherry-pick --no-commit`:

```
CONFLICT: Zend/zend_alloc.c
CONFLICT: ext/opcache/zend_file_cache.c
CONFLICT: ext/zend_test/tests/observer_bug81430_2.phpt   <- test only
CONFLICT: ext/zend_test/tests/observer_error_01.phpt      <- test only
CONFLICT: main/rfc1867.c
```

**3 conflicts in real code**, none of them trivial-without-thinking, none of
them irreversible in the allocator.

## 4. Resolution of each conflict

### 4.1 `Zend/zend_alloc.c` — `exit(1)` vs `_exit(1)`

The file has **two** OCCs (occurrence conflicts) at this point.

**(a) The include.** HEAD (8.2.34) has `#include "zend_mmap.h"`; the patch
adds `#include "zend_execute.h"`. **Both are kept**: they are not mutually
exclusive.

```c
 #include "zend_bitset.h"
+#include "zend_mmap.h"     <- from HEAD
+#include "zend_execute.h"  <- from the patch
 #include <signal.h>
```

**(b) The OOM exit.** This is where the substance is:

| | 8.2.34 (HEAD) | patch (EOL branch) |
|---|---|---|
| `zend_out_of_memory()` | `exit(1)` | `_exit(1)` |

`exit(1)` runs the `atexit` handlers → flushes buffers → **unwinds through
the VM**. That unwinding is precisely what corrupts the allocator state: it
leaves dangling pointers in globals that outlive the worker. `_exit(1)` does
none of that: it kills the process outright.

**The patch wins.** But a detail shows up here that does not surface during
the `cherry-pick`:

> 8.2.34 **already defines** `zend_out_of_memory()` (line 2792, with
> `exit(1)`). The 8.1 branch commit defines it at line 3112 (with
> `_exit(1)`). On the 8.1 branch there was no prior definition, which is why
> the patch generates no conflict — **but applying it on top of 8.2.34
> produces a redefinition**, and the compiler fails with:
>
> ```
> /…/Zend/zend_alloc.c:2820:37: error: redefinition of 'zend_out_of_memory'
> ```
>
> This **is not a textual conflict**: `git apply` accepts it without
> complaint and the failure only appears at compile time. It is the kind of
> semantic conflict that only shows up at link time.

**Resolution:** drop the HEAD definition (the one using `exit(1)`) and keep
the patch's (the one using `_exit(1)`). The net effect is what the patch
intends: the OOM no longer unwinds.

```c
-static ZEND_COLD ZEND_NORETURN void zend_out_of_memory(void)
-{
-	fprintf(stderr, "Out of memory\n");
-	exit(1);
-}
-
```

### 4.2 `main/rfc1867.c` — the `isspace()` cast

8.2.34 already had the `isspace()` security fix applied (cast to
`unsigned char`). The EOL branch patch moves that `do { value++; } while
(isspace(...))` into a new block (the multipart header filtering).

A purely cosmetic conflict: the HEAD cast is kept.

```c
-			do { value++; } while (isspace(*value));
+			do { value++; } while (isspace((unsigned char)*value));
```

### 4.3 `ext/opcache/zend_file_cache.c` — `bool` vs `int`

HEAD (8.2.34) uses `bool ok` (C99); the 8.1 patch uses `int ok`. They are
not incompatible: `bool` is an `int` with range restriction. `bool` from
HEAD is kept and the new variable the patch needs is added.

```c
-	bool ok;
+	bool ok;                      <- from HEAD
+	size_t orig_map_ptr_last = 0; <- from the patch
```

`orig_map_ptr_last` is indispensable: the patch stores the original value of
`CG(map_ptr_last)` so it can **restore** it if deserialization fails
(`zend_accel_pending_ce_cache_discard(); CG(map_ptr_last) = orig_map_ptr_last;`).
It is the mechanism that prevents a failure halfway through script loading
from leaving the OPcache allocator state half-configured.

### 4.4 The `.phpt` tests

Both conflicts are in `ext/zend_test/tests/`. They are observer tests that
do not exist in the same form in 8.2.34. They are resolved by keeping the
HEAD version: they do not affect the binary.

## 5. Code files affected by the backport

```
Zend/zend_API.h
Zend/zend_alloc.c          <- exit(1) -> _exit(1)
Zend/zend_alloc.h
Zend/zend_execute_API.c
Zend/zend_hash.c
Zend/zend_hash.h
Zend/zend_multiply.h       <- zend_error_noreturn -> zend_mm_safe_error_ex
Zend/zend_strtod.c
Zend/zend_types.h
Zend/zend_vm_def.h
Zend/zend_vm_execute.h
ext/opcache/ZendAccelerator.c
ext/opcache/ZendAccelerator.h
ext/opcache/zend_file_cache.c
ext/opcache/zend_persist.c
ext/session/session.c       <- the hunk that disables the callback
main/SAPI.c
main/main.c
main/php_variables.c
main/rfc1867.c
```

20 code files. The `ext/session/session.c` hunk is the one that cuts the
attack chain:

```c
-	if (!PS(rfc1867_enabled)) {
+	if (!PS(rfc1867_enabled) || true) {
 		return retval;
 	}
```

It is an **all-or-nothing** mitigation: with the patch applied, the
upload_progress callback is permanently disabled, and the CVE-2026-109619
branch — which needs that callback to consume the dangling session state —
never gets to execute.

## 6. Reproduction

```bash
# Build the patched image (same version, corrected code)
docker build -f Dockerfile.backport -t php2shell-backport:8.2.34 .

# Check the patch fingerprint in the code
python3 verify_backport.py --source <source tree>

# Differential behaviour against the three targets
python3 behavioural_diff.py 127.0.0.1 8080 "8.2.34 unpatched"
python3 behavioural_diff.py 127.0.0.1 8081 "8.2.35 official"
python3 behavioural_diff.py 127.0.0.1 8082 "8.2.34 + backport"
```

## 7. The honest limitation of this variant

The EOL branch backport is a **minimal mitigation**, not the full upstream
fix. Specifically:

- It permanently disables the `upload_progress` callback. That cuts the
  attack chain, but it also **disables a legitimate PHP feature** (upload
  progress tracking). For a site that uses `session.upload_progress` for a
  progress bar, it is an observable behaviour change.
- It does not include the `UnwindExit` work nor the full allocator
  sanitisation that the 423-file upstream commit does.

**When to use each path:**

| Situation | Recommended path |
|---|---|
| PHP 8.2+ with the ability to update | **Update to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12.** It is the right thing to do. |
| PHP 8.2+ that cannot change version (deps, PECL extensions, ABI) | **Backport the commit** (this document). |
| PHP 7.4 / 8.0 / 8.1 | **Distro patched package** (Sury, Remi, AlmaLinux…) or equivalent backport. |
| PHP cannot be touched right now | Mitigations: `session.upload_progress.enabled=0`, `max_multipart_body_parts`, `max_file_uploads`, blocking `multipart/form-data` at the web server. |

The golden rule remains: **patch, do not rewrite**. A patch preserves the
version number, the extensions and the ABI. An update changes all three.
