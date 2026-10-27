# PHP2Shell — Anatomy of CVE-2026-109618 and CVE-2026-109619

### From a use-after-free in PHP's session layer to unauthenticated RCE

**Author:** Chain-Cortex · JARVIS 🛡️
**Date:** October 27, 2026
**CVSS v4.0:** 9.2 (Critical) on both CVEs
**Status:** Active exploitation reported · Public PoC available

---

## 0. TL;DR for those with 30 seconds

On October 21, 2026 the PHP project published an emergency release that fixed **two** critical vulnerabilities in the **core** of the language, not in any application:

| CVE | Informal name | Type | Effect |
|---|---|---|---|
| CVE-2026-109619 | PHP2Shell (UAF branch) | Use-after-free in `session.upload_progress` | RCE + memory disclosure |
| CVE-2026-109618 | PHP2Shell (OOM branch) | Memory corruption via `longjmp()` on OOM | RCE + memory disclosure |

What makes it especially nasty:

- **It is not an application bug.** It is an interpreter bug. Any endpoint that accepts a multipart upload is vulnerable, even if the application code is perfect.
- **It does not require authentication.** There is no login to go through.
- **It does not require exotic configuration.** `session.upload_progress.enabled=On` is the **factory default** since PHP 5.
- **The patch was an emergency** (Oct 21, 14:00 UTC) because the details leaked before the official disclosure. CISA, Cisco, Akamai, Vercel, Laravel, Autodesk, IC3 and CERT-EU published advisories the same day.
- **PHP 7.4, 8.0 and 8.1 are out of the regular development cycle**, but the
  PHP project **did publish minimal source-code backports** for those
  branches. What does not exist is the regular release cycle: updating
  depends on your distro's package or on applying the backport by hand.

And one detail that explains the name: the delivery mechanism is essentially **Heartbleed applied to PHP**. Just like in Heartbleed, an attacker can read process memory — including data from *other* users — before being able to escalate to code execution.

> **Validated against the official advisory.** The PHP project's advisory
> (`GHSA-6wmf-4rv5-p3rp`, 21-oct-2026) describes the flaw in abstract
> terms — «*global state retained by a worker but pointing to memory owned
> by one request*», «*a fatal error, **including one caused by memory
> exhaustion***», «*a later operation that runs before normal request
> initialization can consume the stale value*» — and proposes a
> **producer + consumer** model across different requests of the same worker. The
> `session.upload_progress` branch measured here is **one** concretization of that
> model. The point-by-point mapping is in §10.12.

**The link almost nobody mentions:** the chain does not start with a UAF, but
with a **memory exhaustion**. The attacker triggers an OOM during multipart
parsing; PHP aborts the request with a `longjmp` that **jumps over the
cleanup**; the heap is freed but the worker survives with dangling pointers;
and the next request consumes them. That is why the patch replaces the
`longjmp` with a soft error, and why `pm.max_requests=1` breaks
exploitability under FPM. Section 10 has the full measurement.

---

## 1. Prerequisites for exploitation

According to the analysis from Akamai Security Intelligence Group and JFrog Security, the attack requires:

1. **PHP 5 or later** vulnerable (without the October patch).
2. **`session.upload_progress.enabled=On`** → factory default.
3. **`session.upload_progress.cleanup=On`** → also factory default. It is
   essential: it is `php_session_rfc1867_cleanup()` that, on the second
   request, calls `php_session_initialize()` and consumes the dangling state.
   With `cleanup=Off` that path does not exist and the chain does not start.
4. **An endpoint that accepts multipart uploads** — even one that ignores them.
   - Key point: the session layer processes `upload_progress` **before** user
     code runs, and therefore before the modules are activated.
5. **An OOM (or fatal error) during multipart parsing** that interrupts the
   request before the cleanup. It is achieved with ~536 KB of HTTP body (§2.6).
6. **The same worker** must handle the next request. In `mod_php` this
   works; under **PHP-FPM the worker dies** when startup fails, and that is why
   the official recommendation includes `pm.max_requests=1`.
7. **The base address of `libphp.so` at runtime**, or an ASLR leak that
   provides it. This is the point that makes this not a "`curl` and done".

Points 5 and 6 are the ones most descriptions omit, and they are precisely
the ones that mark the difference between "it is vulnerable" and "it is
exploitable in my deployment".

---

## 2. Anatomy of the flaw: the root cause (OOM → longjmp → dangling state)

> **Rigor note:** this section was rewritten after cross-checking the analysis
> against the PHP 8.2.34 source code, the official patch `31c0ea7d7ff` and the
> writeups from Calif Research, JFrog and Wiz, and after **experimentally
> isolating** the responsible pointer with A/B controls (§10). The
> first version of this article proposed a mechanism (concurrent session
> restart) that the experimentation **discarded**.

### 2.1 The root cause: an OOM that abandons the cleanup

Both CVEs are, in the end, the **same pattern**:

```
publish state  →  work that can fail  →  initialize / commit
                                              ↑
                    a non-local fatal (OOM) jumps over the commit
                                              ↓
      the next consumer trusts state that was never initialized
```

In PHP, that "jump" is a `zend_bailout()` (a disguised `longjmp`) that is
triggered when an allocation cannot be satisfied.

The concrete case is in `ext/session/session.c`. The session module publishes
state in its globals **before** the modules are activated:

```c
/* main/main.c — php_request_startup() */
PG(modules_activated) = 0;
/* ... */
php_hash_environment();   /* parses $_POST and the multipart */
zend_activate_modules();  /* RINIT of each module */
PG(modules_activated) = 1;
```

And the upload-progress handler writes to the session globals during that
parsing:

```c
/* ext/session/session.c — MULTIPART_EVENT_FILE_START */
if (Z_ISUNDEF(progress->data)) {
    /* ... */
    php_rinit_session(0);
    PS(id) = zend_string_copy(Z_STR(progress->sid));   /* <-- publishes pointer */
    /* ... */
}
php_session_rfc1867_update(progress, 0);                /* <-- initializes PS(http_session_vars) */
```

### 2.2 The cleanup that gets skipped

Normal cleanup happens in the `MULTIPART_EVENT_END` callback and in the session
module's RSHUTDOWN. But `php_request_shutdown()` **conditions** module
deactivation on the flag:

```c
/* main/main.c — php_request_shutdown() */
if (PG(modules_activated) {
    zend_deactivate_modules();   /* <-- NOT executed: the flag stays at 0 */
}
/* ... */
shutdown_memory_manager(CG(unclean_shutdown) || !report_memleaks, 0);
                                                            /* <-- the heap IS FREED anyway */
```

And the Apache path executes the shutdown even after the startup failure:

```c
/* sapi/apache2handler/sapi_apache2.c */
zend_first_try {
    if (php_apache_request_ctor(r, ctx) != SUCCESS) {
        zend_bailout();
    }
    /* ... runs the script ... */
} zend_end_try();

if (!parent_req) {
    php_apache_request_dtor(r);   /* -> php_request_shutdown(NULL) */
}
```

**Result of Request A:**

| Step | What happens | State |
|---|---|---|
| 1 | `MULTIPART_EVENT_FILE_START` → `php_rinit_session(0)` | `PS(id)` points into the request's heap |
| 2 | `php_session_rfc1867_update()` → `php_session_initialize()` | `PS(http_session_vars)` points into the request's heap |
| 3 | Multipart parsing exhausts `memory_limit` → `zend_bailout()` | `MULTIPART_EVENT_END` **is not executed** |
| 4 | `PG(modules_activated)` stays at `0` → session RSHUTDOWN **is not executed** | The session globals **retain** the old pointers |
| 5 | `shutdown_memory_manager()` runs anyway | **The request's heap is freed** |

The Apache worker survives. Its session globals point to memory that no
longer belongs to anyone.

### 2.3 Request B: the consumer

The second request reaches the same worker and **does not go through `FILE_START`** (it
has no file part), so there is no reset:

```c
/* ext/session/session.c — MULTIPART_EVENT_END */
if (Z_TYPE(progress->sid) && progress->key.s) {
    if (PS(rfc1867_cleanup)) {
        php_session_rfc1867_cleanup(progress);   /* <-- enters here */
    }
    /* ... */
}
```

And `php_session_rfc1867_cleanup()` is where the dangling state is consumed:

```c
static void php_session_rfc1867_cleanup(php_session_rfc1867_progress *progress)
{
	php_session_initialize();                              /* <-- READS DANGLING PS(id) */
	PS(session_status) = php_session_active;
	IF_SESSION_VARS() {
		zval *sess_var = Z_REFVAL(PS(http_session_vars)); /* <-- USES THE DANGLING POINTER */
		SEPARATE_ARRAY(sess_var);
		zend_hash_del(Z_ARRVAL_P(sess_var), progress->key.s); /* <-- OPERATES ON FREED MEMORY */
	}
	php_session_flush(1);
}
```

And `php_session_initialize()` reads the dangling `zend_string` on its first
session line:

```c
if (!PS(id) || !ZSTR_VAL(PS(id))[0]) {   /* <-- reads freed PS(id) */
```

**Here are the two weapons:**

- **Memory disclosure**: `PS(id)` is a freed `zend_string*`. Its
  contents are arbitrary heap bytes, and so is its length (`ZSTR_LEN`, at
  offset 16 of the structure). If that length survives intact and
  points to mapped memory, `php_url_encode(ZSTR_VAL(PS(id)), ZSTR_LEN(PS(id)))`
  — which runs when building the `Set-Cookie` header — copies that live
  process memory into the HTTP response. That is **Heartbleed applied to PHP**.
- **RCE**: `PS(http_session_vars)` is a freed `zend_array`. When destroying it
  (`zend_hash_del` → `zend_array_destroy`), PHP invokes its `pDestructor`. If that
  table has been **reclaimed** by the attacker with a forged `pDestructor`
  pointing to `zif_system`, execution is direct.

### 2.4 Which pointer is responsible (experimentally isolated)

This question is not trivial and the experimentation resolves it
unequivocally. The protocol and the results are in §10.3:

| Experiment | Result | Conclusion |
|---|---|---|
| Request B with the **same** `PHPSESSID` | crash 4/4 | — |
| Request B with a **different** `PHPSESSID` | crash 4/4 | The crash **does not depend** on `PS(id)` read as the request's SID |
| Request B **without** `PHP_SESSION_UPLOAD_PROGRESS` | crash 0/4 | The `cleanup` path is **indispensable** |
| **Normal** Request B (GET) after the OOM | crash 0/4 | The worker is **healthy**; there is no general corruption |
| Request B with `upload_progress` **without** a prior OOM | crash 0/4 | The OOM is **necessary** |

The conclusion is that the pointer that triggers the failure is
**`PS(http_session_vars)`** — the freed session hash table — and not the
`zend_string` of the identifier. That has one important practical
consequence: **the RCE path is the hash table one**, not the string one, and
that is why section 2.5 corrects a frequent error in the literature.

### 2.5 Escalation to code execution: hash table, not `zend_internal_function`

A negative result with didactic value, and an important correction: forging
a `zend_internal_function` (with `handler` at offset 72) and depositing it as
a spray is **not** the RCE mechanism.

The actual layout of `zend_internal_function` in PHP 8.2 on 64 bits (verified
with a C program using `offsetof` against `Zend/zend_compile.h`) is:

```c
     0 type | 4 fn_flags | 8 function_name | 16 scope | 24 prototype
    32 num_args | 36 required_num_args | 40 arg_info | 48 attributes
    56 T | 64 run_time_cache | 72 handler | 80 module
```

`handler` at offset **72** and `module` at **80** are the ones that matter. And
the total size is **136 bytes**, not the 288 that circulates in the literature
— that figure corresponds to the total size of the heap allocation, which
includes the `zend_string` wrapping the POST field value plus the allocator's
padding.

The reason that strategy does not work is the **signature**:

- A `zend_internal_function` describes a *function*, and invoking it requires a
  valid `zend_execute_data` (parameters, return values, call context). Forging
  and depositing it is not enough for it to execute.
- A `zend_array`, on the other hand, has a `pDestructor` that `zend_array_destroy`
  invokes **directly with a `zval*` as its only argument** — which is exactly
  the signature of `zif_system` (`ZEND_FUNCTION(system)` takes a `zval*` and a
  return `zval*`).

That apparently minor difference separates an exploit that works from one that
does not. The correct primitive is:

```
1. Request A: OOM -> PS(http_session_vars) is left dangling
2. The freed heap contains the session's zend_array
3. Reclaim that slot with a forged zend_array:
      - consistent nTableSize / nTableMask
      - arData pointing to a controlled array of buckets
      - pDestructor = zif_system
      - a bucket whose value is a zend_string with the command
4. Request B: php_session_rfc1867_cleanup() -> zend_hash_del() ->
   zend_array_destroy() -> pDestructor(&value) -> system("cmd")
```

The spray (149 entries × 288 bytes documented by Akamai) serves here to
**saturate** the freed slot with objects of the same allocation size, so
that the forged hash table lands at the right address. It is not surgical
precision: it is saturation.

### 2.6 The OOM trigger: how to exhaust `memory_limit` with a small payload

This is the detail that makes the chain practical. The goal is to trigger
an OOM with a **small** HTTP body, so as not to give the attack away by its
size.

Calif Research discovered two bypasses. The second is the elegant one:

> A *file part* with `filename=""` **does not count** towards `max_file_uploads`, but
> PHP **does** create the six corresponding `$_FILES` entries (`name`,
> `full_path`, `type`, `tmp_name`, `error`, `size`).
>
> If the field name is nested (`files[a][b][c]...`), PHP has to create that
> hierarchy **separately** for each of the six entries. A single empty
> upload record expands into **many** hash tables, buckets and
> strings. Hundreds of such records occupy more than 128 MiB of PHP heap
> while keeping the HTTP body below `post_max_size`.

Critical implementation detail: **each record needs a distinct top-level name**
(`f0`, `f1`, `f2`, ...). If they all share a prefix
(`files[a][b]`), PHP merges them into a single tree and no real memory
pressure is created. It is a subtle mistake that translates as "it does not
work" if you do not verify it.

Lab measurement (PHP 8.2.34, `memory_limit=32M`):

| Records | Nesting | HTTP body | Result |
|---|---|---|---|
| 3000 | 12 levels | **536 KB** | `Allowed memory size of 33554432 bytes exhausted` |

536 KB of traffic to exhaust 32 MB of heap: a ratio of ~60×.

### 2.7 Why the "same worker" is a hard requirement

The dangling state lives in process memory, not on disk. That is why
Request B **must** be handled by the same worker as Request A.

This explains the difference between SAPIs, which is not trivial:

| SAPI | Behaviour on startup failure | Is there a second request? |
|---|---|---|
| **mod_php** | `php_apache_request_dtor()` → `php_request_shutdown()` → heap freed, **worker survives** | **Yes** → exploitable |
| **PHP-FPM** | `php_module_shutdown()` + `return FPM_EXIT_SOFTWARE` → **the worker dies** | No → not exploitable |

Hence the official recommendation of `pm.max_requests=1` under FPM: it forces
workers to rotate and breaks the same-worker requirement.

It is worth qualifying one point: on Apache with `mpm_prefork`, the worker **does not die**
after the OOM (Request A responds 200 with the fatal error, and the process keeps
serving normal requests normally, 6/6 in the controls). The
worker **dies** later, in Request B, when it consumes the dangling pointer
and crashes with SIGSEGV. The distinction matters: the OOM by itself breaks
nothing; what breaks things is the **subsequent consumption of the state**.

### 2.8 The complete chain

```
1. Request A: multipart with PHP_SESSION_UPLOAD_PROGRESS + a file part
   -> FILE_START publishes PS(id) and PS(http_session_vars) in the request's heap
2. Request A (continuation): nested empty uploads -> OOM
   -> MULTIPART_EVENT_END is skipped, RSHUTDOWN is skipped, the heap is freed
   -> the worker survives with the globals dangling
3. Request B: multipart WITHOUT file part, same worker, with PHP_SESSION_UPLOAD_PROGRESS
   -> MULTIPART_EVENT_END -> cleanup -> php_session_initialize()
   -> operates on freed PS(http_session_vars) -> UAF
4. With the memory reclaimed in a controlled way:
   -> PS(http_session_vars) is a forged hash table
   -> its pDestructor = zif_system -> system("cmd") when destroyed
```

---

## 3. Anatomy of the flaw: CVE-2026-109618 (the `longjmp` that breaks the cleanup)
The official patch (`31c0ea7d7ff`) confirms that **both** CVEs are the same
pattern seen from two angles, and its title says so plainly:
*"Avoid state corruption via bailout"*.

**CVE-2026-109618** is the "generic" angle:

1. The attacker triggers an OOM (or another fatal) **during an operation that has
   published state in a persistent global variable**.
2. PHP aborts the request with `zend_bailout()` (a `longjmp`), which **jumps over
   the local cleanup code**.
3. The global variable retains a pointer to memory that shutdown will free.
4. The **next request**, served by the same worker, consumes that state
   as if it were alive.

**CVE-2026-109619** is the "specific" angle: the concrete persistent state is
the session state during upload-progress (as detailed in section 2).

The patch attacks the pattern at its root, in three moves:

| Layer | What it does | Where |
|---|---|---|
| **Root** | The OOM stops being a `longjmp`; it becomes a soft error at the next *safe point* (or a hard `_exit()` above a threshold) | `main/main.c` / `Zend/zend_execute.c` |
| **Defense in depth** | By resetting all the state that survives between requests (backtrace, OPcache, session, error state), nothing is left dangling | several modules |
| **Session-specific** | `PS(in_rfc1867_update)` forces `__PHP_Incomplete_Class` during the decode, and `if (PG(modules_activated)) return retval;` prevents the callback from running outside the legitimate window | `ext/session/session.c` |

The conceptual difference between the two branches, now with the real measured mechanism:

| | CVE-2026-109619 (upload-progress) | CVE-2026-109618 (generic) |
|---|---|---|
| Trigger | OOM during multipart parsing | Any fatal after publishing global state |
| Mechanism | `PS(id)` / `PS(http_session_vars)` dangling | Fatal error backtrace / OPcache state dangling |
| Consumer | `php_session_rfc1867_cleanup()` → `php_session_initialize()` | The next request that touches that global |
| Affected SAPI | mod_php (FPM kills the worker) | mod_php **and** FPM (if the fatal occurs after a successful startup) |
| Weapon | Memory disclosure + corruption | RCE and shared state corruption |

---

## 4. Why "PHP2Shell"?

The name comes from the parallelism with **Shellshock** (CVE-2014-6271) and from the delivery vector: by being able to write arbitrary bytes into heap memory, the attacker can forge **any** internal PHP function, not just `system()`. From there:

```c
system("id")            // ejecución de comandos
exec("...")             // idem, ejecución de comandos
file_get_contents(...)  // lectura de ficheros
phpinfo()               // fingerprinting
```

It is "shell" because the end result is a shell. It is "PHP" because the bug is in the interpreter, not in the application. It is "2" because there are two chained CVEs.

---

## 5. Building the lab

All the work below was done in an **isolated** environment (Docker, local network, no public exposure).

### 5.1 Architecture

```
┌─────────────────────────┐        ┌─────────────────────────┐
│  php2shell-vuln        │        │  php2shell-patched      │
│  PHP 8.2.34             │        │  PHP 8.2.35             │
│  Apache + mod_php       │        │  Apache + mod_php       │
│  localhost:8080         │        │  localhost:8081         │
│  [VULNERABLE]           │        │  [PARCHEADO]            │
└─────────────────────────┘        └─────────────────────────┘
```

**Apache + mod_php** is used (and not `php -S` nor FPM) because the confirmed RCE of the UAF branch requires the stale state to survive between requests **in the same worker**, something the prefork model of Apache naturally guarantees.

### 5.2 Critical target configuration

```ini
; ext/session/php_session.h — requisitos de explotación
session.upload_progress.enabled = On   ; default de fábrica
session.upload_progress.name = PHP_SESSION_UPLOAD_PROGRESS
session.upload_progress.min_freq = 1  ; el atacante debe pausar > 1s
session.upload_progress.cleanup = Off
session.save_path = /tmp/
memory_limit = 256M
```

And in Apache, the `upload_progress` module (needed so many installations show progress bars):

```apache
UploadProgressSharedMemorySize 1024
```

> ⚠️ **Important clarification (verified in the source code):** PHP's `upload_progress` and the Apache module `mod_upload_progress` are **independent mechanisms**.
>
> - The **PHP** one (`session.upload_progress.*`) writes the upload state into the **session file** (`session.save_path`) and is the one involved in the vulnerability. It is a mechanism **of the core**, available with any SAPI.
> - The **Apache** one (`mod_upload_progress`) is a shared memory cache so that a frontend can *query* the progress of an in-flight upload. **It does not take part in the UAF.**
>
> The Apache module is **not necessary** to exploit the vulnerability. It is included in the lab because it is what many real installations use for progress bars, and because its configuration was a common source of errors during setup.
>
> Version detail: the modern `libapache2-mod-upload-progress` package uses `UploadProgressSharedMemorySize`. Older variants used `UploadProgressCacheDir`. If you see `Invalid command 'UploadProgressCacheDir'`, you have a modern version.

### 5.3 Application target

The application is deliberately harmless. This is a key point for the blog: **the bug is not here**.

```php
<?php
// index.php — endpoint que acepta uploads y los ignora
if (isset($_GET['probe'])) {
    echo "PHP_VERSION=" . phpversion() . "\n";
    echo "SAPI=" . php_sapi_name() . "\n";
    echo "SESSION_UPLOAD_PROGRESS_ENABLED=" . ini_get('session.upload_progress.enabled') . "\n";
    // ... deteccion de parche por tabla de versiones
}

$uploaded = [];
foreach ($_FILES as $field => $info) {
    $uploaded[] = sprintf('%s: name=%s size=%d', $field, $info['name'], $info['size']);
}
echo "SESSION:\n";
foreach ($_SESSION as $k => $v) {
    echo "  $k => " . json_encode($v) . "\n";
}
```

### 5.4 Patched versions per branch

| Branch | Patched version | Status |
|---|---|---|
| 8.2.x | **8.2.35** | Support until 31 Dec 2026 |
| 8.3.x | **8.3.36** | Supported |
| 8.4.x | **8.4.27** | Supported |
| 8.5.x | **8.5.12** | Supported (adds `fatal_error_backtraces=0`) |
| 7.4.x | minimal backport published by PHP | Outside the regular cycle: update via distro or manual backport |

---

## 6. The differential test: exposure proof without RCE

A detector that needs offsets and ASLR is useless for a quick audit. The test we built is **purely functional** and discriminates reliably.

### 6.1 The idea

- In **vulnerable** PHP, the `upload_progress` handler runs and **writes the upload state into `$_SESSION`**.
- In **patched** PHP, the callback aborts (`if (PG(modules_activated)) return retval;`) and the session **is not modified**.

The difference is observable from the outside: the presence or absence of the `upload_progress_<value>` key in the session.

### 6.2 Implementation

The technical key is **fine-grained control of the TCP stream**: we need to pause the writing of the multipart body halfway through so that the clock's elapsed time exceeds `session.upload_progress.min_freq`.

```python
import socket, time

def upload_probe(host, port, session_id, progress_key, delay=1.6):
    boundary = "----php2shellDiff1234567890"

    phase1  = field("PHPSESSID", session_id)
    phase1 += field("PHP_SESSION_UPLOAD_PROGRESS", progress_key)
    phase1 += file_field("file", "probe.bin", b"P" * 4096)   # <- FILE_START

    phase2  = b"".join(
        field("t[]", b"A" * 288) for _ in range(149)        # <- heap spray
    )

    phase3  = file_field("file2", "probe2.bin", b"Q" * 2048) # <- trigger
    phase3 += b"--" + boundary.encode() + b"--\r\n"

    body = phase1 + phase2 + phase3
    head = (f"POST /index.php HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Cookie: PHPSESSID={session_id}\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n").encode()

    s = socket.create_connection((host, port), timeout=20)
    s.sendall(head + phase1)
    time.sleep(delay)           # <<< LA PAUSA: dispara el segundo update()
    s.sendall(phase2 + phase3)
    # ... leer respuesta
```

### 6.3 Results obtained

**VULNERABLE target (PHP 8.2.34):**

```
PHP 8.2.34 | SAPI apache2handler
SESSION_ID=
UPLOADS:
  file: name=probe.bin size=4096 error=0
  file2: name=probe2.bin size=2048 error=0
SESSION:
  upload_progress_behavcheck => {"start_time":1793121467,"content_length":61359,
    "bytes_processed":61359,"done":true,"files":[
      {"field_name":"file","name":"probe.bin","bytes_processed":4096},
      {"field_name":"file2","name":"probe2.bin","bytes_processed":2048}]}
```

**PATCHED target (PHP 8.2.35):**

```
PHP 8.2.35 | SAPI apache2handler
SESSION_ID=
UPLOADS:
  file: name=probe.bin size=4096 error=0
  file2: name=probe2.bin size=2048 error=0
SESSION:
  (vacia)
```

### 6.4 Interpretation

| Target | `upload_progress_*` in session | Verdict |
|---|---|---|
| 8.2.34 | ✅ Present | **VULNERABLE** — the handler writes state, the UAF is reachable |
| 8.2.35 | ❌ Absent | **PATCHED** — the callback aborts, the chain is cut |

> **Honest limitation of the method:** this test demonstrates **exposure** (that the UAF branch is reachable), not code execution. Full RCE additionally requires resolving the binary offsets or leaking ASLR. For auditing and patch prioritization, exposure is the metric that matters: if the test comes out positive, you need to patch now.

---

## 7. What the patch does exactly

The official patch (`31c0ea7d7ff`, "Avoid state corruption via bailout") **does not rewrite** the vulnerable code. It is a defense in layers. And this is fascinating from the point of view of security engineering:

### 7.1 Layer 1 — Reset the state at upload startup

```c
case MULTIPART_EVENT_START: {
    multipart_event_start *data = (multipart_event_start *) event_data;

    /* This runs before RINIT, so we need to clear these early */
    php_rinit_session_globals();

    progress = ecalloc(1, sizeof(php_session_rfc1867_progress));
    /* ... */
}
```

### 7.2 Layer 2 — Prevent the second execution of the callback (the key!)

```c
if (PG(modules_activated)) {
    /* request_parse_body(). Do not run here as it corrupts the session. */
    return retval;
}
```

This is **the** fix that cuts the UAF chain. The multipart callback is invoked at two moments: during the parsing of the request (before RINIT) and again from `request_parse_body()`. The second invocation, with `PG(modules_activated)` already at 1, is what produced the `update()` → flush → re-init → free. Aborting there, **Tree-A is never freed** and the cached pointers never remain dangling.

### 7.3 Layer 3 — Force `__PHP_Incomplete_Class` during the decode

```c
/* The upload progress handler (php_session_rfc1867_update()) decodes and
 * re-encodes the session during request startup, before RINIT, when no
 * user code may run. Objects are then kept as __PHP_Incomplete_Class: no
 * autoloading, no unserialize_callback_func, no __wakeup() or __unserialize(),
 * and they are written back unchanged. */
static void php_session_unserialize_init(php_unserialize_data_t *var_hash)
{
    PHP_VAR_UNSERIALIZE_INIT(*var_hash);
    if (PS(in_rfc1867_update)) {
        php_var_unserialize_set_incomplete_classes_only(*var_hash, true);
    }
}
```

This also closes **object injection** via the session file. The attacker controls bytes of the session file through the uploaded file name (`$_SESSION["upload_progress_x"]["files"][0]["name"]`). Without this layer, they could instantiate arbitrary classes with malicious `__wakeup()` / `__destruct()`. With it, objects are decoded as inert `__PHP_Incomplete_Class`.

### 7.4 Layer 4 — Eliminate the `longjmp()` on OOM

The commit replaces the OOM bailout (`longjmp()`) with an `UnwindExit` / soft error at the next *safe point* of the VM. Thus the cleanup **always** runs and the pointer **always** is cleared before freeing the memory. This closes the CVE-2026-109618 branch.

### 7.5 Layer 5 — Defensive reset of the persistent state

At shutdown, all long-lived state (backtrace, OPcache, session, error state) is reset, so that nothing "stale" survives into the next request. This includes the `zend_delete_global_variable("_SESSION")` in `MULTIPART_EVENT_END`.

---

## 8. Remediations

### 8.1 Primary remediation — update (mandatory)

| Action | Priority |
|---|---|
| Update to **8.2.35 / 8.3.36 / 8.4.27 / 8.5.12** | **Immediate** |
| If you use **7.4 / 8.0 / 8.1**: migrate to the supported cycle, or apply the PHP backport. | **Critical** |
| Restart **all** workers after updating (Apache + FPM + php-fpm reload) | **Immediate** |
| Verify the real version at runtime, not the package version | **Immediate** |

```bash
# Verificar versión en runtime
php -r 'echo PHP_VERSION, PHP_EOL;'

# Apache: reiniciar workers
sudo systemctl restart apache2

# PHP-FPM: recargar todos los pools
sudo systemctl reload php8.2-fpm   # o restart para guarantee

# FPM: recommendation defensiva adicional
# pm.max_requests=1  (rompe el requisito de "mismo worker")
```

### 8.2 Partial mitigations (if you cannot update yet)

These are **partial**. Each one covers one arm and leaves the other open.

```ini
; Desactivar upload_progress: cierra la rama UAF (CVE-2026-109619)
; en la mayoría de las instalaciones. Es la mitigación más efectiva.
session.upload_progress.enabled = 0

; En PHP 8.5+: neutralizar la rama de backtraces (CVE-2026-109619)
fatal_error_backtraces = 0
```

### 8.2.1 Two mitigations the advisory does not mention, but which the
lab demonstrates do work

These are deduced from the real mechanism (OOM → dangling state) and were verified
empirically in the lab of this work:

```ini
; Limita el numero de partes del multipart. Con el limite activo, PHP corta
; la peticion con "Multipart body parts limit exceeded" ANTES de que se
; agote la memoria, y la cadena de explotacion no llega a arrancar.
; Valor por defecto en las imagenes oficiales de PHP: 1500.
; ATENCION: 0 NO significa "ilimitado" (significa "usa el default").
; Para desactivar el limite: -1.
max_multipart_body_parts = 1000

; Limita el numero de ficheros por peticion. Con el default (20), PHP deja
; de procesar los uploads anidados y el heap nunca se agota.
max_file_uploads = 20
```

**Important limitation of both:** they mitigate the **trigger** (the OOM), not the
vulnerability. If some other path in the core allows exhausting memory
—a large body, a recursive request, an endpoint that deserializes
huge payloads— the mitigations do not Activate. The only complete defense
is still updating the interpreter.

**And a quick check for your fleet**, based on the fact that the
official patch **eliminates the OOM entirely** (it turns it into a soft
error, according to its own title *"Avoid state corruption via bailout"*). The
`check_exposure.sh` script of this repository automates it:

```bash
./check_exposure.sh https://tu-app.example.com/upload
```

```
$ ./check_exposure.sh http://127.0.0.1:8080/index.php     # 8.2.34
[!] VULNERABLE: el servidor agoto su memoria durante el parseo multipart.
    exit=1

$ ./check_exposure.sh http://127.0.0.1:8081/index.php     # 8.2.35
[+] NO vulnerable: no se disparo el OOM (probablemente PHP parcheado).
    exit=0
```

The probe **does not exploit**: it only triggers the OOM and looks at the response. It is
detectable and auditable, unlike an exploit. Even so, it causes memory
exhaustion on the server: use it only against your own systems or with
explicit written authorization.

A detail worth not overlooking: the probe needs **thousands** of
nested multipart parts, not one. Each part additionally needs a distinct
**top-level name** (`f0`, `f1`, ...). A single nested part does not
trigger OOM, and this is the reason why many manual checks of
this vulnerability give a false negative.

```bash
# Tras cambiar cualquier INI: reiniciar TODOS los workers
sudo systemctl restart php8.2-fpm
sudo systemctl restart apache2
```

> ⚠️ **Warnings from the official advisory:**
> - The `upload_progress` flag **does not** affect the OPcache nor the backtrace arms.
> - `memory_limit=-1` **removes** the protection against resource exhaustion (do not do it unless you have other controls).
> - `pm.max_requests=1` breaks the same-worker requirement, useful as an extra layer under FPM.
> - Do not use `RLIMIT_AS` / `RLIMIT_DATA`.

### 8.3 WAF rules / detection

Akamai published rule **3000991 v1** ("PHP Remote Code Execution Attack Detected") for its App & API Protector customers, and confirms that its existing command injection rules already mitigate the weaponized payloads.

Key indicators for custom rules:

- Presence of the `PHP_SESSION_UPLOAD_PROGRESS` field in multipart requests **without** functional need for a progress bar.
- **Fields with deeply nested names** (`f0[a][b][c]...`) and
  empty `filename=`. This is the signature of the OOM trigger, and it is more specific
  than any RCE indicator.
- **High density of multipart parts** in a single request (on the order of
  thousands), with a comparatively small `Content-Length`.
- Requests that systematically return `500`/`Fatal error: Allowed memory size ...
  exhausted`.
- **`PHPSESSID` anomalies**: in the rounds where the dangling pointer is
  read, PHP may emit a `Set-Cookie: PHPSESSID=<random-hex-value>` that
  does not correspond to any of those sent by the client, or a `Warning:
  Session ID is too long or contains illegal characters`.
- `t[]` fields with anomalous size values (≈288 bytes) and high repetition density (spray mechanism described in the public literature).

### 8.4 Post-exploitation — what to look for

If a server was exposed:

- Session files modified with unexpected content.
- Creation of files in `session.save_path` with non-serialized content.
- Child processes of the PHP worker running shells.
- `mod_php` logs with `system()`, `exec()`, `passthru()`, `shell_exec()`, `popen()`, `proc_open()`.
- Files such as `.htaccess`, `webshell.php`, in the `document_root`.

---

## 9. Verifying exposure in your fleet

```bash
# 1. Sonda de versión via HTTP (sin ejecutar código)
curl -s "https://tu-sitio/index.php?probe=1"

# 2. Test diferencial completo (el que construimos)
python3 behavioural_diff.py <host> <port> "ETIQUETA"

# 3. Escaneo masivo: version de PHP via cabeceras HTTP
#    (Vercel, Akamai y otros ya exponen la version en cabeceras)
curl -sI https://tu-sitio/ | grep -i "^x-powered-by\|^server"

# 4. En servidores, buscar la version real
find / -name "php" -type f -perm -u+x 2>/dev/null | head -20
```

Real priority: **PHP 7.4/8.0/8.1 + anything that accepts uploads = RCE without authentication**, because they are outside the regular release cycle.

---

## 10. Experimental results
Everything that follows was reproduced in this repository's laboratory on
**PHP 8.2.34 compiled from source with symbols**, Apache 2.4.68
(`mod_php`, `mpm_prefork`, a single worker) with ASLR disabled.

### 10.1 The OOM trigger works

Trigger used: multipart with `PHP_SESSION_UPLOAD_PROGRESS`, a real file part and
3 000 nested empty uploads (`f0[a][a]...[a]` … `f2999[a][a]...[a]`, 12
levels, `filename=""`).

```
Request A: 536 289 bytes de cuerpo HTTP
Respuesta: Fatal error: Allowed memory size of 33554432 bytes exhausted
            (tried to allocate 20480 bytes) in Unknown on line 0
```

Relevant observations:

- The response **does not** include script output: the fatal error occurred during
  `php_request_startup()`, that is, **before** the application code ran. This
  confirms the `parse → RINIT` ordering of `main/main.c`.
- With `memory_limit=32M`, the required HTTP body is ~536 KB. The
  memory/payload ratio is ~60×.
- If the 3 000 records share a **first-level prefix** (`files[a][b]…`),
  PHP merges them into a single `$_FILES` tree and there is **no** OOM. The
  first-level name must differ in each record. It is a silent failure
  that makes one believe the technique does not work.

### 10.2 The UAF triggers reproducibly

With the single worker, the sequence Request A (OOM) → Request B (multipart without
file part, same `PHPSESSID`, **with** `PHP_SESSION_UPLOAD_PROGRESS`) produces
one of two outcomes, in a ~50/50 proportion:

| Request B outcome | What it means |
|---|---|
| **Empty** response (the worker dies with SIGSEGV) | The dangling pointer points to unmapped memory |
| `Warning: PHP Request Startup: Session ID is too long or contains illegal characters` | The dangling `zend_string` **was read** and contained heap garbage; PHP rejected it on validation |

The second outcome is **direct proof** that the dangling pointer is consumed:
it is not an arbitrary crash, it is a freed `zend_string` whose
content is no longer a valid session ID.

In the Apache log, the pattern is unambiguous:

```
[core:notice] child pid 328 exit signal Segmentation fault (11)
[core:notice] child pid 461 exit signal Segmentation fault (11)
```

That is: the worker **survives the OOM** and **dies on Request B**.

### 10.3 Isolation of the responsible pointer (A/B controls)

In order not to remain at the level of the source-code description, controls
were designed that separate each variable. All of them with a prior `docker restart`,
so that each test starts from a freshly spawned worker and a clean heap.

| # | Experiment | Result | Conclusion |
|---|---|---|---|
| 1 | Request B with the **same** `PHPSESSID` | crash 4/4 | — |
| 2 | Request B with a **different** `PHPSESSID` | crash 4/4 | The crash **does not depend** on `PS(id)` being read as the request's SID |
| 3 | Request B **without** `PHP_SESSION_UPLOAD_PROGRESS` | crash **0/4** | The `cleanup` path is **essential** |
| 4 | **Normal** Request B (GET) after the OOM | crash **0/4** | The worker is **healthy**: there is no general corruption of the allocator |
| 5 | Request B with `upload_progress` **without** a prior OOM | crash **0/4** | The OOM is **necessary and sufficient** |

Experiment 2 is the most informative: since the crash reproduces identically with
a different `PHPSESSID`, **the session identifier does not participate in the
failure**. Combined with experiment 3, which removes the field that triggers
`php_session_rfc1867_cleanup()`, the conclusion is that the responsible pointer
is **`PS(http_session_vars)`** —the freed session hash table.

Experiment 4 is the one that refines the model in the most important way: the OOM
**does not corrupt the worker's allocator in general**. The worker keeps
serving normal requests perfectly. What fails is
**specifically** the consumption of the dangling state. It is a *targeted* UAF, not
a diffuse corruption.

**Final results matrix** (laboratory target, OPcache disabled
for reproducibility — see §10.10):

| Target | Version | OOM | UAF observed | Verdict |
|---|---|---|---|---|
| `:8080` | 8.2.34 (official image) | 6/6 | **6/6** (SIGSEGV) | **VULNERABLE** |
| `:8081` | 8.2.35 (official image) | 0/6 | 0 | **Patched** |
| `:8082` | 8.2.34 (source build, with symbols) | 6/6 | 6/6 | **VULNERABLE** |

Important calibration detail: in 8.2.35 the number of multipart parts
is limited to **2000** (an internal limit of that version, different from
PHP 8.1's `max_multipart_body_parts`). That is why the test uses **1500** parts and
not 3000: with 3000, the patched target aborts due to the limit *before*
reaching the OOM and the test does not allow any conclusion to be drawn. With 1500 parts, both
versions process the complete request and the comparison is fair: the
vulnerable one exhausts memory and the patched one does not.

### 10.4 Disassembly of the failure point

The crash occurs at `libphp.so + 0x3b0750`:

```asm
3b0726: lea 0x89be53(%rip),%rcx     # -> bin_data_size (tabla de bins de Zend MM)
3b072d: mov (%rcx,%rdx,4),%ecx
3b0743: mov (%rax,%rdx,8),%rcx      # rcx = puntero de página del bin
3b074b: test %rcx,%rcx
3b074e: je   3b0790                 # si NULL -> pedir página nueva
3b0750: mov  (%rcx),%rsi            # <-- CRASH: lee el primer qword de la página
```

The kernel registers at the moment of the failure:

```
RIP: 0033:0x7ffff5bed750
RAX: 00007ffff7400040  RBX: 0000000000000106  RCX: 007ffff745520000
RDX: 0000000000000007  RSI: 0000000000000003  RDI: 0000000000066d08
R10: 0000000000078000  R11: 00007ffff7477588  R14: 00007ffff7477588
```

`RCX = 0x7ffff745520000` is page-aligned but **outside** the
mapping of `libphp.so` (base `0x7ffff593a000`, size `0x3bd000`):
it is a pointer to memory managed by Zend MM. `zend_mm_alloc_small()` is
following an entry of the **free list** (`bin->slots[]`) that was
overwritten — the state of the list became inconsistent after the OOM, and the
next small allocation of that size class follows the corrupted pointer.

### 10.5 Binary instrumentation: the UAF with addresses (new)

Until here, the UAF was argued by its **effect** (SIGSEGV, `Session ID is too
long`) and by A/B controls. The direct proof was missing: **that the pointer
that Request B consumes is exactly the one that Request A freed**.

For that, PHP itself was instrumented: the patch
`patches/apply_trace_patch.py` (idempotent, 78 lines) adds two traces to
`ext/session/session.c`:

- `TRACK_INIT` — in `php_session_track_init()`, right after publishing
  `PS(http_session_vars)`: records address, flags, `nTableSize`,
  `nNumUsed`, `arData`, `pDestructor` and `sizeof(zend_array)`.
- `CLEANUP` — in `php_session_rfc1867_cleanup()`, right before
  `php_session_initialize()`: records the address that Request B will
  operate on.

**Result (instrumented target, ASLR active):**

```
TRACK_INIT  arr=0x79c99ce54310 gc=1          flags=0x8 nTableSize=8
            nNumUsed=0 arData=0x79c99bf98468 pDestructor=0x79c99b71be50
            sizeof=56

CLEANUP     ps_http_session_vars=0x79c99c0dd760
            arr=0x79c99ce54310 gc=2632270664  flags=0x0
            nTableSize=8 nNumUsed=1 arData=0x79c99ce647c0
```

**The `arr` address is identical at both points: `0x79c99ce54310`.** Request
B literally operates on the same object that Request A freed.
This is the definition of a use-after-free, demonstrated and not inferred.

The values of the freed state are the classic signature:

| Field | Request A (alive) | Request B (freed) | Reading |
|---|---|---|---|
| `arr` | `0x79c99ce54310` | `0x79c99ce54310` | **same slot** |
| `gc.refcount` | **1** | **2632270664** | garbage: a real refcount is never that |
| `flags` | `0x8` | `0x0` | flags stomped by the reassignment |
| `nNumUsed` | 0 | 1 | reused bucket |
| `nTableSize` | 8 | 8 | survives: that is why the crash is late |
| `pDestructor` | `zval_ptr_dtor` | `zval_ptr_dtor` | survives intact |

That `nTableSize` and `pDestructor` survive intact explains the failure
window: the corruption is not total. The `gc.refcount` blown up to
`0x9D2C…` is what later makes `zend_mm_alloc_small` follow a
corrupted free list and die inside `zend_mm_alloc_small`.

### 10.6 The slot size: why the classic spray never worked

The instrumentation provides the datum that explains the **historical failure**
of the PoCs that use a large blob:

```
sizeof(zend_array) = 56 bytes
```

In Zend MM, small allocations are grouped into bins. The function
`zend_mm_small_size_to_bin()` (`Zend/zend_alloc.c`) gives, for `size <= 64`:

```c
return (size - !!size) >> 3;
```

That is, **bin = (size − 1) >> 3**. From this:

| Size | Bin | Bin range |
|---|---|---|
| 32 B (SID's `zend_string`) | 3 | 25–32 B |
| **56 B (session `zend_array`)** | **6** | **49–56 B** |
| 288 B (the "classic" blob from the writeups) | **68** | outside the small range |

**The 288-byte blob used by the public PoCs lives in bin 68. The slot
that must be claimed is in bin 6.** Two different bins **never**
share blocks: the spray could not work no matter how well calibrated the
number of iterations or the precision of the filler were.

It is not a timing problem, nor a precision problem, nor an ASLR problem. It is a
**size class** problem. That is why classic grooming always fails in PHP 8.2 and
why the escalation requires forging a structure of exactly 56 bytes
(or control of the allocator that forces that class).

The design consequence is uncomfortable: a forged 56-byte `zend_array`
has no room to carry the command to execute inside it. The payload
(command string) must live in **another** allocation — a `zend_string` — to
which the structure points.

### 10.6-bis Inside the allocator: the bin 6 pool is predictable

Instrumenting `Zend/zend_alloc.c` (patch `patches/apply_alloc_trace_patch.py`,
also idempotent) makes it possible to see the real lifecycle of the block:

```
ALLOC_SMALL bin=6 size=56 free_slots=59 head=0x7cd8a2e54310   ← se asigna
FREE_SMALL  ptr=0x7cd8a2e54310 bin=6 size=56                   ← se libera
ALLOC_SMALL bin=6 size=56 free_slots=37 head=0x7cd8a2e54310   ← se reasigna
```

Three consequences that change the design of the exploit:

**1. The slot returns to the free list and is reassigned.** It is not lost along with
the chunk: it enters `heap->free_slot[6]` and the next allocation of 56 bytes
receives it. The window exists.

**2. The bin 6 pool is contiguous and deterministic.** The sequence of
addresses served is a constant-step progression of **0x38 (56 bytes)**:

```
0x7cd8a2e54038 → 04070 → 040a8 → 040e0 → 04118 → 04150 → 04188 → 041c0
→ 041f8 → 04230 → 04268 → 042a0 → 042d8 → 04310 ← el slot de la zend_array
→ 04348 → 04380 → 043b8 → 043f0 → 04428 → …
```

The `zend_array` slot is the **element number 14** of that sequence. The
position within the pool is predictable, and with it the address — which
turns the problem of "finding an address" into "computing an
offset".

**3. The allocation order is LIFO, but not guaranteed.** Over 7,463 consecutive
bin 6 free→alloc pairs:

| Outcome | Cases | Proportion |
|---|---|---|
| The next alloc uses **exactly** the freed slot | 2,123 | **28.4 %** |
| Uses another slot | 5,340 | 71.6 % |

The remaining 71.6 % is not random: `heap->free_slot[bin]` is a stack
**per page**. If the free occurs on another page, that page has its own
stack head and the freed slot does not come out first.

**Why this matters.** 28.4 % per attempt is not a problem, it is an
advantage: 3-4 attempts give more than 70 % cumulative success, and 10 attempts
>96 %. That explains why the public PoCs spray massively, and it suggests
that **a 56-byte spray —not a 288-byte one— should work**, against the
assumption that a large blob is required.

The requirement that remains to be solved is not timing but **control**:
achieving that the 56-byte allocation landing in the slot be a
forged `zend_array` with `pDestructor = zif_system`, and that the command to
execute live in a separate `zend_string`, because 56 bytes do not allow for more.

### 10.7 ASLR and verified offsets

The laboratory target runs with ASLR disabled (`setarch -R`) and with
symbols, which makes it possible to confirm the real offsets extracted from the binary:

```
BASE=0x7ffff593a000        (idéntico en 4 peticiones consecutivas)
SIZE=0x3bd000
ZIF_SYSTEM=0x7ffff5d41ae0
ZVAL_PTR_DTOR=0x7ffff5e0dc00
PHP_URL_ENCODE=0x7ffff5c7be50
```

The base is **stable across requests**, therefore the absolute offsets are
usable in this environment. In a real deployment with ASLR active, one would
have to resolve the base at runtime (ASLR leak) or use a gadget
independent of the base address.

### 10.8 The mechanism of the leak, deduced from the code

When the dangling `zend_string` **does** pass validation, PHP emits it in the
`Set-Cookie` header. The validation occurs in
`ext/session/mod_files.c` → `ps_files_open()`:

```c
if (php_session_valid_key(ZSTR_VAL(key)) == FAILURE) {
    php_error_docref(NULL, E_WARNING, "Session ID is too long or contains illegal characters. ...");
    return;
}
```

And `php_session_valid_key()` in `ext/session/session.c`:

```c
for (p = key; (c = *p); p++) {          /* recorre hasta el primer NUL */
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
          || c == ',' || c == '-')) {
        ret = FAILURE; break;
    }
}
len = p - key;                           /* longitud real, por NUL */
if (len == 0 || len > PS_MAX_SID_LENGTH) {   /* PS_MAX_SID_LENGTH = 256 */
    ret = FAILURE;
}
```

**Here is the key to the disclosure, and it is subtle:**

- The length that is validated is the one **computed by the NUL terminator**, not
  `ZSTR_LEN`. The function never consults `ZSTR_LEN(key)`.
- Therefore, if the freed `zend_string` has a `ZSTR_LEN` larger than the
  real one, but its content is alphanumeric up to a NUL, **PHP accepts the
  entire string** and emits it in `Set-Cookie` and uses it as a session
  file name.
- The hard limit is `PS_MAX_SID_LENGTH = 256`: at most 256 bytes of
  process memory per response.

In the laboratory, the observed `ZSTR_LEN` of the dangling pointer was
**always 32** (`session.sid_length = 32` in PHP 8.2), and the emitted value
always had 32 hexadecimal characters, different on each attempt
(16/16 unique values). That is consistent with the slot being claimed by another
32-byte `zend_string` containing a new, legitimate session ID: that is, in the
"OK" rounds PHP **detected** the pointer as invalid and
**regenerated** the identifier.

The rounds in which PHP emitted "Session ID is too long" are the case in which
the freed content was **not** alphanumeric: the UAF was read, the
validation failed and PHP aborted the session initialization.

**Consequently:** the memory read primitive is **demonstrated**
(the pointer is read and its content is processed), but **controlled
exfiltration** of arbitrary bytes requires that the `ZSTR_LEN` of the freed
object survive with a large value —which requires fine-grained *grooming* of the
heap that was not achieved with direct filling of POST fields (tested with
lengths 16→64, 6 replicas each: the cookie length remained
fixed at 32 in 100 % of cases).

### 10.9 Other observations

- **The filename is serialized literally in the session file.** The
  `upload_progress` format writes `s:10:"field_name";s:2:"fz";s:4:"name";s:5:"a.txt";`
  with explicit lengths. This confirms that the upload's `filename` is
  a byte-injection vector into the session file.
- **But the filename does not carry arbitrary bytes over HTTP.** PHP sanitizes
  the value: a `filename` with `0x00` is truncated there and `0xff` is converted
  to `'`. Tested: `A\x00B\xffC\x01D` reached the script as `x01D`. That is, arbitrary
  byte injection is possible **through the session
  file**, not through the `filename` field directly.
- **The length of the filename's `zend_string` is indeed controllable** (16, 64 and
  200 bytes were reflected exactly in `$_FILES['name']`), which opens the
  door to occupying slots of a chosen size on the heap.
- **`session.upload_progress.cleanup=On` is mandatory** for the UAF branch:
  with `cleanup=Off`, `php_session_rfc1867_cleanup()` is not invoked at
  `MULTIPART_EVENT_END` and the dangling state is never consumed. It is the
  factory default value, but it is worth verifying it on every deployment.
- **`max_multipart_body_parts` is a real mitigation.** With the limit
  active (1500 by default in the official PHP images, 1000 in
  earlier versions), the request is aborted with *"Multipart body parts
  limit exceeded"* **before** reaching the OOM, and the chain does not start. In the
  laboratory it was necessary to set it to `-1` to reproduce the failure. Technical
  note: the value `0` **does not** mean "unlimited" — it means "use the
  default value". To disable the limit you must use `-1`.
- **`max_file_uploads` is the second limiter.** With its default value
  (20), PHP stops processing the nested uploads and the heap is never exhausted.
  The laboratory uses 1000.
- **`memory_limit` amplifies the ratio.** With 32 MB, 3 000 nested
  uploads and 12 levels of nesting suffice: **536 KB of HTTP body**
  to exhaust 32 MB of heap (~60×).

### 10.10 OPcache changes the behavior of the UAF (unforeseen finding)

This finding was not in the research plan, and it appeared while trying to
reproduce the UAF on the official PHP image target (8.2.34 from Docker
Hub) after having achieved it on the source-compiled target.

The result was puzzling: **on the official binary, the OOM was triggered
(6/6) but the UAF was not observed in any round (0/6)**. The worker did not
crash and Request B responded cleanly.

The difference between both targets, isolated experimentally:

| Target | Binary | OPcache | OOM | UAF observed |
|---|---|---|---|---|
| `:8080` | official Docker Hub | **ON** | 6/6 | **0/6** |
| `:8084` | official Docker Hub | **OFF** | 6/6 | **6/6** |
| `:8082` | compiled from source | OFF (`--disable-opcache`) | 6/6 | 6/6 |

To isolate the variable, the **same official binary** was run with OPcache
disabled (deleting `docker-php-ext-opcache.ini` before starting Apache):
the UAF went from 0/6 to 6/6. **It is OPcache, not the binary.**

Plausible explanation: the session hash table is materialized in
`EG(symbol_table)`, and with OPcache active the persistent memory manager
of OPcache intervenes in the management of that storage, so that the
`zend_array` freed during the OOM is not left in the state that Request B
expects (or the resulting pointer still points to shared memory
that is still mapped, so the access does not cause a SIGSEGV). Without OPcache, the table
lives entirely in the request heap and the effect is the one described in §10.2.

**What this means for an attacker:**

- **It is an environment variable, not a barrier.** Disabling OPcache does not
  "patch" PHP: it only changes the expression of the failure. With OPcache active, the
  UAF **also exists** — what changes is whether it manifests as a detectable
  crash or as a silent access to reused memory. A silent access is, in practice,
  **worse**: there is no SIGSEGV to give the attacker away.
- **A real exploit cannot assume deterministic behavior.** The
  reproducibility of the crash depends on the specific configuration of the
  interpreter. That is why most public PoCs are calibrated against a
  specific binary: the success rate is a function of the target.
- **And it is a mitigation of luck, not of design.** OPcache should not be
  counted on as a defense: the official patch is the only answer.

### 10.11 What was NOT achieved in this work

**What remains unachieved (and is not claimed):**

- **Full RCE.** The instrumentation has resolved *where* the slot is
  (`arr=0x79c99ce54310`, 56 bytes, bin 6) and has proven that Request B
  consumes exactly that slot. What is missing is **placing** a controlled
  structure at that exact position with `pDestructor = zif_system`.
- **Arbitrary memory exfiltration.** The dangling `zend_string` is
  read, but its observed length is still that of the legitimate SID (32
  characters). Controlling *which* bytes are read requires the same kind of
  allocator control that is missing for the RCE.

**Why the classic spray cannot work (demonstrated, §10.6):** the
288-byte blob from the writeups lives in bin 68 of the allocator; the freed
slot is in bin 6. They are different size classes and the allocator
never mixes bins. No amount of iterations or filler precision
resolves that. The escalation requires allocator control or a
structure of exactly 56 bytes.

**Remaining path, in order of difficulty:**

1. ~~Observe the allocator~~ → **done** (§10.6-bis). The slot is freed, it is
   reassigned, and its position in the pool is predictable (element 14 of a
   0x38 progression). The LIFO allocation order hits 28.4 % of the time.
2. Force the placement of a 56-byte `zend_array` in that specific
   slot, with `pDestructor = zif_system` and the command in a
   separate `zend_string`. **This is the step that blocks the RCE.**
3. Verify execution on the local target.

Point 2 is a problem of **allocator control**, not of timing. The
tools to attempt it are already in place: the instrumented binary
(`Dockerfile.trace`) and the idempotent patches that log every
allocation and every free of bin 6.

---

### 10.11-bis The RCE escalation attempt: what was measured and what is missing

With the UAF mechanism verified and the gadget located in the source code,
the primitive can be stated precisely:

```c
/* Zend/zend_types.h:104 */
typedef void (*dtor_func_t)(zval *pDest);

/* Zend/zend_hash.c:1701 — the call */
ht->pDestructor(&p->val);

/* Zend/zend_hash.c:1757 — the condition */
if (UNEXPECTED(ht->pDestructor != ZVAL_PTR_DTOR)) {
    zend_hash_destroy(ht);
    goto free_ht;
}
```

`ZEND_FUNCTION(system)` has the signature `void system(zval *, ...)`, compatible
with `dtor_func_t`. Therefore: **if the freed `zend_array` carries
`pDestructor == zif_system` and one of its buckets contains a `zval` of type
`IS_STRING`, the destructor call becomes `system(&bucket.val)`,
and the string is the command.**

The exact point where this fits is in `php_session_track_init()`
(`ext/session/session.c`):

```c
if (!Z_ISUNDEF(PS(http_session_vars))) {
    zval_ptr_dtor(&PS(http_session_vars));   /* destroys the DANGLING array */
}
array_init(&session_vars);                   /* emalloc(56) */
```

**What was measured in the instrumented binary:** after the OOM, the dangling
array **preserves** `pDestructor == zval_ptr_dtor` and `nTableSize == 8`.
The corruption is partial: the refcount and the flags are garbage, but the
pointer to the destructor and the table size survive intact.

That defines exactly what is missing:

| Requirement | Status |
|---|---|
| The freed `zend_array` is 56 bytes (bin 6) | ✅ measured |
| The slot position in the pool is predictable | ✅ measured (element 14, step 0x38) |
| The next 56 B allocation reuses it | ⚠️ 28,4 % per attempt (LIFO, per page) |
| The slot's `pDestructor` is `zif_system` | ❌ **it is still `zval_ptr_dtor`** |
| An `IS_STRING` bucket with the command | ❌ not reached |

**The requirement that blocks the RCE is the fourth one.** To achieve it, two
things are needed at the same time:

1. For a 56-byte allocation to land **exactly** in the freed slot.
   This is an allocator control problem, and the 28,4 % per attempt makes it
   reachable with several attempts — but with a spray, not with exact control.
2. For that allocation to write `zif_system` at offset `0x30` of the slot
   while keeping the rest of the structure as a valid hash table with an
   `IS_STRING` bucket.

Point 2 is the hard one, because a forged `zend_array` cannot carry the
command inside itself: 56 bytes do not allow for more. The command has to live
in another allocation — a `zend_string` — that the bucket points to.

**What was NOT done and why it is not claimed:** a 56-byte allocation with
attacker-chosen content was not built. The classic 288-byte spray from the
writeups does not work (§10.6), and in this work a 56-byte spray with the
required pointer precision was not modelled. The
`php2shell_rce_exploit.py` image executes the real scenario and reports the
state of the gadget on every attempt, so progress is measurable, but it
**does not produce code execution**.

### 10.12 Validation against the official advisory (`GHSA-6wmf-4rv5-p3rp`)

On 21 October, the PHP project published the advisory
[`GHSA-6wmf-4rv5-p3rp`](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
for CVE-2026-109619. Its description, verbatim:

> PHP contains various global state, such as error, session, object and
> extension state that is retained by a worker but points to memory owned by
> one request. That state must be reset before the request memory is
> released. […] A fatal error, **including one caused by memory exhaustion**,
> can abandon an operation before it performs its matching reset. […] The
> request heap is then freed while the **worker global field still refers to
> it**. A later operation that runs before normal request initialization can
> **consume the stale value**.

And the abstract model it proposes:

> Successful exploitation of this vulnerability requires both a **producer**
> and a **consumer**. The producer is a PHP operation that stores state owned
> by one request in a location PHP can access later in a subsequent request.
> The consumer is a subsequent PHP operation that reads, frees, branches or
> otherwise acts on the stale state.

**This work's measurement is the concrete session case of that abstract
model.** The mapping, point by point:

| Official advisory (generic) | This work's measurement (`session.upload_progress` case) |
|---|---|
| *state retained by a worker but points to memory owned by one request* | `PS(http_session_vars)` published in `php_session_track_init()` |
| *a fatal error, including one caused by memory exhaustion* | `zend_bailout()` due to `Allowed memory size … exhausted` |
| *the request heap is then freed* | `shutdown_memory_manager()` runs nonetheless |
| *the worker global field still refers to it* | `PS(http_session_vars)` still points to the freed slot |
| *producer* | Request A (multipart + `PHP_SESSION_UPLOAD_PROGRESS` + file part) |
| *consumer* | Request B (multipart + `PHP_SESSION_UPLOAD_PROGRESS` without file part) |
| *same worker* | Requirement confirmed: with `MaxRequestWorkers 1` the UAF is 6/6 |
| *before normal request initialization* | `php_session_rfc1867_cleanup()` → `php_session_initialize()` at `MULTIPART_EVENT_END` |

The official advisory describes **CVE-2026-109619** as *"remote code execution
via stale request-owned global state reused by a later request on the same
worker"*, and **CVE-2026-109618** as *"remote code execution via out-of-memory
corruption during request cleanup"*. Both descriptions match what
this work measured separately and with experimental controls.

This has a consequence for the confidence in the rest of the work: the
chain OOM → `longjmp` → freed heap → dangling consumer **is not a
hypothesis of this work**, it is the one the PHP project itself describes. What
this work adds is the **measurement**: the A/B controls that isolate the
responsible pointer, the concrete addresses, the real slot size and the
explanation of why the classic spray from the literature cannot work.

### Note: a quote the literature does not make correctly

The description of CVE-2026-109619 in the advisory is deliberately
abstract: it speaks of «global state» without specifying the session. The `session.upload_progress`
branch is **one** of the possible concretizations of the pattern
— the advisory does not present it as the only one, and this work does not
claim it as an exhaustive account of the failure. What is established is that the session branch
is reproducibly exploitable in 8.2.34, and that its fix
requires the 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 patches.

---

## 11. Conclusions for defense
**The patch is the only complete answer.** INI-based mitigations are partial by design, and the advisory says so explicitly.

**A language bug, not an application bug.** Your code may be perfect and still be vulnerable. This changes the mental model: auditing "my code" does not replace auditing "my runtime".

**The flaw does not require timing, it requires memory.** The first
   description of the attack—a network pause of more than one second to allow
   `session.upload_progress.min_freq` to expire—was **incorrect**, and the
   experimentation in this work ruled it out. The actual chain is
   deterministic: an OOM during multipart parsing, followed by a request that
   triggers `session.upload_progress.cleanup`. There is no timing window to
   tune. This has one direct practical consequence: **rate limiting and
   WAFs that inspect request cadence do not detect this attack**, because
   there is no cadence to inspect.

**The OOM is an attack trigger, not an accident.** The same class of
   request (empty nested uploads) that an attacker would use for a
   denial of service is the one that opens the door to remote execution. In
   the lab, ~536 KB of HTTP body was sufficient to exhaust 32 MB of PHP
   heap. A WAF that limits the *body size* stops nothing; one that limits
   the **number of nested files** does.

**Detection is possible without causing harm.** This work follows a detector
   that triggers the OOM and observes the next request, and that **reliably
   distinguishes** vulnerable behaviour from patched behaviour without requiring
   RCE. For an exposure inventory, this is far more operationally useful than
   an exploit: two requests are sufficient, and it is only necessary to observe
   whether the worker dies or whether the session restarts cleanly. The details
   are in §6 and in `php2shell_leak.py`.

**Defense in depth works.** The patch does not fix the pattern of "publishing
   pointers in globals and trusting that cleanup will run"; it prevents that
   from being exploitable. It remains a design *smell* in the core: the
   correct mechanism would have been to not publish state before the modules
   are activated, or to invalidate the state in `php_request_shutdown()`.

**PHP 7.4/8.0/8.1 are a hole with legs.** Outside the regular development
   cycle for an RCV of 9.2 in the most widely used language in the world. PHP
   published minimal source-code backports for these branches, so the claim
   "EOL and unpatched, vulnerable forever" would be inaccurate: what is missing
   is the regular release cycle, which turns updating into a distro dependency
   or manual work. Any exposure inventory must treat it as a priority.

**For those who distrust third-party PoCs (justifiably).** During
   this investigation it was found that part of the literature on these CVEs
   describes a mechanism that **does not reproduce actual behaviour** (in
   particular, forging `zend_internal_function` as a spray). The lesson is
   methodological and applies to all security work: **always contrast the
   described chain against the source code and the observed behaviour**, and
   not against the height of other PoCs.

---

## Appendix A — Reproducing the lab

```bash
cd research/php2shell-lab

# --- Targets 1 y 2: vulnerable (8.2.34) y parcheado (8.2.35) -----------
docker build -t php2shell-vuln:8.2.34 .
sed 's/8\.2\.34/8.2.35/g' Dockerfile > Dockerfile.patched
docker build -f Dockerfile.patched -t php2shell-patched:8.2.35 .

./lab.sh          # levanta ambos en 8080 (vulnerable) y 8081 (patched)

# Test diferencial vulnerable/patched
python3 behavioural_diff.py 127.0.0.1 8080 "VULNERABLE"
python3 behavioural_diff.py 127.0.0.1 8081 "PATCHED"

# --- Target 3: PHP con símbolos + ASLR off, para análisis de bajo nivel ---
# (compila PHP 8.2.34 desde el código fuente; tarda ~5 minutos)
docker build -f Dockerfile.rce -t php2shell-rce:8.2.34 .
./lab-rce.sh     # lo levanta en 8082

# Verificar la base de libphp.so y los offsets en runtime
curl -s http://127.0.0.1:8082/base.php

# --- Detector/verificador del UAF (con controles negativos) -------------
python3 php2shell_leak.py --host 127.0.0.1 --port 8082 --rounds 8 --controls
```

Expected detector output against the vulnerable target:

```
OOM confirmado:            8/8
Request B -> crash:        4
Request B -> stale SID:    4   ('Session ID is too long' = UAF leido)
Request B -> ok:           0
Control GET tras OOM:      {'ok': 4, 'crash': 0}
Control sin OOM:           {'ok': 4, 'crash': 0}
```

And against the patched target (8081), the same detector must not observe
`crash` nor `stale_sid`: that is the discriminant.

## Appendix B — References

- PHP Security Advisory — `GHSA-w8hw-w9fx-j79w` (CVE-2026-109618)
- PHP Security Advisory — `GHSA-6wmf-4rv5-p3rp` (CVE-2026-109619)
- Official patch `31c0ea7d7ff` — "Avoid state corruption via bailout" (Arnaud Le Blanc)
- Akamai Security Intelligence Group — "Understanding PHP2Shell: Everything You Need to Know"
- Akamai SIG — "Critical Remote Code Execution Vulnerabilities in PHP Core"
- JFrog Security Research — "PHP2Shell: All You Need to Know"
- Wiz — "PHP2Shell: PHP RCE" · Calif Security Lab — `calif.io/php2shell`
- CISA Alert — "Critical Vulnerabilities in PHP Require Immediate Patching" (21 Oct 2026)
- CERT-EU — Advisory 2026-018
- Recorded Future — "PHP2Shell Exploitation: Two Critical PHP Flaws Explained"
- Vercel, Cisco, Laravel Forge, Autodesk, IC3 — advisories from 21-23 Oct 2026

---

> **Scope note:** all tests in this article were performed against local servers in isolated Docker containers, with no Internet exposure. The lab, detector and PoC are published exclusively for defensive and security-research purposes. Exploiting third-party systems without explicit written authorization is illegal in most jurisdictions.

---

## Appendix C — Methodology and traceability

### What was verified firsthand in this work

| Claim | How it was verified |
|---|---|
| Exact UAF location | Direct reading of `ext/session/session.c` (lines ~3090) and `ext/session/php_session.h` (line 136) in PHP 8.2.34 |
| Layout of `zend_internal_function` | C program checking `offsetof` against the actual definition in `Zend/zend_compile.h` |
| `sizeof(zend_internal_function)` = 136 | Compilation and execution of the offsets program |
| Differential vulnerable/patched behaviour | Test executed against real 8.2.34 and 8.2.35 in Docker, with output captured |
| That the patch cuts the handler | Reading the official patch `31c0ea7d7ff` and contrasting it with observed behaviour |
| That `mod_upload_progress` is independent of PHP's `upload_progress` | Search in `ext/session/*.c` and `*.h`: no cross-references |
| Patched versions by branch | Official PHP announcements and Akamai/JFrog/CISA advisories |
| That the OOM during multipart parsing aborts **before** RINIT | `php_request_startup()` in `main/main.c`: `php_hash_environment()` (parsing) precedes `zend_activate_modules()` (RINIT); additionally confirmed because the Request A response includes no script output |
| That the OOM trigger works with ~500 KB of HTTP body | Direct measurement: 3 000 empty nested uploads → `Allowed memory size of 33554432 bytes exhausted` with `memory_limit=32M` |
| That the trigger requires distinct top-level names | A/B comparison: with a shared prefix there is no OOM; with distinct names there is |
| That the UAF is triggered in Request B | `signal 11` in the kernel log + disassembly of the failure point (`libphp.so+0x3b0750`, in `_emalloc`/`zend_mm_alloc_small`) |
| That Request B must go to the same worker | Comparison of worker PIDs before/after each request pair: identical in 100 % of cases |
| That the failure manifests as corruption of the Zend MM allocator | Disassembly of the crash site: the read of `bin->slots[]` follows an unmapped page pointer (`RCX=0x7ffff745520000`) |
| That the official patch cuts the OOM path | Reading the hunk for `ext/session/session.c` in `31c0ea7d7ff`: `PS(in_rfc1867_update)`, `php_rinit_session_globals()` in `MULTIPART_EVENT_START` and `if (PG(modules_activated)) return retval;` |
| That injection into the session file is possible | The upload's `filename` is stored literally in the session file (verified by reading `/tmp/sess_*`) |
| That the actual RCE mechanism uses a hash table with `pDestructor`, not a `zend_internal_function` | Reading the PHP source code (`zend_array_destroy` invokes `pDestructor` with a `zval*`, which is the signature of `zif_system`) and contrasting it with working public PoCs |
| That the crash **does not depend** on Request B's `PHPSESSID` | A/B control: Request B with identical SID (crash 4/4) vs different SID (crash 4/4) |
| That the `PHP_SESSION_UPLOAD_PROGRESS` field in Request B is **essential** | A/B control: Request B without that field → crash 0/4 |
| That the OOM is **necessary and sufficient** | A/B control: Request B with `upload_progress` but no prior OOM → crash 0/4; with OOM → crash 4/4 |
| That the OOM **does not** corrupt the worker in general | Control: normal Request B (GET) after the OOM → 4/4 correct responses |
| That the worker survives the OOM and dies in Request B | Apache log: the SIGSEGV corresponds to the worker's PID **after** the OOM, not during it |
| That the `filename` is serialized literally in the session file | Direct reading of `/tmp/sess_*`: `s:4:"name";s:5:"a.txt";` with explicit lengths |
| That the `filename` **does not** carry arbitrary bytes over HTTP | Direct test: `A\x00B\xffC\x01D` reaches the script as `x01D` (sanitized by PHP) |
| That the length of the filename's `zend_string` is controllable | `$_FILES['name']` reflects exactly 16, 64 and 200 bytes |
| That the failure point is in `zend_mm_alloc_small` following a corrupted free list | Disassembly of `libphp.so+0x3b0750` and disassembly of `Zend/zend_alloc.c` (`bin_data_size`, `bin->slots[]`) |
| That **OPcache** changes the expression of the UAF | A/B on the **same official binary**: with OPcache 0/6, without OPcache 6/6 (the only change was deleting `docker-php-ext-opcache.ini`) |
| That ASLR is not the determining variable | The same lab target with ASLR ON (base `0x7957e39c0000`) also yielded 6/6, the same as with ASLR OFF |
| That the number of Apache workers is determining | With 5 workers (the official image's default) Request B goes to a different process and the UAF is not observed; with `MaxRequestWorkers 1` it is observed 6/6 |
| That `session.upload_progress.cleanup=On` is mandatory for the UAF branch | A/B control: with `cleanup=Off` the `php_session_rfc1867_cleanup()` path does not execute (0/4 crashes) |
| That `max_multipart_body_parts` and `max_file_uploads` block the trigger | Direct observation: with the limit active "Multipart body parts limit exceeded" appears and the OOM never triggers; with `max_file_uploads=20` (default) the heap is never exhausted |
| That PHP 8.2.35 enforces an internal limit of 2000 multipart parts | Server message: "Multipart body parts limit exceeded 2000" |
| That the official patch **eliminates the OOM** rather than merely fixing the corruption | With 1500 parts, 8.2.35 does not exhaust memory (0/6) while 8.2.34 does (6/6) |

### What comes from public analysis and was not reproduced here

- **Memory exfiltration** (leak) via `php_url_encode(ZSTR_VAL(PS(id)), ZSTR_LEN(PS(id)))`
  requires heap *grooming* that was not achieved in this lab: in
  Request B, the dangling pointer points to unmapped memory (crash) or is
  detected as invalid (clean failure of `php_session_initialize()`).
- **Full RCE** additionally requires resolving the base address of `libphp.so`
  at runtime—or using the purely-HTTP ASLR leak described in the write-ups—and
  placing the forged hash table in the exact slot.
- The spray figures (149 × 288) come from Akamai's analysis. The struct layout
  was independently cross-checked against the source code.
- The four-stage ASLR leak chain (chunk base → `libphp` base →
  `zif_system` → table forging) is documented in the cited public PoCs; it was
  not reimplemented here.

### Note on public PoCs: two sources of risk

1. **Fake malicious payloads.** During the investigation it was observed that
   some PoC repositories published for these CVEs **distribute fake malicious
   payloads** (JFrog documents at least one case: a script that only changed
   the system wallpaper). Before running any third-party PoC, audit it line by
   line.
2. **Possibly obsolete fixtures.** Part of this work relied on public PoCs;
   their artifacts may contain fixtures that do not correspond to the actual
   mechanism. The primitives described in this article were verified
   **independently** against the source code and against the behaviour
   observed in the lab; no claim relies solely on a third-party PoC.
