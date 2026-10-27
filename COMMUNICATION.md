# PHP2Shell — Executive summary for Chain-Cortex

**Communication and services sales material.**

---

## Option A — LinkedIn / long post (GitHub-style)

### 🔴 PHP2Shell: two CVEs rated 9.2 in the PHP core. Your application may be flawless and still be vulnerable.

On October 21, the PHP project published an emergency release fixing two critical
vulnerabilities in the language's **core**:

| CVE | Impact |
|---|---|
| **CVE-2026-109619** | RCE + memory disclosure (use-after-free in `session.upload_progress`) |
| **CVE-2026-109618** | RCE + memory disclosure (corruption due to OOM) |

CVSS v4.0: **9.2** for both.

What makes this not "just another bug":

1. **It is not an application bug.** It is in the interpreter. Any endpoint that accepts
   a multipart upload is vulnerable, even if your code is flawless.
2. **No authentication.** There is no login to bypass.
3. **Vulnerable default configuration.** `session.upload_progress.enabled=On` has been the
   factory default since PHP 5.
4. **PHP 7.4 is EOL and will not receive a patch.** It remains vulnerable forever.

CISA, Cisco, Akamai, Vercel, Laravel, Autodesk, IC3 and CERT-EU published advisories on
the same day. There are indications of active exploitation.

**Patched versions:** 8.2.35 · 8.3.36 · 8.4.27 · 8.5.12

**The technical detail that hurts the most:** the official patch *does not rewrite the
vulnerable code*. Instead, it preventively aborts the second execution of the callback
that freed the memory, and forces objects deserialized in the session file to remain as
`__PHP_Incomplete_Class`. This is defense in depth over a fragile design pattern
that is still there.

**In the Chain-Cortex lab** we set up the vulnerable and patched environments,
verified differential behavior, analyzed the source code for the core and the
official patch, and published the complete analysis with a PoC.

→ Link to the full article

---

## Option B — Newsletter / executive summary (300 words)

**Subject:** PHP2Shell — urgent PHP exposure audit

On October 21, 2026, PHP published an emergency release fixing two critical
vulnerabilities (CVSS 9.2) in the language's **core**: CVE-2026-109619
(use-after-free) and CVE-2026-109618 (memory corruption due to exhaustion). Both
allow remote code execution **without authentication**.

What matters for your organization:

- **The flaw is in PHP, not in your application.** Your code may be correct and the
  server may still be exploitable. A code audit does not cover this.
- **Default requirement.** `session.upload_progress.enabled=On` is enabled out of
  the box. All that is needed is an endpoint that accepts uploads.
- **Double impact:** command execution and reading process memory, which can expose
  data belonging to other users sharing the worker (Heartbleed pattern).
- **PHP 7.4 has no fix.** It is out of support and will not receive a patch.

**What to do:**
1. Inventory the actual PHP version running (not the package version).
2. Update to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 and restart all workers.
3. For PHP 7.4: plan a migration.
4. If you cannot update immediately: `session.upload_progress.enabled=0` mitigates
   the main branch, but it is a partial mitigation.
5. Review logs looking for `PHP_SESSION_UPLOAD_PROGRESS` in multipart requests and
   anomalous activity in `session.save_path`.

**Chain-Cortex proposal:** PHP2Shell exposure audit for your fleet —
version inventory, exposure verification with differential testing on non-intrusive
services, and remediation validation. The detector we use distinguishes vulnerable
from patched without needing to run exploits or know binary offsets.

---

## Option C — Notes for the technical team (internal)

### Exposure checklist

```bash
# Actual version at runtime
php -r 'echo PHP_VERSION, PHP_EOL;'

# Relevant configuration
php -i | grep -E "upload_progress|memory_limit"

# SAPI (mod_php = app-independent RCE confirmed)
php -r 'echo php_sapi_name(), PHP_EOL;'
```

| SAPI | Status |
|---|---|
| `apache2handler` | App-independent RCE confirmed |
| `fpm-fcgi` | Susceptible via state published after startup; `pm.max_requests=1` breaks the same-worker requirement |
| `cli-server` | Not exposed as a web service |

### Differential test (the reliable detector)

```bash
python3 behavioural_diff.py <host> <port>
```

Behavior observed in the lab:

- **Vulnerable (8.2.34):** the session contains `upload_progress_<key>` with the
  upload state. 588-byte response.
- **Patched (8.2.35):** the session is not modified. 332-byte response.

Advantage: **no offsets, no ASLR, and no need to run exploits.** It works against
any PHP accessible over HTTP. Ideal for fleet inventory at scale.

### Indicators for SIEM/WAF

- `PHP_SESSION_UPLOAD_PROGRESS` field in multipart requests without a functional need.
- `t[]` fields with values of ~288 bytes and a high repetition density.
- Multipart requests with a temporary pause between the start of the file and the rest of the body.
- `PHPSESSID` with an anomalous format.

### Post-exploitation

- Session files with unexpected content.
- Child processes of the PHP worker executing shells.
- `mod_php` logs containing `system()`, `exec()`, `passthru()`, `shell_exec()`,
  `popen()`, `proc_open()`.
- New files in `document_root` (`.htaccess`, `webshell.php`).

### Internal warning about third-party PoCs

There are public PoC repositories for these CVEs that **distribute fake malicious
payloads** (documented by JFrog: one script only changed the system wallpaper
to NSFW content). Audit any PoC before running it.
