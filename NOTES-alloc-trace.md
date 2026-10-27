# PHP2Shell — Instrumentation logbook (2026-10-27)

## Objective
Escalate the verified UAF to RCE, determining the real mechanism of release
and Consumption of the `PS(http_session_vars)` slot.

## Instrumentation
- `patches/apply_trace_patch.py` → `ext/session/session.c`
  - `TRACK_INIT` in `php_session_track_init()`: address, flags, nTableSize,
    nNumUsed, arData, pDestructor, sizeof(zend_array).
  - `CLEANUP` in `php_session_rfc1867_cleanup()`: address consumed by Request B.
- `patches/apply_alloc_trace_patch.py` → `Zend/zend_alloc.c`
  - `FREE_SMALL ptr=... bin=... size=...`
  - `ALLOC_SMALL bin=... size=... free_slots=... head=...`

Both idempotent. Applied BEFORE compiling (`Dockerfile.trace`).

## Results

### 1. UAF confirmed with addresses (2/2 runs)

```
TRACK_INIT arr=0x79c99ce54310 gc=1          flags=0x8 nTableSize=8 sizeof=56
CLEANUP    arr=0x79c99ce54310 gc=2632270664 flags=0x0 nTableSize=8 nNumUsed=1
```

Second run (different ASLR):
```
TRACK_INIT arr=0x7cd8a2e54310 gc=1          flags=0x8 nTableSize=8 sizeof=56
CLEANUP    arr=0x7cd8a2e54310 gc=2732933960 flags=0x0 nTableSize=8 nNumUsed=1
```

**The `arr` address is IDENTICAL in TRACK_INIT and CLEANUP.** Request B operates
on exactly the object that Request A freed. UAF demonstrated, not inferred.

Signature of the freed state:
- `gc.refcount`: 1 → 2632270664 / 2732933960 (garbage: a real refcount is never that)
- `flags`: 0x8 → 0x0 (stomped)
- `nNumUsed`: 0 → 1 (bucket reused)
- `nTableSize`: 8 → 8 (survives)
- `pDestructor`: zval_ptr_dtor → zval_ptr_dtor (survives intact)

### 2. sizeof(zend_array) = 56 bytes → bin 6

`zend_mm_small_size_to_bin()` (Zend/zend_alloc.c), for size <= 64:
`bin = (size - !!size) >> 3` → 56 → (56-1)>>3 = 6.

Ranges: bin 3 = 25-32 B (SID zend_string), bin 6 = 49-56 B (zend_array),
bin 68 = outside small range (288 B blob from the writeups).

**Consequence: the classic 288-byte spray lives in bin 68 and can NEVER
reclaim the bin 6 slot. It is not timing, not precision, not ASLR: it is
SIZE CLASS.**

### 3. The bin 6 pool is contiguous and deterministic

Single `head` sequence in ALLOC_SMALL bin=6:
```
0x7cd8a2e54038 → 04070 → 040a8 → 040e0 → 04118 → 04150 → 04188 → 041c0
→ 041f8 → 04230 → 04268 → 042a0 → 042d8 → 04310 ← the zend_array slot
→ 04348 → 04380 → 043b8 → 043f0 → 04428 → ...
```
Constant step of **0x38 (56 bytes)**. The `zend_array` slot is number 14 of
the sequence. The position within the pool is **predictable**.

### 4. The slot is freed and reassigned (measured lifecycle)

```
line 113      ALLOC_SMALL bin=6 head=0x7cd8a2e54310  ← allocated (session zend_array)
line 100295   FREE_SMALL  ptr=0x7cd8a2e54310         ← freed
line 100297   ALLOC_SMALL bin=6 head=0x7cd8a2e54310  ← REASSIGNED 2 lines later
line 197814   FREE_SMALL  ptr=0x7cd8a2e54310
line 197816   ALLOC_SMALL bin=6 head=0x7cd8a2e54310
```

The slot **does** return to the free list and **is** reassigned.

### 5. LIFO: 28.4% hit rate

Over 7.463 consecutive bin 6 (free→alloc) pairs:
- **Strict LIFO: 2.123 (28.4%)** — the next 56 B alloc uses the just-freed slot.
- **No match: 5.340 (71.6%)** — contention from other slots/pages.

Reason: `heap->free_slot[bin]` is a stack **per page**. A free on another
page pushes its own slot onto the head of that page's list.

**Implication for the escalation:** 28% per attempt is not a problem, it is an
advantage: 3-4 attempts give >70% cumulative success. It explains why the
public PoCs use massive spraying, and why a 56-byte spray (not 288) should
work.

## Status
- Full RCE: **NOT achieved**.
- Pending: force a controlled 56-byte allocation right after the OOM
  so that it lands in the slot, with `pDestructor = zif_system` and the command
  in a separate `zend_string`.
