# Evidence — raw instrumented logs

Raw logs captured from the instrumented PHP 8.2.34 build
(`php2shell-trace:8.2.34`) while running the OOM -> Request B scenario.

## `peek2_dangling_array.log`

Raw 8-byte dump of the **dangling** `zend_array`, taken at the exact moment
`php_session_rfc1867_cleanup()` reads it — i.e. after the OOM freed the
heap and before `zend_array_destroy()` runs on it.

This is the measurement that corrected an earlier wrong conclusion.

| Offset | Field | Observed | Meaning |
|---|---|---|---|
| 0x00 | `gc.refcount` | 1 | intact |
| 0x08 | `u.flags` | 0x07 | intact |
| 0x0C | `nTableMask` | 0xfffffff0 | intact |
| 0x10 | `arData` | `arr + 0x30` | **garbage — self-referential** |
| 0x18 | `nNumUsed` / `nNumOfElements` | 1 / 1 | intact |
| 0x20 | `nTableSize` | 8 | intact |
| 0x28 | `nNextFreeElement` | 0x8000000000000000 | intact |
| 0x30 | `pDestructor` | `arr + 0x50` | **garbage — NOT `zval_ptr_dtor`** |

The base of the run was `0x728fa4a87000`, so:

- `zval_ptr_dtor` resolved to `0x728fa4e60950` (offset `0x3d9950`)
- `zif_system`    resolved to `0x728fa4d94560` (offset `0x30d560`)

Neither matches the observed `pDestructor = 0x728fa6655360`.

**Correction to the article.** An earlier revision of this work stated that
the dangling array "keeps `pDestructor == zval_ptr_dtor`". That was an
inference from reading the field, not a verified value, and the raw dump
disproves it: the last 24 bytes of the freed slot were overwritten by the
allocator, and `pDestructor` holds a self-referential pointer
(`arr + 0x50`) rather than any function address.

The consequence for the exploit is more severe than previously stated: the
`pDestructor` field is not merely "not yet `zif_system`" — it no longer
holds a function pointer at all. Any RCE has to restore a valid
`pDestructor` *and* a valid `arData` bucket table, not just overwrite one
field.

## `trace_session.log`

`TRACK_INIT` and `CLEANUP` records for the same run, showing the identity
of the array that the consuming request operates on, and the state of the
array as read by `php_session_rfc1867_cleanup()`.
