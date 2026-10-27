#!/usr/bin/env python3
"""
apply_trace_patch.py — Instrumenta ext/session/session.c de PHP 8.2 para
registrar la zend_array de sesion y el punto donde se consume el estado
colgante (UAF).

Motivo
------
Para escalar a RCE hay que saber, con exactitud:
  1. La DIRECCION del zend_array de sesion (el slot a reclamar).
  2. Su TAMANO en bytes (determina el bin del allocator de Zend MM).
  3. Su pDestructor actual.
  4. Que el Request B opera exactamente sobre esa misma direccion.

Sin estos datos, cualquier "spray" es a ciegas. Este parche los expone.

Notas de layout (PHP 8.2)
-------------------------
En PHP 8.2, zend_array NO tiene un miembro .ht: la HashTable esta
EMBEBIDA en zend_array mediante uniones (arData / arHash / arPacked).
Los campos del layout son planos:

    struct _zend_array {
        zend_refcounted_h gc;
        union { ... } u;          // u.flags
        uint32_t          nTableMask;
        union { uint32_t *arHash; Bucket *arData; zval *arPacked; };
        uint32_t          nNumUsed;
        uint32_t          nNumOfElements;
        uint32_t          nTableSize;
        uint32_t          nInternalPointer;
        zend_long         nNextFreeElement;
        dtor_func_t       pDestructor;
    };

Ademas, ZEND_HASH_FOREACH_STR_KEY_VAL ya NO existe en 8.2 (solo
ZEND_HASH_FOREACH(_ht, indirect)), asi que el recorrido se hace a mano
sobre arData como Bucket*.

Uso
---
    python3 apply_trace_patch.py /ruta/a/php-8.2.34/ext/session/session.c

Es idempotente: si el fichero ya esta instrumentado, no hace nada.
"""

from __future__ import annotations

import sys

MARK = "PHP2SHELL_TRACE"

TRACK_BLOCK = r'''	/* === PHP2SHELL_TRACE: instrumentacion de investigacion ===
	 * PHP 8.2: zend_array NO tiene .ht; la HashTable esta embebida
	 * (uniones arData/arHash/arPacked). Campos planos:
	 *   u.flags, nTableMask, arData, nNumUsed, nNumOfElements,
	 *   nTableSize, nInternalPointer, nNextFreeElement, pDestructor
	 */
	{
		zend_array *arr = Z_ARRVAL_P(Z_REFVAL(PS(http_session_vars)));
		FILE *tf;
		tf = fopen("/tmp/php2shell_trace.log", "a");
		if (tf) {
			fprintf(tf,
				"TRACK_INIT arr=%p gc=%u flags=0x%x nTableMask=0x%x arData=%p "
				"nNumUsed=%u nNumOfElements=%u nTableSize=%u nInternalPointer=%u "
				"nNextFreeElement=%ld pDestructor=%p sizeof=%zu\n",
				(void*)arr, arr->gc.refcount,
				(unsigned)arr->u.flags,
				(unsigned)arr->nTableMask,
				(void*)arr->arData,
				arr->nNumUsed, arr->nNumOfElements, arr->nTableSize,
				arr->nInternalPointer,
				(long)arr->nNextFreeElement,
				(void*)(uintptr_t)arr->pDestructor,
				sizeof(zend_array));
			/* Recorrido manual: en PHP 8.2 la HashTable esta embebida en
			 * zend_array, y arData apunta a un array de Bucket. */
			if (!HT_IS_PACKED(arr)) {
				Bucket *b = arr->arData;
				uint32_t i;
				for (i = 0; i < arr->nNumUsed; i++, b++) {
					if (Z_TYPE(b->val) == IS_UNDEF) {
						continue;
					}
					fprintf(tf, "  ENTRY key=%s type=%d keylen=%d\n",
						b->key ? ZSTR_VAL(b->key) : "(numeric)",
						(int)Z_TYPE(b->val),
						b->key ? (int)ZSTR_LEN(b->key) : 0);
				}
			} else {
				zval *v = arr->arPacked;
				uint32_t i;
				for (i = 0; i < arr->nNumUsed; i++, v++) {
					if (Z_TYPE_P(v) == IS_UNDEF) {
						continue;
					}
					fprintf(tf, "  ENTRY key=(packed:%u) type=%d\n",
						i, (int)Z_TYPE_P(v));
				}
			}
			fclose(tf);
		}
	}
	/* === FIN PHP2SHELL_TRACE === */'''

FREE_BLOCK = r'''	/* === PHP2SHELL_FREE: traza del consumidor del estado colgante === */
	{
		FILE *tf;
		tf = fopen("/tmp/php2shell_trace.log", "a");
		if (tf) {
			if (!Z_ISUNDEF(PS(http_session_vars))) {
				zval *zv = &PS(http_session_vars);
				zend_array *arr = Z_ARRVAL_P(Z_REFVAL(*zv));
				fprintf(tf,
					"CLEANUP ps_http_session_vars=%p arr=%p gc=%u flags=0x%x "
					"nTableSize=%u nNumUsed=%u arData=%p pDestructor=%p\n",
					(void*)zv, (void*)arr, arr->gc.refcount,
					(unsigned)arr->u.flags,
					arr->nTableSize, arr->nNumUsed,
					(void*)arr->arData,
					(void*)(uintptr_t)arr->pDestructor);
			} else {
				fprintf(tf, "CLEANUP ps_http_session_vars=UNDEF\n");
			}
			fclose(tf);
		}
	}
	/* === FIN PHP2SHELL_FREE === */'''


def patch_track_init(text: str) -> str:
    """Inserta la traza en php_session_track_init()."""
    anchor = """	array_init(&session_vars);
	ZVAL_NEW_REF(&PS(http_session_vars), &session_vars);
	Z_ADDREF_P(&PS(http_session_vars));
	zend_hash_update_ind(&EG(symbol_table), var_name, &PS(http_session_vars));
	zend_string_release_ex(var_name, 0);
}"""
    if anchor not in text:
        raise SystemExit("ERROR: no encuentro el bloque de php_session_track_init")
    return text.replace(
        anchor,
        anchor[:-1] + TRACK_BLOCK + "\n}",
        1,
    )


def patch_cleanup(text: str) -> str:
    """Inserta la traza al inicio de php_session_rfc1867_cleanup()."""
    lines = text.split("\n")

    sig_idx = None
    for i, ln in enumerate(lines):
        if "static void php_session_rfc1867_cleanup(" in ln:
            sig_idx = i
            break
    if sig_idx is None:
        raise SystemExit("ERROR: no encuentro php_session_rfc1867_cleanup")

    # La firma usa el estilo "/* {" -> la llave real esta unas lineas despues.
    open_idx = None
    for i in range(sig_idx + 1, min(sig_idx + 12, len(lines))):
        if lines[i].strip() == "{":
            open_idx = i
            break
    if open_idx is None:
        raise SystemExit("ERROR: no encuentro la llave de apertura de la funcion")

    block = FREE_BLOCK.split("\n")
    lines = lines[:open_idx + 1] + block + lines[open_idx + 1:]
    return "\n".join(lines)


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(f"uso: {sys.argv[0]} <ruta a ext/session/session.c>")

    path = sys.argv[1]
    with open(path, encoding="utf-8", errors="surrogateescape") as fh:
        text = fh.read()

    if MARK in text:
        print("ya instrumentado; no se toca")
        return

    text = patch_track_init(text)
    text = patch_cleanup(text)

    with open(path, "w", encoding="utf-8", errors="surrogateescape") as fh:
        fh.write(text)

    print(f"instrumentado: {path}")


if __name__ == "__main__":
    main()
