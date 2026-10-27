#!/usr/bin/env python3
"""
apply_dtor_trace_patch.py — Instrumenta el punto EXACTO donde se dispara el
destructor del array colgante.

Contexto
--------
En `php_session_track_init()` (ext/session/session.c):

    if (!Z_ISUNDEF(PS(http_session_vars))) {
        zval_ptr_dtor(&PS(http_session_vars));   <-- DESTRUYE EL ARRAY COLGANTE
    }
    array_init(&session_vars);                   <-- emalloc(56) NUEVO

`zval_ptr_dtor` -> `rc_dtor_func` -> `zend_array_destroy` -> si
`pDestructor != ZVAL_PTR_DTOR` -> `zend_hash_destroy(ht)` -> `ht->pDestructor(data)`.

Es decir: el `pDestructor` del array liberado es un puntero que se invoca
indirectamente. Este parche registra:

  1. DTOR_PRE:  la direccion del array, su `pDestructor` actual, `nNumUsed`,
     `arData` y el contenido de los primeros buckets — justo ANTES de que
     se dispare el destructor.
  2. DTOR_POST: el estado despues, por si el destructor crashea.

Esto permite ver si `pDestructor` sobrevive (medido: si, era zval_ptr_dtor)
y que elemento seria el que se pasaria a `system()`.

Uso
---
    python3 apply_dtor_trace_patch.py /ruta/a/php-8.2.34/ext/session/session.c

Idempotente.
"""

from __future__ import annotations

import re
import sys

MARK = "PHP2SHELL_DTOR"

ANCHOR_RE = re.compile(
    r"(\n\tif \(!Z_ISUNDEF\(PS\(http_session_vars\)\)\) \{\n"
    r"\t\tzval_ptr_dtor\(&PS\(http_session_vars\)\);)")

BLOCK = r'''
	/* === PHP2SHELL_DTOR: traza del punto de destruccion del array colgante === */
	{
		FILE *tf;
		tf = fopen("/tmp/php2shell_dtor.log", "a");
		if (tf) {
			if (!Z_ISUNDEF(PS(http_session_vars))) {
				zval *zv = &PS(http_session_vars);
				/* Z_REFVAL() toma un zval (no un zval*), igual que hace el
				 * propio modulo en php_session_rfc1867_cleanup(). */
				if (Z_ISREF_P(zv) && Z_TYPE_P(Z_REFVAL(*zv)) == IS_ARRAY) {
					zend_array *arr = Z_ARRVAL_P(Z_REFVAL(*zv));
					fprintf(tf,
						"DTOR_PRE arr=%p gc=%u flags=0x%x nTableSize=%u "
						"nNumUsed=%u nNumOfElements=%u arData=%p "
						"pDestructor=%p nNextFreeElement=%ld\n",
						(void*)arr, arr->gc.refcount,
						(unsigned)arr->u.flags,
						arr->nTableSize, arr->nNumUsed, arr->nNumOfElements,
						(void*)arr->arData,
						(void*)(uintptr_t)arr->pDestructor,
						(long)arr->nNextFreeElement);

					/* Volcado de los primeros buckets: si el destructor
					 * acaba siendo zif_system, el valor que recibe es el
					 * que hay en zv del bucket. */
					if (arr->nNumUsed && arr->nTableSize && !HT_IS_PACKED(arr)) {
						Bucket *b = arr->arData;
						unsigned i, lim = arr->nNumUsed < 4 ? arr->nNumUsed : 4;
						for (i = 0; i < lim; i++) {
							fprintf(tf,
								"DTOR_BUCKET arr=%p idx=%u key=%p val_type=%d "
								"val_str=%p val_str_len=%zu\n",
								(void*)arr, i, (void*)b[i].key,
								(int)Z_TYPE(b[i].val),
								(Z_TYPE(b[i].val) == IS_STRING)
									? (void*)Z_STR(b[i].val) : NULL,
								(Z_TYPE(b[i].val) == IS_STRING)
									? Z_STRLEN(b[i].val) : 0);
							if (Z_TYPE(b[i].val) == IS_STRING) {
								zend_string *zs = Z_STR(b[i].val);
								fprintf(tf, "DTOR_BUCKET_STR arr=%p idx=%u val=[%.*s]\n",
									(void*)arr, i, (int)zs->len,
									zs->len ? ZSTR_VAL(zs) : "");
							}
						}
					}
				} else {
					fprintf(tf, "DTOR_PRE (no es array/ref)\n");
				}
			} else {
				fprintf(tf, "DTOR_PRE (undef)\n");
			}
			fclose(tf);
		}
	}
	/* === FIN PHP2SHELL_DTOR === */
'''


def patch(path: str) -> None:
    with open(path, encoding="utf-8", errors="surrogateescape") as fh:
        text = fh.read()

    if MARK in text:
        print("ya instrumentado; no se toca")
        return

    m = ANCHOR_RE.search(text)
    if not m:
        raise SystemExit("ERROR: no encuentro el zval_ptr_dtor de "
                         "PS(http_session_vars)")

    # Insertar justo ANTES del if que hace el zval_ptr_dtor, de modo que la
    # traza se emite con el array colgante todavia intacto.
    patched = text[:m.start()] + BLOCK + text[m.start():]

    # --- post-condiciones -------------------------------------------------
    # El fallo original de este parche fue un regex que se comia la llave
    # de apertura de la funcion y dejaba el source sin compilar. Estas
    # comprobaciones hacen que el parche falle ruidosamente en vez de
    # romper el build.
    if patched.count("{") != patched.count("}"):
        raise SystemExit("ERROR: post-condicion fallida — desbalance de llaves "
                         "introducido por el parche. Abortando.")
    if "static void php_session_track_init(void) /* {{{ */" not in patched:
        raise SystemExit("ERROR: la firma de php_session_track_init se ha "
                         "alterado. Abortando.")
    if "static void php_session_track_init(void) /* {*/" in patched:
        raise SystemExit("ERROR: el comentario de la funcion quedo mal "
                         "cerrado. Abortando.")
    if patched.count("PHP2SHELL_DTOR") != 2:
        raise SystemExit("ERROR: marcadores PHP2SHELL_DTOR incompletos "
                         f"({patched.count('PHP2SHELL_DTOR')}). Abortando.")

    with open(path, "w", encoding="utf-8", errors="surrogateescape") as fh:
        fh.write(patched)
    print(f"instrumentado: {path}")


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(f"uso: {sys.argv[0]} <ruta a ext/session/session.c>")
    patch(sys.argv[1])


if __name__ == "__main__":
    main()
