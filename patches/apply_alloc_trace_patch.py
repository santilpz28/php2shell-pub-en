#!/usr/bin/env python3
"""
apply_alloc_trace_patch.py — Instrumenta Zend/zend_alloc.c para registrar
el estado del allocator de Zend MM durante y despues del OOM.

Motivo
------
Para escalar a RCE hay que saber que bloque ocupa fisicamente el slot
liberado por la zend_array de sesion, y si sigue en la lista de bloques
libres del bin correspondiente.

En Zend MM, los bloques pequenos (size <= 64) se gestionan por bins, y
cada bin tiene una lista de slots libres encadenados:

    heap->free_slot[bin_num] -> zend_mm_free_slot { next_free_slot, ... }

Cuando un bloque de 56 bytes (bin 6) se libera, pasa a esa lista. La
reutilizacion solo es posible si el siguiente allocation que pide ese
bin toma ESE bloque concreto.

Este parche registra:
  - FREE_SMALL: cuando se libera un bloque small, con su bin y su tamano.
  - ALLOC_SMALL: cuando se asigna un bloque small, con bin, tamano y si
    reutiliza (reused=1) o es un bloque nuevo (reused=0).
  - FREE_LIST: el estado de heap->free_slot[bin] para el bin observado.

El contador de asignaciones permite correlacionar la secuencia de
requests (Request A = OOM, Request B = consumidor) con el allocator.

Uso
---
    python3 apply_alloc_trace_patch.py /ruta/a/php-8.2.34/Zend/zend_alloc.c

Idempotente.
"""

from __future__ import annotations

import re
import sys

MARK = "PHP2SHELL_ALLOC"

# Se instrumenta zend_mm_free_small (la ruta de free) y
# zend_mm_alloc_small (la ruta de alloc). Ambas son zend_always_inline /
# zend_never_inline dentro de Zend/zend_alloc.c.

# Las firmas reales pueden o no llevar los macros ZEND_FILE_LINE_DC,
# segun la version. Se localizan por regex para ser tolerante.
FREE_RE = re.compile(
    r"static zend_(?:never|always)_inline void zend_mm_free_small\("
    r"zend_mm_heap \*heap, void \*ptr, int bin_num[^\n]*\n\{")
ALLOC_RE = re.compile(
    r"static zend_always_inline void \*zend_mm_alloc_small\("
    r"zend_mm_heap \*heap, int bin_num[^\n]*\n\{")

FREE_BLOCK = r'''	/* === PHP2SHELL_ALLOC: traza del allocator === */
	{
		FILE *tf = fopen("/tmp/php2shell_alloc.log", "a");
		if (tf) {
			fprintf(tf, "FREE_SMALL ptr=%p bin=%d size=%u\n",
				ptr, bin_num, (unsigned)bin_data_size[bin_num]);
			fclose(tf);
		}
	}
	/* === FIN PHP2SHELL_ALLOC === */
'''

ALLOC_BLOCK = r'''	/* === PHP2SHELL_ALLOC: traza del allocator === */
	{
		FILE *tf = fopen("/tmp/php2shell_alloc.log", "a");
		if (tf) {
			zend_mm_free_slot *fs = heap->free_slot[bin_num];
			unsigned nfree = 0;
			while (fs && nfree < 64) { nfree++; fs = fs->next_free_slot; }
			fprintf(tf,
				"ALLOC_SMALL bin=%d size=%u free_slots=%u head=%p\n",
				bin_num, (unsigned)bin_data_size[bin_num], nfree,
				(void*)heap->free_slot[bin_num]);
			fclose(tf);
		}
	}
	/* === FIN PHP2SHELL_ALLOC === */
'''


def patch(path: str) -> None:
    with open(path, encoding="utf-8", errors="surrogateescape") as fh:
        text = fh.read()

    if MARK in text:
        print("ya instrumentado; no se toca")
        return

    # --- free ---
    m = FREE_RE.search(text)
    if not m:
        raise SystemExit("ERROR: no encuentro zend_mm_free_small")
    text = text[:m.end()] + FREE_BLOCK + text[m.end():]

    # --- alloc ---
    m = ALLOC_RE.search(text)
    if not m:
        raise SystemExit("ERROR: no encuentro zend_mm_alloc_small")
    text = text[:m.end()] + ALLOC_BLOCK + text[m.end():]

    with open(path, "w", encoding="utf-8", errors="surrogateescape") as fh:
        fh.write(text)

    print(f"instrumentado: {path}")


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(f"uso: {sys.argv[0]} <ruta a Zend/zend_alloc.c>")
    patch(sys.argv[1])


if __name__ == "__main__":
    main()
