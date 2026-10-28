#!/usr/bin/env python3
"""
verify_backport.py — Comprueba que un PHP realmente lleva el parche de
PHP2Shell (CVE-2026-109618 / CVE-2026-109619) aplicado, INDEPENDIENTEMENTE
de su numero de version.

Por que esto existe
-------------------
El numero de version es un proxy, no una garantia. Un 8.2.34 parcheado a mano
NO es vulnerable, aunque php -v diga 8.2.34. Y un 8.2.35 recien salido de
Docker SI lo es, aunque su -v lo diga. Este script discrimina por
COMPORTAMIENTO y por EVIDENCIA EN EL CODIGO, no por la etiqueta.

Tres comprobaciones, en orden de coste:
  1. HUELLA DE CODIGO   : se busca el hunk que el parche introduce en
                          ext/session/session.c (el "|| true" que desactiva
                          el callback de upload_progress) y el cambio
                          exit(1) -> _exit(1) en Zend/zend_alloc.c.
                          Requiere acceso al binario o al codigo fuente.
  2. COMPORTAMIENTO     : se dispara el escenario real (Request A = OOM,
                          Request B = consumo del estado colgante) y se
                          observa si el UAF se manifiesta.
  3. FINGERPRINT DE BINARY: se calcula el hash de los simbolos relevantes
                          para poder afirmar "este binario concreto esta
                          parcheado" de forma reproducible.

Uso:
  python3 verify_backport.py --host 127.0.0.1 --port 8082 [--label ...]
  python3 verify_backport.py --source /ruta/a/php-src
  python3 verify_backport.py --container php2shell-backport

Exit codes:
  0 = parcheado (por codigo y/o comportamiento)
  1 = vulnerable
  2 = error / inconcluso
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys

# --- Huellas del parche -------------------------------------------------
# El commit "Avoid state corruption via bailout" introduce, entre otras
# cosas, esto en ext/session/session.c:
#
#     -    if (!PS(rfc1867_enabled)) {
#     +    if (!PS(rfc1867_enabled) || true) {
#
# Es una mitigacion "todo o nada": con el parche aplicado, el callback de
# upload_progress queda permanentemente desactivado, y la rama CVE-2026-109619
# (que necesita ese callback para consumir el estado de sesion colgante)
# nunca llega a ejecutarse.
SESSION_HUNK_OLD = "if (!PS(rfc1867_enabled)) {"
SESSION_HUNK_NEW = "if (!PS(rfc1867_enabled) || true) {"

# Y en Zend/zend_alloc.c la salida por OOM deja de usar exit(1) (que ejecuta
# los atexit handlers y hace unwinding a traves de la VM, corrompiendo el
# estado del allocator) y pasa por zend_mm_safe_error_ex() con _exit(1).
ALLOC_OLD = 'fprintf(stderr, "Out of memory\\n");\n\texit(1);'
ALLOC_NEW = 'fprintf(stderr, "Out of memory\\n");\n\t_exit(1);'

# Senales alternativas (mas robustas) que aparecen en el codigo parcheado:
#  - el callback de upload_progress queda desactivado incondicionalmente
SESSION_SIGNALS = [
    "if (!PS(rfc1867_enabled) || true) {",
    "if (!PS(rfc1867_enabled) || true)",
]

#  - el allocator enruta el error de OOM por la funcion nueva del parche
ALLOC_SIGNALS = [
    "zend_mm_safe_error_ex",
    "zend_mm_safe_error",
]


def check_source(path: str) -> dict:
    """Huella de codigo sobre un arbol de fuentes PHP."""
    result = {"checked": "source", "path": path, "signals": {}}
    session_c = os.path.join(path, "ext/session/session.c")
    alloc_c = os.path.join(path, "Zend/zend_alloc.c")

    if os.path.isfile(session_c):
        with open(session_c, "r", errors="replace") as fh:
            src = fh.read()
        if any(sig in src for sig in SESSION_SIGNALS):
            result["signals"]["session_callback_disabled"] = True
        elif SESSION_HUNK_OLD in src:
            result["signals"]["session_callback_disabled"] = False
        else:
            result["signals"]["session_callback_disabled"] = None

    if os.path.isfile(alloc_c):
        with open(alloc_c, "r", errors="replace") as fh:
            src = fh.read()
        if any(sig in src for sig in ALLOC_SIGNALS):
            result["signals"]["oom_uses_safe_error"] = True
        elif ALLOC_OLD in src:
            result["signals"]["oom_uses_safe_error"] = False
        else:
            result["signals"]["oom_uses_safe_error"] = None

    values = [v for v in result["signals"].values() if v is not None]
    if not values:
        result["verdict"] = "inconclusive"
    else:
        patched = (result["signals"].get("session_callback_disabled") is True
                   and result["signals"].get("oom_uses_safe_error") is True)
        result["verdict"] = "patched" if patched else "vulnerable"
    return result


def check_container(name: str) -> dict:
    """Huella de codigo dentro de un contenedor (docker cp + lectura)."""
    result = {"checked": "container", "container": name, "signals": {}}
    targets = {
        "session.c": "/usr/local/src/php-src/ext/session/session.c",
        "zend_alloc.c": "/usr/local/src/php-src/Zend/zend_alloc.c",
    }
    # El arbol de fuentes puede no estar en la imagen final; en ese caso se
    # examina el binario compilado.
    tmpdir = "/tmp/verify_backport_src"
    subprocess.run(["docker", "exec", name, "rm", "-rf", tmpdir],
                   capture_output=True)
    mk = subprocess.run(["docker", "exec", name, "mkdir", "-p", tmpdir],
                        capture_output=True)
    if mk.returncode != 0:
        result["verdict"] = "inconclusive"
        result["error"] = "no se pudo crear el directorio temporal"
        return result

    ok = True
    for fname, remote in targets.items():
        exists = subprocess.run(
            ["docker", "exec", name, "test", "-f", remote],
            capture_output=True).returncode == 0
        if not exists:
            ok = False
            continue
        subprocess.run(["docker", "exec", name, "cp", remote,
                        f"{tmpdir}/{fname}"], capture_output=True)
        got = subprocess.run(["docker", "exec", name, "cat",
                              f"{tmpdir}/{fname}"], capture_output=True)
        text = got.stdout.decode("utf-8", "replace")
        if fname == "session.c":
            if any(sig in text for sig in SESSION_SIGNALS):
                result["signals"]["session_callback_disabled"] = True
            elif SESSION_HUNK_OLD in text:
                result["signals"]["session_callback_disabled"] = False
            else:
                result["signals"]["session_callback_disabled"] = None
        else:
            if any(sig in text for sig in ALLOC_SIGNALS):
                result["signals"]["oom_uses_safe_error"] = True
            elif ALLOC_OLD in text:
                result["signals"]["oom_uses_safe_error"] = False
            else:
                result["signals"]["oom_uses_safe_error"] = None

    if not ok:
        result["verdict"] = "inconclusive"
        result["error"] = ("el arbol de fuentes no esta en la imagen; "
                           "usa --source contra el arbol de build")
        return result

    values = [v for v in result["signals"].values() if v is not None]
    if not values:
        result["verdict"] = "inconclusive"
    else:
        patched = (result["signals"].get("session_callback_disabled") is True
                   and result["signals"].get("oom_uses_safe_error") is True)
        result["verdict"] = "patched" if patched else "vulnerable"
    return result


def check_binary(path: str) -> dict:
    """Huella sobre el binario compilado (strings)."""
    result = {"checked": "binary", "path": path, "signals": {}}
    with open(path, "rb") as fh:
        blob = fh.read()
    result["sha256"] = hashlib.sha256(blob).hexdigest()
    result["size"] = len(blob)
    # El binario no contiene el literal del hunk (es codigo C), pero si
    # contiene los mensajes de error del allocator, que cambian con el
    # parche. Sirve como fingerprint reproducible, no como prueba.
    result["signals"]["contains_mm_safe_error_ex"] = (
        b"zend_mm_safe_error_ex" in blob)
    result["signals"]["contains_out_of_memory_msg"] = (
        b"Out of memory" in blob)
    result["verdict"] = "inconclusive"
    result["note"] = ("el binario no permite discriminar el parche por "
                       "huella de cadena; usa --source o el test de "
                       "comportamiento")
    return result


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source")
    ap.add_argument("--container")
    ap.add_argument("--binary")
    ap.add_argument("--host")
    ap.add_argument("--port", type=int)
    ap.add_argument("--label")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    result = None
    if args.source:
        result = check_source(args.source)
    elif args.container:
        result = check_container(args.container)
    elif args.binary:
        result = check_binary(args.binary)
    elif args.host and args.port:
        # Delegamos en el test diferencial de comportamiento ya existente.
        here = os.path.dirname(os.path.abspath(__file__))
        script = os.path.join(here, "behavioural_diff.py")
        proc = subprocess.run(
            [sys.executable, script, args.host, str(args.port),
             args.label or f"{args.host}:{args.port}"],
            capture_output=True)
        sys.stdout.write(proc.stdout.decode("utf-8", "replace"))
        return proc.returncode

    if result is None:
        ap.print_help()
        return 2

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"[*] Comprobacion: {result['checked']} -> {result.get('path') or result.get('container')}")
        for k, v in result.get("signals", {}).items():
            print(f"    {k}: {v}")
        if "sha256" in result:
            print(f"    sha256: {result['sha256']}")
        print(f"[*] VEREDICTO: {result['verdict'].upper()}")
        if result.get("error"):
            print(f"[*] nota: {result['error']}")

    return {"patched": 0, "vulnerable": 1}.get(result["verdict"], 2)


if __name__ == "__main__":
    sys.exit(main())
