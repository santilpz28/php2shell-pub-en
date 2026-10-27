#!/usr/bin/env bash
# Arranca el laboratorio PHP2Shell: dos targets Apache+mod_php
#   - php2shell-vuln    : PHP 8.2.34  (vulnerable)
#   - php2shell-patched : PHP 8.2.35  (parcheado)
# Ambos en localhost, sin exposicion a la red publica.
set -euo pipefail

cd "$(dirname "$0")"

VULN_PORT="${VULN_PORT:-8080}"
PATCHED_PORT="${PATCHED_PORT:-8081}"

echo "[*] Levantando target VULNERABLE en localhost:${VULN_PORT} (PHP 8.2.34)"
docker rm -f php2shell-vuln >/dev/null 2>&1 || true
docker run -d --name php2shell-vuln \
  -p "127.0.0.1:${VULN_PORT}:80" \
  -v "$(pwd)/web:/var/www/html" \
  php2shell-vuln:8.2.34 >/dev/null

echo "[*] Levantando target PARCHEADO en localhost:${PATCHED_PORT} (PHP 8.2.35)"
docker rm -f php2shell-patched >/dev/null 2>&1 || true
docker run -d --name php2shell-patched \
  -p "127.0.0.1:${PATCHED_PORT}:80" \
  -v "$(pwd)/web:/var/www/html" \
  php2shell-patched:8.2.35 >/dev/null

sleep 3

echo "[*] Esperando readiness..."
for port in "$VULN_PORT" "$PATCHED_PORT"; do
  for i in $(seq 1 20); do
    if curl -sf "http://127.0.0.1:${port}/index.php?probe=1" >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
done

echo
echo "===== TARGET VULNERABLE (${VULN_PORT}) ====="
curl -s "http://127.0.0.1:${VULN_PORT}/index.php?probe=1" || echo "(sin respuesta)"
echo
echo "===== TARGET PARCHEADO (${PATCHED_PORT}) ====="
curl -s "http://127.0.0.1:${PATCHED_PORT}/index.php?probe=1" || echo "(sin respuesta)"
echo
echo "[*] Lab listo."
echo "    Vulnerable : http://127.0.0.1:${VULN_PORT}"
echo "    Parcheado  : http://127.0.0.1:${PATCHED_PORT}"
