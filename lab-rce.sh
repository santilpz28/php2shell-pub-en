#!/usr/bin/env bash
# Arranca el target de RCE (PHP 8.2.34 compilado con simbolos + ASLR off).
#
# Requisitos:
#   docker build -f Dockerfile.rce -t php2shell-rce:8.2.34 .
set -euo pipefail

cd "$(dirname "$0")"
PORT="${RCE_PORT:-8082}"

echo "[*] Levantando target RCE en localhost:${PORT} (ASLR desactivado)"
docker rm -f php2shell-rce >/dev/null 2>&1 || true
docker run -d --name php2shell-rce \
  -p "127.0.0.1:${PORT}:80" \
  --cap-add SYS_ADMIN \
  --security-opt seccomp=unconfined \
  --security-opt apparmor=unconfined \
  -v "$(pwd)/web:/var/www/html" \
  php2shell-rce:8.2.34 >/dev/null

sleep 4

echo "[*] Verificando..."
for i in $(seq 1 20); do
  if curl -sf "http://127.0.0.1:${PORT}/index.php?probe=1" >/dev/null 2>&1; then break; fi
  sleep 1
done

echo
echo "===== TARGET RCE (${PORT}) ====="
curl -s "http://127.0.0.1:${PORT}/index.php?probe=1" || echo "(sin respuesta)"

echo
echo "[*] Comprobando ASLR (debe ser 0 dentro del contenedor):"
docker exec php2shell-rce cat /proc/sys/kernel/randomize_va_space 2>/dev/null || echo "(no verificable)"

echo
echo "[*] Extrayendo offsets del binario PHP:"
BIN=$(docker exec php2shell-rce sh -c 'ls /usr/local/php-symbols/bin/php' 2>/dev/null | tr -d '\r')
echo "    binario: ${BIN}"
docker exec php2shell-rce nm "${BIN}" 2>/dev/null | grep -E " (zif_system|zval_ptr_dtor|zend_call_function)$" || true

echo
echo "[*] Listo. Para ejecutar la PoC:"
echo "    python3 php2shell_rce.py --host 127.0.0.1 --port ${PORT} --cmd 'id' \\"
echo "        --binary /ruta/local/al/php"
echo
echo "    (o extraer el binario: docker cp php2shell-rce:${BIN} ./php-symbols)"
