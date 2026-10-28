#!/usr/bin/env bash
# apply_backport.sh — Aplica el parche oficial de PHP2Shell SOBRE 8.2.34
#
# Que hace
# --------
# Clona php-src en el tag php-8.2.34, le aplica el commit de parche
# "Avoid state corruption via bailout" y recompila el binario de PHP con
# el SAPI de Apache (mod_php), igual que la imagen base php:8.2.34-apache.
#
# El resultado es un PHP que:
#
#   - sigue siendo 8.2.34 (mismo numero de version)
#   - tiene el codigo corregido (mismo fix que 8.2.35)
#   - expone las mismas extensiones que la imagen oficial (mod_php, session)
#
# Es la OPERACION INVERSA de "actualizar PHP": en lugar de cambiar de
# version y arriesgar las dependencias, se corrige el codigo in situ.
#
# Por que el commit de la rama EOL
# --------------------------------
# El commit upstream de la rama PHP-8.2 (31c0ea7d7ff) toca 423 ficheros
# y reescribe el allocator de Zend MM: no es cherry-pickeable sobre 8.2.34
# (conflictos en el nucleo del allocator).
#
# Las ramas EOL (7.4, 8.0, 8.1) llevan el MISMO fix reducido a su forma
# minima, con el mensaje explicito:
#     "Minimal mitigation for EOL version.
#      Fix GHSA-w8hw-w9fx-j79w (CVE-2026-109618)
#      Fix GHSA-6wmf-4rv5-p3rp (CVE-2026-109619)"
#
# Ese commit (1d7dec17, 23 ficheros) es el que se aplica aqui. Conflictos
# reales al aplicarlo sobre 8.2.34: 3, todos en codigo y todos triviales.
# Ver patches/RESOLUTION-NOTES.md.
#
# Uso
# ---
#   ./apply_backport.sh [PREFIX]     # PREFIX = destino de la instalacion
#                                     # por defecto /usr/local
#
# Variables de entorno
# -------------------
#   PHP_SRC_REPO   URL del repo (por defecto https://github.com/php/php-src.git)
#   PHP_TAG        tag base (por defecto php-8.2.34)
#   BACKPORT_SHA   commit de referencia del fix en las ramas EOL
#   KEEP_TREE      =1 para no borrar el arbol de fuentes al final
set -euo pipefail

PREFIX="${1:-/usr/local}"
REPO="${PHP_SRC_REPO:-https://github.com/php/php-src.git}"
TAG="${PHP_TAG:-php-8.2.34}"
BACKPORT_SHA="${BACKPORT_SHA:-1d7dec178a094e6e75b229ce22754045f8c6070a}"

# El patch ya resuelto. Se aplica con `git apply` sobre el tag base, que
# evita por completo el paso de cherry-pick y sus conflictos: el patch
# PRE-RESUELTO se genero una vez, de forma reproducible, contra php-8.2.34.
PATCH_FILE="$(dirname "$0")/php-8.2.34-backport-bailout.patch"

# Se guardan las fuentes en el arbol para poder auditar el parche despues
# (verify_backport.py --source).
SRC_KEEP_DIR="${SRC_KEEP_DIR:-/usr/local/src/php-src}"

log() { printf '[backport] %s\n' "$*"; }

if [ ! -f "$PATCH_FILE" ]; then
    log "ERROR: no encuentro el patch $PATCH_FILE"
    exit 1
fi

BUILD_DIR="$(mktemp -d /tmp/php-backport-XXXXXX)"
SRC_DIR="$BUILD_DIR/php-src"

cleanup() {
    if [ "${KEEP_TREE:-0}" != "1" ]; then
        rm -rf "$BUILD_DIR"
    else
        log "arbol conservado en $BUILD_DIR"
    fi
}
trap cleanup EXIT

log "1/6 clonando $REPO @ $TAG"
git clone --quiet --filter=blob:none --no-checkout --branch PHP-8.2 "$REPO" "$SRC_DIR"
cd "$SRC_DIR"
git fetch --quiet --depth 1 origin "refs/tags/$TAG:refs/tags/$TAG"
git checkout --quiet "$TAG"
git log --oneline -1

log "2/6 aplicando el patch de parche (resuelto previamente)"
git apply --verbose "$PATCH_FILE"

log "3/6 verificando que no quedan marcadores de conflicto"
if grep -rn '^<<<<<<<\|^>>>>>>>' --include='*.c' --include='*.h' . ; then
    log "ERROR: quedan marcadores de conflicto"
    exit 1
fi

# Se conservan las fuentes parcheadas para auditoria posterior.
mkdir -p "$SRC_KEEP_DIR"
cp -a "$SRC_DIR"/. "$SRC_KEEP_DIR"/

log "4/6 configurando (Apache2 SAPI + session + opcache)"
# El SAPI de Apache es obligatorio: el estado colgante de sesion tiene que
# sobrevivir entre peticiones en el MISMO worker de Apache. El servidor
# integrado de PHP (-S) es monoproceso y se muere con el crash.
./buildconf --force
./configure \
    --prefix="$PREFIX" \
    --with-config-file-path="$PREFIX/etc/php" \
    --with-config-file-scan-dir="$PREFIX/etc/php/conf.d" \
    --enable-session \
    --enable-opcache \
    --with-apxs2="/usr/bin/apxs2" \
    --enable-mbstring

log "5/6 compilando"
make -j"$(nproc)"
make install

# El SAPI de Apache se instala en <prefix>/libs/ (libphp.so), pero la imagen
# base php:8.2.34-apache carga el modulo desde
# /usr/lib/apache2/modules/libphp.so (convención de Debian). Hay que
# sobreescribir ESE fichero, no solo el de /usr/local, o Apache seguiría
# ejecutando el PHP SIN parchear.
APACHE_MOD_DIR="/usr/lib/apache2/modules"
mkdir -p "$APACHE_MOD_DIR"
if [ -f "$PREFIX/libs/libphp.so" ]; then
    log "instalando mod_php parcheado en $APACHE_MOD_DIR/libphp.so"
    cp -f "$PREFIX/libs/libphp.so" "$APACHE_MOD_DIR/libphp.so"
    ls -la "$APACHE_MOD_DIR/libphp.so"
fi

log "6/6 registrando las extensiones"
# La imagen oficial php:8.2.34-apache deja las extensiones como modulos
# compartidos en conf.d. Aqui se replica exactamente.
EXT_DIR="$(find "$PREFIX/lib/php/extensions" -mindepth 1 -maxdepth 1 -type d | head -1)"
for ext in session mbstring; do
    if [ -f "$EXT_DIR/$ext.so" ]; then
        echo "extension=$ext.so" > "$PREFIX/etc/php/conf.d/docker-php-ext-$ext.ini"
    fi
done
# opcache es una ZEND EXTENSION, no una extension normal: cargarlo con
# "extension=" falla con "Invalid library (appears to be a Zend Extension)".
if [ -f "$EXT_DIR/opcache.so" ]; then
    echo "zend_extension=opcache.so" > "$PREFIX/etc/php/conf.d/docker-php-ext-opcache.ini"
fi

log "instalado en $PREFIX"
"$PREFIX/bin/php" -v
"$PREFIX/bin/php" -r 'echo "session.upload_progress.enabled = ", ini_get("session.upload_progress.enabled"), PHP_EOL;'
"$PREFIX/bin/php" -r 'echo "mod_php presente: ", (extension_loaded("session") ? "session OK" : "session FALTA"), PHP_EOL;'
log "OK"
