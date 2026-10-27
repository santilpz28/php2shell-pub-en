#!/bin/sh
# apache2-aslr-tolerant
#
# El entrypoint de la imagen intenta arrancar Apache con ASLR desactivado
# (setarch -R). Eso requiere CAP_SYS_ADMIN, que Docker no concede por
# defecto, asi que el arranque aborta con:
#
#   setarch: failed to set personality to x86_64: Operation not permitted
#
# Este wrapper intenta primero el modo sin ASLR y, si falla, arranca Apache
# con ASLR activo. El propio trabajo de investigacion ya concluyo que ASLR
# NO es la variable determinante (mismo binario con ASLR on reproduce 6/6),
# asi que perder el modo determinista no impide la reproduccion: lo que
# cambia es que las direcciones sean relativas al base del binario.

set -e

if /usr/bin/setarch "$(uname -m)" -R /bin/true 2>/dev/null; then
    echo "[entrypoint] ASLR off (setarch -R disponible)"
    exec /usr/bin/setarch "$(uname -m)" -R /usr/sbin/apache2 -D FOREGROUND
fi

echo "[entrypoint] setarch -R no disponible (sin CAP_SYS_ADMIN); ASLR activo"
echo "[entrypoint] las direcciones del trace seran relativas al base del binario"
exec /usr/sbin/apache2 -D FOREGROUND
