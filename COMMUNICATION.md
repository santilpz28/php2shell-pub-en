# PHP2Shell — Resumen ejecutivo para Chain-Cortex

**Material de comunicación y venta de servicios.**

---

## Opción A — LinkedIn / post largo (GitHub-style)

### 🔴 PHP2Shell: dos CVEs de 9.2 en el núcleo de PHP. Tu aplicación puede ser perfecta y seguir siendo vulnerable.

El 21 de octubre, el proyecto PHP publicó una release de emergencia que corrigió dos
vulnerabilidades críticas en el **núcleo** del lenguaje:

| CVE | Efecto |
|---|---|
| **CVE-2026-109619** | RCE + divulgación de memoria (use-after-free en `session.upload_progress`) |
| **CVE-2026-109618** | RCE + divulgación de memoria (corrupción por OOM) |

CVSS v4.0: **9.2** en ambos.

Lo que hace que esto no sea "un bug más":

1. **No es un bug de aplicación.** Es del intérprete. Cualquier endpoint que acepte
   un upload multipart es vulnerable, aunque tu código sea impecable.
2. **Sin autenticación.** No hay login que saltar.
3. **Configuración por defecto vulnerable.** `session.upload_progress.enabled=On` es el
   default de fábrica desde PHP 5.
4. **PHP 7.4 es EOL y no tendrá parche.** Sigue vulnerable para siempre.

CISA, Cisco, Akamai, Vercel, Laravel, Autodesk, IC3 y CERT-EU publicaron alertas el
mismo día. Hay indications de explotación activa.

**Versiones parcheadas:** 8.2.35 · 8.3.36 · 8.4.27 · 8.5.12

**El detalle técnico que más duele:** el parche oficial *no reescribe el código
vulnerable*. En su lugar, preventivamente aborta la segunda ejecución del callback
que liberaba la memoria, y fuerza a que los objetos deserializados en el fichero de
sesión se queden como `__PHP_Incomplete_Class`. Es defensa en capas sobre un
patrón de diseño frágil que sigue ahí.

**En el laboratorio de Chain-Cortex** montamos el entorno vulnerable + parcheado,
verificamos el comportamiento diferencial, analizamos el código fuente del
núcleo y del parche oficial, y publicamos el análisis completo con PoC.

→ Enlace al artículo completo

---

## Opción B — Newsletter / resumen executivo (300 palabras)

**Asunto:** PHP2Shell — auditoría urgente de exposición en PHP

El 21 de octubre de 2026 se publicó una release de emergencia de PHP que corrige dos
vulnerabilidades críticas (CVSS 9.2) en el **núcleo** del lenguaje: CVE-2026-109619
(use-after-free) y CVE-2026-109618 (corrupción de memoria por agotamiento). Ambas
permiten ejecución remota de código **sin autenticación**.

Lo relevante para su organización:

- **El fallo está en PHP, no en su aplicación.** Su código puede ser correcto y el
  servidor seguir siendo explotable. La auditoría de código no cubre esto.
- **Requisito por defecto.** `session.upload_progress.enabled=On` viene activo de
  fábrica. Solo hace falta un endpoint que acepte uploads.
- **Impacto doble:** ejecución de comandos y lectura de memoria del proceso, lo que
  puede exponer datos de otros usuarios que compartan el worker (patrón Heartbleed).
- **PHP 7.4 no tiene arreglo.** Está fuera de soporte y no recibirá parche.

**Qué hacer:**
1. Inventariar la versión real de PHP en ejecución (no la del paquete).
2. Actualizar a 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 y reiniciar todos los workers.
3. Para PHP 7.4: planificar migración.
4. Si no puede actualizar de inmediato: `session.upload_progress.enabled=0` mitiga
   la rama principal, pero es una mitigación parcial.
5. Revisar logs buscando `PHP_SESSION_UPLOAD_PROGRESS` en peticiones multipart y
   actividad anómala en `session.save_path`.

**Propuesta Chain-Cortex:** auditoría de exposición PHP2Shell para su flota —
inventario de versiones, verificación de exposición con test diferencial sobre
servicios no-intrusivos, y validación de la remediación. El detector que usamos
distingue vulnerable de parcheado sin necesidad de ejecutar exploits ni conocer
offsets del binario.

---

## Opción C — Notas para el equipo técnico (interno)

### Checklist de exposición

```bash
# Versión real en runtime
php -r 'echo PHP_VERSION, PHP_EOL;'

# Configuracion relevante
php -i | grep -E "upload_progress|memory_limit"

# SAPI (mod_php = RCE app-independent confirmado)
php -r 'echo php_sapi_name(), PHP_EOL;'
```

| SAPI | Estado |
|---|---|
| `apache2handler` | RCE app-independent confirmado |
| `fpm-fcgi` | Susceptible vía estado publicado tras arranque; `pm.max_requests=1` rompe el requisito de mismo worker |
| `cli-server` | No expuesto como servicio web |

### Test diferencial (el detector fiable)

```bash
python3 behavioural_diff.py <host> <port>
```

Comportamiento observado en el laboratorio:

- **Vulnerable (8.2.34):** la sesión contiene `upload_progress_<clave>` con el
  estado del upload. Respuesta de 588 bytes.
- **Parcheado (8.2.35):** la sesión no se modifica. Respuesta de 332 bytes.

Ventaja: **no necesita offsets, ni ASLR, ni ejecutar exploits.** Funciona sobre
cualquier PHP accesible por HTTP. Ideal para inventariar flota a escala.

### Indicadores para SIEM/WAF

- Campo `PHP_SESSION_UPLOAD_PROGRESS` en multipart sin necesidad funcional.
- Campos `t[]` con valores de ~288 bytes y alta densidad de repetición.
- Multipart con pausa temporal entre el inicio del fichero y el resto del body.
- `PHPSESSID` con formato anómalo.

### Post-explotación

- Ficheros de sesión con contenido no esperado.
- Procesos hijos del worker PHP ejecutando shells.
- Logs de `mod_php` con `system()`, `exec()`, `passthru()`, `shell_exec()`,
  `popen()`, `proc_open()`.
- Ficheros nuevos en `document_root` (`.htaccess`, `webshell.php`).

### Advertencia interna sobre PoC de terceros

Hay repositorios de PoC públicos para estas CVEs que **distribuyen cargas
maliciosas falsas** (documentado por JFrog: un script que solo cambiaba el fondo
de pantalla del sistema a NSFW). Auditar cualquier PoC antes de ejecutarlo.
