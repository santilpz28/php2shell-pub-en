<?php
/**
 * Objetivo de laboratorio para PHP2Shell (CVE-2026-109619 / CVE-2026-109618).
 *
 * Endpoint deliberadamente inocuo: acepta uploads multipart y los ignora.
 * La vulnerabilidad NO está en esta aplicacion, esta en el nucleo PHP:
 * la capa de sesiones procesa upload_progress ANTES de que corra el codigo
 * de usuario, por lo que cualquier endpoint con upload es vulnerable.
 *
 * Este archivo solo sirve para:
 *  - exponer un endpoint de upload que el PoC pueda golpear
 *  - servir una sonda de deteccion (modo 'probe') que comprueba si el
 *    servidor sigue siendo susceptible al patron de ataque
 */

header('Content-Type: text/plain; charset=utf-8');

// --- Modo session-init: llama a session_start() para REINICIALIZAR y
// --- LIBERAR el HashTable de sesion. Es la pieza que hace posible el UAF:
// --- una peticion concurrente con el mismo PHPSESSID ejecuta esto mientras
// --- la peticion de upload esta en vuelo, y el puntero cacheado en
// --- progress->current_file_bytes_processed queda colgando.
if (isset($_GET['sess'])) {
    @session_start();
    echo "SESSION_STARTED=" . session_id() . "\n";
    echo "SESSION_VARS=" . count($_SESSION ?? []) . "\n";
    exit;
}

// --- Modo sonda: usado para detectar si el target sigue vulnerable ---------
if (isset($_GET['probe'])) {
    $ver = phpversion();
    $upload_progress = ini_get('session.upload_progress.enabled');
    $mem_limit = ini_get('memory_limit');
    $sapi = php_sapi_name();

    echo "PHP_VERSION={$ver}\n";
    echo "SAPI={$sapi}\n";
    echo "SESSION_UPLOAD_PROGRESS_ENABLED={$upload_progress}\n";
    echo "MEMORY_LIMIT={$mem_limit}\n";
    echo "SESSION_UPLOAD_PROGRESS_CLEANUP=" . ini_get('session.upload_progress.cleanup') . "\n";
    echo "FATAL_ERROR_BACKTRACES=" . var_export(ini_get('fatal_error_backtraces'), true) . "\n";

    // Indicador directo de vulnerabilidad de la rama UAF:
    // un PHP parcheado resetea el estado de sesion en shutdown y ya no
    // deja punteros colgantes entre peticiones.
    //
    // Tabla de versiones parcheadas por rama:
    //   8.2.x -> 8.2.35 | 8.3.x -> 8.3.36 | 8.4.x -> 8.4.27 | 8.5.x -> 8.5.12
    // PHP 7.4 es EOL y NO recibira parche: es vulnerable por definicion.
    $fixed = [
        '8.2' => '8.2.35',
        '8.3' => '8.3.36',
        '8.4' => '8.4.27',
        '8.5' => '8.5.12',
    ];

    $vulnerable = true;
    if (preg_match('/^(\d+\.\d+)\.(\d+)/', $ver, $m)) {
        $series = $m[1];
        if (isset($fixed[$series])) {
            $vulnerable = version_compare($ver, $fixed[$series], '<');
        } elseif (version_compare($series, '8.2', '<')) {
            // ramas EOL (7.x y anteriores): sin parche disponible
            $vulnerable = true;
        } else {
            // serie desconocida y mas nueva que 8.5 -> asumir parcheada
            $vulnerable = false;
        }
    }

    echo "PATCHED=" . ($vulnerable ? 'no' : 'yes') . "\n";
    exit;
}

// --- Endpoint de upload (vulnerable por diseno del nucleo) ----------------
$uploaded = [];
if (!empty($_FILES)) {
    foreach ($_FILES as $field => $info) {
        $uploaded[] = sprintf(
            '%s: name=%s size=%d error=%d',
            $field,
            $info['name'] ?? '(null)',
            $info['size'] ?? 0,
            $info['error'] ?? -1
        );
    }
}

// Informacion de sesion, si el upload_progress la ha creado
$session_data = [];
if (isset($_SESSION)) {
    foreach ($_SESSION as $k => $v) {
        if (is_array($v)) {
            $session_data[] = $k . ' => ' . json_encode($v);
        } else {
            $session_data[] = $k . ' => ' . var_export($v, true);
        }
    }
}

echo "PHP " . phpversion() . " | SAPI " . php_sapi_name() . "\n";
echo "SESSION_ID=" . session_id() . "\n";
echo "UPLOADS:\n" . (empty($uploaded) ? "  (ninguno)\n" : "  " . implode("\n  ", $uploaded) . "\n");
echo "SESSION:\n" . (empty($session_data) ? "  (vacia)\n" : "  " . implode("\n  ", $session_data) . "\n");
