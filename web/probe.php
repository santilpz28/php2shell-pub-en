<?php
/**
 * probe.php — instrumentacion para entender el patron de heap.
 *
 * Objetivo: saber que objeto queda colgando tras el OOM y con que
 * longitud, para poder reclamarlo con una asignacion controlada.
 *
 * Solo diagnostico: imprime punteros y longitudes internos.
 */
$sid = 'abcdefghijklmnopqrstuvwxyz';
session_id($sid);
session_start();

echo "=== PS(id) ===\n";
// tras session_start, el id esta en la sesion activa
$arr = $_SESSION;
echo "session keys: ", implode(',', array_keys($arr)), "\n";

if (isset($_SESSION['upload_progress_pwn'])) {
    $up = $_SESSION['upload_progress_pwn'];
    echo "upload_progress presente: ", implode(',', array_keys($up)), "\n";
    echo "  name = ", var_export($up['name'] ?? null, true), "\n";
    echo "  size = ", var_export($up['size'] ?? null, true), "\n";
    echo "  bytes_processed = ", var_export($up['bytes_processed'] ?? null, true), "\n";
}

echo "\n=== memoria ===\n";
echo "cur=", memory_get_usage(true), " peak=", memory_get_peak_usage(true), "\n";
echo "real=", memory_get_usage(false), " peak_real=", memory_get_peak_usage(false), "\n";
