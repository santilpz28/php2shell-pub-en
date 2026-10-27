<?php
foreach (["max_multipart_body_parts","memory_limit","max_file_uploads","post_max_size","upload_max_filesize","session.upload_progress.enabled","session.upload_progress.cleanup"] as $k) {
    echo $k, " = ", var_export(ini_get($k), true), "\n";
}
echo "SAPI = ", php_sapi_name(), "\n";
