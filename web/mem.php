<?php
echo "peak=", memory_get_peak_usage(true), "\n";
echo "cur=", memory_get_usage(true), "\n";
echo "files=", count($_FILES), "\n";
