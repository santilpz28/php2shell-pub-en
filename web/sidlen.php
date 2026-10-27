<?php
// ¿que longitud de session id genera PHP?
session_start();
echo "session_id()  = '", session_id(), "'  len=", strlen(session_id()), "\n";
echo "sessid的长度 depende de sid_bits_per_character (default 4) y hash bits\n";
