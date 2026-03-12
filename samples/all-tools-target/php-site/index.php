<?php

$secret = "demo_php_secret_for_static_scan_only";
$code = $_GET["code"] ?? "echo 'ok';";
eval($code);

echo substr($secret, 0, 4);
