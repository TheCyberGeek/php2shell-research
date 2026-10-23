<?php
session_start();
echo "PHP " . PHP_VERSION . " / " . php_sapi_name() . "\n";
echo "memory_limit " . ini_get('memory_limit') . "\n";
echo "OK\n";
