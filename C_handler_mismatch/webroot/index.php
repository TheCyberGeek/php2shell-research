<?php
session_start();
echo "PHP " . PHP_VERSION . " / " . php_sapi_name() . "\n";
echo "serialize_handler " . ini_get('session.serialize_handler') . "\n";
echo "OK\n";
