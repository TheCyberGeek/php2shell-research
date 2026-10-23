<?php
// Writes sessions in php_serialize (per /app/.user.ini). The upload_progress
// record - including our |O:"Evil"... gadget filename - is stored in this format.
session_start();
echo "PHP " . PHP_VERSION . "\nhandler: " . ini_get('session.serialize_handler') . "\n";
