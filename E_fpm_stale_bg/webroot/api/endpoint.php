<?php
// Producer + consumer endpoint. A GET with the planted SID cookie makes
// session_start() decode the malicious session -> OOM -> stale BG(unserialize).
// A multipart upload_progress POST on the same worker re-enters the unserializer
// and reuses the stale state -> UAF.
session_start();
echo "OK " . session_id() . "\n";
