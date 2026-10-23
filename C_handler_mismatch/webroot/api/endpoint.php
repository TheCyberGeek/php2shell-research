<?php
// Reads sessions with the default `php` handler (per /api/.user.ini). When it
// reads a session written as php_serialize, it mis-parses at '|' and
// unserializes the trailing bytes as an object -> Evil::__destruct fires.
class Evil {
    public $cmd;
    public function __destruct() {
        if ($this->cmd) {
            file_put_contents("/tmp/rce_proof.txt", shell_exec($this->cmd), FILE_APPEND);
        }
    }
}
session_start();
echo "OK\n";
