#!/usr/bin/env python3
"""Unpack a Wise installer's files, pure Python: tools/unwise.py INSTALL.EXE OUTDIR

Gunman's retail installer (REWOLF/INSTALL.EXE on the disc) is a Wise package.
tools/install.py used E_WISE from Universal Extractor to open it, a tool most
machines don't have; this does the same job with the standard library, so the
one-click setup needs nothing but Python.

The format, as this installer has it:
  - after the PE sections, the overlay holds every file as a raw deflate stream
    followed by its CRC32. The CRC normally follows the last compressed byte,
    but can sit a byte or so later (stream 139 here), so it is searched for.
  - stream 2 is the install script. A file record ends with the file's
    inflated size, 20 reserved bytes, its CRC32 and its destination, a
    %VARIABLE%\\path string. Records are matched to streams by (size, CRC).
Only %MAINDIR% files are written: that tree is what Setup puts in Program
Files. Checked against E_WISE: all 3,667 streams byte-identical, and the
MAINDIR tree identical file for file.
"""
import os
import re
import struct
import sys
import zlib


def overlay_start(data):
    pe = struct.unpack_from('<I', data, 0x3C)[0]
    count = struct.unpack_from('<H', data, pe + 6)[0]
    opt = struct.unpack_from('<H', data, pe + 20)[0]
    sec = pe + 24 + opt
    return max(struct.unpack_from('<I', data, sec + i * 40 + 20)[0] +
               struct.unpack_from('<I', data, sec + i * 40 + 16)[0] for i in range(count))


def inflate_at(data, o):
    """(bytes, next offset) for a deflate+CRC32 stream at o, or None."""
    d = zlib.decompressobj(-15)
    try:
        out = d.decompress(data[o:])
    except zlib.error:
        return None
    if not d.eof:
        return None
    used = len(data) - o - len(d.unused_data)
    crc = zlib.crc32(out) & 0xFFFFFFFF
    for k in range(8):                   # the CRC can trail the stream by a byte or two
        if o + used + k + 4 <= len(data) and struct.unpack_from('<I', data, o + used + k)[0] == crc:
            return out, o + used + k + 4
    return None


def streams(data):
    start = overlay_start(data)
    o = next((o for o in range(start, start + 0x10000) if inflate_at(data, o)), None)
    if o is None:
        raise SystemExit('no Wise data found after the PE sections')
    out = []
    while len(data) - o >= 8:
        r = inflate_at(data, o)
        if not r:
            break
        out.append(r[0])
        o = r[1]
    return out


def unwise(installer, outdir, want='%MAINDIR%'):
    data = open(installer, 'rb').read()
    blobs = streams(data)
    by_key = {(len(b), zlib.crc32(b) & 0xFFFFFFFF): b for b in blobs}
    script = next((b for b in blobs if b'%MAINDIR%\\' in b), None)
    if script is None:
        raise SystemExit('no install script among %d streams' % len(blobs))
    written = 0
    for m in re.finditer(rb'%[A-Z0-9_]+%\\[^\x00]+', script):
        p = m.start()
        if p < 28:
            continue
        crc = struct.unpack_from('<I', script, p - 4)[0]
        size = struct.unpack_from('<I', script, p - 28)[0]
        blob = by_key.get((size, crc))
        name = m.group().decode('latin-1')
        if blob is None or not name.startswith(want + '\\'):
            continue
        dest = os.path.join(outdir, *name[len(want) + 1:].split('\\'))
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, 'wb') as f:
            f.write(blob)
        written += 1
    return len(blobs), written


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    n, w = unwise(sys.argv[1], sys.argv[2])
    print('%d streams, %d files written to %s' % (n, w, sys.argv[2]))
