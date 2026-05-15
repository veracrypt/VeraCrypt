#!/usr/bin/env python3
#
# Copyright (c) 2026 VeraCrypt
# Governed by the Apache License 2.0.
#
# Zero the gzip mtime in a makeself archive and refresh CRCsum/MD5.
# Workaround: makeself runs `gzip -c9 < tmpfile' which writes tmpfile's
# filesystem mtime into the gzip header (gzip ignores SOURCE_DATE_EPOCH
# for redirected stdin). Installer --check still passes after the edit.
#
# Usage: makeself_repro_finalize.py <archive>

import hashlib
import re
import sys
import zlib


def finalize(path):
    with open(path, "rb") as f:
        raw = bytearray(f.read())
    text = raw.decode("latin1", errors="replace")
    # Locate payload start by line count, mirroring makeself's own extractor.
    m = re.search(r'^skip="(\d+)"', text, re.MULTILINE)
    if not m:
        sys.exit(f"{path}: no skip= line in makeself header")
    skip = int(m.group(1))
    header_text = "\n".join(text.split("\n")[:skip]) + "\n"
    offset = len(header_text.encode("latin1"))
    if bytes(raw[offset:offset + 3]) != b"\x1f\x8b\x08":
        sys.exit(f"{path}: no gzip magic at payload offset {offset}")
    # gzip header mtime: 4-byte LE uint at offset+4 (RFC 1952 §2.3.1).
    raw[offset + 4:offset + 8] = b"\x00\x00\x00\x00"
    payload = bytes(raw[offset:])
    new_crc = zlib.crc32(payload) & 0xffffffff
    new_md5 = hashlib.md5(payload).hexdigest()
    new_header = re.sub(r'CRCsum="\d+"',    f'CRCsum="{new_crc}"', header_text)
    new_header = re.sub(r'MD5="[0-9a-f]+"', f'MD5="{new_md5}"',    new_header)
    new_bytes = new_header.encode("latin1")
    # Line count must stay the same so makeself's "skip=" remains accurate.
    if new_bytes.count(b"\n") != skip:
        sys.exit(f"{path}: header line count changed during rewrite")
    with open(path, "wb") as f:
        f.write(new_bytes + payload)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("Usage: makeself_repro_finalize.py <archive>")
    finalize(sys.argv[1])
