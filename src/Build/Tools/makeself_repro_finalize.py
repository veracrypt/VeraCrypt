#!/usr/bin/env python
#
# Copyright (c) 2026 VeraCrypt
# Governed by the Apache License 2.0.
#
# Zero the gzip mtime in a makeself archive and refresh its integrity
# fields. makeself runs `gzip -c9 < tmpfile' which writes tmpfile's
# mtime into the gzip header (gzip ignores SOURCE_DATE_EPOCH for
# redirected stdin), so the installer is otherwise not reproducible.
#
# After editing the payload the recorded checksums are refreshed:
#   - CRCsum is set to "0000000000". Makeself stores a POSIX cksum(1)
#     value there, not a zlib CRC-32 (the two differ); an all-zero
#     CRCsum makes its extractor skip the redundant CRC check.
#   - MD5 is recomputed, which the extractor still verifies.
#
# Compatible with Python >= 2.6 and Python 3.
#
# Usage: makeself_repro_finalize.py <archive>

import hashlib
import re
import sys


def finalize(path):
    with open(path, "rb") as f:
        raw = f.read()
    text = raw.decode("latin1")
    # Locate payload start by line count, mirroring makeself's own extractor.
    m = re.search(r'^skip="(\d+)"', text, re.MULTILINE)
    if not m:
        sys.exit("%s: no skip= line in makeself header" % path)
    skip = int(m.group(1))
    header_text = "\n".join(text.split("\n")[:skip]) + "\n"
    offset = len(header_text.encode("latin1"))
    if raw[offset:offset + 3] != b"\x1f\x8b\x08":
        sys.exit("%s: no gzip magic at payload offset %d" % (path, offset))
    # gzip header mtime: 4-byte LE uint at offset+4 (RFC 1952 section 2.3.1).
    payload = raw[offset:offset + 4] + b"\x00\x00\x00\x00" + raw[offset + 8:]
    new_md5 = hashlib.md5(payload).hexdigest()
    # CRCsum -> all zeros (extractor then skips the CRC check); MD5 -> fresh.
    new_header = re.sub(r'CRCsum="[^"]*"', 'CRCsum="0000000000"', header_text)
    new_header = re.sub(r'MD5="[0-9a-fA-F]+"', 'MD5="%s"' % new_md5, new_header)
    new_bytes = new_header.encode("latin1")
    # Line count must stay the same so makeself's "skip=" remains accurate.
    if new_bytes.count(b"\n") != skip:
        sys.exit("%s: header line count changed during rewrite" % path)
    with open(path, "wb") as f:
        f.write(new_bytes + payload)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("Usage: makeself_repro_finalize.py <archive>")
    finalize(sys.argv[1])
