"""Extract PyInstaller archive from TrustSettle exe."""
from pathlib import Path
import struct
import zlib
import marshal
import sys
import os

exe = Path(r"C:\src\projects\HackTheBox CTF Holme\SilentDividend\extracted\TrustSettle_1.0.0.exe")
data = exe.read_bytes()

# PyInstaller cookie magic: MEI\014\013\012\013\016
magic = b"MEI\x0c\x0b\x0a\x0b\x0e"
idx = data.find(magic)
print("MEI magic at", idx, "file size", len(data))
if idx < 0:
    # try just MEI
    idx = data.find(b"MEI")
    print("fallback MEI", idx)

# Cookie is at end of archive typically. Search from end.
# CArchive cookie structure (pyinstaller 2.1+):
# magic (8) + pkg_len (I) + toc_off (I) + toc_len (I) + pyvers (I) + pylibname (64s)  = 88 bytes? 
# Actually for py3: 
# struct: !8sIIii64s  or similar

# Find last occurrence of magic
last = data.rfind(magic)
print("last MEI", last)
print("bytes after last MEI", len(data) - last)

cookie = data[last:]
print("cookie len", len(cookie), cookie[:88])
# try parse
# PyInstaller 4/5 CArchiveReader:
# MAGIC length 8, then
# TOC has: (position, size, uncompressed, compression flag, type, name)
# cookie: magic + length + TOC + TOClen + pyver + pylibname
# format from PyInstaller source:
# _COOKIE_FORMAT = '!8sIIii64s'
# MAGIC, archive_len, toc_off, toc_len, pyver, pylibname

fmt = '!8sIIii64s'
size_cookie = struct.calcsize(fmt)
print("cookie struct size", size_cookie)
if len(cookie) >= size_cookie:
    magic_b, archive_len, toc_off, toc_len, pyver, pylibname = struct.unpack(fmt, cookie[:size_cookie])
    print("archive_len", archive_len)
    print("toc_off", toc_off)
    print("toc_len", toc_len)
    print("pyver", pyver)
    print("pylibname", pylibname.split(b'\x00',1)[0])
    # overlay position
    # archive starts at: end - archive_len? or cookie_pos - (archive_len - cookie_size)?
    # From source: overlay = cookie_pos + size_cookie - archive_len  ... wait
    # Actually: cookie is at the END of the archive.
    # archive starts at: last + size_cookie - archive_len
    start = last + size_cookie - archive_len
    print("archive start", start, "hex", hex(start))
    if start < 0:
        # try alternate cookie format with pylib longer or int64
        print("negative start, trying variants")
        # PyInstaller 5.x might use different
        for fmt2 in ['!8sIIii64s', '!8sIIQi64s', '!8sQQii64s', '!8sIIIII64s']:
            try:
                sz = struct.calcsize(fmt2)
                vals = struct.unpack(fmt2, cookie[:sz])
                print(fmt2, vals)
            except Exception as e:
                print(fmt2, e)

# Also try pyinstxtractor approach: cookie at end-24 for older, or search
# Look for PYZ
print("PYZ at", data.rfind(b'PYZ'))
print("pyz-00 at", data.rfind(b'pyz-'))
