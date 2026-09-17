"""Parse Electron asar without external tools (header is JSON)."""
from pathlib import Path
import json
import struct
import os

asar_path = Path(r"C:\src\projects\HackTheBox CTF Holme\SilentDividend\nsis\resources\app.asar")
out_dir = Path(r"C:\src\projects\HackTheBox CTF Holme\SilentDividend\asar_py")
out_dir.mkdir(parents=True, exist_ok=True)

data = asar_path.read_bytes()
print("asar size", len(data))
print("header first 16", data[:16].hex())

# asar header: uint32 pickle size fields
# format: [uint32 header_pickle_size][uint32 header_string_size][uint32 header_object_size][uint32 header_string_size2][json]
# Actually: 4 uint32s then JSON string
if len(data) < 16:
    raise SystemExit("too small")

# try common layout
u32s = struct.unpack_from("<IIII", data, 0)
print("first 4 u32", u32s)

# Typically first is 4, second is header size, then json follows at 16
json_size = u32s[1]  # often the json payload size
# more reliable: find first '{'
brace = data.find(b"{")
print("first brace", brace)
# header json is usually right after 16-byte prefix; size in pickle
# pickle: size (4) + string size (4) + string
# Standard asar:
# uint32(4) uint32(headerSize) uint32(headerSize) uint32(headerSize) then JSON of headerSize bytes?
# Actually from asar source:
# Pickle format: payload size fields

# Try: JSON starts at 16 and length = u32s[1] - something
for start in [16, 12, 8, 4]:
    for length in [u32s[1], u32s[2], u32s[3], u32s[1]-4, u32s[2]-4]:
        if length <= 0 or start + length > len(data):
            continue
        chunk = data[start:start+length]
        try:
            header = json.loads(chunk)
            print("SUCCESS start", start, "length", length, "top keys", list(header)[:10])
            Path(out_dir / "_header.json").write_text(json.dumps(header, indent=2)[:500000], encoding="utf-8")
            break
        except Exception:
            continue
    else:
        continue
    break
else:
    # brute: parse from first brace
    brace = data.find(b'{')
    # find matching - use raw_decode
    import json as js
    try:
        header, end = js.JSONDecoder().raw_decode(data[brace:].decode('utf-8', errors='replace'))
        print("raw_decode from", brace, "ended at relative", end)
        Path(out_dir / "_header.json").write_text(js.dumps(header, indent=2)[:500000], encoding="utf-8")
        print("keys", list(header)[:20])
    except Exception as e:
        print("raw decode failed", e)
        raise SystemExit("could not parse asar header")

# dump file list recursively
def walk(node, prefix=""):
    if not isinstance(node, dict):
        return
    files = node.get("files")
    if not isinstance(files, dict):
        return
    for name, meta in files.items():
        p = f"{prefix}/{name}" if prefix else name
        if "files" in meta:
            print("DIR ", p)
            walk(meta, p)
        else:
            size = meta.get("size")
            offset = meta.get("offset")
            print(f"FILE {p} size={size} offset={offset}")

print("\n=== ASAR CONTENTS ===")
walk(header)

# extract all files
# base offset: after header json + padding
# asar: header_pickle is 4 + 4 + header_string_len padded
# From electron asar: after 8-byte (or 16) header, content base = 8 + header_size_aligned?
# Layout:
# uint32 header_object_size? Let's use known formula:
# base = 4 + 4 + 4 + 4 + header_json_size  but header is stored with pickle padding to 4
# Electron: read header as:
#  UInt32LE pickle header size
#  then pickle containing string
# Common working approach:
#  offset_base = 16 + json_byte_len? No.

# From @electron/asar:
# const headerSize = this.headerSize  // from pickle
# data offset = 8 + headerSize? or 16 + headerSize?

# Try both and verify by reading first file size

def extract_all(base):
    extracted = 0
    def walk_ex(node, prefix=""):
        nonlocal extracted
        files = node.get("files")
        if not isinstance(files, dict):
            return
        for name, meta in files.items():
            p = f"{prefix}/{name}" if prefix else name
            if "files" in meta:
                (out_dir / p).mkdir(parents=True, exist_ok=True)
                walk_ex(meta, p)
            else:
                off = int(meta.get("offset", 0))
                size = int(meta.get("size", 0))
                raw = data[base + off: base + off + size]
                dest = out_dir / p
                dest.parent.mkdir(parents, exist_ok=True) if False else dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(raw)
                extracted += 1
    walk_ex(header)
    return extracted

# compute header json byte length
json_bytes = Path(out_dir / "_header.json").read_bytes()
# re-read original header size from file
# header JSON in original file:
brace = data.find(b'{')
header_js, end = __import__('json').JSONDecoder().raw_decode(data[brace:].decode('utf-8'))
# find where json ends in bytes - approximate: brace + end chars may differ if non-ascii
# better: try bases
candidates = []
# pickle size at [0]=4? second value is header size
hsize = u32s[1]
candidates += [8 + hsize, 12 + hsize, 16 + hsize, 4 + hsize, hsize]
# also aligned
for hs in [hsize, hsize + 4, (hsize + 3) & ~3]:
    candidates += [8 + hs, 16 + hs]

print("candidate bases", sorted(set(candidates)))

# validate base by checking if first file starts with known pattern
def find_first_file(node, prefix=""):
    files = node.get("files")
    if not isinstance(files, dict):
        return None
    for name, meta in files.items():
        p = f"{prefix}/{name}" if prefix else name
        if "files" in meta:
            r = find_first_file(meta, p)
            if r:
                return r
        else:
            return p, int(meta.get("offset", 0)), int(meta.get("size", 0))
    return None

ff = find_first_file(header)
print("first file", ff)

if ff:
    p, off, size = ff
    for base in sorted(set(candidates)):
        sample = data[base + off: base + off + min(32, size)]
        print(f" base={base} sample={sample[:32]!r}")

# pick base that looks most like text/js if first file is js/json
best = None
if ff:
    p, off, size = ff
    for base in sorted(set(candidates)):
        sample = data[base + off: base + off + min(64, max(size,1))]
        if sample and all(32 <= b < 127 or b in (9,10,13) for b in sample[:16]):
            best = base
            print("chosen base", base, "via printable")
            break
if best is None:
    # default electron: 8 + headerSize from pickle
    best = 8 + u32s[1]
    print("fallback base", best)

n = extract_all(best)
print("extracted", n, "files to", out_dir)

# list js files
for p in sorted(out_dir.rglob("*")):
    if p.is_file() and p.suffix.lower() in {".js", ".json", ".html", ".lua", ".txt", ".env", ".md"}:
        print(p.relative_to(out_dir), p.stat().st_size)
