"""Static decode attempts on api.txt string table (no execution)."""
from pathlib import Path
import re
import base64

raw = Path(r"C:\src\projects\HackTheBox CTF Holme\SilentDividend\nsis\extraResources\api.txt").read_text(encoding="utf-8", errors="replace")
strings = re.findall(r'"((?:\\.|[^"\\])*)"', raw)

def unescape(s):
    return bytes(s, "utf-8").decode("unicode_escape", errors="replace")

q_strs = [unescape(s) for s in strings if s.startswith("Q") and len(s) >= 8]
n_strs = [unescape(s) for s in strings if s.startswith("n") and len(s) >= 4]

print(f"Q strings: {len(q_strs)}, N strings: {len(n_strs)}")

def is_mostly_printable(b: bytes) -> bool:
    if not b:
        return False
    good = sum(1 for x in b if 32 <= x < 127 or x in (9,10,13))
    return good / len(b) > 0.85

# Try Q -> strip Q, base64 decode
print("\n--- Q strip prefix b64 ---")
for s in q_strs[:30]:
    body = s[1:]
    pad = body + "=" * ((4 - len(body) % 4) % 4)
    for label, fn in [
        ("b64", lambda x: base64.b64decode(x + "=" * ((4-len(x)%4)%4))),
        ("b64s", lambda x: base64.standard_b64decode(x + "=" * ((4-len(x)%4)%4))),
    ]:
        try:
            d = fn(body)
            if is_mostly_printable(d) and len(d) >= 3:
                print(f"{s[:40]!r} -> {d!r}")
                break
        except Exception:
            continue

# Try rolling XOR on n strings
print("\n--- N xor key brute (1 byte) ---")
interesting = []
for key in range(256):
    hits = []
    for s in n_strs[:40]:
        b = bytes(ord(c) ^ key for c in s[1:])  # skip n prefix
        if is_mostly_printable(b) and any(x.isalpha() for x in b.decode("latin-1", errors="ignore")):
            hits.append(b.decode("latin-1", errors="replace"))
    if len(hits) >= 5:
        interesting.append((key, hits[:5], len(hits)))
if interesting:
    for key, hits, n in interesting[:10]:
        print(f"key=0x{key:02x} hits={n} samples={hits}")
else:
    print("no single-byte xor key")

# 2-byte xor
print("\n--- N xor 2-byte sample ---")
s0 = n_strs[0][1:]
best = []
for k0 in range(256):
    for k1 in range(32, 127):
        key = bytes([k0, k1])
        b = bytes(ord(c) ^ key[i % 2] for i, c in enumerate(s0))
        if is_mostly_printable(b) and b[:4].isalpha() or (is_mostly_printable(b) and any(w in b.lower() for w in [b"http", b"powershell", b"curl", b"wallet", b"flag", b"htb", b"users", b"appdata", b"discord", b"telegram", b"chrome", b"metamask"])):
            best.append((key.hex(), b[:80]))
            if len(best) >= 5:
                break
    if len(best) >= 5:
        break
print(best[:5])

# Look at the long n string (2802 chars) - likely bytecode or payload
long_n = max(n_strs, key=len)
print("\n--- longest n string ---")
print("len", len(long_n), "prefix", long_n[:80])
print("charset unique", len(set(long_n[1:])))

# Try base64 of n without prefix
body = long_n[1:]
for alphabet_name, alphabet in [("std", None)]:
    pad = body + "=" * ((4 - len(body) % 4) % 4)
    try:
        d = base64.b64decode(pad)
        print("b64 decode longest", len(d), d[:40], "printable?", is_mostly_printable(d))
    except Exception as e:
        print("b64 fail", e)

# Maybe strings are XOR'd with position
print("\n--- positional xor (i or i%256) on first n ---")
for mode_name, mode_fn in [
    ("i", lambda i: i & 0xFF),
    ("i+1", lambda i: (i + 1) & 0xFF),
    ("0x42", lambda i: 0x42),
    ("i^0x20", lambda i: i ^ 0x20),
]:
    b = bytes(ord(c) ^ mode_fn(i) for i, c in enumerate(s0))
    print(mode_name, is_mostly_printable(b), b[:60])

# Extract any readable ASCII already in api.txt outside strings
readable = re.findall(rb"[ -~]{8,}", raw.encode())
print("\n--- raw ascii runs in api.txt (first 20) ---")
for r in readable[:20]:
    print(r[:120])

# Check if luajit bytecode header
print("\nfile starts with return(function - lua source not bytecode")
print(raw[:80])
