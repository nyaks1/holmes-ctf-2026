"""Static Luraph-class string recovery for api.txt using stage-1 cribs.

Does NOT execute package luajit.exe.
"""
from pathlib import Path
import re
import base64

API = Path(r"C:\src\projects\HackTheBox CTF Holme\SilentDividend\nsis\extraResources\api.txt")
raw = API.read_text(encoding="utf-8", errors="replace")

def unescape_lua(s: str) -> str:
    out = []
    i = 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            n = s[i + 1]
            mapping = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"', "'": "'", "0": "\0", "a": "\a", "b": "\b", "f": "\f", "v": "\v"}
            if n in mapping:
                out.append(mapping[n]); i += 2; continue
            if n == "x" and i + 3 < len(s):
                try:
                    out.append(chr(int(s[i+2:i+4], 16))); i += 4; continue
                except Exception:
                    pass
            out.append(n); i += 2
        else:
            out.append(s[i]); i += 1
    return "".join(out)

lits = [unescape_lua(s) for s in re.findall(r'"((?:\\.|[^"\\])*)"', raw)]
q = [s[1:] for s in lits if s.startswith("Q") and len(s) >= 4]
n = [s[1:] for s in lits if s.startswith("n") and len(s) >= 4]
print(f"literals={len(lits)} Q={len(q)} n={len(n)}")

# cribs from stage 1
CRIBS = [b"powershell", b"luajit", b"Public", b"HTB{", b"flag{", b"NAPOLEON",
         b"api.txt", b"settlement", b"wallet", b"PRIVATE_KEY", b"http",
         b"C:\\Users", b"echo", b"start"]

def score(pt: bytes) -> float:
    if not pt:
        return 0.0
    good = sum(1 for x in pt if 32 <= x < 127 or x in (9, 10, 13))
    return good / len(pt)

def try_decode_q(body: str):
    """Q entries look base64-shaped; try std/urlsafe, optional prefix strip."""
    cands = [body, body[1:] if body[:1] in "Qn" else body]
    for c in cands:
        pad = c + "=" * ((4 - len(c) % 4) % 4)
        for fn in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                d = fn(pad)
            except Exception:
                continue
            if score(d) > 0.85 and len(d) >= 3:
                return d
    return None

def try_xor_crib(strings, crib: bytes):
    """Derive repeating XOR key from first crib-aligned string if possible."""
    # For each string, see if any offset produces crib; extract key stream
    for s in strings:
        b = s.encode("latin-1", errors="replace")
        if len(b) < len(crib):
            continue
        for off in range(min(8, len(b) - len(crib) + 1)):
            key = bytes(b[off + i] ^ crib[i] for i in range(len(crib)))
            # extend key periodically if key looks low-entropy repeating
            for klen in range(1, min(16, len(key) + 1)):
                if key[:klen] * (len(key) // klen) + key[:len(key) % klen] != key:
                    continue
                # apply to all strings
                decoded = []
                ok = 0
                for t in strings:
                    tb = t.encode("latin-1", errors="replace")
                    pt = bytes(tb[i] ^ key[i % klen] for i in range(len(tb)))
                    decoded.append(pt)
                    if score(pt) > 0.85:
                        ok += 1
                if ok >= max(3, len(strings) // 4):
                    return klen, key, decoded
    return None

print("\n=== Q base64 attempts ===")
q_hits = []
for s in q:
    d = try_decode_q(s)
    if d:
        q_hits.append((s, d))
        flaggy = b"HTB{" in d or b"flag{" in d or b"NAPOLEON" in d
        print(("FLAG?" if flaggy else "ok"), repr(s[:40]), "->", d[:80])
print("q_hits", len(q_hits))

print("\n=== n-string XOR vs cribs ===")
for crib in CRIBS:
    res = try_xor_crib(n[:60], crib)
    if not res:
        continue
    klen, key, decoded = res
    print(f"CRIB {crib!r} klen={klen} key={key.hex()}")
    for pt in decoded[:15]:
        if score(pt) > 0.8:
            print(" ", pt[:100])
    # search all decoded for flags
    for pt in decoded:
        if b"HTB{" in pt or b"flag{" in pt:
            print("  *** FLAG", pt[:200])

print("\n=== single-byte xor scan n for HTB{/flag{ ===")
for key in range(256):
    for s in n:
        b = s.encode("latin-1", errors="replace")
        pt = bytes(x ^ key for x in b)
        if b"HTB{" in pt or b"flag{" in pt:
            print(f"xor=0x{key:02x}", pt[:120])

print("\n=== full-file xor HTB{ crib location ===")
data = raw.encode("latin-1", errors="replace")
target = b"HTB{"
for key in range(256):
    enc = bytes(c ^ key for c in target)
    i = data.find(enc)
    if i >= 0:
        win = bytes(c ^ key for c in data[i:i+60])
        print(f"file xor 0x{key:02x} @{i}: {win!r}")
