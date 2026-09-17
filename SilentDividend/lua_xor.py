"""Try decode api.txt strings XOR with known blockchain keys."""
from pathlib import Path
import re
import base64

raw = Path(r"C:\src\projects\HackTheBox CTF Holme\SilentDividend\nsis\extraResources\api.txt").read_text(encoding="utf-8", errors="replace")
strings = re.findall(r'"((?:\\.|[^"\\])*)"', raw)

def unescape(s):
    out = []
    i = 0
    while i < len(s):
        if s[i] == "\\" and i+1 < len(s):
            n = s[i+1]
            mapping = {"n":"\n","t":"\t","r":"\r","\\":"\\","\"":"\"","'":"'", "0":"\0"}
            out.append(mapping.get(n, n))
            i += 2
        else:
            out.append(s[i]); i += 1
    return "".join(out)

decoded_s = [unescape(s) for s in strings]
n_s = [s[1:] for s in decoded_s if s.startswith("n") and len(s) > 4]
q_s = [s[1:] for s in decoded_s if s.startswith("Q") and len(s) > 4]

keys = [
    bytes.fromhex("3460743bb1ce2e6209e65e8ee3023f8414bc8416aef842b69c2a318bcef952f4"),
    bytes.fromhex("b5209fa26dd09d3d6a000ce1fb7d8f88629986ef45823d9dad95d0ea69729d52"),
    bytes.fromhex("b8d65bb591ae443f301f3272efd8bb8bd24045dbe20d2ae77063d07d9a5f7af9"),
    bytes.fromhex("8f1aabeb8412c3196908960250e93aa20ae7819ea3d1828541169f59fa65d641"),
    bytes.fromhex("81555eea89b714fd6ad80eda5ea6c7e6cceae50193b82eabb48ced56adb81ec7"),
    bytes.fromhex("ebfc1ed96b1c6b940fb6b06359ff4a6776df7a9a"),
    bytes.fromhex("474274f44ceac3ee57f986608d94"),
    b"NAPOLEON",
    b"SR-4821",
    b"HTB{",
    b"TrustSettle",
    bytes([0x42]),
]

def is_print(b):
    return sum(32<=x<127 or x in (9,10,13) for x in b) / max(len(b),1) > 0.9

print("Trying XOR n-strings with keys on first 25 strings")
for kn, key in enumerate(keys):
    hits = 0
    samples = []
    for s in n_s[:25]:
        rawb = s.encode("latin-1", errors="replace")
        pt = bytes(rawb[i] ^ key[i % len(key)] for i in range(len(rawb)))
        if is_print(pt) and any(c.isalpha() for c in pt.decode("latin-1", "ignore")):
            hits += 1
            if len(samples) < 3:
                samples.append(pt[:60])
    if hits >= 3:
        print(f"key#{kn} hits={hits}", samples)

# try Q strings with custom base64 - maybe alphabet rotated
print("\nQ samples raw:")
for s in q_s[:15]:
    print(repr(s), "len", len(s))

# maybe Q strings are base64 of xor-decoded content using alphabet
# try standard b64 after replacing chars
std_alph = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
# Luraph sometimes uses a custom alphabet

# try treating Q body as base64url
print("\nb64url Q:")
for s in q_s[:20]:
    body = s
    pad = body + "=" * ((4-len(body)%4)%4)
    for fn in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            d = fn(pad)
            if is_print(d) and len(d)>=3:
                print(repr(s), "->", d)
                break
        except Exception:
            continue

# Look at entire api.txt for any leftover readable after removing strings
rest = re.sub(r'"(?:\\.|[^"\\])*"', '""', raw)
readable = re.findall(r"[A-Za-z0-9_\{\}]{6,}", rest)
print("\nidentifier-like in code:", readable[:50])

# check if HTB appears after any simple transform of whole file
data = raw.encode()
for key in [0x42, 0x20, 0x13, 0x37]:
    x = bytes(b^key for b in data)
    if b"HTB{" in x or b"flag{" in x.lower():
        print("FOUND with xor", hex(key))
        idx = x.find(b"HTB{") if b"HTB{" in x else x.lower().find(b"flag{")
        print(x[idx:idx+40])
