"""Deobfuscate TrustSettle api.txt Lua script (static only)."""
from pathlib import Path
import re
import base64
import binascii

raw = Path(r"C:\src\projects\HackTheBox CTF Holme\SilentDividend\nsis\extraResources\api.txt").read_text(encoding="utf-8", errors="replace")
print("api.txt length", len(raw))
print("head:", raw[:200])
print("tail:", raw[-400:])

# extract string literals from local z={...}
# pattern "..."
strings = re.findall(r'"((?:\\.|[^"\\])*)"', raw)
print("string count", len(strings))

def try_b64(s):
    # many start with Q or n - might be custom
    # Q-prefixed look like base64
    candidates = [s, s[1:] if s and s[0] in "Qn" else s]
    # also try urlsafe
    for c in list(candidates):
        pad = c + "=" * ((4 - len(c) % 4) % 4)
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                d = decoder(pad, validate=False)
                if d and all(32 <= b < 127 or b in (9,10,13) for b in d[:20]):
                    return d.decode("latin-1", errors="replace")
            except Exception:
                continue
    return None

print("\n=== base64 attempts (Q-prefix stripped) ===")
for s in strings:
    if s.startswith("Q") and len(s) >= 8:
        d = try_b64(s[1:])
        if d and len(d) > 2:
            print(repr(s[:40]), "->", repr(d[:80]))

print("\n=== base64 attempts raw ===")
for s in strings:
    if len(s) >= 8:
        d = try_b64(s)
        if d and len(d) > 2 and any(c.isalpha() for c in d):
            print(repr(s[:40]), "->", repr(d[:80]))

# n-prefixed might be XOR or custom cipher
print("\n=== n-prefix samples ===")
for s in strings:
    if s.startswith("n"):
        print(repr(s[:60]), "len", len(s))

# save full file for inspection
Path(r"C:\src\projects\HackTheBox CTF Holme\SilentDividend\api_raw.txt").write_text(raw, encoding="utf-8")
print("\nfull raw saved")
