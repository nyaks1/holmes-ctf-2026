"""Hunt Win32 API / structure names in api.txt via multi-byte XOR and encodings."""
from pathlib import Path
import re
import itertools

raw = Path(r"C:\src\projects\HackTheBox CTF Holme\SilentDividend\nsis\extraResources\api.txt").read_bytes()

targets = [
    b"FILE_NOTIFY_INFORMATION",
    b"FILE_NOTIFY",
    b"ReadDirectoryChanges",
    b"WinHttpSendRequest",
    b"WinHttpOpen",
    b"WinHttpConnect",
    b"WinHttpReadData",
    b"InternetOpen",
    b"InternetOpenUrl",
    b"HttpSendRequest",
    b"HttpOpenRequest",
    b"InternetReadFile",
    b"WinInet",
    b"winhttp",
    b"URLDownload",
    b"WSASend",
    b"send(",
]

# 1-byte xor
print("=== 1-byte XOR ===")
for t in targets:
    for key in range(256):
        enc = bytes(c ^ key for c in t)
        if enc in raw:
            print(f"FOUND {t!r} xor=0x{key:02x} at {raw.find(enc)}")

# rolling xor with short keys derived from cribs
keys = [
    b"HTB", b"lua", b"api", b"key", b"flag", b"NAPOLEON", b"SETTLE",
    b"TrustSettle", b"Public", b"powershell", b"0x42",
    bytes([0x42]), bytes([0x13, 0x37]),
]
print("\n=== named key XOR ===")
for t in targets:
    for key in keys:
        enc = bytes(t[i] ^ key[i % len(key)] for i in range(len(t)))
        if enc in raw:
            print(f"FOUND {t!r} key={key!r} at {raw.find(enc)}")

# custom: xor with position
print("\n=== positional ===")
for t in targets:
    for mode, fn in [
        ("i", lambda i: i & 0xFF),
        ("i+1", lambda i: (i + 1) & 0xFF),
        ("i^0x42", lambda i: (i ^ 0x42) & 0xFF),
    ]:
        enc = bytes(t[i] ^ fn(i) for i in range(len(t)))
        if enc in raw:
            print(f"FOUND {t!r} mode={mode}")

# extract all n/Q strings and xor each against each target to get candidate keys, apply globally
lits = re.findall(rb'"((?:\\.|[^"\\])*)"', raw)
print("\n=== per-string crib keys ===")
for t in targets[:8]:
    for lit in lits:
        # unescape roughly
        s = lit.replace(b"\\n", b"\n").replace(b"\\t", b"\t").replace(b'\\\"', b'"').replace(b"\\\\", b"\\")
        if len(s) < len(t):
            continue
        for off in range(min(4, len(s) - len(t) + 1)):
            key = bytes(s[off + i] ^ t[i] for i in range(len(t)))
            # if key is repeating short
            for klen in range(1, min(9, len(key) + 1)):
                if key == (key[:klen] * (len(key) // klen + 1))[:len(key)]:
                    # search target encoded with this key in whole file
                    enc = bytes(t[i] ^ key[i % klen] for i in range(len(t)))
                    idx = raw.find(enc)
                    if idx >= 0:
                        print(f"{t!r} key={key[:klen]!r} klen={klen} @{idx}")

print("\n=== base32/base58-ish Q decode ===")
import base64
for lit in lits:
    if not lit.startswith(b"Q"):
        continue
    body = lit[1:]
    # try rot1 then b64
    for rot in range(26):
        # only for alpha-heavy
        pass
    pad = body + b"=" * ((4 - len(body) % 4) % 4)
    try:
        d = base64.b64decode(pad)
        if any(t in d for t in targets) or b"Win" in d or b"FILE" in d or b"Http" in d:
            print(body[:40], d[:80])
    except Exception:
        continue
