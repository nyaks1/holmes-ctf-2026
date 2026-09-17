"""Search other challenge PDFs and remaining binaries for flag-like strings."""
from pathlib import Path
import re
from pypdf import PdfReader

ROOT = Path(r"C:\src\projects\HackTheBox CTF Holme")

for pdf in ROOT.rglob("*.pdf"):
    print("\n====", pdf)
    data = pdf.read_bytes()
    reader = PdfReader(str(pdf))
    print("meta", reader.metadata)
    for pat in [rb"HTB\{[^}]+\}", rb"flag", rb"NAPOLEON", rb"0x[a-fA-F0-9]{40}"]:
        for m in re.finditer(pat, data, re.I):
            print(" ", m.group()[:80])
    # images
    for pi, page in enumerate(reader.pages):
        try:
            for ii, img in enumerate(page.images):
                blob = img.data
                hits = re.findall(rb"HTB\{[^}]+\}", blob)
                print(f"  page{pi+1} img{ii} {img.name} size={len(blob)} htb={hits}")
                # after JPEG EOI
                if blob[:2] == b"\xff\xd8":
                    eoi = blob.rfind(b"\xff\xd9")
                    if eoi != -1 and eoi+2 < len(blob):
                        print("   jpeg extra", len(blob)-eoi-2, blob[eoi+2:eoi+2+40])
        except Exception as e:
            print("  img err", e)

# asar non-node_modules files
print("\n==== asar app files strings ====")
asar = ROOT / "SilentDividend" / "asar"
for p in asar.rglob("*"):
    if not p.is_file():
        continue
    if "node_modules" in p.parts:
        continue
    if p.stat().st_size > 5_000_000:
        continue
    data = p.read_bytes()
    if b"HTB" in data or b"flag{" in data.lower() or b"NAPOLEON" in data:
        print(p, "HIT")
        for m in re.finditer(rb".{0,20}(HTB|flag\{|NAPOLEON|SR-).{0,40}", data, re.I):
            print(" ", m.group())

# load all5 registry keys and try decrypting ENCRYPTED_DATA AND cipher with variants
print("\n==== decrypt variants for HTB ====")
import hashlib
cipher = bytes.fromhex("474274f44ceac3ee57f986608d94")
enc = bytes.fromhex(
    "560c325bdd0aeea2cd2690a2ed1c1b4a28deca7ac2a40ce8d2725d539a950ca8"
    "f4a4bcf375806c36532258a0cf16c19c12989e0aa0e25a72be241da7d2f74cfa"
    "2c4c4e1bbfc6204207fe5c801d201f5af84864f0"
)
owner = bytes.fromhex("ebfc1ed96b1c6b940fb6b06359ff4a6776df7a9a")

def keccak_stream(data, key_addr20, start_counter=0):
    try:
        from eth_hash.auto import keccak
    except Exception:
        # pysha3 or pycryptodome
        try:
            from Crypto.Hash import keccak as k
            def keccak(b):
                h = k.new(digest_bits=256)
                h.update(b)
                return h.digest()
        except Exception:
            def keccak(b):
                # fallback sha3 if available
                import sha3
                return sha3.keccak_256(b).digest()
    out = bytearray(len(data))
    i = 0
    counter = start_counter
    while i < len(data):
        block = keccak(key_addr20 + counter.to_bytes(32, "big"))
        for j in range(32):
            if i >= len(data):
                break
            out[i] = data[i] ^ block[j]
            i += 1
        counter += 1
    return bytes(out)

# verify known plaintext
try:
    pt = keccak_stream(cipher, owner)
    print("keccak stream cipher->owner:", pt, pt.decode("latin-1", errors="replace"))
except Exception as e:
    print("keccak fail", e)
    # try encodePacked address + uint256 counter as solidity does
    # abi.encodePacked(address, counter) = 20 bytes + 32 bytes
    try:
        from eth_hash.auto import keccak as kec
    except Exception:
        from Crypto.Hash import keccak as K
        def kec(b):
            h = K.new(digest_bits=256); h.update(b); return h.digest()
    out = bytearray()
    i = 0
    c = 0
    while i < len(cipher):
        block = kec(owner + c.to_bytes(32, "big"))
        for j in range(32):
            if i >= len(cipher):
                break
            out.append(cipher[i] ^ block[j])
            i += 1
        c += 1
    print("retry", bytes(out), bytes(out).decode("latin-1", errors="replace"))

# try HTB wrap of x9 result and other high-confidence
print("\nHigh-confidence flag list:")
vals = [
    "TrustSettle",
    "TrustSettle 1.0.0",
    "1.0.0",
    "NAPOLEON",
    "SR-4821",
    "51.5049,0.0348",
    "0xebfc1ed96b1c6b940fb6b06359ff4a6776df7a9a",
    "0x69Bf5b7aBA51C3Ee8bF169aB47479ba95DBF709D",
    "0xbB63Ae28E4f75C9392bae69cDf5394Ca0ACdA6B1",
    "0x6B2B0C0d0a376255Ac70Bf1366f50982bF476Bb2",
    "0x3460743bb1ce2e6209e65e8ee3023f8414bc8416aef842b69c2a318bcef952f4",
    "ethereum-sepolia-rpc.publicnode.com",
    "C:\\Users\\Public",
    "luajit.exe",
    "api.txt",
    "x0",
    "StateRegistry",
    "cipherFlag",
    "not quite - keep analyzing",
    "only hidden owner",
    "MockToken",
    "wallet.sol",
    "KeyVault.sol",
    "sepolia",
]
for v in vals:
    print(f"  HTB{{{v}}}")
