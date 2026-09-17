"""Extract Solidity IPFS metadata from contract bytecode and fetch sources."""
from pathlib import Path
import re
import urllib.request

out_dir = Path(r"C:\src\projects\HackTheBox CTF Holme\SilentDividend\chain")
base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def extract_ipfs(code_hex: str):
    if not code_hex.startswith("0x"):
        return None
    raw = bytes.fromhex(code_hex[2:])
    # look for "dipfsX" = 64 69 70 66 73 58
    idx = raw.find(b"dipfsX")
    print("dipfs at", idx, "file len", len(raw))
    if idx < 0:
        # search hex pattern
        idx = raw.find(bytes.fromhex("646970667358"))
        print("dipfs hex at", idx)
    if idx < 0:
        return None
    # after dipfsX: 0x22 = '"' then 34 bytes CID
    if idx + 7 < len(raw) and raw[idx+6] == 0x22:
        cid_bytes = raw[idx+7:idx+7+34]
        print("cid raw", cid_bytes.hex())
        # CIDv0 is Qm + base58(sha256 multihash)
        # The 34 bytes are typically the multihash: 0x12 0x20 + 32 byte sha256
        if cid_bytes[0] == 0x12 and cid_bytes[1] == 0x20:
            mh = cid_bytes
            # base58 encode
            n = int.from_bytes(mh, "big")
            enc = ""
            while n:
                n, r = divmod(n, 58)
                enc = base58[r] + enc
            # leading zeros
            for b in mh:
                if b == 0:
                    enc = "1" + enc
                else:
                    break
            cid = "Qm" + enc if not enc.startswith("Qm") else enc
            # actually multihash base58 already starts with Qm
            return enc
        else:
            # maybe already includes more
            return cid_bytes.hex()
    return None

gateways = [
    "https://ipfs.io/ipfs/",
    "https://cloudflare-ipfs.com/ipfs/",
    "https://dweb.link/ipfs/",
    "https://gateway.pinata.cloud/ipfs/",
]

for p in sorted(out_dir.glob("*_code.hex")):
    code = p.read_text().strip()
    print("\n===", p.name, "len", (len(code)-2)//2)
    cid = extract_ipfs(code)
    print("CID candidate:", cid)
    if not cid:
        continue
    for gw in gateways:
        url = gw + cid
        print("fetch", url)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=20) as r:
                data = r.read()
            print("  got", len(data), data[:200])
            dest = out_dir / f"{p.stem}_{cid[:16]}.sol"
            dest.write_bytes(data)
            print("  saved", dest)
            break
        except Exception as e:
            print("  fail", e)
