"""Call x0 views correctly and derive hidden owner; download sourcify sources."""
import json
import urllib.request
from pathlib import Path

DRAIN = "0x69Bf5b7aBA51C3Ee8bF169aB47479ba95DBF709D"
TOKEN = "0x6B2B0C0d0a376255Ac70Bf1366f50982bF476Bb2"
CREATOR = "0xc65a47bC149C655c5A114a8e76b231B6405Bd3a4"
RPC = "https://ethereum-sepolia-rpc.publicnode.com"
OUT = Path(r"C:\src\projects\HackTheBox CTF Holme\SilentDividend\chain")
OUT.mkdir(exist_ok=True)

def rpc(method, params):
    payload = json.dumps({"jsonrpc":"2.0","id":1,"method":method,"params":params}).encode()
    req = urllib.request.Request(RPC, data=payload, headers={"Content-Type":"application/json","User-Agent":"Mozilla/5.0"}, method="POST")
    with urllib.request.urlopen(req, timeout=25) as r:
        return json.loads(r.read().decode())

def call(to, data):
    res = rpc("eth_call", [{"to": to, "data": data}, "latest"])
    return res.get("result", "")

def decode_abi_string(hexval):
    if not hexval or hexval == "0x":
        return None
    raw = bytes.fromhex(hexval[2:])
    if len(raw) < 64:
        return raw
    off = int.from_bytes(raw[0:32], "big")
    if off + 32 <= len(raw):
        ln = int.from_bytes(raw[off:off+32], "big")
        return raw[off+32:off+32+ln]
    return raw

def addr_arg(a):
    return "0x" + a[2:].lower().rjust(64, "0")

# selectors from ABI
# x1() 0x0bfac020
# x7() 0x282940a7
# x8(bytes) 0x343943bd
# x9(address) 0xf8e6e11f
# x11(address) 0x8f7f391e

print("x1 MockToken:", call(DRAIN, "0x0bfac020"))
x7 = call(DRAIN, "0x282940a7")
print("x7 raw:", x7)
if x7 and len(x7) == 66:
    print("x7 addr:", "0x" + x7[26:])

# storage
s1 = rpc("eth_getStorageAt", [DRAIN, "0x"+"1"*64, "latest"])  # wrong
s = {}
for i in range(4):
    slot = "0x" + f"{i:064x}"
    s[i] = rpc("eth_getStorageAt", [DRAIN, slot, "latest"]).get("result")
    print(f"slot{i}", s[i])

def as_addr(word):
    return "0x" + word[-40:]

def last20(word):
    return int(word, 16) & ((1<<160)-1)

print("addr slot0", as_addr(s[0]))
print("addr slot1", as_addr(s[1]))
print("addr slot2", as_addr(s[2]))
print("slot1^slot2 addr", "0x" + format(last20(s[1]) ^ last20(s[2]), "040x"))
print("slot2 as addr", as_addr(s[2]))

# try x9 with various addresses
candidates = {
    "creator": CREATOR,
    "token": TOKEN,
    "drain": DRAIN,
    "slot0": as_addr(s[0]),
    "slot1": as_addr(s[1]),
    "slot2": as_addr(s[2]),
    "xor12": "0x" + format(last20(s[1]) ^ last20(s[2]), "040x"),
    "zero": "0x" + "0"*40,
    "x7": "0x" + x7[26:] if x7 and len(x7)==66 else None,
}
# also StateRegistry and some others
candidates["registry"] = "0xbB63Ae28E4f75C9392bae69cDf5394Ca0ACdA6B1"
candidates["eoa_guess"] = "0xc65a47bC149C655c5A114a8e76b231B6405Bd3a4"

for name, addr in candidates.items():
    if not addr:
        continue
    data = "0xf8e6e11f" + addr_arg(addr)
    try:
        val = call(DRAIN, data)
        decoded = decode_abi_string(val)
        print(f"x9({name}={addr}) -> {val[:80]} decoded={decoded!r}")
    except Exception as e:
        print(f"x9({name}) ERR {e}")

# download sourcify sources
print("\n=== sourcify sources ===")
addrs = [
    ("x0", DRAIN),
    ("StateRegistry", "0xbB63Ae28E4f75C9392bae69cDf5394Ca0ACdA6B1"),
    ("MockToken", TOKEN),
]
for name, addr in addrs:
    for base in [
        f"https://repo.sourcify.dev/contracts/full_match/11155111/{addr}/",
        f"https://repo.sourcify.dev/contracts/partial_match/11155111/{addr}/",
    ]:
        for fname in ["sources/wallet.sol", "metadata.json", "sources/StateRegistry.sol", "sources/MockToken.sol", "sources/token.sol"]:
            url = base + fname
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=15) as r:
                    data = r.read()
                dest = OUT / f"sourcify_{name}_{fname.replace('/','_')}"
                dest.write_bytes(data)
                print("saved", dest, len(data))
                if fname.endswith(".sol") or fname.endswith(".json"):
                    print(data[:1500].decode("utf-8", errors="replace"))
            except Exception as e:
                pass
