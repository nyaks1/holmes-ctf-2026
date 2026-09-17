"""Expand answers bank: x9 variants, decrypt cipherFlag, HTB candidates."""
import json
import urllib.request
from pathlib import Path
import hashlib

RPC = "https://ethereum-sepolia-rpc.publicnode.com"
DRAIN = "0x69Bf5b7aBA51C3Ee8bF169aB47479ba95DBF709D"
OWNER = "0xebfc1ed96b1c6b940fb6b06359ff4a6776df7a9a"
CREATOR = "0xc65a47bC149C655c5A114a8e76b231B6405Bd3a4"

def rpc(method, params):
    payload = json.dumps({"jsonrpc":"2.0","id":1,"method":method,"params":params}).encode()
    req = urllib.request.Request(RPC, data=payload, headers={"Content-Type":"application/json","User-Agent":"Mozilla/5.0"}, method="POST")
    with urllib.request.urlopen(req, timeout=25) as r:
        return json.loads(r.read().decode())

def x9(addr):
    data = "0xf8e6e11f" + addr[2:].lower().rjust(64, "0")
    res = rpc("eth_call", [{"to": DRAIN, "data": data}, "latest"])
    val = res.get("result", "0x")
    if not val or val == "0x":
        return val
    raw = bytes.fromhex(val[2:])
    if len(raw) >= 64:
        ln = int.from_bytes(raw[32:64], "big")
        return raw[64:64+ln].decode("latin-1", errors="replace")
    return val

for name, addr in [
    ("owner", OWNER),
    ("creator", CREATOR),
    ("zero", "0x" + "0"*40),
    ("dead", "0x" + "dEaD"*10),
    ("lower", OWNER.lower()),
]:
    print(f"x9({name})", repr(x9(addr)))

# cipherFlag from x8
cipher = bytes.fromhex("474274f44ceac3ee57f986608d94")
print("cipher", cipher, len(cipher))

# registry keys
keys = {
    "resolveStage": bytes.fromhex("b5209fa26dd09d3d6a000ce1fb7d8f88629986ef45823d9dad95d0ea69729d52"),
    "resolveState": bytes.fromhex("3460743bb1ce2e6209e65e8ee3023f8414bc8416aef842b69c2a318bcef952f4"),
    "resolveStatee": bytes.fromhex("b8d65bb591ae443f301f3272efd8bb8bd24045dbe20d2ae77063d07d9a5f7af9"),
    "resolveStates": bytes.fromhex("8f1aabeb8412c3196908960250e93aa20ae7819ea3d1828541169f59fa65d641"),
    "resolveStatus": bytes.fromhex("81555eea89b714fd6ad80eda5ea6c7e6cceae50193b82eabb48ced56adb81ec7"),
}

# decrypt cipher with same algorithm as preload
MAGIC, ROT = 0x42, 7
def dec(data, key):
    out = bytearray(len(data))
    for i, b in enumerate(data):
        step1 = b ^ key[i % len(key)]
        step2 = ((step1 << ROT) | (step1 >> (8-ROT))) & 0xFF
        out[i] = step2 ^ MAGIC
    return bytes(out)

print("\n=== cipher decrypt attempts ===")
for kn, k in keys.items():
    pt = dec(cipher, k)
    pr = sum(32<=c<127 for c in pt)
    print(kn, pr, "/", len(pt), pt)

# xor cipher with owner address
owner_bytes = bytes.fromhex(OWNER[2:])
xor_owner = bytes(cipher[i] ^ owner_bytes[i % 20] for i in range(len(cipher)))
print("xor owner", xor_owner, xor_owner.decode("latin-1", errors="replace"))

# try x9 result interpretation
print("\ncoords 51.5049,0.0348 -> London-ish")
print("HTB candidates:")
answers = [
    "TrustSettle",
    "1.0.0",
    "TrustSettle 1.0.0",
    "0x69Bf5b7aBA51C3Ee8bF169aB47479ba95DBF709D",
    "0xbB63Ae28E4f75C9392bae69cDf5394Ca0ACdA6B1",
    "0x6B2B0C0d0a376255Ac70Bf1366f50982bF476Bb2",
    "0xebfc1ed96b1c6b940fb6b06359ff4a6776df7a9a",
    "0xc65a47bC149C655c5A114a8e76b231B6405Bd3a4",
    "0x3460743bb1ce2e6209e65e8ee3023f8414bc8416aef842b69c2a318bcef952f4",
    "NAPOLEON",
    "SR-4821",
    "51.5049,0.0348",
    "x0",
    "StateRegistry",
    "MockToken",
    "wallet.sol",
    "https://ethereum-sepolia-rpc.publicnode.com",
    "ethereum-sepolia-rpc.publicnode.com",
    "publicnode.com",
    "C:\\Users\\Public",
    "luajit.exe",
    "api.txt",
    "settlement.html",
    "0x42",
    "rotate-left-7",
    "xor",
    "not quite - keep analyzing",
    "already set",
    "only hidden owner",
    "MILVERTON",
    "Milverton",
    "Martin Vale",
    "Miriam Cross",
    "Peter Rance",
    "AUTH=NAPOLEON",
    "SETTLEMENT_REFERENCE=SR-4821",
    "start \"\" \"%TEMP%\\settlement.html\" && echo AUTH=NAPOLEON SETTLEMENT_REFERENCE=SR-4821",
    "c366e00a4ac1b4df56d1e4e7bb94e1c10937f86cffde733424fb7c7dd5a444fc",
    "6bbe955cd020702da6b91ef0b484fd8a14bf6c0afaa265199882c25e486cda33",
    "eedeee1dedcac2a560ee6f950ad11e33",
    "contextIsolation",
    "nodeIntegration",
    "MaxUint256",
    "unlimited",
    "Sepolia",
    "sepolia",
    "11155111",
    "resolveState",
    "resolveStage",
    "resolveStatee",
    "resolveStates",
    "resolveStatus",
    "x8",
    "x9",
    "x7",
    "x1",
    "x11",
    "cipherFlag",
    "hidden owner",
    "powershell.exe",
    "exec bypass",
    "-exec bypass",
    "extraResources",
    "TrustSettle_1.0.0.exe",
    "Danger",
    "E9$LQ2@Mr7A!",
    "0x77b3774c",
    "0x0bfac020",
]
for a in answers:
    print(f"HTB{{{a}}}")
