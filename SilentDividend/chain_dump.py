"""Pull Sepolia contract data: code, storage, txs hints for key + drainer."""
import json
import urllib.request
from pathlib import Path

RPCS = [
    "https://ethereum-sepolia-rpc.publicnode.com",
    "https://rpc.sepolia.org",
    "https://1rpc.io/sepolia",
    "https://sepolia.drpc.org",
]

KEY_C = "0xbB63Ae28E4f75C9392bae69cDf5394Ca0ACdA6B1"
DRAIN_C = "0x69Bf5b7aBA51C3Ee8bF169aB47479ba95DBF709D"
TOKEN_C = "0x6B2B0C0d0a376255Ac70Bf1366f50982bF476Bb2"

def rpc(url, method, params):
    payload = json.dumps({"jsonrpc":"2.0","id":1,"method":method,"params":params}).encode()
    req = urllib.request.Request(
        url, data=payload,
        headers={"Content-Type":"application/json","User-Agent":"Mozilla/5.0"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=25) as r:
        return json.loads(r.read().decode())

def first_ok(method, params):
    last = None
    for url in RPCS:
        try:
            res = rpc(url, method, params)
            if "result" in res and res["result"] not in (None,):
                return res["result"], url
            last = res
        except Exception as e:
            last = str(e)
    raise RuntimeError(f"all failed {method}: {last}")

out_dir = Path(r"C:\src\projects\HackTheBox CTF Holme\SilentDividend\chain")
out_dir.mkdir(exist_ok=True)

for name, addr in [("key", KEY_C), ("drainer", DRAIN_C), ("token", TOKEN_C)]:
    print(f"\n=== {name} {addr} ===")
    try:
        code, url = first_ok("eth_getCode", [addr, "latest"])
        print("code len", (len(code)-2)//2 if isinstance(code,str) else code)
        (out_dir / f"{name}_code.hex").write_text(code)
        # decode bytecode printable
        raw = bytes.fromhex(code[2:]) if code.startswith("0x") and len(code)>2 else b""
        import re
        strs = re.findall(rb"[\x20-\x7e]{6,}", raw)
        print("printable in code:")
        for s in strs[:40]:
            print(" ", s.decode("latin-1")[:160])
    except Exception as e:
        print("getCode fail", e)

    try:
        bal, _ = first_ok("eth_getBalance", [addr, "latest"])
        print("balance wei", int(bal, 16))
    except Exception as e:
        print("bal fail", e)

    # storage slots 0..20
    for i in range(24):
        try:
            slot = "0x" + f"{i:064x}"
            val, _ = first_ok("eth_getStorageAt", [addr, slot, "latest"])
            if val and val != "0x" + "0"*64:
                print(f"storage[{i}] {val}")
                # try ascii
                try:
                    b = bytes.fromhex(val[2:])
                    s = b.decode("latin-1", errors="replace")
                    if any(32 <= c < 127 for c in s):
                        print("  ascii:", repr("".join(chr(c) if 32<=c<127 else "." for c in b)))
                except Exception:
                    pass
        except Exception as e:
            print(f"storage[{i}] fail {e}")
            break
