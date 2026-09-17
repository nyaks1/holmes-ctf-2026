"""Call drainer x0 view functions and decode storage as strings."""
import json
import urllib.request

DRAIN = "0x69Bf5b7aBA51C3Ee8bF169aB47479ba95DBF709D"
TOKEN = "0x6B2B0C0d0a376255Ac70Bf1366f50982bF476Bb2"
CREATOR = "0xc65a47bC149C655c5A114a8e76b231B6405Bd3a4"
RPC = "https://ethereum-sepolia-rpc.publicnode.com"

def rpc(method, params):
    payload = json.dumps({"jsonrpc":"2.0","id":1,"method":method,"params":params}).encode()
    req = urllib.request.Request(RPC, data=payload, headers={"Content-Type":"application/json","User-Agent":"Mozilla/5.0"}, method="POST")
    with urllib.request.urlopen(req, timeout=25) as r:
        return json.loads(r.read().decode())

def sel(sig_bytes4):
    return sig_bytes4

# x1() MockToken -> 0x0bfac020?
# x7() owner -> 0x282940a7
# x9(address) -> 0xf8e6e11f
# From jump table in bytecode:
# 0bfac020, 282940a7, 343943bd, 8f7f391e, f8e6e11f

calls = [
    ("x1 token", "0x0bfac020"),
    ("x7 owner", "0x282940a7"),
    ("x9 creator", "0xf8e6e11f" + creator[2:].lower().zfill(64) if False else "0xf8e6e11f" + "0"*24 + creator[2:].lower()),
    ("x9 token", "0xf8e6e11f" + "0"*24 + TOKEN[2:].lower()),
    ("x9 drain", "0xf8e6e11f" + "0"*24 + DRAIN[2:].lower()),
    ("x9 zero", "0xf8e6e11f" + "0"*64),
]

for name, data in calls:
    try:
        res = rpc("eth_call", [{"to": DRAIN, "data": data}, "latest"])
        val = res.get("result", "")
        print(f"\n{name}: {val[:200]}")
        if val and val.startswith("0x") and len(val) > 2:
            raw = bytes.fromhex(val[2:])
            # ABI string: offset, length, data
            if len(raw) >= 64:
                # try decode as abi string
                try:
                    # standard: 32 byte offset, 32 byte length, data
                    off = int.from_bytes(raw[0:32], "big")
                    if off == 32 and len(raw) >= 64:
                        ln = int.from_bytes(raw[32:64], "big")
                        s = raw[64:64+ln]
                        print("  abi string:", s)
                    elif len(raw) == 32:
                        print("  word ascii:", "".join(chr(c) if 32<=c<127 else "." for c in raw))
                        print("  word hex:", raw.hex())
                    else:
                        print("  raw ascii:", "".join(chr(c) if 32<=c<127 else "." for c in raw[:200]))
                except Exception as e:
                    print("  decode err", e)
            else:
                print("  short", raw)
    except Exception as e:
        print(name, "ERR", e)

# also token name/symbol via common selectors
# name() 0x06fdde03, symbol() 0x95d89b41, decimals() 0x313ce567
print("\n=== token ERC20 ===")
for name, data in [("name", "0x06fdde03"), ("symbol", "0x95d89b41"), ("decimals", "0x313ce567"), ("totalSupply", "0x18160ddd")]:
    try:
        res = rpc("eth_call", [{"to": TOKEN, "data": data}, "latest"])
        val = res.get("result", "")
        print(name, val[:120])
        if val.startswith("0x") and len(val) > 66:
            raw = bytes.fromhex(val[2:])
            if len(raw) >= 64:
                off = int.from_bytes(raw[0:32], "big")
                if off == 32:
                    ln = int.from_bytes(raw[32:64], "big")
                    print("  ", raw[64:64+ln])
                else:
                    print("  ascii", "".join(chr(c) if 32<=c<127 else "." for c in raw))
        elif val.startswith("0x") and len(val) == 66:
            print("  int", int(val, 16))
    except Exception as e:
        print(name, e)

# storage more slots for drainer
print("\n=== more storage ===")
for i in range(0, 30):
    slot = "0x" + f"{i:064x}"
    res = rpc("eth_getStorageAt", [DRAIN, slot, "latest"])
    val = res.get("result")
    if val and val != "0x" + "0"*64:
        b = bytes.fromhex(val[2:])
        ascii_s = "".join(chr(c) if 32<=c<127 else "." for c in b)
        print(f"[{i}] {val}")
        print(f"     {ascii_s}")
        # solidity short string
        length_flag = b[-1]
        if length_flag % 2 == 0 and 0 < length_flag <= 62:
            slen = length_flag // 2
            print(f"     shortstring({slen}): {b[:slen]!r}")
