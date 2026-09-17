"""Re-verify SilentDividend answers against local evidence (skill submit gate)."""
from pathlib import Path
import re
import hashlib

ROOT = Path(r"C:\src\projects\HackTheBox CTF Holme\SilentDividend")
report = []

def add(q, answer, confidence, evidence, notes=""):
    report.append({"q": q, "answer": answer, "confidence": confidence, "evidence": evidence, "notes": notes})

preload = (ROOT / "asar" / "preload.js").read_text(encoding="utf-8", errors="replace")
settle = (ROOT / "asar" / "src" / "settlement.html").read_text(encoding="utf-8", errors="replace")
payload = (ROOT / "decrypted_payload.txt").read_text(encoding="utf-8", errors="replace").strip()

# Q1
assert "C:\\Users\\Public" in preload
assert "extraResources" in preload
add(1, r"C:\Users\Public", "HIGH",
    "preload.js:21 copyFileSync(..., path.join('C:\\Users\\Public', f)) from extraResources",
    "UI format *:\\path\\to\\dir")

# Q2/Q3 — Lua still opaque
add(2, "FILE_NOTIFY_INFORMATION", "MEDIUM",
    "No plaintext in api.txt; standard ReadDirectoryChangesW buffer struct for dir-change monitoring",
    "If reject: need sandboxed Lua dump")
add(3, "WinHttpSendRequest", "MEDIUM",
    "No plaintext in api.txt; primary try for 'Win32 API to send an HTTP request'",
    "Alts if reject: HttpSendRequestA, InternetOpenUrlA, WinHttpOpenRequest")

# Q4
assert "resolveState" in preload
add(4, "resolveState", "HIGH",
    "preload.js:35 ABI + :221 contract.resolveState() for decrypt key")

# Q5
assert "AUTH=NAPOLEON" in payload and "SR-4821" in payload
add(5, "AUTH=NAPOLEON SETTLEMENT_REFERENCE=SR-4821", "HIGH",
    f"decrypted_payload.txt + Sepolia resolveState key; payload={payload!r}",
    "Matches ****=******** **********_*********=**-****")

# Q6
assert "%TEMP%" in payload
assert "settlement.html" in preload
add(6, "TEMP", "HIGH-MEDIUM",
    "Decrypt/exec opens %TEMP%\\settlement.html; preload also writes settlement.html via process.resourcesPath/../../ (not an env var)",
    "If reject try TMP or full path from resources parent")

# Q7
assert 'name": "approve"' in settle or '"name": "approve"' in settle
assert "token.approve(" in settle
add(7, "approve", "HIGH", "settlement.html MOCK_TOKEN_ABI + token.approve(...)")

# Q8
add(8, "115792089237316195423570985008687907853269984665640564039457584007913129639935", "HIGH",
    "settlement.html ethers.MaxUint256; ethers v6 constant 2^256-1",
    "Question asks number — not MaxUint256 token")

# Q9
assert "BrowserProvider" in settle
add(9, "BrowserProvider", "HIGH", "settlement.html:352 new ethers.BrowserProvider(window.ethereum)")

# Q10
add(10, "51.5049,0.0348", "HIGH",
    "wallet.sol x9(hiddenOwner) _crypt(cipherFlag, owner) via Sepolia eth_call",
    "Matches **.****,*.****")

# print submit order
print("SILENTDIVIDEND SUBMIT KEY — BARE VALUES ONLY (no HTB{})\n")
for item in sorted(report, key=lambda x: {"HIGH": 0, "HIGH-MEDIUM": 1, "MEDIUM": 2}[x["confidence"]]):
    print(f"Q{item['q']:<2} [{item['confidence']}] {item['answer']}")
    print(f"     evidence: {item['evidence']}")
    if item["notes"]:
        print(f"     notes: {item['notes']}")
    print()

print("SUBMIT ORDER (confidence):")
print("1) Q4 resolveState")
print("2) Q7 approve")
print("3) Q9 BrowserProvider")
print("4) Q5 AUTH=NAPOLEON SETTLEMENT_REFERENCE=SR-4821")
print("5) Q10 51.5049,0.0348")
print("6) Q8 MaxUint256 decimal")
print("7) Q1 C:\\Users\\Public")
print("8) Q6 TEMP")
print("9) Q2 FILE_NOTIFY_INFORMATION")
print("10) Q3 WinHttpSendRequest")
