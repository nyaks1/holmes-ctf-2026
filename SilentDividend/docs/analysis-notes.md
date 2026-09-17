# SilentDividend (HTB Holmes CTF 2026 Sherlock 01)

Challenge id 75958. Flags 0/10. No listed questions — submit HTB{value}.

## Confirmed

- TrustSettle 1.0.0, NSIS→Electron, SHA256 c366e00a4ac1b4df56d1e4e7bb94e1c10937f86cffde733424fb7c7dd5a444fc
- Drop C:\Users\Public + hidden powershell luajit api.txt
- Sepolia RPC ethereum-sepolia-rpc.publicnode.com
- StateRegistry 0xbB63Ae28E4f75C9392bae69cDf5394Ca0ACdA6B1 (KeyVault.sol)
  resolveState key 0x3460743bb1ce2e6209e65e8ee3023f8414bc8416aef842b69c2a318bcef952f4
- Drainer x0 0x69Bf5b7aBA51C3Ee8bF169aB47479ba95DBF709D (wallet.sol)
- MockToken 0x6B2B0C0d0a376255Ac70Bf1366f50982bF476Bb2
- Hidden owner 0xebfc1ed96b1c6b940fb6b06359ff4a6776df7a9a
- x9(owner) → 51.5049,0.0348 (keccak XOR of cipherFlag)
- Decrypt cmd → AUTH=NAPOLEON SETTLEMENT_REFERENCE=SR-4821
- Wrong x9 string: not quite - keep analyzing
- Creator 0xc65a47bC149C655c5A114a8e76b231B6405Bd3a4
- Event APT: NAPOLEON
- Lua api.txt still obfuscated; do not execute on host

## Other

BottleOut = Sherlock 02 XMPP (no evidence zip). WhisperChain = Sherlock 03 (PDF only).
