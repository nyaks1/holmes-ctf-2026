---
name: eth-contract-ctf-forensics
description: Smart-contract and crypto-malware CTF extraction for HTB/Holmes style challenges. Use when analyzing Ethereum/Sepolia contracts, drainers, token approvals, on-chain dead-drops, Electron wallet malware, or when a challenge mentions Solidity, etherscan, resolveState, cipherFlag, or malicious settlement clients. Produces IOC tables from verified source, view calls, storage, and decrypt pipelines. Do NOT use for non-chain forensics or to invent flag wraps.
---

# Ethereum contract CTF forensics

Extract every chain-backed secret **without** treating each secret as a flag.

## Steps

1. **Identify chain + addresses** from client code (preload/main/settlement HTML).
2. **Get verified source** (Sourcify, explorer). Prefer `sources/*.sol` over bytecode guessing.
3. **Map ABI:** every view function; call all of them (not just the one the malware uses).
4. **Storage + constructor args** — immutables live in code/ctor, not always slots.
5. **Reimplement crypto exactly** (e.g. XOR+ROL+magic; keccak keystream `abi.encodePacked(addr, counter)`).
6. **Tx input** for write functions that stored blobs (`cipherFlag` etc.).
7. **Record IOCs** with source: address, function, plaintext, algorithm.
8. **Submit gate:** follow `htb-ctf-forensics` — no invented `HTB{}` wraps.

## SilentDividend-style pipeline (example)

- Client decrypt key ← `StateRegistry.resolveState()`
- Hidden owner ← `x2 ^ x3` / `x7()`
- On-chain plaintext ← `x9(hiddenOwner)` after `x8(cipherFlag)`
- Client command decrypt ← key + fixed algo in preload
- Drainer UX ← separate contract + unlimited approve

## Tools

- `eth_call` via public RPC (User-Agent; try several RPCs)
- Sourcify `https://sourcify.dev/server/files/any/<chainId>/<address>`
- Node + ethers from the sample’s own `node_modules` when present

## Anti-patterns

- Only calling the function the malware calls
- Submitting every bytes32 / address as a flag
- Skipping verified Solidity when explorer shows “Verified”
