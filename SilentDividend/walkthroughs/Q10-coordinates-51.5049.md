# SilentDividend Q10 — Finding `51.5049,0.0348`

**Challenge:** Holmes CTF 2026 — Sherlock 01 / Silent Dividend  
**Question:** Analyze the HTML page to uncover a smart contract reference. Investigate the contract’s logic and determine how to interact with it to recover the hidden flag. (`**.****,*.****`)  
**Answer (confirmed):** `51.5049,0.0348`  
**Format:** bare lat/lon string — **no** `HTB{}`, **no** spaces around the comma

---

## What the question is asking

Two contracts in play:

| Contract | Role |
|----------|------|
| **StateRegistry** (`KeyVault.sol`) | Holds decrypt **keys** for the Electron payload (other questions) |
| **`x0` drainer** (`wallet.sol`) | Referenced from **HTML**; hides a **second** flag in contract storage/logic |

Q10 is about the **HTML → drainer contract** path. Format hint `**.****,*.****` is a **coordinate** (e.g. `51.5049,0.0348`).

---

## Attack path

### 1. Get the contract address from the HTML

**File:** `asar/src/settlement.html` (also in installer `src/settlement.html`)

```javascript
const X0_CONTRACT_ADDRESS = "0x69Bf5b7aBA51C3Ee8bF169aB47479ba95DBF709D";
const MOCK_TOKEN_ADDRESS  = "0x6B2B0C0d0a376255Ac70Bf1366f50982bF476Bb2";
```

Drainer = **`x0`** at `0x69Bf5b7aBA51C3Ee8bF169aB47479ba95DBF709D` (Sepolia).

### 2. Pull verified source (do not trust bytecode alone)

Sourcify / explorer Sepolia → `wallet.sol` → contracts `MockToken` and **`x0`**.

Important pieces of **`x0`**:

```solidity
bytes32 private x2 = 0x7ccb3a44…669b;
bytes32 private x3 = 0x7ccb3a44…1c01;
bytes private x4;   // cipherFlag stored via x8

function x7() public view returns (address) {
    return address(uint160(uint256(x2) ^ uint256(x3)));
}

function x8(bytes calldata cipherFlag) external {
    require(x4.length == 0, "already set");
    x4 = cipherFlag;
}

function x9(address x10) external view returns (string memory) {
    require(x10 == x7(), "not quite - keep analyzing");
    bytes memory decrypted = _crypt(x4, x10);
    return string(decrypted);
}

function _crypt(bytes memory data, address key) internal pure returns (bytes memory) {
    // XOR keystream: keccak256(abi.encodePacked(key, counter))
    ...
}
```

### 3. Recover the hidden owner (`x7`)

```text
x7 = address( uint160(x2) ^ uint160(x3) )
   = 0xebfc1ed96b1c6b940fb6b06359ff4a6776df7a9a
```

Confirmed on-chain via `eth_call` of `x7()`.

### 4. See what `x8` stored (`cipherFlag`)

Deployer tx called `x8` with **14 bytes** (also visible in storage slot 3):

```text
0x474274f44ceac3ee57f986608d94
```

That is **ciphertext**, not the flag.

### 5. Call `x9` with the hidden owner (this is the flag)

Only `x9(hiddenOwner)` succeeds; other addresses revert with  
`not quite - keep analyzing`.

```text
eth_call x0.x9(0xebfc1ed96b1c6b940fb6b06359ff4a6776df7a9a)
→ string 51.5049,0.0348
```

Example (conceptually):

```javascript
const { ethers } = require("ethers");
const provider = new ethers.JsonRpcProvider("https://ethereum-sepolia-rpc.publicnode.com");
const x0 = new ethers.Contract(
  "0x69Bf5b7aBA51C3Ee8bF169aB47479ba95DBF709D",
  ["function x7() view returns (address)",
   "function x9(address) view returns (string)"],
  provider
);
const owner = await x0.x7();
console.log(owner);                 // 0xebfc1ed9…7a9a
console.log(await x0.x9(owner));    // 51.5049,0.0348
```

`_crypt` = XOR cipherFlag with `keccak256(owner || counter)` blocks — same result as the view function.

### 6. Match the format hint

```text
**.****,*.****
51.5049,0.0348
```

Submit:

```text
51.5049,0.0348
```

---

## Team checklist

- [ ] Read drainer address from `settlement.html` (`X0_CONTRACT_ADDRESS`).
- [ ] Get **verified** `wallet.sol` (Sourcify).
- [ ] Compute/call **`x7()`** hidden owner.
- [ ] Note `x8` stored `cipherFlag` (14 bytes).
- [ ] **`x9(owner)`** on Sepolia → coordinates.
- [ ] Submit bare `51.5049,0.0348`.

---

## One-line brief

> HTML points at drainer `x0`; `x9(hiddenOwner)` decrypts on-chain `cipherFlag` to `51.5049,0.0348`.

---

*Confirmed flag. Read-only `eth_call` only.*
