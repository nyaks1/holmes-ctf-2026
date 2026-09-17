const { ethers } = require("ethers");
const cipher = Buffer.from("474274f44ceac3ee57f986608d94", "hex");
const key = "0xebfc1ed96b1c6b940fb6b06359ff4a6776df7a9a";
// abi.encodePacked(address, uint256 counter) = 20 + 32 bytes
function crypt(data, keyAddr) {
  const out = Buffer.alloc(data.length);
  let i = 0, counter = 0n;
  while (i < data.length) {
    const packed = ethers.concat([
      keyAddr,
      ethers.zeroPadValue(ethers.toBeHex(counter), 32),
    ]);
    const block = Buffer.from(ethers.keccak256(packed).slice(2), "hex");
    for (let j = 0; j < 32 && i < data.length; j++) {
      out[i] = data[i] ^ block[j];
      i++;
    }
    counter++;
  }
  return out;
}
const pt = crypt(cipher, key);
console.log("plain bytes", pt);
console.log("plain utf8", pt.toString("utf8"));
console.log("as flag", `HTB{${pt.toString("utf8")}}`);

// also try wrapping other confirmed secrets
const flags = [
  "NAPOLEON",
  "SR-4821",
  "51.5049,0.0348",
  "0xebfc1ed96b1c6b940fb6b06359ff4a6776df7a9a",
  "0x69Bf5b7aBA51C3Ee8bF169aB47479ba95DBF709D",
  "0xbB63Ae28E4f75C9392bae69cDf5394Ca0ACdA6B1",
  "0x6B2B0C0d0a376255Ac70Bf1366f50982bF476Bb2",
  "0x3460743bb1ce2e6209e65e8ee3023f8414bc8416aef842b69c2a318bcef952f4",
  "TrustSettle",
  "ethereum-sepolia-rpc.publicnode.com",
  "C:\\Users\\Public",
  "luajit.exe",
  "x0",
  "StateRegistry",
  "MockToken",
  "not quite - keep analyzing",
  "only hidden owner",
  "cipherFlag",
  "wallet.sol",
  "KeyVault.sol",
  "sepolia",
  "11155111",
  "0xc65a47bC149C655c5A114a8e76b231B6405Bd3a4",
  "AUTH=NAPOLEON",
  "SETTLEMENT_REFERENCE=SR-4821",
  "1.0.0",
];
for (const f of flags) console.log(`HTB{${f}}`);
