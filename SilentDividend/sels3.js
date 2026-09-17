
const { ethers } = require("ethers");
const iface = new ethers.Interface([
  "function x1() view returns (address)",
  "function x7() view returns (address)",
  "function x8(bytes cipherFlag)",
  "function x9(address x10) view returns (string)",
  "function x11(address x12)",
]);
for (const f of ["x1","x7","x8","x9","x11"]) {
  console.log(f, iface.getFunction(f).selector, iface.getFunction(f).format());
}
console.log("encode x9", iface.encodeFunctionData("x9", ["0xebfc1ed96b1c6b940fb6b06359ff4a6776df7a9a"]));
