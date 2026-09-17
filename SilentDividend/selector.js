
const { id } = require("ethers");
// ethers v6: id("resolveState()") is keccak of full string
// selector = first 4 bytes of keccak256
try {
  const { ethers } = require("ethers");
  const iface = new ethers.Interface(["function resolveState() view returns (bytes32)"]);
  console.log(iface.getFunction("resolveState").selector);
} catch (e) {
  // standalone
  const { id } = require("ethers");
  const h = id("resolveState()");
  console.log("0x" + h.slice(2, 10));
}
