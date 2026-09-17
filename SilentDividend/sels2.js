
const { ethers } = require("ethers");
const iface = new ethers.Interface([
  "function resolveStage() view returns (bytes32)",
  "function resolveState() view returns (bytes32)",
  "function resolveStatee() view returns (bytes32)",
  "function resolveStates() view returns (bytes32)",
  "function resolveStatus() view returns (bytes32)",
]);
for (const f of ["resolveStage","resolveState","resolveStatee","resolveStates","resolveStatus"]) {
  console.log(f, iface.getFunction(f).selector);
}
