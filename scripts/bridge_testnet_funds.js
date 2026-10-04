const { ethers } = require("ethers");
const fs = require("fs");
const path = require("path");

const walletFile = path.resolve(__dirname, ".deployer_wallet.json");
const walletData = JSON.parse(fs.readFileSync(walletFile, "utf8"));

const SEPOLIA_RPC = "https://ethereum-sepolia-rpc.publicnode.com";
const BASE_PORTAL_ADDR = "0x49048044D57e1C92A77f79988d21Fa8fAF74E97e";
const ARB_INBOX_ADDR = "0xaAe29B0366299461418F5324a79Afc425BE5ae21";

const BASE_PORTAL_ABI = [
  "function depositTransaction(address _to, uint256 _value, uint64 _gasLimit, bool _isCreation, bytes memory _data) external payable"
];

const ARB_INBOX_ABI = [
  "function depositEth() external payable returns (uint256)"
];

async function main() {
  const provider = new ethers.JsonRpcProvider(SEPOLIA_RPC);
  const wallet = new ethers.Wallet(walletData.privateKey, provider);

  console.log("=".repeat(60));
  console.log("BRIDGING SEPOLIA ETH -> BASE SEPOLIA & ARBITRUM SEPOLIA");
  console.log("=".repeat(60));
  console.log("Wallet address:", wallet.address);

  const balance = await provider.getBalance(wallet.address);
  console.log("Ethereum Sepolia balance:", ethers.formatEther(balance), "ETH");

  if (balance < ethers.parseEther("0.05")) {
    console.error("Balance too low to bridge");
    return;
  }

  // 1. Bridge to Base Sepolia (0.06 ETH)
  const baseAmount = ethers.parseEther("0.06");
  console.log("\n[1/2] Bridging 0.06 ETH to Base Sepolia via OptimismPortal...");
  const basePortal = new ethers.Contract(BASE_PORTAL_ADDR, BASE_PORTAL_ABI, wallet);
  try {
    const tx1 = await basePortal.depositTransaction(
      wallet.address,
      baseAmount,
      100000,
      false,
      "0x",
      { value: baseAmount }
    );
    console.log("Base bridge tx submitted:", tx1.hash);
    const r1 = await tx1.wait();
    console.log("Base bridge tx confirmed in block:", r1.blockNumber);
  } catch (err) {
    console.error("Base bridge failed:", err.message);
  }

  // 2. Bridge to Arbitrum Sepolia (0.06 ETH)
  const arbAmount = ethers.parseEther("0.06");
  console.log("\n[2/2] Bridging 0.06 ETH to Arbitrum Sepolia via Inbox...");
  const arbInbox = new ethers.Contract(ARB_INBOX_ADDR, ARB_INBOX_ABI, wallet);
  try {
    const tx2 = await arbInbox.depositEth({ value: arbAmount });
    console.log("Arbitrum bridge tx submitted:", tx2.hash);
    const r2 = await tx2.wait();
    console.log("Arbitrum bridge tx confirmed in block:", r2.blockNumber);
  } catch (err) {
    console.error("Arbitrum bridge failed:", err.message);
  }

  console.log("\nBridging transactions broadcast! Funds will appear on L2 in ~1-2 minutes.");
}

main().catch(console.error);
