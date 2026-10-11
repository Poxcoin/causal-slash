const fs = require('fs');
const path = require('path');
const { ethers } = require('ethers');

const RPC_URL = process.env.ARBITRUM_SEPOLIA_RPC || 'https://arbitrum-sepolia-rpc.publicnode.com';
const CHAIN_ID = 421614;

const MOCK_USDC_ADDRESS = '0x8faAD06ef5937Ad1019CD49f5Dcab36181e266A5';
const VAULT_ADDRESS = '0x7ff2D6B943e23d5A31772482417FB67c2ED0b8b6';

async function main() {
    console.log('='.repeat(70));
    console.log('CAUSAL-SLASH PROTOCOL: LIVE ON-CHAIN ARBITRUM SEPOLIA VERIFICATION');
    console.log('='.repeat(70));

    const provider = new ethers.JsonRpcProvider(RPC_URL);
    const network = await provider.getNetwork();
    console.log(`Connected to Arbitrum Sepolia (Chain ID: ${network.chainId})`);

    const walletFile = path.resolve(__dirname, '.deployer_wallet.json');
    const walletData = JSON.parse(fs.readFileSync(walletFile, 'utf8'));
    const deployer = new ethers.Wallet(walletData.privateKey, provider);

    console.log(`Deployer Address: ${deployer.address}`);
    const ethBalance = await provider.getBalance(deployer.address);
    console.log(`ETH Balance:      ${ethers.formatEther(ethBalance)} ETH`);

    // Load ABIs
    const mockArtifact = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../out/MockUSDC.sol/MockUSDC.json'), 'utf8'));
    const vaultArtifact = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../out/SwarmDelegationVault.sol/SwarmDelegationVault.json'), 'utf8'));

    const usdc = new ethers.Contract(MOCK_USDC_ADDRESS, mockArtifact.abi, deployer);
    const vault = new ethers.Contract(VAULT_ADDRESS, vaultArtifact.abi, deployer);

    const initialUSDC = await usdc.balanceOf(deployer.address);
    console.log(`Initial USDC Balance: ${Number(initialUSDC) / 1e6} USDC`);

    // Create a designated Vendor wallet to receive streaming settlement
    const vendor = ethers.Wallet.createRandom().connect(provider);
    console.log(`\nGenerated Test Vendor Address: ${vendor.address}`);

    // Create an ephemeral Swarm Sub-Agent
    const subAgent = ethers.Wallet.createRandom();
    console.log(`Generated Ephemeral Sub-Agent Address: ${subAgent.address}`);

    // STEP 1 & 2: Check or Deposit Collateral Bond
    const depositAmount = ethers.parseUnits('5000', 6); // 5,000 USDC
    const [existingBond] = await vault.vaults(deployer.address);
    console.log(`Current Vault Bond on-chain: ${ethers.formatUnits(existingBond, 6)} USDC`);

    if (existingBond < depositAmount) {
        console.log(`\n[STEP 1] Approving ${ethers.formatUnits(depositAmount, 6)} USDC to SwarmDelegationVault...`);
        const approveTx = await usdc.approve(VAULT_ADDRESS, depositAmount);
        await approveTx.wait();
        console.log('Approve Confirmed!');

        console.log(`\n[STEP 2] Depositing ${ethers.formatUnits(depositAmount, 6)} USDC collateral bond into Vault...`);
        const depositTx = await vault.depositCollateral(depositAmount, ethers.ZeroHash, deployer.address);
        const depositReceipt = await depositTx.wait();
        console.log(`Deposit Confirmed in block ${depositReceipt.blockNumber}! Gas Used: ${depositReceipt.gasUsed.toString()}`);
    } else {
        console.log(`[STEPS 1 & 2] Vault already funded with ${ethers.formatUnits(existingBond, 6)} USDC bond.`);
    }

    // STEP 3: Register Swarm Merkle Root (2-leaf tree matching contracts)
    const subAgent2 = ethers.Wallet.createRandom();
    const leaf0 = ethers.solidityPackedKeccak256(['address'], [subAgent.address]);
    const leaf1 = ethers.solidityPackedKeccak256(['address'], [subAgent2.address]);

    let root, proof;
    if (BigInt(leaf0) <= BigInt(leaf1)) {
        root = ethers.solidityPackedKeccak256(['bytes32', 'bytes32'], [leaf0, leaf1]);
        proof = [leaf1];
    } else {
        root = ethers.solidityPackedKeccak256(['bytes32', 'bytes32'], [leaf1, leaf0]);
        proof = [leaf1];
    }

    console.log(`\n[STEP 3] Registering Sub-Agent delegation root: ${root}`);
    const setRootTx = await vault.setDelegationRoot(root, 1);
    console.log(`SetDelegationRoot Tx Submitted: ${setRootTx.hash}`);
    const setRootReceipt = await setRootTx.wait();
    console.log(`SetDelegationRoot Confirmed in block ${setRootReceipt.blockNumber}!`);

    // Verify root on-chain
    const onchainRoot = await vault.swarmMerkleRoots(deployer.address);
    console.log(`  • On-Chain Swarm Root: ${onchainRoot}`);
    const isRootValid = await vault.isRootValid(deployer.address, root);
    console.log(`  • Is Root Valid:        ${isRootValid}`);

    // Fund vendor with 0.001 ETH for gas
    console.log(`\nFunding vendor with 0.001 ETH for gas...`);
    const fundTx = await deployer.sendTransaction({
        to: vendor.address,
        value: ethers.parseEther('0.001')
    });
    console.log(`Fund Vendor Tx Submitted: ${fundTx.hash}`);
    await fundTx.wait();
    console.log(`Vendor funded with 0.001 ETH!`);

    // STEP 4: Sub-Agent issues EIP-712 Swarm Cheque
    console.log('\n[STEP 4] Sub-Agent signing EIP-712 Swarm Cheque...');
    const settleAmount = ethers.parseUnits('250', 6); // 250 USDC
    const channelHeight = 1;

    const domain = {
        name: 'CausalSlashVault',
        version: '2.0',
        chainId: CHAIN_ID,
        verifyingContract: VAULT_ADDRESS
    };

    const types = {
        SwarmCheque: [
            { name: 'agent', type: 'address' },
            { name: 'vendor', type: 'address' },
            { name: 'channelHeight', type: 'uint64' },
            { name: 'cumulativeAmount', type: 'uint64' }
        ]
    };

    const value = {
        agent: deployer.address,
        vendor: vendor.address,
        channelHeight: channelHeight,
        cumulativeAmount: settleAmount
    };

    const signature = await subAgent.signTypedData(domain, types, value);
    console.log(`Sub-Agent Signature: ${signature}`);

    // STEP 5: Vendor settles Swarm Cheque on Arbitrum Sepolia
    console.log(`\n[STEP 5] Vendor settling Swarm Cheque on-chain (vendor=${vendor.address}, amount=250 USDC)...`);
    const vaultAsVendor = vault.connect(vendor);
    const settleTx = await vaultAsVendor.settleSwarmCheque(
        deployer.address,
        channelHeight,
        settleAmount,
        proof,
        signature
    );
    console.log(`SettleSwarmCheque Tx Submitted: ${settleTx.hash}`);
    const settleReceipt = await settleTx.wait();
    console.log(`SettleSwarmCheque Confirmed in block ${settleReceipt.blockNumber}! Gas Used: ${settleReceipt.gasUsed.toString()}`);

    // STEP 6: Verify Vendor Balance
    const vendorBal = await usdc.balanceOf(vendor.address);
    console.log(`\n[STEP 6] Verification:`);
    console.log(`  • Vendor Received USDC Balance: ${ethers.formatUnits(vendorBal, 6)} USDC (Expected: 250.0)`);

    const [finalBond] = await vault.vaults(deployer.address);
    console.log(`  • Remaining Vault Bond:        ${ethers.formatUnits(finalBond, 6)} USDC (Expected: 4750.0)`);

    console.log('\n' + '='.repeat(70));
    console.log('LIVE ON-CHAIN ARBITRUM SEPOLIA SETTLEMENT SUCCEEDED 100%!');
    console.log('='.repeat(70));
    console.log(`1. Root Update:   https://sepolia.arbiscan.io/tx/${setRootTx.hash}`);
    console.log(`2. Settlement Tx: https://sepolia.arbiscan.io/tx/${settleTx.hash}`);
    console.log(`3. Vault Contract: https://sepolia.arbiscan.io/address/${VAULT_ADDRESS}`);
    console.log(`4. MockUSDC:      https://sepolia.arbiscan.io/address/${MOCK_USDC_ADDRESS}`);
    console.log(`5. Vendor Wallet: https://sepolia.arbiscan.io/address/${vendor.address}`);
    console.log('='.repeat(70));
}

main().catch(err => {
    console.error('Verification failed with error:', err);
    process.exit(1);
});
