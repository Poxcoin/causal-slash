const fs = require('fs');
const path = require('path');
const { ethers } = require('ethers');

const RPC_URL = process.env.ARBITRUM_SEPOLIA_RPC || 'https://arbitrum-sepolia-rpc.publicnode.com';
const CHAIN_ID = 421614;

// Deployed MockUSDC on Arbitrum Sepolia
const MOCK_USDC_ADDRESS = '0x8faAD06ef5937Ad1019CD49f5Dcab36181e266A5';

async function main() {
    console.log('='.repeat(70));
    console.log('DEPLOYING SwarmDelegationVault (paired with MockUSDC) TO ARBITRUM SEPOLIA');
    console.log('='.repeat(70));

    const provider = new ethers.JsonRpcProvider(RPC_URL);
    const network = await provider.getNetwork();
    console.log(`Connected to Network: Chain ID ${network.chainId} (Expected: ${CHAIN_ID})`);

    const walletFile = path.resolve(__dirname, '.deployer_wallet.json');
    const walletData = JSON.parse(fs.readFileSync(walletFile, 'utf8'));
    const wallet = new ethers.Wallet(walletData.privateKey, provider);

    console.log(`Deployer Wallet Address: ${wallet.address}`);
    const balance = await provider.getBalance(wallet.address);
    console.log(`Arbitrum Sepolia ETH Balance: ${ethers.formatEther(balance)} ETH`);

    // Verify MockUSDC
    console.log(`\nVerifying MockUSDC at ${MOCK_USDC_ADDRESS}...`);
    const mockArtifactPath = path.resolve(__dirname, '../out/MockUSDC.sol/MockUSDC.json');
    const mockRaw = JSON.parse(fs.readFileSync(mockArtifactPath, 'utf8'));
    const mockContract = new ethers.Contract(MOCK_USDC_ADDRESS, mockRaw.abi, wallet);
    const usdcBal = await mockContract.balanceOf(wallet.address);
    console.log(`  • MockUSDC Symbol:  ${await mockContract.symbol()}`);
    console.log(`  • MockUSDC Decimals: ${await mockContract.decimals()}`);
    console.log(`  • Deployer Balance:  ${Number(usdcBal) / 1e6} USDC`);

    // Load newly optimized SwarmDelegationVault artifact
    console.log('\nLoading optimized SwarmDelegationVault artifact...');
    const vaultArtifactPath = path.resolve(__dirname, '../out/SwarmDelegationVault.sol/SwarmDelegationVault.json');
    const vaultRaw = JSON.parse(fs.readFileSync(vaultArtifactPath, 'utf8'));
    const deployedBytecode = vaultRaw.deployedBytecode.object || vaultRaw.deployedBytecode;
    const sizeInBytes = deployedBytecode.length / 2;
    console.log(`  • SwarmDelegationVault Deployed Bytecode Size: ${sizeInBytes} bytes (Limit: 24576)`);
    if (sizeInBytes > 24576) {
        throw new Error(`Bytecode exceeds limit: ${sizeInBytes} > 24576`);
    }

    const vaultFactory = new ethers.ContractFactory(vaultRaw.abi, vaultRaw.bytecode.object || vaultRaw.bytecode, wallet);
    const treasury = wallet.address;
    const insuranceReserve = wallet.address;

    console.log('\nDeploying SwarmDelegationVault with parameters:');
    console.log(`  • USDC Token:        ${MOCK_USDC_ADDRESS}`);
    console.log(`  • Protocol Treasury: ${treasury}`);
    console.log(`  • Insurance Reserve: ${insuranceReserve}`);

    console.log('\nSubmitting deployment transaction...');
    const vaultContract = await vaultFactory.deploy(MOCK_USDC_ADDRESS, treasury, insuranceReserve);
    const vaultTxHash = vaultContract.deploymentTransaction().hash;
    console.log(`Transaction submitted! Hash: ${vaultTxHash}`);
    console.log('Waiting for confirmation on Arbitrum Sepolia...');

    await vaultContract.waitForDeployment();
    const vaultAddress = await vaultContract.getAddress();

    console.log('\n' + '='.repeat(70));
    console.log('[SUCCESS] SWARM DELEGATION VAULT DEPLOYED!');
    console.log('='.repeat(70));
    console.log(`Contract Address: ${vaultAddress}`);
    console.log(`Arbiscan Explorer: https://sepolia.arbiscan.io/address/${vaultAddress}`);
    console.log(`Tx Explorer Link:  https://sepolia.arbiscan.io/tx/${vaultTxHash}`);

    // Verify on-chain getters
    console.log('\nVerifying on-chain state...');
    const onchainUSDC = await vaultContract.usdc();
    const maxDepth = await vaultContract.MAX_SWARM_TREE_DEPTH();
    const gracePeriod = await vaultContract.ROOT_GRACE_PERIOD();
    const onchainTreasury = await vaultContract.treasury();
    const onchainReserve = await vaultContract.insuranceReserve();

    console.log(`  • onchain usdc:             ${onchainUSDC}`);
    console.log(`  • MAX_SWARM_TREE_DEPTH:     ${maxDepth.toString()}`);
    console.log(`  • ROOT_GRACE_PERIOD:        ${gracePeriod.toString()} seconds`);
    console.log(`  • treasury:                 ${onchainTreasury}`);
    console.log(`  • insuranceReserve:         ${onchainReserve}`);

    // Save deployed contract info
    const deploymentReceipt = {
        contractName: 'SwarmDelegationVault',
        network: 'Arbitrum Sepolia',
        chainId: CHAIN_ID,
        contractAddress: vaultAddress,
        deployer: wallet.address,
        txHash: vaultTxHash,
        usdcToken: MOCK_USDC_ADDRESS,
        treasury: treasury,
        insuranceReserve: insuranceReserve,
        maxSwarmTreeDepth: Number(maxDepth),
        rootGracePeriodSeconds: Number(gracePeriod),
        deployedAt: new Date().toISOString()
    };

    const receiptPaths = [
        path.resolve(__dirname, 'deployment_receipt_arbitrum_mock_swarm.json'),
        path.resolve(__dirname, 'deployment_receipt_latest.json'),
        '/home/minus/Рабочий стол/causal_term2_sdk/scripts/deployment_receipt_latest.json',
        '/home/minus/Рабочий стол/causal_term2_sdk/scripts/deployment_receipt_arbitrum_swarm.json'
    ];

    for (const p of receiptPaths) {
        fs.writeFileSync(p, JSON.stringify(deploymentReceipt, null, 2));
        console.log(`Saved deployment receipt to ${p}`);
    }

    console.log('\n' + '='.repeat(70));
    console.log('SWARM DELEGATION VAULT READY FOR USE');
    console.log('='.repeat(70));
}

main().catch(err => {
    console.error('Fatal deployment error:', err);
    process.exit(1);
});
