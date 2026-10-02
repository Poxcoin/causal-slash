const fs = require('fs');
const path = require('path');
const { ethers } = require('ethers');

// Support loading .env from either project root or scripts folder
const envCandidates = [
    path.resolve(__dirname, '../.env'),
    path.resolve(__dirname, '.env')
];
for (const envPath of envCandidates) {
    if (fs.existsSync(envPath)) {
        require('dotenv').config({ path: envPath });
        break;
    }
}

const RPC_URL = process.env.ARBITRUM_SEPOLIA_RPC || 'https://sepolia-rollup.arbitrum.io/rpc';
const CHAIN_ID = 421614;

// Official Circle Arbitrum Sepolia native USDC address
const ARBITRUM_SEPOLIA_USDC = process.env.USDC_ADDRESS || '0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d';

async function main() {
    console.log('='.repeat(70));
    console.log('CAUSAL-SLASH: ARBITRUM SEPOLIA SWARM DELEGATION VAULT DEPLOYMENT');
    console.log('='.repeat(70));

    const provider = new ethers.JsonRpcProvider(RPC_URL);
    const network = await provider.getNetwork();
    console.log(`Connected to Network: Chain ID ${network.chainId} (Expected: ${CHAIN_ID})`);

    let privateKey = process.env.DEPLOYER_PRIVATE_KEY || process.env.PRIVATE_KEY;
    const walletFile = path.resolve(__dirname, '.deployer_wallet.json');

    let wallet;
    if (privateKey) {
        wallet = new ethers.Wallet(privateKey, provider);
        console.log(`Using configured private key from environment`);
    } else if (fs.existsSync(walletFile)) {
        const data = JSON.parse(fs.readFileSync(walletFile, 'utf8'));
        wallet = new ethers.Wallet(data.privateKey, provider);
        console.log(`Loaded existing testnet deployer wallet: ${wallet.address}`);
    } else {
        throw new Error('.deployer_wallet.json not found!');
    }

    console.log(`\nDeployer Address: ${wallet.address}`);
    const balance = await provider.getBalance(wallet.address);
    const ethBalance = ethers.formatEther(balance);
    console.log(`Arbitrum Sepolia ETH Balance: ${ethBalance} ETH`);

    if (balance === 0n) {
        throw new Error('Insufficient Arbitrum Sepolia ETH for deployment');
    }

    console.log('\nLoading SwarmDelegationVault.sol artifact...');
    const candidates = [
        path.resolve(__dirname, '../out/SwarmDelegationVault.sol/SwarmDelegationVault.json'),
        path.resolve(__dirname, '../out/SwarmDelegationVault.json')
    ];
    let compiled = null;
    for (const c of candidates) {
        if (fs.existsSync(c)) {
            const raw = JSON.parse(fs.readFileSync(c, 'utf8'));
            compiled = {
                abi: raw.abi,
                bytecode: raw.bytecode?.object || raw.bytecode
            };
            break;
        }
    }
    if (!compiled) {
        throw new Error("SwarmDelegationVault artifact not found. Please run 'forge build' first.");
    }

    const factory = new ethers.ContractFactory(compiled.abi, compiled.bytecode, wallet);

    const treasury = process.env.TREASURY_ADDRESS || wallet.address;
    const insuranceReserve = process.env.INSURANCE_RESERVE_ADDRESS || wallet.address;

    console.log(`Constructor Parameters:`);
    console.log(`  • USDC Token:        ${ARBITRUM_SEPOLIA_USDC}`);
    console.log(`  • Protocol Treasury: ${treasury}`);
    console.log(`  • Insurance Reserve: ${insuranceReserve}`);

    console.log(`\nSubmitting deployment transaction...`);
    const contract = await factory.deploy(ARBITRUM_SEPOLIA_USDC, treasury, insuranceReserve);
    const txHash = contract.deploymentTransaction().hash;
    console.log(`Transaction submitted! Hash: ${txHash}`);
    console.log('Waiting for confirmation on Arbitrum Sepolia...');

    await contract.waitForDeployment();
    const deployedAddress = await contract.getAddress();

    console.log('\n' + '='.repeat(70));
    console.log('[SUCCESS] SWARM DELEGATION VAULT DEPLOYED TO ARBITRUM SEPOLIA');
    console.log('='.repeat(70));
    console.log(`Contract Address: ${deployedAddress}`);
    console.log(`Arbiscan Explorer: https://sepolia.arbiscan.io/address/${deployedAddress}`);
    console.log(`Tx Explorer Link:  https://sepolia.arbiscan.io/tx/${txHash}`);

    // Verify on-chain getters
    console.log('\nVerifying on-chain state...');
    const onchainUSDC = await contract.usdc();
    const maxDepth = await contract.MAX_SWARM_TREE_DEPTH();
    const gracePeriod = await contract.ROOT_GRACE_PERIOD();
    const onchainTreasury = await contract.treasury();
    const onchainReserve = await contract.insuranceReserve();

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
        contractAddress: deployedAddress,
        deployer: wallet.address,
        txHash: txHash,
        usdcToken: ARBITRUM_SEPOLIA_USDC,
        treasury: treasury,
        insuranceReserve: insuranceReserve,
        maxSwarmTreeDepth: Number(maxDepth),
        rootGracePeriodSeconds: Number(gracePeriod),
        deployedAt: new Date().toISOString()
    };

    const receiptPath = path.resolve(__dirname, 'deployment_receipt_arbitrum_swarm.json');
    fs.writeFileSync(receiptPath, JSON.stringify(deploymentReceipt, null, 2));
    console.log(`\nSaved deployment receipt to ${receiptPath}`);

    const latestReceiptPath = path.resolve(__dirname, 'deployment_receipt_latest.json');
    fs.writeFileSync(latestReceiptPath, JSON.stringify(deploymentReceipt, null, 2));
    console.log(`Updated latest deployment receipt to ${latestReceiptPath}`);
}

main().catch((err) => {
    console.error('Fatal deployment error:', err);
    process.exit(1);
});
