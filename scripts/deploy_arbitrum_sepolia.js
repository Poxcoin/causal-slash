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
    console.log('CAUSAL-SLASH: ARBITRUM SEPOLIA DEPLOYMENT ENGINE');
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
        wallet = ethers.Wallet.createRandom(provider);
        fs.writeFileSync(walletFile, JSON.stringify({
            address: wallet.address,
            privateKey: wallet.privateKey,
            createdAt: new Date().toISOString()
        }, null, 2));
        console.log(`[INFO] Generated new testnet deployer wallet: ${wallet.address}`);
        console.log(`Saved credentials to .deployer_wallet.json (keep this file safe and gitignored)`);
    }

    console.log(`\nDeployer Address: ${wallet.address}`);
    const balance = await provider.getBalance(wallet.address);
    const ethBalance = ethers.formatEther(balance);
    console.log(`Arbitrum Sepolia ETH Balance: ${ethBalance} ETH`);

    if (balance === 0n) {
        console.log('\n' + '='.repeat(70));
        console.log('[WARN] INSUFFICIENT ARBITRUM SEPOLIA ETH FOR DEPLOYMENT');
        console.log('='.repeat(70));
        console.log(`Please send testnet Arbitrum Sepolia ETH to deployer address:`);
        console.log(`Address: ${wallet.address}\n`);
        console.log('Free Faucets:');
        console.log('1. https://faucet.triangleplatform.com/arbitrum/sepolia');
        console.log('2. https://arbitrum.faucet.dev/');
        console.log('3. https://faucets.chain.link/arbitrum-sepolia');
        console.log('4. Bridge Sepolia ETH via https://bridge.arbitrum.io/');
        console.log('\nAfter claiming ~0.005 testnet ETH, re-run this script to deploy!');
        return;
    }

    console.log('\nDeploying PerformanceCollateralVault.sol on Arbitrum Sepolia...');
    const candidates = [
        path.resolve(__dirname, '../out/PerformanceCollateralVault.sol/PerformanceCollateralVault.json'),
        path.resolve(__dirname, '../out/PerformanceCollateralVault.json')
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
        throw new Error("PerformanceCollateralVault artifact not found. Please run 'forge build' first.");
    }

    const factory = new ethers.ContractFactory(compiled.abi, compiled.bytecode, wallet);

    // Constructor parameters:
    // _usdcToken: Arbitrum Sepolia USDC (0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d)
    // _treasury: protocol treasury / deployer
    // _insuranceReserve: bad-debt buffer reserve / deployer
    const treasury = process.env.TREASURY_ADDRESS || wallet.address;
    const insuranceReserve = process.env.INSURANCE_RESERVE_ADDRESS || wallet.address;

    console.log(`Constructor Parameters:`);
    console.log(`  • USDC Token:        ${ARBITRUM_SEPOLIA_USDC}`);
    console.log(`  • Protocol Treasury: ${treasury}`);
    console.log(`  • Insurance Reserve: ${insuranceReserve}`);

    const contract = await factory.deploy(ARBITRUM_SEPOLIA_USDC, treasury, insuranceReserve);
    console.log(`\nTransaction submitted! Hash: ${contract.deploymentTransaction().hash}`);
    console.log('Waiting for confirmation on Arbitrum Sepolia...');

    await contract.waitForDeployment();
    const deployedAddress = await contract.getAddress();

    console.log('\n' + '='.repeat(70));
    console.log('[SUCCESS] CONTRACT DEPLOYED TO ARBITRUM SEPOLIA');
    console.log('='.repeat(70));
    console.log(`Contract Address: ${deployedAddress}`);
    console.log(`Arbiscan Explorer: https://sepolia.arbiscan.io/address/${deployedAddress}`);
    console.log(`Tx Explorer Link:  https://sepolia.arbiscan.io/tx/${contract.deploymentTransaction().hash}`);

    // Save deployed contract info
    const deploymentReceipt = {
        network: 'Arbitrum Sepolia',
        chainId: CHAIN_ID,
        contractAddress: deployedAddress,
        deployer: wallet.address,
        txHash: contract.deploymentTransaction().hash,
        usdcToken: ARBITRUM_SEPOLIA_USDC,
        treasury: treasury,
        insuranceReserve: insuranceReserve,
        deployedAt: new Date().toISOString()
    };

    const receiptPath = path.resolve(__dirname, 'deployment_receipt_arbitrum_sepolia.json');
    fs.writeFileSync(receiptPath, JSON.stringify(deploymentReceipt, null, 2));
    console.log(`Saved deployment receipt to scripts/deployment_receipt_arbitrum_sepolia.json`);
}

main().catch((err) => {
    console.error('Fatal deployment error:', err);
    process.exit(1);
});
