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

    // Step 1: Deploy SwarmDelegationVault.sol
    console.log('\n--- Step 1: Deploying SwarmDelegationVault.sol on Arbitrum Sepolia ---');
    const swarmArtifactPath = path.resolve(__dirname, '../out/SwarmDelegationVault.sol/SwarmDelegationVault.json');
    if (!fs.existsSync(swarmArtifactPath)) {
        throw new Error("SwarmDelegationVault artifact not found. Please run 'forge build' first.");
    }
    const swarmRaw = JSON.parse(fs.readFileSync(swarmArtifactPath, 'utf8'));
    const swarmFactory = new ethers.ContractFactory(swarmRaw.abi, swarmRaw.bytecode?.object || swarmRaw.bytecode, wallet);
    const swarmContract = await swarmFactory.deploy(ARBITRUM_SEPOLIA_USDC, treasury, insuranceReserve);
    console.log(`Submitted SwarmDelegationVault tx: ${swarmContract.deploymentTransaction().hash}`);
    await swarmContract.waitForDeployment();
    const swarmAddress = await swarmContract.getAddress();
    console.log(`SwarmDelegationVault deployed at: ${swarmAddress}`);
    console.log(`Arbiscan Explorer: https://sepolia.arbiscan.io/address/${swarmAddress}`);

    // Step 2: Deploy PerformanceCollateralVault.sol
    console.log('\n--- Step 2: Deploying PerformanceCollateralVault.sol on Arbitrum Sepolia ---');
    const pcvArtifactPath = path.resolve(__dirname, '../out/PerformanceCollateralVault.sol/PerformanceCollateralVault.json');
    if (!fs.existsSync(pcvArtifactPath)) {
        throw new Error("PerformanceCollateralVault artifact not found. Please run 'forge build' first.");
    }
    const pcvRaw = JSON.parse(fs.readFileSync(pcvArtifactPath, 'utf8'));
    const pcvFactory = new ethers.ContractFactory(pcvRaw.abi, pcvRaw.bytecode?.object || pcvRaw.bytecode, wallet);
    const pcvContract = await pcvFactory.deploy(ARBITRUM_SEPOLIA_USDC, treasury, insuranceReserve);
    console.log(`Submitted PerformanceCollateralVault tx: ${pcvContract.deploymentTransaction().hash}`);
    await pcvContract.waitForDeployment();
    const pcvAddress = await pcvContract.getAddress();
    console.log(`PerformanceCollateralVault deployed at: ${pcvAddress}`);
    console.log(`Arbiscan Explorer: https://sepolia.arbiscan.io/address/${pcvAddress}`);

    console.log('\n' + '='.repeat(70));
    console.log('[SUCCESS] ALL CONTRACTS DEPLOYED TO ARBITRUM SEPOLIA');
    console.log('='.repeat(70));
    console.log(`SwarmDelegationVault:       ${swarmAddress}`);
    console.log(`PerformanceCollateralVault: ${pcvAddress}`);
}

main().catch((err) => {
    console.error('Fatal deployment error:', err);
    process.exit(1);
});
