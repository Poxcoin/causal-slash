const fs = require('fs');
const path = require('path');
const { ethers } = require('ethers');

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

const RPC_URL = process.env.OP_SEPOLIA_RPC || 'https://sepolia.optimism.io';
const CHAIN_ID = 11155420;

// Official Circle OP Sepolia USDC address
const OP_SEPOLIA_USDC = process.env.OP_USDC_ADDRESS || '0x5fd84259d66Cd46123540766Be93DFE6D43130D7';

async function main() {
    console.log('='.repeat(70));
    console.log('CAUSAL-SLASH: OPTIMISM SEPOLIA DEPLOYMENT ENGINE');
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
        throw new Error('No private key found. Run deploy_arbitrum_sepolia.js first to generate wallet.');
    }

    console.log(`\nDeployer Address: ${wallet.address}`);
    const balance = await provider.getBalance(wallet.address);
    const ethBalance = ethers.formatEther(balance);
    console.log(`Optimism Sepolia ETH Balance: ${ethBalance} ETH`);

    if (balance === 0n) {
        console.log('\n' + '='.repeat(70));
        console.log('[WARN] INSUFFICIENT OP SEPOLIA ETH FOR DEPLOYMENT');
        console.log('='.repeat(70));
        console.log(`Please send testnet ETH to:`);
        console.log(`Address: ${wallet.address}\n`);
        console.log('Free Faucets:');
        console.log('1. https://app.optimism.io/faucet');
        console.log('2. https://faucets.chain.link/optimism-sepolia');
        console.log('3. https://www.alchemy.com/faucets/optimism-sepolia');
        console.log('\nAfter claiming ~0.005 testnet ETH, re-run this script!');
        return;
    }

    const candidates = [
        path.resolve(__dirname, '../out/PerformanceCollateralVault.sol/PerformanceCollateralVault.json'),
        path.resolve(__dirname, '../out/PerformanceCollateralVault.json')
    ];
    let compiled = null;
    for (const c of candidates) {
        if (fs.existsSync(c)) {
            const raw = JSON.parse(fs.readFileSync(c, 'utf8'));
            compiled = { abi: raw.abi, bytecode: raw.bytecode?.object || raw.bytecode };
            break;
        }
    }
    if (!compiled) throw new Error("Artifact not found. Run 'forge build' first.");

    const factory = new ethers.ContractFactory(compiled.abi, compiled.bytecode, wallet);
    const treasury = process.env.TREASURY_ADDRESS || wallet.address;
    const insuranceReserve = process.env.INSURANCE_RESERVE_ADDRESS || wallet.address;

    console.log(`\nDeploying PerformanceCollateralVault on Optimism Sepolia...`);
    console.log(`  • USDC Token:        ${OP_SEPOLIA_USDC}`);
    console.log(`  • Protocol Treasury: ${treasury}`);
    console.log(`  • Insurance Reserve: ${insuranceReserve}`);

    const contract = await factory.deploy(OP_SEPOLIA_USDC, treasury, insuranceReserve);
    console.log(`\nTx Hash: ${contract.deploymentTransaction().hash}`);
    console.log('Waiting for confirmation...');

    await contract.waitForDeployment();
    const deployedAddress = await contract.getAddress();

    console.log('\n' + '='.repeat(70));
    console.log('[SUCCESS] CONTRACT DEPLOYED TO OPTIMISM SEPOLIA');
    console.log('='.repeat(70));
    console.log(`Contract Address: ${deployedAddress}`);
    console.log(`Explorer: https://sepolia-optimism.etherscan.io/address/${deployedAddress}`);
    console.log(`Tx Link:  https://sepolia-optimism.etherscan.io/tx/${contract.deploymentTransaction().hash}`);

    const receipt = {
        network: 'Optimism Sepolia',
        chainId: CHAIN_ID,
        contractAddress: deployedAddress,
        deployer: wallet.address,
        txHash: contract.deploymentTransaction().hash,
        usdcToken: OP_SEPOLIA_USDC,
        treasury,
        insuranceReserve,
        deployedAt: new Date().toISOString()
    };

    const receiptPath = path.resolve(__dirname, 'deployment_receipt_optimism_sepolia.json');
    fs.writeFileSync(receiptPath, JSON.stringify(receipt, null, 2));
    console.log(`Saved receipt to scripts/deployment_receipt_optimism_sepolia.json`);
}

main().catch((err) => {
    console.error('Fatal deployment error:', err);
    process.exit(1);
});
