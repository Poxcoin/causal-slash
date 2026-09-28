const fs = require('fs');
const path = require('path');
const { ethers } = require('ethers');
require('dotenv').config({ path: path.resolve(__dirname, '.env') });

const RPC_URL = process.env.BASE_SEPOLIA_RPC || 'https://sepolia.base.org';
const CHAIN_ID = 84532;

// Official Circle Base Sepolia USDC address
const BASE_SEPOLIA_USDC = process.env.USDC_ADDRESS || '0x036CbD53842c5426634e7929541eC2318f3dCF7e';

async function main() {
    console.log('='.repeat(70));
    console.log('CAUSAL-SLASH: BASE SEPOLIA DEPLOYMENT ENGINE');
    console.log('='.repeat(70));

    const provider = new ethers.JsonRpcProvider(RPC_URL);
    const network = await provider.getNetwork();
    console.log(`Connected to Network: Chain ID ${network.chainId} (Expected: ${CHAIN_ID})`);

    let privateKey = process.env.DEPLOYER_PRIVATE_KEY;
    const walletFile = path.resolve(__dirname, '.deployer_wallet.json');

    let wallet;
    if (privateKey) {
        wallet = new ethers.Wallet(privateKey, provider);
        console.log(`Using configured private key from .env`);
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
        console.log(`Saved credentials to .deployer_wallet.json (ignored by git)`);
    }

    console.log(`\nDeployer Address: ${wallet.address}`);
    const balance = await provider.getBalance(wallet.address);
    const ethBalance = ethers.formatEther(balance);
    console.log(`Base Sepolia ETH Balance: ${ethBalance} ETH`);

    if (balance === 0n) {
        console.log('\n' + '='.repeat(70));
        console.log('[WARN] INSUFFICIENT TESTNET FUNDS FOR DEPLOYMENT');
        console.log('='.repeat(70));
        console.log(`Please send free testnet Base Sepolia ETH to deployer address:`);
        console.log(`Address: ${wallet.address}\n`);
        console.log('Free Faucets:');
        console.log('1. https://faucets.chain.link/base-sepolia');
        console.log('2. https://superchain.fyi/faucet (select Base Sepolia)');
        console.log('3. https://www.alchemy.com/faucets/base-sepolia');
        console.log('4. https://learnweb3.io/faucets/base_sepolia');
        console.log('\nAfter claiming ~0.01 testnet ETH, re-run this script to deploy!');
        return;
    }

    console.log('\nDeploying PerformanceCollateralVault.sol...');
    const candidates = [
        path.resolve(__dirname, '../out/PerformanceCollateralVault.sol/PerformanceCollateralVault.json'),
        path.resolve(__dirname, '../.internal/deploy/PerformanceCollateralVault.json'),
        path.resolve(__dirname, 'PerformanceCollateralVault.json')
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
    // _usdcToken: Base Sepolia USDC (0x036CbD53842c5426634e7929541eC2318f3dCF7e)
    // _treasury: deployer address (for protocol revenue)
    // _insuranceReserve: deployer address (for bad debt reserve)
    const treasury = wallet.address;
    const insuranceReserve = wallet.address;

    console.log(`Constructor Args:`);
    console.log(`  • USDC Token:        ${BASE_SEPOLIA_USDC}`);
    console.log(`  • Protocol Treasury: ${treasury}`);
    console.log(`  • Insurance Reserve: ${insuranceReserve}`);

    const contract = await factory.deploy(BASE_SEPOLIA_USDC, treasury, insuranceReserve);
    console.log(`\nTransaction submitted! Hash: ${contract.deploymentTransaction().hash}`);
    console.log('Waiting for confirmation on Base Sepolia...');

    await contract.waitForDeployment();
    const deployedAddress = await contract.getAddress();

    console.log('\n' + '='.repeat(70));
    console.log('[SUCCESS] CONTRACT DEPLOYED TO BASE SEPOLIA');
    console.log('='.repeat(70));
    console.log(`Contract Address: ${deployedAddress}`);
    console.log(`Basescan Link:    https://sepolia.basescan.org/address/${deployedAddress}`);
    console.log(`Tx Explorer Link: https://sepolia.basescan.org/tx/${contract.deploymentTransaction().hash}`);

    // Save deployed contract info
    const deploymentReceipt = {
        network: 'Base Sepolia',
        chainId: CHAIN_ID,
        contractAddress: deployedAddress,
        deployer: wallet.address,
        txHash: contract.deploymentTransaction().hash,
        usdcToken: BASE_SEPOLIA_USDC,
        deployedAt: new Date().toISOString()
    };

    fs.writeFileSync(path.resolve(__dirname, 'deployment_receipt.json'), JSON.stringify(deploymentReceipt, null, 2));
    console.log(`Saved deployment receipt to deployment_receipt.json`);
}

main().catch((err) => {
    console.error('Fatal deployment error:', err);
    process.exit(1);
});
