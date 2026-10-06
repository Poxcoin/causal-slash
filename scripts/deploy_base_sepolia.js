const fs = require('fs');
const path = require('path');
const { ethers } = require('ethers');

const RPC_URL = process.env.BASE_SEPOLIA_RPC || 'https://sepolia.base.org';
const CHAIN_ID = 84532;

async function main() {
    console.log('='.repeat(70));
    console.log('CAUSAL-SLASH: BASE SEPOLIA FULL DEPLOYMENT');
    console.log('='.repeat(70));

    const provider = new ethers.JsonRpcProvider(RPC_URL);
    const network = await provider.getNetwork();
    console.log(`Connected to Chain ID ${network.chainId} (Expected: ${CHAIN_ID})`);

    const walletFile = path.resolve(__dirname, '.deployer_wallet.json');
    if (!fs.existsSync(walletFile)) {
        throw new Error('.deployer_wallet.json not found');
    }
    const walletData = JSON.parse(fs.readFileSync(walletFile, 'utf8'));
    const wallet = new ethers.Wallet(walletData.privateKey, provider);

    console.log(`Deployer Wallet: ${wallet.address}`);
    const balance = await provider.getBalance(wallet.address);
    console.log(`Base Sepolia ETH Balance: ${ethers.formatEther(balance)} ETH`);

    if (balance === 0n) {
        console.log('[WARN] Balance is 0 ETH. Waiting for bridge deposit or faucet transfer...');
        return;
    }

    // 1. Deploy MockUSDC
    console.log('\n--- Step 1: Deploying MockUSDC ---');
    const mockArtifactPath = path.resolve(__dirname, '../out/MockUSDC.sol/MockUSDC.json');
    const mockRaw = JSON.parse(fs.readFileSync(mockArtifactPath, 'utf8'));
    const mockFactory = new ethers.ContractFactory(mockRaw.abi, mockRaw.bytecode.object || mockRaw.bytecode, wallet);
    
    const mockContract = await mockFactory.deploy();
    console.log(`Submitted MockUSDC tx: ${mockContract.deploymentTransaction().hash}`);
    await mockContract.waitForDeployment();
    const mockAddress = await mockContract.getAddress();
    console.log(`MockUSDC deployed at: ${mockAddress}`);
    console.log(`Basescan Link: https://sepolia.basescan.org/address/${mockAddress}`);

    // 2. Deploy SwarmDelegationVault
    console.log('\n--- Step 2: Deploying SwarmDelegationVault ---');
    const swarmArtifactPath = path.resolve(__dirname, '../out/SwarmDelegationVault.sol/SwarmDelegationVault.json');
    const swarmRaw = JSON.parse(fs.readFileSync(swarmArtifactPath, 'utf8'));
    const swarmBytecode = swarmRaw.deployedBytecode.object || swarmRaw.deployedBytecode;
    const swarmSize = swarmBytecode.length / 2;
    console.log(`SwarmDelegationVault deployed size: ${swarmSize} bytes (limit 24576)`);
    if (swarmSize > 24576) {
        throw new Error(`SwarmDelegationVault exceeds EIP-170 size limit: ${swarmSize}`);
    }

    const swarmFactory = new ethers.ContractFactory(swarmRaw.abi, swarmRaw.bytecode.object || swarmRaw.bytecode, wallet);
    const treasury = wallet.address;
    const insuranceReserve = wallet.address;

    const swarmContract = await swarmFactory.deploy(mockAddress, treasury, insuranceReserve);
    console.log(`Submitted SwarmDelegationVault tx: ${swarmContract.deploymentTransaction().hash}`);
    await swarmContract.waitForDeployment();
    const swarmAddress = await swarmContract.getAddress();
    console.log(`SwarmDelegationVault deployed at: ${swarmAddress}`);
    console.log(`Basescan Link: https://sepolia.basescan.org/address/${swarmAddress}`);

    // 3. Deploy PerformanceCollateralVault (standalone single-agent vault)
    console.log('\n--- Step 3: Deploying PerformanceCollateralVault ---');
    const pcvArtifactPath = path.resolve(__dirname, '../out/PerformanceCollateralVault.sol/PerformanceCollateralVault.json');
    const pcvRaw = JSON.parse(fs.readFileSync(pcvArtifactPath, 'utf8'));
    const pcvBytecode = pcvRaw.deployedBytecode.object || pcvRaw.deployedBytecode;
    const pcvSize = pcvBytecode.length / 2;
    console.log(`PerformanceCollateralVault deployed size: ${pcvSize} bytes (limit 24576)`);

    const pcvFactory = new ethers.ContractFactory(pcvRaw.abi, pcvRaw.bytecode.object || pcvRaw.bytecode, wallet);
    const pcvContract = await pcvFactory.deploy(mockAddress, treasury, insuranceReserve);
    console.log(`Submitted PerformanceCollateralVault tx: ${pcvContract.deploymentTransaction().hash}`);
    await pcvContract.waitForDeployment();
    const pcvAddress = await pcvContract.getAddress();
    console.log(`PerformanceCollateralVault deployed at: ${pcvAddress}`);
    console.log(`Basescan Link: https://sepolia.basescan.org/address/${pcvAddress}`);

    // Receipt
    const receipt = {
        network: 'Base Sepolia',
        chainId: CHAIN_ID,
        deployer: wallet.address,
        mockUSDC: mockAddress,
        swarmDelegationVault: swarmAddress,
        performanceCollateralVault: pcvAddress,
        treasury: treasury,
        insuranceReserve: insuranceReserve,
        txHashes: {
            mockUSDC: mockContract.deploymentTransaction().hash,
            swarmDelegationVault: swarmContract.deploymentTransaction().hash,
            performanceCollateralVault: pcvContract.deploymentTransaction().hash
        },
        deployedAt: new Date().toISOString()
    };

    fs.writeFileSync(path.resolve(__dirname, 'deployment_receipt_base_sepolia.json'), JSON.stringify(receipt, null, 2));
    console.log('\n' + '='.repeat(70));
    console.log('[SUCCESS] ALL CONTRACTS DEPLOYED TO BASE SEPOLIA');
    console.log('='.repeat(70));
    console.log(JSON.stringify(receipt, null, 2));
}

main().catch((err) => {
    console.error('Fatal deployment error:', err);
    process.exit(1);
});
