'use strict';

// Live usage requires BASE_MAINNET_RPC, DEPLOYER_PRIVATE_KEY, TREASURY_ADDRESS and
// INSURANCE_RESERVE_ADDRESS. No wallet files, RPC fallbacks or address defaults.
// Offline usage: node scripts/deploy_base_mainnet.js --dry-run
const fs = require('fs');
const path = require('path');
const { ethers } = require('ethers');

const CHAIN_ID = 8453n;
// Circle native USDC (not bridged USDbC):
// https://developers.circle.com/stablecoins/usdc-contract-addresses
const USDC = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const CONTRACTS = ['SwarmDelegationVault', 'PerformanceCollateralVault'];
const CONFIRMATION = 'I_UNDERSTAND_REAL_ETH';

function address(value, label) {
    if (!value || !ethers.isAddress(value)) {
        throw new Error(`${label} must be a valid Ethereum address (with a valid checksum if mixed-case)`);
    }
    const result = ethers.getAddress(value);
    if (result === ethers.ZeroAddress) throw new Error(`${label} must not be the zero address`);
    return result;
}

function required(name) {
    const value = process.env[name];
    if (!value || !value.trim()) throw new Error(`Required environment variable: ${name}`);
    return value;
}

function bytecode(field, label) {
    const value = typeof field === 'string' ? field : field && field.object;
    // Require actual, nonempty, byte-aligned hex, rejecting unresolved libraries.
    if (typeof value !== 'string' || !/^0x(?:[0-9a-fA-F]{2})+$/.test(value)) {
        throw new Error(`${label} must be nonempty 0x-prefixed hex bytecode; run forge build`);
    }
    return value;
}

async function validateArtifacts(args) {
    const validated = [];
    for (const name of CONTRACTS) {
        const file = path.resolve(__dirname, `../out/${name}.sol/${name}.json`);
        const artifact = JSON.parse(fs.readFileSync(file, 'utf8'));
        if (!Array.isArray(artifact.abi)) throw new Error(`${name}: missing ABI`);
        const constructors = artifact.abi.filter((item) => item.type === 'constructor');
        if (constructors.length !== 1 || !Array.isArray(constructors[0].inputs)
            || constructors[0].inputs.length !== 3
            || constructors[0].inputs.some((input) => input.type !== 'address')) {
            throw new Error(`${name}: constructor must be exactly three addresses (USDC, treasury, insurance)`);
        }
        const creation = bytecode(artifact.bytecode, `${name} creation`);
        const runtime = bytecode(artifact.deployedBytecode, `${name} runtime`);
        const runtimeSize = ethers.dataLength(runtime);
        if (runtimeSize > 24576) throw new Error(`${name}: runtime ${runtimeSize} exceeds EIP-170 limit 24576`);
        const factory = new ethers.ContractFactory(artifact.abi, creation);
        const encoded = ethers.AbiCoder.defaultAbiCoder().encode(['address', 'address', 'address'], args);
        if (factory.interface.encodeDeploy(args) !== encoded || ethers.dataLength(encoded) !== 96) {
            throw new Error(`${name}: unexpected constructor encoding`);
        }
        const tx = await factory.getDeployTransaction(...args);
        if (tx.data.toLowerCase() !== ethers.concat([creation, encoded]).toLowerCase()) {
            throw new Error(`${name}: deployment data does not match bytecode and constructor encoding`);
        }
        console.log(`${name}: ABI validated; runtime ${runtimeSize}/24576 bytes; constructor 3 addresses / 96 bytes`);
        validated.push({ name, factory, runtimeSize });
    }
    return validated;
}

async function main() {
    const flags = process.argv.slice(2);
    if (flags.some((flag) => flag !== '--dry-run') || flags.length > 1) {
        throw new Error('Usage: node scripts/deploy_base_mainnet.js [--dry-run]');
    }
    const dryRun = flags.includes('--dry-run');
    // Fail closed before loading a signer or contacting any RPC.
    if (!dryRun && process.env.CONFIRM_MAINNET_DEPLOY !== CONFIRMATION) {
        throw new Error(`Broadcast refused: set CONFIRM_MAINNET_DEPLOY=${CONFIRMATION} to explicitly authorize real ETH deployment`);
    }
    if (address(USDC, 'Circle USDC') !== USDC) throw new Error('Circle USDC checksum mismatch');

    if (dryRun) {
        // ABI validation-only addresses, NEVER deployment defaults. This branch
        // deliberately ignores RPC/key/address environment and creates no signer.
        const validationOnlyTreasury = '0x0000000000000000000000000000000000000001';
        const validationOnlyInsurance = '0x0000000000000000000000000000000000000002';
        console.log('DRY RUN: offline ABI validation only; no RPC, signer, simulation or broadcast');
        console.log(`Target chain: ${CHAIN_ID}; Circle USDC: ${USDC}`);
        console.log(`ABI validation-only treasury: ${validationOnlyTreasury} (NOT a deployment default)`);
        console.log(`ABI validation-only insurance: ${validationOnlyInsurance} (NOT a deployment default)`);
        const contracts = await validateArtifacts([USDC, validationOnlyTreasury, validationOnlyInsurance]);
        console.log(JSON.stringify({
            mode: 'dry-run', chainId: Number(CHAIN_ID), usdc: USDC,
            broadcast: false, rpcUsed: false, signerCreated: false,
            recipients: { purpose: 'ABI validation only', treasury: validationOnlyTreasury, insuranceReserve: validationOnlyInsurance },
            contracts: contracts.map(({ name, runtimeSize }) => ({ name, deployedBytecodeBytes: runtimeSize, eip170Limit: 24576, constructorEncodingBytes: 96 })),
        }, null, 2));
        console.log('Offline validation passed. Live chain state, gas and recipient ownership were not checked.');
        return;
    }

    // All live configuration is mandatory, even before constructing a provider.
    const rpc = required('BASE_MAINNET_RPC');
    const key = required('DEPLOYER_PRIVATE_KEY');
    const treasury = address(required('TREASURY_ADDRESS'), 'TREASURY_ADDRESS');
    const insurance = address(required('INSURANCE_RESERVE_ADDRESS'), 'INSURANCE_RESERVE_ADDRESS');
    const url = new URL(rpc);
    if (!['https:', 'http:'].includes(url.protocol)) throw new Error('BASE_MAINNET_RPC must use HTTP(S)');
    const signer = new ethers.Wallet(key);
    if ((treasury === signer.address || insurance === signer.address)
        && process.env.ALLOW_EOA_TREASURY !== '1') {
        throw new Error('Treasury or insurance equals deployer wallet; use independent recipients or explicitly set ALLOW_EOA_TREASURY=1');
    }
    const args = [USDC, treasury, insurance];
    const contracts = await validateArtifacts(args);
    const provider = new ethers.JsonRpcProvider(rpc);
    try {
        const network = await provider.getNetwork();
        if (network.chainId !== CHAIN_ID) throw new Error(`Wrong chain: ${network.chainId}; expected ${CHAIN_ID}`);
        if (await provider.getCode(USDC) === '0x') throw new Error('Circle USDC has no code on the connected chain');
        const wallet = signer.connect(provider);
        if (await provider.getBalance(wallet.address) === 0n) throw new Error('Deployer has no ETH');
        console.log(`LIVE Base mainnet deployment: deployer ${wallet.address}, treasury ${treasury}, insurance ${insurance}`);
        for (const { name, factory } of contracts) {
            const contract = await factory.connect(wallet).deploy(...args);
            console.log(`${name} submitted: ${contract.deploymentTransaction().hash}`);
            await contract.waitForDeployment();
            const deployed = await contract.getAddress();
            if (await provider.getCode(deployed) === '0x') throw new Error(`${name}: no runtime code after deployment`);
            console.log(`${name} deployed: ${deployed}`);
        }
    } finally {
        provider.destroy();
    }
}

main().catch((error) => {
    console.error(`Deployment stopped: ${error.message}`);
    process.exitCode = 1;
});