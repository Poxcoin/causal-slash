const { ethers } = require('ethers');
const { spawn } = require('child_process');
const path = require('path');

const provider = new ethers.JsonRpcProvider('https://sepolia-rollup.arbitrum.io/rpc');
const ADDRESS = '0xEa2CdaEab16afFD49eD0715CD345fD7292D6c144';

async function waitAndDeploy() {
    console.log(`Watching for bridged ETH deposit on Arbitrum Sepolia (${ADDRESS})...`);
    while (true) {
        try {
            const balance = await provider.getBalance(ADDRESS);
            if (balance > 0n) {
                console.log(`\n========================================================`);
                console.log(`[DEPOSIT CONFIRMED] Balance: ${ethers.formatEther(balance)} ETH`);
                console.log(`Starting automated contract deployment...`);
                console.log(`========================================================\n`);

                const deployProcess = spawn('node', [path.resolve(__dirname, 'deploy_arbitrum_sepolia.js')], {
                    stdio: 'inherit'
                });

                deployProcess.on('close', (code) => {
                    process.exit(code);
                });
                break;
            } else {
                process.stdout.write('.');
            }
        } catch (e) {
            console.error('RPC check error:', e.message);
        }
        await new Promise((r) => setTimeout(r, 10000));
    }
}

waitAndDeploy();
