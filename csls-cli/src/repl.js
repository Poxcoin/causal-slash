// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

import readline from "node:readline";
import { colors, printInfo, printError } from "./ui.js";

export function startRepl(agent, wallet) {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: `${colors.bold}${colors.cyan}csls${colors.reset} > `,
  });

  const lineQueue = [];
  let isProcessing = false;

  async function processQueue() {
    if (isProcessing || lineQueue.length === 0) return;
    isProcessing = true;
    const input = lineQueue.shift();

    if (input.startsWith("/")) {
      const [cmd, ...args] = input.split(" ");
      handleSlashCommand(cmd, args, agent, wallet, rl);
      isProcessing = false;
      if (lineQueue.length > 0) {
        processQueue();
      } else {
        rl.prompt();
        checkExitOnEof();
      }
      return;
    }

    try {
      await agent.runTurn(input, (token) => {
        process.stdout.write(token);
      });
    } catch (err) {
      printError(err.message || String(err));
    } finally {
      isProcessing = false;
      if (lineQueue.length > 0) {
        processQueue();
      } else {
        rl.prompt();
        checkExitOnEof();
      }
    }
  }

  let eofReceived = false;

  function checkExitOnEof() {
    if (eofReceived && !isProcessing && lineQueue.length === 0) {
      console.log(`\n${colors.gray}Exiting CSLS Agent session. Session wire cheques committed.${colors.reset}`);
      process.exit(0);
    }
  }

  rl.prompt();

  rl.on("line", (line) => {
    const input = line.trim();
    if (!input) {
      if (!isProcessing) rl.prompt();
      return;
    }
    lineQueue.push(input);
    processQueue();
  });

  rl.on("close", () => {
    eofReceived = true;
    checkExitOnEof();
  });
}

function handleSlashCommand(cmd, args, agent, wallet, rl) {
  switch (cmd.toLowerCase()) {
    case "/help":
      console.log(`\n${colors.bold}Available CSLS Commands:${colors.reset}`);
      console.log(`  ${colors.cyan}/balance${colors.reset}           View on-chain Base L2 collateral vault balance and cleared cheques`);
      console.log(`  ${colors.cyan}/deposit <amt>${colors.reset}     Deposit additional USDC into the on-chain collateral vault`);
      console.log(`  ${colors.cyan}/clear${colors.reset}             Reset current conversation history and start fresh turn`);
      console.log(`  ${colors.cyan}/model [name]${colors.reset}     View or switch active sovereign model`);
      console.log(`  ${colors.cyan}/history${colors.reset}           Inspect total message turns in active session`);
      console.log(`  ${colors.cyan}/exit, /quit${colors.reset}       Exit the CSLS interactive session\n`);
      break;

    case "/balance": {
      const bal = wallet.getBalance();
      console.log(`\n${colors.bold}CSLS Collateral Vault Status (Base L2):${colors.reset}`);
      console.log(`  Vault Collateral:   ${colors.green}$${bal.vaultDepositUsdc.toFixed(6)} USDC${colors.reset}`);
      console.log(`  Accumulated Cost:   ${colors.yellow}$${bal.accumulatedSettledUsdc.toFixed(6)} USDC${colors.reset}`);
      console.log(`  Cheques Issued:     ${colors.white}${bal.sessionHeight}${colors.reset}`);
      console.log(`  Settlement Mode:    ${colors.cyan}167-byte Session MAC (0 Gas)${colors.reset}`);
      console.log(`  Off-chain Wallet:   ${colors.gray}${bal.address}${colors.reset}\n`);
      break;
    }

    case "/deposit": {
      const amt = parseFloat(args[0]);
      if (isNaN(amt) || amt <= 0) {
        printError("Usage: /deposit <amount_in_usdc>");
        return;
      }
      const newBal = wallet.deposit(amt);
      console.log(`\n${colors.green}Successfully deposited $${amt.toFixed(2)} USDC to Base L2 Collateral Vault.${colors.reset}`);
      console.log(`New Vault Balance: ${colors.bold}$${newBal.toFixed(6)} USDC${colors.reset}\n`);
      break;
    }

    case "/clear":
      agent.clearHistory();
      console.log(`\n${colors.cyan}Session context cleared. System prompt re-initialized.${colors.reset}\n`);
      break;

    case "/model": {
      if (args[0]) {
        agent.model = args[0];
        agent.client.model = args[0];
        console.log(`\n${colors.green}Switched active model to: ${colors.bold}${args[0]}${colors.reset}\n`);
      } else {
        console.log(`\nActive model: ${colors.bold}${agent.model}${colors.reset}\n`);
      }
      break;
    }

    case "/history":
      console.log(`\nActive session message count: ${colors.bold}${agent.history.length}${colors.reset}\n`);
      break;

    case "/exit":
    case "/quit":
      rl.close();
      break;

    default:
      printError(`Unknown command: ${cmd}. Type /help for available commands.`);
      break;
  }
}
