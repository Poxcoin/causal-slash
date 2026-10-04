// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

export const colors = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  italic: "\x1b[3m",
  underline: "\x1b[4m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
  white: "\x1b[37m",
  gray: "\x1b[90m",
  bgCyan: "\x1b[46m\x1b[30m",
  bgMagenta: "\x1b[45m\x1b[30m",
  bgGreen: "\x1b[42m\x1b[30m",
  bgBlue: "\x1b[44m\x1b[37m",
};

export function getTerminalWidth() {
  return process.stdout.columns || 80;
}

export function drawBox(lines, title = "", borderColor = colors.cyan) {
  const width = Math.min(getTerminalWidth() - 4, 88);
  const horizontal = "─";
  const topLeft = "╭";
  const topRight = "╮";
  const bottomLeft = "╰";
  const bottomRight = "╯";
  const vertical = "│";

  let header = topLeft + horizontal;
  if (title) {
    header += ` ${colors.bold}${title}${colors.reset}${borderColor} `;
  }
  const remainingHeader = width - (title ? title.length + 4 : 2);
  header += horizontal.repeat(Math.max(0, remainingHeader)) + topRight;

  console.log(`${borderColor}${header}${colors.reset}`);

  for (const line of lines) {
    const cleanLine = line.replace(/\x1b\[[0-9;]*m/g, "");
    const pad = Math.max(0, width - cleanLine.length - 2);
    console.log(`${borderColor}${vertical}${colors.reset} ${line}${" ".repeat(pad)} ${borderColor}${vertical}${colors.reset}`);
  }

  const footer = bottomLeft + horizontal.repeat(width) + bottomRight;
  console.log(`${borderColor}${footer}${colors.reset}`);
}

export function printWelcomeBanner(info) {
  const {
    version = "1.0.0",
    model = "qwen2.5-coder:14b",
    depositUsdc = 10.0,
    sessionHeight = 0,
    cwd = process.cwd(),
    address = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
    macActive = true,
  } = info;

  const lines = [
    `${colors.bold}${colors.white}CSLS Autonomous Terminal Coding Agent${colors.reset} ${colors.gray}v${version}${colors.reset}`,
    `${colors.gray}Protocol: Causal-Slash Sovereign M2M Settlement (Base L2)${colors.reset}`,
    "",
    `  ${colors.cyan}Collateral Vault:${colors.reset}    ${colors.green}$${depositUsdc.toFixed(6)} USDC${colors.reset} ${colors.gray}(Base L2 Contract)${colors.reset}`,
    `  ${colors.cyan}Agent Identity:${colors.reset}      ${colors.white}${address.slice(0, 10)}...${address.slice(-8)}${colors.reset}`,
    `  ${colors.cyan}Session Wire MAC:${colors.reset}    ${macActive ? colors.green + "Active [167-byte Session MAC]" : colors.yellow + "Initializing"}${colors.reset}`,
    `  ${colors.cyan}Active Model:${colors.reset}        ${colors.magenta}${model}${colors.reset} ${colors.gray}(Sovereign Inference / Zero Gas)${colors.reset}`,
    `  ${colors.cyan}Web2 Credentials:${colors.reset}    ${colors.bold}${colors.green}Strictly Banned (Zero API Keys / Zero KYC / Zero Cards)${colors.reset}`,
    `  ${colors.cyan}Workspace Directory:${colors.reset} ${colors.white}${cwd}${colors.reset}`,
    "",
    `${colors.gray}Type your request below. For available commands, type ${colors.cyan}/help${colors.gray}.${colors.reset}`,
  ];

  drawBox(lines, "CSLS PROTOCOL AGENT", colors.cyan);
  console.log("");
}

export function printToolInvocation(toolName, args) {
  const argStr = typeof args === "string" ? args : JSON.stringify(args, null, 2);
  console.log(`\n${colors.cyan}╭─ Tool Call: ${colors.bold}${toolName}${colors.reset}${colors.cyan} ─${"─".repeat(Math.max(0, getTerminalWidth() - toolName.length - 20))}╮${colors.reset}`);
  const lines = argStr.split("\n");
  for (const l of lines.slice(0, 20)) {
    console.log(`${colors.cyan}│${colors.reset}   ${colors.dim}${l}${colors.reset}`);
  }
  if (lines.length > 20) {
    console.log(`${colors.cyan}│${colors.reset}   ${colors.gray}... (${lines.length - 20} more lines)${colors.reset}`);
  }
  console.log(`${colors.cyan}╰${"─".repeat(Math.max(0, getTerminalWidth() - 4))}╯${colors.reset}`);
}

export function printToolResult(toolName, result, isError = false) {
  const color = isError ? colors.red : colors.green;
  const status = isError ? "ERROR" : "RESULT";
  console.log(`${color}╭─ Tool ${status}: ${toolName} ─${"─".repeat(Math.max(0, getTerminalWidth() - toolName.length - status.length - 18))}╮${colors.reset}`);
  const content = typeof result === "string" ? result : JSON.stringify(result, null, 2);
  const lines = content.split("\n");
  for (const l of lines.slice(0, 25)) {
    console.log(`${color}│${colors.reset}   ${l}`);
  }
  if (lines.length > 25) {
    console.log(`${color}│${colors.reset}   ${colors.gray}... (${lines.length - 25} lines truncated)${colors.reset}`);
  }
  console.log(`${color}╰${"─".repeat(Math.max(0, getTerminalWidth() - 4))}╯${colors.reset}\n`);
}

export function printSettlementNotice(settledUsdc, remainingDepositUsdc, height) {
  const text = `[CSLS Wire Settled: $${settledUsdc.toFixed(6)} USDC | Vault Balance: $${remainingDepositUsdc.toFixed(6)} USDC | Height: ${height} | Gas: 0]`;
  console.log(`${colors.gray}${text}${colors.reset}\n`);
}

export function printError(msg) {
  console.log(`${colors.red}${colors.bold}Error:${colors.reset} ${colors.red}${msg}${colors.reset}`);
}

export function printInfo(msg) {
  console.log(`${colors.cyan}${msg}${colors.reset}`);
}
