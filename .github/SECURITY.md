# Security Policy

## Supported Versions

We actively support and provide security patches for the following versions:

| Version | Supported   |
| ------- | ----------- |
| 0.3.x   | Supported   |
| < 0.3.0 | Unsupported |

## Reporting a Vulnerability

The Causal-Slash Protocol team takes security, fund safety, and cryptographic integrity extremely seriously.

If you believe you have discovered a vulnerability related to:
- Solvency or drain of `PerformanceCollateralVault` or `SwarmDelegationVault`
- EOTS equivocation evasion or fraudulent key recovery
- Buffer overflows, memory corruption, or race conditions in `csls_daemon.c`
- Cryptographic replay or signature forgery in `sdk/crypto.py`

Please **DO NOT** disclose the vulnerability publicly in an open GitHub issue.

### Disclosure Process
1. Email details of the vulnerability to **`security@causal-slash.org`**.
2. If possible, encrypt your message or include a minimal Foundry / Python proof-of-concept (PoC).
3. We will acknowledge receipt within 24 hours and provide an assessment and timeline for a patch.
4. Once remediated, a security advisory will be published and credit will be acknowledged.

### Bug Bounty Program
Qualified vulnerability disclosures affecting mainnet or testnet contracts are eligible for bounties based on severity according to the protocol bounty guidelines.
