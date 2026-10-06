# Contributing to Causal-Slash Protocol

Thank you for contributing. We welcome bug reports, architectural improvements, and security disclosures.

## Prerequisites

- **Foundry** (`forge`, `anvil`) >= 0.2.0
- **GCC / Clang** supporting C11, OpenSSL, and POSIX threads (`-pthread -lcrypto`)
- **Python** >= 3.10 with `pip`

## Getting Started

1. Clone the repository with submodules:
   ```bash
   git clone --recurse-submodules https://github.com/causal-slash/causal-slash-protocol.git
   cd causal-slash-protocol
   ```

2. Install the Python SDK in editable development mode:
   ```bash
   pip install -e . && pip install pytest coincurve httpx
   ```

## Verification & Test Gates

Run all protocol test suites before submitting a pull request:

1. **EVM Smart Contracts (Fuzzing & Invariants):**
   ```bash
   forge test
   ```

2. **C11 Native Cryptographic Engine & AddressSanitizer:**
   ```bash
   make test
   make test-asan
   ```

3. **Python Native SDK & Multi-Agent Swarm Tests:**
   ```bash
   pytest tests/
   ```

## Code Guidelines

- **Zero Warnings:** All C11 code must compile cleanly under `-Wall -Wextra`.
- **Latency Gates:** Bloodhound interception latency must remain under 50 ns.
- **CI Gates:** All PRs must pass the GitHub Actions validation pipeline.
