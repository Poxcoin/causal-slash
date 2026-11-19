# Arbitrum ArbiFuel application draft: CSLS

## Applicant and project

Project: Causal-Slash Protocol (CSLS, by KADO).
Website: https://kadoclub.net/
Repository: https://github.com/Poxcoin/causal-slash
Contact: desk@kadoclub.net (human submitter confirms ownership before submission).
Category: agent-native payments, non-custodial clearing, developer infrastructure.

CSLS lets agents exchange signed 167-byte Session MAC cheques off-chain, net
reciprocal obligations in memory, and settle net residuals through L2 vaults.
Agent collateral stays in isolated vault accounts; operators do not pool user
funds. Arbitrum Sepolia is the deployed test environment for this application.
We are not claiming an Arbitrum mainnet launch, funded sponsorship, or existing
merchant revenue.

## Why ArbiFuel

We request gas sponsorship for bounded agent/merchant onboarding on Arbitrum:
`deposit` (the `depositCollateral` vault operation), `setDelegationRoot`, and
batch settlement. These are proposed sponsored transaction paths, not a claim
that a paymaster is already integrated. Off-chain cheques themselves consume no
chain gas; sponsorship addresses the remaining onboarding and settlement UX.
It does not fund collateral principal, merchant usage, or founder expenses.

Implementation plan: select a program-supported smart-account/paymaster path,
restrict sponsorship by chain, target contract, selector, per-team budget and
expiry, simulate transactions, and record receipts and actual sponsored gas.
Confirm program eligibility, supported networks, coverage, and available budget
with the Foundation before deployment; Sepolia evidence is not mainnet usage.
No grant amount or acceptance is asserted.

Program reference: [Arbitrum Foundation ArbiFuel announcement](https://blog.arbitrum.foundation/arbifuel-is-live-arbitrum-builders-claim-your-gas-fee-sponsorship).
Its gas-sponsorship purpose is the basis of this proposal; current application
terms must be rechecked by the human submitter.

## Deployed and source-verified testnet contracts

Arbitrum Sepolia, chain ID `421614`:

| Contract | Address | Explorer source |
| --- | --- | --- |
| SwarmDelegationVault | `0x45Cd2B0d1319C158a5B37B74DcBE3D78C9861f1F` | [Code](https://sepolia.arbiscan.io/address/0x45Cd2B0d1319C158a5B37B74DcBE3D78C9861f1F#code) |
| PerformanceCollateralVault | `0xfEaA1F897FF4540d7B43010A80912FCEcCd95A9a` | [Code](https://sepolia.arbiscan.io/address/0xfEaA1F897FF4540d7B43010A80912FCEcCd95A9a#code) |
| MockUSDC | `0x8faAD06ef5937Ad1019CD49f5Dcab36181e266A5` | [Code](https://sepolia.arbiscan.io/address/0x8faAD06ef5937Ad1019CD49f5Dcab36181e266A5#code) |

Addresses and verification status follow [README section 9](../../README.md#9-deployed--verified-contracts).
MockUSDC is a test asset, not evidence of real settlement volume. Source
verification is not an independent security audit.

## Verified repository test and benchmark ledger

These are recorded repository results, not new measurements performed while
preparing this application. Preserve the evidence revision and rerun before
submission; do not translate synthetic benchmarks into live adoption claims.

| Evidence | Recorded result | Reproduction / source |
| --- | --- | --- |
| Foundry ledger | 82/82, including the 12 Halmos SMT proof cases listed in the verification matrix | `forge test -vvv`; [README section 6](../../README.md#6-on-chain-verification--test-matrix), `tests/invariants/HalmosProtocolInvariants.t.sol` |
| Python SDK ledger | At least 74 passing Pytest tests | `pytest -v`; README section 6 |
| C11 single-core engine | >500k ops/s | `make test`; README section 6 |
| TCP swarm benchmark | 289,575 cheques/s | `benchmarks/stress_tcp_swarm.c`; [README section 5](../../README.md#5-verified-empirical-benchmarks) |
| Kirchhoff benchmark | 99.9875% compression | `benchmarks/run_kirchhoff_netting.py`; README section 5 |

Foundry execution alone is not a fresh SMT solver proof run; the 12 formal
proofs are the recorded Halmos result. Unit/fuzz/invariant tests and formal
proofs are internal verification, not a third-party audit. An independent
external smart-contract audit remains a pre-mainnet milestone. Performance
figures are workload- and hardware-dependent, not service guarantees.

## Deliverables and measurement

1. Reproduce Arbitrum Sepolia collateral onboarding and delegation-root updates;
   retain chain ID, contract address, receipt status, and transaction hash.
2. Implement and test selector-allowlisted sponsorship for onboarding and batch
   settlement, subject to ArbiFuel approval and supported infrastructure.
3. Onboard consented Cohort #001 teams via Connect/Apply -> Run Quickstart ->
   10 Test Cheques -> Live Integration -> Submit Feedback. Count Activated only
   after the first four stages; label testnet integrations explicitly.
4. Report unique activated teams, reproducible integration links, sponsored
   transactions and gas, failures, and feedback. Never count local meter events
   as on-chain settlement or synthetic obligations as merchant revenue.

## Cohort #001 evidence fields

| Required application field | Evidence to insert |
| --- | --- |
| Live Cohort #001 team count | [FILL AFTER COHORT #001 ACTIVATIONS] |
| Independent integration repository / PR / demo links | [FILL AFTER COHORT #001 ACTIVATIONS] |
| Arbitrum onboarding, delegation and batch-settlement transaction hashes | [FILL AFTER COHORT #001 ACTIVATIONS] |

These fields are deliberately unfilled. Cohort capacity is 25 teams, not
achieved traction. Obtain permission to name teams and validate each hash on
chain `421614`. The human submitter completes mandatory evidence fields before
submitting; omit unachieved milestones rather than inventing results.
