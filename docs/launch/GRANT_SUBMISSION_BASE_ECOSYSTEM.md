# Base Ecosystem / Founders Fuel / Base Batches application draft

## Submission routing: human confirmation required

This is reusable application copy, not an assertion of program eligibility or
funding. The roadmap names Base Ecosystem, Founders Fuel, and Base Batches as
outreach routes. Confirm the exact current program, application window, legal
entity requirements, and funding instrument before submitting.

The official [Base Batches application page](https://www.base.org/batches/apply)
states Batch 004 applications are closed as checked on November 19, 2026.
Use this draft for a future confirmed intake or a permitted ecosystem referral,
not a claim that Batch 004 remains open. [Base Batches](https://www.base.org/batches)
is an accelerator offering investment, not an automatic grant.
[CDP Founders Fuel](https://coinbase.com/developer-platform/discover/launches/founders-fuel)
is Coinbase Developer Platform's selective infrastructure-credit, product-support,
and go-to-market program, not an interchangeable Base cash grant. Its published
criteria include a working product, CDP tool integration, and a public launch
plan within three months; confirm present intake and fit directly. No award,
acceptance, amount, or deadline is claimed for CSLS.

## Project and applicant

Project: Causal-Slash Protocol (CSLS, by KADO).
Website: https://kadoclub.net/
Repository: https://github.com/Poxcoin/causal-slash
Contact: desk@kadoclub.net (human submitter confirms ownership).
Focus: Base-first agent-native USDC clearing and settlement infrastructure.
Founder identity, legal entity, team background, and financing history must be
supplied accurately by the human applicant in the selected program's form.

## Problem and solution

Agents calling multiple paid services face fragmented prefunded balances and
bilateral billing integrations. CSLS provides isolated collateral accounts,
bounded authorization, signed 167-byte Session MAC usage cheques, in-memory
netting, and settlement of residual obligations on Base L2. The hot path does
not submit a transaction for every cheque. Contracts arbitrate collateral and
provable equivocation; the operator does not pool or custody user funds.

We request ecosystem engineering and distribution support for reproducible
AgentKit onboarding, testnet integrator activation, merchant reconciliation,
and the independent audit milestone. Scope and budget are to be agreed with
the selected program, not presented as an approved award.

## What exists today

- `@causal-slash/agentkit-action-provider`: TypeScript ActionProvider integration
  in [the repository](../../integrations/agentkit-causal-slash/README.md).
- `causal-slash-sdk` version `0.3.0` in [pyproject.toml](../../pyproject.toml):
  Python wallet, session bootstrap, cheque handling, and integration primitives.
- Go TUI `csls`: native terminal client with explicit collateral funding and
  configurable relay discovery.
- C11 clearing engine and Schnorr EOTS bloodhound: recorded `320 us` algebraic
  key extraction on conflicting signatures, not normal request latency.
- Local testnet sandbox meter: verifies authenticated cheques and returns
  labeled receipts; it is not a live inference provider or on-chain settler.

Source availability and version metadata do not establish registry publication
or production adoption. Publication is a separate human action in the
[runbook](HUMAN_PUBLISH_RUNBOOK.md).

## Base Sepolia deployments

Chain ID `84532`; test assets only:

| Contract | Address | Explorer source |
| --- | --- | --- |
| SwarmDelegationVault | `0x901c98Da847DD24ff23FcC37B6D1549A17F12253` | [Code](https://sepolia.basescan.org/address/0x901c98Da847DD24ff23FcC37B6D1549A17F12253#code) |
| PerformanceCollateralVault | `0x8faAD06ef5937Ad1019CD49f5Dcab36181e266A5` | [Code](https://sepolia.basescan.org/address/0x8faAD06ef5937Ad1019CD49f5Dcab36181e266A5#code) |
| MockUSDC | `0xa07eA15D1FE0B884Ffb51b19d98D938b2Bf04D6B` | [Code](https://sepolia.basescan.org/address/0xa07eA15D1FE0B884Ffb51b19d98D938b2Bf04D6B#code) |

Source: [README section 9](../../README.md#9-deployed--verified-contracts).
These deployments are testnet evidence, not Base mainnet volume.

## Verification and honest audit posture

Open-source, explorer-verified contracts have a recorded 82/82 Foundry ledger
covering unit/fuzz/invariant checks and the listed 12 Halmos SMT formal proof
cases. The 12 proofs are part of that recorded ledger, not an additional claim
of 94 Foundry tests. Running Foundry alone does not rerun the Halmos solver.
The repository also records at least 74 passing Pytest tests.

Recorded performance: C11 single-core >500k ops/s; TCP swarm 289,575 cheques/s;
Kirchhoff workload 99.9875% compression; Schnorr EOTS key extraction `320 us`.
These are local benchmark results, not production SLA or customer usage.

Evidence: [README sections 5-6](../../README.md#5-verified-empirical-benchmarks),
[benchmark claim ledger](../benchmarks.md), `make test`, `pytest -v`,
`forge test -vvv`, `tests/invariants/HalmosProtocolInvariants.t.sol`.
Retain the source revision and fresh output when submitting; these figures
were not remeasured while drafting this application.

Internal tests, formal proofs, and explorer source verification do not replace
a third-party review. The next pre-mainnet milestone is an independent external
smart-contract audit scoped to PerformanceCollateralVault and
SwarmDelegationVault, delegation quotas/root rotation, collateral and yield
accounting, settlement/replay protection, and commit-reveal slashing. Include
remediation, retesting, and a public report before approving mainnet deployment.
No completed third-party external audit is claimed.

## Milestones and success evidence

1. Reproduce Base Sepolia quickstart and explicit test-collateral funding;
   document AgentKit and Python integration failure cases.
2. Activate consented Cohort #001 teams through Connect/Apply -> Run Quickstart
   -> 10 Test Cheques -> Live Integration -> Submit Feedback. Activated requires
   the first four stages; identify testnet versus production explicitly.
3. Secure one merchant-authorized sandbox or capped-credit pilot with written
   endpoint scope, exposure cap, payout address, and reconciliation cadence.
   Zero omnibus user funds, zero unauthorized shared API keys, and zero founder
   personal-card financing. Target Base L2 USDC settlement after audit/mainnet
   gates; testnet receipts are not real merchant payments.
4. Complete the external audit, remediate findings, and make a separate human
   mainnet release decision. `scripts/deploy_base_mainnet.js` stays deferred
   until both pilot merchant and external audit requirements are satisfied.

## Cohort #001 and merchant evidence

| Application field | Verified evidence to insert |
| --- | --- |
| Cohort #001 connected / trial / activated team counts, deduplicated | [FILL AFTER COHORT #001 ACTIVATIONS] |
| Independent live integration links and permission to name teams | [FILL AFTER COHORT #001 ACTIVATIONS] |
| Base Sepolia deposit / delegation / settlement transaction hashes | [FILL AFTER COHORT #001 ACTIVATIONS] |
| Pilot merchant status, written authorization, sandbox or credit cap | [FILL AFTER COHORT #001 ACTIVATIONS] |

Cohort capacity is 25 teams; this is not an achieved team count. No merchant
partnership, revenue, mainnet settlement volume, or customer traction is
asserted. Complete mandatory application fields only from consented evidence;
leave optional unachieved milestones explicitly pending.
