# Cohort #001 outreach playbook

## Scope and daily cadence

Recruit up to 25 developer and service-provider teams, not 25 claimed users.
Send 10 personalized outreaches per day: 7 builders and 3 merchants. These are
activity targets, not results. Follow channel rules, ask permission before DMs,
and use GitHub Discussions or an explicitly invited integration issue, not
unrelated issue threads. Replace bracketed recipient fields before sending.

Start with the [repository Quickstart](../../README.md#8-quickstart--verification-commands)
and [sandbox deployment guide](../../deploy/SANDBOX_DEPLOY.md). Intake:
https://kadoclub.net/ (confirm intake health before outreach).
The sandbox verifies cryptographic test cheques; it does not deliver inference,
transfer USDC, or prove a production merchant integration. The Python quickstart
is an independent in-process demonstration, not traffic to the sandbox.

## A. Coinbase AgentKit and Base builders

Use `@causal-slash/agentkit-action-provider`; source and integration instructions:
[integration README](../../integrations/agentkit-causal-slash/README.md).

| Channel | Copy, personalize, then send manually |
| --- | --- |
| X | Building an AgentKit agent on Base? CSLS Cohort #001 is inviting testnet integrators. Try @causal-slash/agentkit-action-provider with our cheque-meter sandbox; stream signed cheques off-chain, with residual settlement designed for Base. Interested in a quickstart? https://kadoclub.net/ |
| Discord | [Name], your [agent/tool] looks like a fit for a bounded payment-channel experiment. We have an AgentKit ActionProvider and a local testnet sandbox. Could we help you run the quickstart and verify 10 test cheques? No production funds or inference service implied. |
| Telegram | [Name], can I share a Base Sepolia integration quickstart for @causal-slash/agentkit-action-provider? Cohort #001 is looking for actionable developer feedback after 10 accepted test cheques. |
| GitHub | Subject: Opt-in AgentKit testnet integration. Your [repo/component] could try CSLS via @causal-slash/agentkit-action-provider. Proposed scope: sandbox setup, 10 verified cheques, then an integration branch and feedback. May we open a scoped PR after you review the integration README? |

Local sandbox: `python3 scripts/run_testnet_sandbox.py`. Go terminal:
`CSLS_PUBLIC_RELAYS=http://127.0.0.1:8402 csls`. Fund the Base Sepolia
collateral bond explicitly through `/deposit` instructions; no default funded bond.
Use the discovered vendor public key and initialize the session per integration
docs before sending cheques. Do not treat a local receipt as an on-chain payment.

## B. ElizaOS, CrewAI, MCP, and Python agent builders

Use `causal-slash-sdk` for Python-side integration, or
`@causal-slash/elizaos-plugin` for ElizaOS:
[plugin README](../../integrations/elizaos-plugin-causal-slash/README.md).
CrewAI and MCP are integration targets for a Python wrapper/tool, not a claim
that dedicated framework packages have been shipped.

| Channel | Copy, personalize, then send manually |
| --- | --- |
| X | ElizaOS / CrewAI / MCP / Python builders: want to test agent-native streaming cheques? CSLS Cohort #001 offers causal-slash-sdk and @causal-slash/elizaos-plugin source integrations. Start with the local quickstart, verify 10 test cheques, then share integration feedback. https://kadoclub.net/ |
| Discord | [Name], could we pair on a small [framework] tool around causal-slash-sdk, or register @causal-slash/elizaos-plugin in your ElizaOS runtime? First milestone is 10 accepted test cheques, not production service delivery. Happy to help with session bootstrap and monotonic counters. |
| Telegram | [Name], interested in a testnet-only CSLS integration for [agent]? Python SDK or ElizaOS plugin, a short quickstart, then 10 verifiable cheques. Could you share your runtime and one integration pain point? |
| GitHub | Subject: Optional streaming-cheque integration for [repo]. We can propose a minimal Python tool using causal-slash-sdk, or an ElizaOS plugin registration. Acceptance: authenticated session, 10 accepted cheques, reproducible integration instructions, and maintainer feedback. Is that in scope? |

Use a reviewed source checkout until the human publish runbook confirms registry
availability. Do not promise a registry release merely because packaging exists.

## C. Tier-1 API merchant candidates

Candidate list from the [merchant specification](../merchant/CSLS_MERCHANT_NETWORK_2026_SPECIFICATION.md#tier-1-high-speed-inference--ai-model-apis-cryptoweb3-open):
UsePod, DeepInfra, Novita AI, Together AI, Fireworks AI, Baseten, Crusoe, Groq,
Hyperbolic, Replicate, and fal.ai. Prioritize three relevant API teams daily.
These are outreach candidates, not signed partners; confirm each merchant's
commercial terms, permitted access, and settlement support directly.

Pilot terms: zero omnibus user funds, zero unauthorized shared API keys, zero
founder personal-card financing. Propose a merchant sandbox, merchant-funded
trial, or explicitly capped credit pilot with settlement in Base L2 USDC.
Specify the cap, endpoint scope, metering unit, payout address, reconciliation
cadence, and stop condition in writing. No client-held upstream credentials.
Begin on Base Sepolia with test assets; any real-value Base pilot remains gated
on the external audit and mainnet release decision. Do not promise immediate
mainnet settlement or advance founder funds to satisfy a merchant deposit.

| Channel | Copy, personalize, then send manually |
| --- | --- |
| X | [Merchant], does your API team support an agent-payment sandbox pilot? CSLS is testing signed usage cheques and batched Base L2 USDC settlement. Seeking a merchant sandbox or agreed capped credit, not a prepaid founder balance. Who owns developer partnerships? |
| Discord | [Name], could we scope a merchant-authorized pilot for [API]? Start with sandbox usage, agree a hard credit cap and reconciliation cadence, then validate signed usage receipts and the Base L2 USDC settlement path. No pooled user funds or unauthorized shared credentials. Production settlement is gated on external audit and mainnet approval. |
| Telegram | [Name], may we send a one-page capped-credit sandbox proposal for [API]? Merchant supplies approved test capacity; agents use bounded cheque authorization. No founder personal-card financing. Could your team confirm commercial authorization and a settlement contact? |
| GitHub | Subject: Request for an authorized API sandbox integration. We propose a small merchant-approved adapter, authenticated usage receipts, a written exposure cap, and Base L2 USDC reconciliation design. We do not assume resale permission. Is there a partnerships channel where we can agree sandbox capacity and terms before implementation? |

## Activation funnel and evidence

Match the [roadmap](../roadmap.md#42-activation-funnel):

1. Connect/Apply: record consent, team identity, stack, and intake receipt.
2. Run Quickstart: retain reproducible command/output and environment details.
3. 10 Test Cheques: record 10 accepted authenticated cheques with monotonic
   heights; keep receipts and distinguish local meter results from chain events.
4. Live Integration: independently runnable agent/API integration with a team
   owner, repository/PR, and observed usage. State testnet or production explicitly.
5. Submit Feedback: capture issue, failure case, and next action with permission.

Mark a team Activated only after stages 1-4, as the roadmap requires. Stage 5
is still tracked. Deduplicate teams; consented outreach and trials alone are
not activations. Use transaction hashes only for actual chain submissions.

## Daily tracker

One row per day; targets are fixed, actuals remain blank until observed.
Store private contact details outside the public repository.

| Date | Builder target | Merchant target | Builder actual | Merchant actual | Connect/Apply | Run Quickstart | 10 Test Cheques | Live Integration | Submit Feedback | Evidence / next action |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| [YYYY-MM-DD] | 7 | 3 | | | | | | | | |

Maintain a consented per-team evidence register behind these daily counts.
Do not sum funnel columns as unique teams or report targets as achieved traction.
