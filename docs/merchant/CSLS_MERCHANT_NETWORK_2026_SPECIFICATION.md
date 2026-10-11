# CSLS MERCHANT NETWORK & AGENTIC CLEARING SPECIFICATION (2026)
## Canonical Multi-Tier Merchant Architecture & Channel Strategy

---

## 1. Executive Summary & Strategic Rationale

### The Core Problem: Direct Frontier Access Barrier
1. **Direct Access Impossibility:** Tier-1 AI Frontier Labs (Anthropic, OpenAI, Google) do NOT grant direct enterprise API agreements or wholesale credit lines to unverified early-stage decentralized crypto protocols.
   - Traditional Tier-1 labs mandate corporate US/EU legal entities, extensive KYC/AML compliance, strict фиат-only billing (US bank wire commitments of $10,000–$50,000/month), and explicitly forbid raw crypto-settlement layers without commercial partner certification.
2. **The Crypto-Friendly Merchant Strategy:**
   - Instead of futile attempts to obtain direct enterprise billing from Anthropic/OpenAI, CSLS routes settlement through **Crypto-Friendly Merchants, Aggregators, and Authorized Channel Partners**.
   - These merchants already hold active enterprise tiers with OpenAI/Anthropic/Google, accept cryptocurrency/stablecoins (USDC/USDT), or are open to B2B off-chain programmatic settlement via high-throughput clearing.
   - The end-user agent deposits USDC into `PerformanceCollateralVault.sol` on Base L2, streams 167-byte Session MAC micro-cheques to the merchant, and receives live token streams and media artifacts without personal credit cards or KYC.

---

## 2. Canonical 2026 Merchant Directory (37 Validated Providers)

### Tier 1: High-Speed Inference & AI Model APIs (Crypto/Web3 Open)
These merchants provide sub-second token generation, OpenAI-compatible APIs, and flexible billing models (crypto-deposit, prepay, or B2B invoicing):

1. **UsePod:** High-throughput inference gateway, developer-first billing.
2. **DeepInfra:** Ultra-low-cost serverless inference for open-weights & reasoning models, crypto-native friendly.
3. **Novita AI:** High-concurrency AI API hub, flexible payment rails.
4. **Together AI (Together Inference):** Scalable frontier open model endpoints (Llama, DeepSeek, Qwen), high-speed context caching.
5. **Fireworks AI:** Ultra-fast compound AI system inference, optimized MoE serving.
6. **Baseten:** Enterprise-grade low-latency model serving, custom gateway integration.
7. **Crusoe (Crusoe Cloud):** High-density AI cloud with clean-energy compute infrastructure.
8. **Groq:** Ultra-low latency LPU inference engine (sub-10ms time-to-first-token).
9. **Hyperbolic:** Decentralized high-performance inference cluster, native crypto-settlement support.
10. **Replicate:** Production API platform for open-source model execution.
11. **fal.ai:** Real-time multimodal media and diffusion inference with sub-second generation.

---

### Tier 2: Voice & Audio Generation APIs
18. **ElevenLabs:**
    - Models: Eleven v4, Eleven v4 Turbo, ElevenAgents real-time conversational platform.
    - Integration mode: B2B API gateway via authorized merchant proxies or enterprise API token bundles.

---

### Tier 3: Frontier & Enterprise Channel Networks (Indirect Claude & GPT Access)
Access to closed frontier models (Claude Opus 5.5 / Sonnet 5.5, GPT-6.1 Sol / Luna) is achieved strictly via authorized reseller networks and enterprise cloud partners:

19. **OpenAI — Partner Network:** Authorized solution partners and enterprise resellers with pooled enterprise limits.
20. **Anthropic — Claude Partner Network:** Official enterprise partners providing managed Claude access.
21. **Anthropic — Services Track / Partner Hub:** Certified systems integrators with dedicated provisioned throughput (PTU).
22. **AWS / Amazon Bedrock:** Enterprise AWS partner instances with Claude Sonnet/Opus models, billable via managed billing accounts.
23. **Google Cloud / Vertex AI:** Managed cloud resellers supplying Gemini 4 Argon and Project Astra streaming APIs.
24. **Microsoft Azure AI / Foundry:** Enterprise Azure partner tenants with dedicated GPT-6 deployment endpoints.

---

### Tier 4: Direct Sovereign & Asian Frontier Partner Channels
Specialized frontier Asian labs and media generators with native offshore settlement (Hong Kong HKMA / OTC / stablecoins):

25. **DeepSeek:** Direct API and SiliconFlow gateway channels (DeepSeek-V4-Pro, DeepSeek-V4.1-Flash).
26. **Kimi / Moonshot AI:** Long-context frontier reasoning and Chinese document comprehension models.
27. **GLM / Z.ai (Zhipu AI):** GLM-5.3 and GLM-5.3-Flash frontier reasoning engines.
28. **Kling AI (Kuaishou):** Kling 4.0 and Kling 4.0 Flash next-generation video generation (30s 4K HDR, multi-keyframe control).

---

### Tier 5: Extended High-Performance Compute & Inference Network
Candidates for network expansion, specialized silicon, and developer platform integration:

29. **Grok / xAI:** Frontier reasoning and real-time multimodal search APIs.
30. **Mistral AI:** High-efficiency European frontier models (Mistral Large, Codestral).
31. **Cohere:** Enterprise command, search, and semantic rerank models.
32. **SambaNova:** Ultra-high throughput DataScale SN40L inference systems.
33. **Cerebras:** WSE-3 wafer-scale inference engine with extreme generation speeds.
34. **Together Inference:** Dedicated reserved endpoint clusters.
35. **Modal Labs:** Serverless containerized micro-inference with rapid cold starts.
36. **Paperspace (DigitalOcean):** Developer-focused scalable cloud compute and inference APIs.
37. **TensorDock:** Cost-efficient marketplace compute and serverless API routing.

---

## 3. Clearing Architecture: Zero-Custody Invariants

### 1. Zero Omnibus User Funds
- CSLS smart contracts (`PerformanceCollateralVault.sol` on Base L2) maintain isolated, sovereign collateral accounts per agent key.
- Operators never pool, custody, or commingle agent deposits.

### 2. High-Frequency Micro-Cheque Settlement
- Communication over wire uses **167-byte Session MAC packets**:
  $$\text{Cheque} = \text{AgentPK (33B)} \parallel \text{VendorPK (33B)} \parallel \text{Height (8B)} \parallel \text{CumulativeAmount (16B)} \parallel \text{Sig (61B)} \parallel \text{MAC (16B)}$$
- Zero on-chain transaction fees during active sessions.
- Finalization occurs via cooperative mutual close or automated batched netting.

### 3. Merchant Payout Execution
- Merchants hold their own payout addresses (`ProviderPayoutAddress`).
- Merchants withdraw accumulated USDC directly from the vault on Base L2 using EIP-712 settlement signatures.
- Fiat off-ramping, if needed, is conducted independently by the merchant via their own regulated banking or OTC rails.
