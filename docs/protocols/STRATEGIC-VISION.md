# ARC Protocol Stack: Strategic Vision

**Date:** 2026-04-13
**Status:** Active strategy document
**Scope:** Cross-protocol position, priority stack, novel security features, long-term roadmap

---

## 0. How To Read This Document

This document mixes three kinds of statements. They should not be read as if
they have the same epistemic weight:

- **Current state.** What is shipped in the repo today, or what the current
  CLI/runtime demonstrably supports.
- **Design proposal.** Architecture we intend to build, but which is not yet
  implemented.
- **Strategic assumption.** A directional thesis about the market, buyer, or
  eventual business model. These guide prioritization, but are not primary
  evidence by themselves.

Where a surface is only proposed, this document now labels it explicitly. In
particular: `arc mcp serve`, `arc mcp serve-http`, and the receipt dashboard
ship today; `arc start --config arc.yaml` and cross-protocol ACP attestation
remain proposed.

---

## 1. The One-Sentence Vision

ARC is the comptroller of the agent economy -- a system designed to provide
cryptographically signed, cross-protocol attestation of what AI agents actually
did across MCP, A2A, and ACP, with a liability market for pricing the residual
risk as a long-term extension.

---

## 2. The Protocol Landscape (April 2026)

Three protocols now dominate agent infrastructure. Each solves one problem
well. None solves the problem that matters most.

### MCP: Agent-to-Tool (Anthropic)

MCP is the leading open tool-calling wire format in the current agent tooling
ecosystem. It defines tool schemas, resources, prompts, sampling, and
completions over stdio or HTTP+SSE. In this document, MCP's importance is a
working strategic assumption based on ecosystem observation, not a citation-
backed market measurement.

MCP is a tool-calling wire format. It explicitly defers authorization to the
application layer. OpenTelemetry logging provides observability, not proof.
There are no capability tokens, no delegation chains, no signed receipts, and
no revocation semantics.

### A2A: Agent-to-Agent (Google / Linux Foundation)

A2A is the clearest open attempt to standardize agent-to-agent discovery and
task exchange. It introduces signed Agent Cards, task lifecycle streaming, and
DNS/HTTP discovery. ARC treats A2A as strategically important, but this
document does not use it as the system of record for ecosystem metrics.

A2A added cryptographic identity for card publishers but still has no scoped
authorization tokens, no capability delegation, and no mechanism to constrain
what a discovered agent can do beyond transport-layer controls.

### ACP: Editor-to-Agent (Zed Industries)

The LSP for AI. ACP defines how editors and IDEs communicate with coding
agents through a structured JSON-RPC protocol. Permission requests, filesystem
operations, terminal commands, and session lifecycle flow through a typed
message contract.

ACP has permission-request semantics but no cryptographic attestation of what
the agent actually did, no signed receipts, and no delegation model.

### The Convergence

ARC's working strategic assumption is that many enterprise agent deployments
will encounter all three interaction patterns: MCP for tool access, A2A for
multi-agent coordination, and ACP for developer-facing agent integration. The
three protocols are complementary, not competitive.

### The Gap Nobody Fills

No protocol provides cross-protocol cryptographic attestation. An agent that
reads a database via MCP, delegates a subtask via A2A, and modifies code via
ACP produces three separate, unlinked, unsigned event streams. There is no
unified proof of what happened. There is no cross-protocol receipt chain.
There is no single artifact an auditor, insurer, or regulator can verify.

ARC fills that gap.

---

## 3. ARC's Unique Position

ARC is not an alternative to MCP, A2A, or ACP. It is the authorization,
attestation, and audit layer that sits across all three.

### ARC Is Not Just an MCP Gateway

MCP gateway-style enforcement is an important adoption wedge, but it is not the
full ARC architecture and should not be treated as the end-state product
identity.

A pure gateway gives a clean enforcement chokepoint for wrapped MCP traffic.
That is useful. It is also structurally incomplete:

- It evaluates requests at the protocol boundary, often with weaker access to
  full workflow history, delegation ancestry, and cross-step intent than the
  kernel itself can preserve.
- It only governs the traffic that actually passes through it. Agent actions
  may migrate to A2A, ACP, native APIs, or framework-specific skill surfaces.
- If the market shifts from MCP-heavy integrations toward protocol-mixed or
  native-function architectures, an MCP-only control point secures a shrinking
  fraction of agent behavior.

ARC should therefore position wrapped MCP enforcement as the fastest current
on-ramp, not the complete runtime-security strategy.

Detailed research notes and open questions live in
`RUNTIME-SECURITY-GATEWAY-VS-CONTEXT-RESEARCH.md`. The complementary HTTP and
framework adoption track lives in `HTTP-FRAMEWORK-INTEGRATION-STRATEGY.md`.

### Three Runtime Security Layers

ARC's runtime-security story is strongest when described as three layers, not
one:

1. **Deterministic governance.** Capability validation, static policy checks,
   guards, budgets, revocation, and fail-closed enforcement.
2. **Continuous observability.** Signed receipts, delegation lineage, session
   traces, cost attribution, and evidence bundles that explain what happened.
3. **Dynamic governance.** Optional future controls that use live context,
   drift signals, and intent/risk scoring to change what is allowed mid-session.

Today ARC is strongest in layers 1 and 2. Layer 3 is strategic expansion, not a
claim of fully shipped intent-aware runtime intervention.

### Three Protocol Adapters, One Kernel

```
  MCP Server  <-->  arc-mcp-adapter  <--\
                                         \
  A2A Agent   <-->  arc-a2a-adapter  <---+--->  ARC Kernel  --->  Receipt Log
                                         /         |
  ACP Agent   <-->  arc-acp-proxy    <--/     Guard Pipeline
```

Every tool invocation, agent delegation, and code action flows through the
same trusted kernel. The kernel validates capability tokens, runs the guard
pipeline, and signs receipts -- regardless of which protocol originated the
request.

### Target Signed Receipts Across All Three Protocols

The receipt log is protocol-agnostic. An MCP tool call, an A2A task
delegation, and a future ACP filesystem write are intended to produce the same
`ArcReceipt` structure: signed, timestamped, capability-bound, and append-only.
Today that is fully shipped for MCP and A2A; ACP receipt promotion remains a
Tier 1 design/implementation gap. Nested operations produce parent-child
receipt chains that preserve the full lineage across protocol boundaries.

### The Receipt Log as the Deepest Long-Term Moat

The receipt log is not just an audit trail. It is a billing ledger, a
compliance record, a behavioral dataset, and an underwriting input -- all from
one data structure. Every receipt that flows through ARC deepens a dataset that
would be hard to match: a competitor would need comparable authorization,
attestation, portability, and real deployment distribution before they could
assemble an equivalent evidence corpus.

The key nuance: observability is not equivalent to enforcement. ARC should not
collapse those concepts. The receipt log is valuable because it is rooted in
enforced, signed execution, not because it is "just more telemetry."

### ARC vs. Microsoft AGT

Microsoft's Agent Governance Toolkit is the clearest emerging runtime-
governance reference point as of April 2026. Public Microsoft material
emphasizes multi-language packaging, a stateless policy engine, DID-based
identity, and dynamic trust scoring. ARC should not dismiss AGT as a toy or as
an Azure-only niche. The better contrast is:

- AGT appears strongest on packaging, language reach, and enterprise
  distribution.
- ARC's differentiation thesis is portable signed receipts, cross-protocol
  delegation/evidence chains, and economic primitives in the decision path.
- AGT is not best framed as "single protocol"; ARC wins if it proves broader
  attested lineage and third-party-verifiable evidence, not if it relies on a
  weak competitor caricature.

Cross-protocol signed receipts are fully shipped for MCP and A2A adapters.
ACP proxy kernel integration remains the largest open attestation gap and is a
Tier 1 priority (see `ACP-KERNEL-INTEGRATION.md`).

### ARC's Differentiation Thesis Today

| Area | ARC position | Status / caveat |
|------|--------------|-----------------|
| **Capability tokens** | Attenuated, time-bounded, subject-bound, revocable, formally verified (Lean 4 P1) | Shipped in the core model |
| **Guard evidence** | Composable fail-closed guards with signed evidence capture | Shipped; advanced stateful guards remain planned |
| **Receipt signing** | Kernel-signed receipts for MCP/A2A, with ACP as the major remaining gap | Partial today, important Tier 1 gap |
| **Merkle commitment** | Append-only receipt log with checkpoint publication | Shipped in the receipt architecture |
| **Formal verification** | Capability monotonicity and cascade revocation proofs in Lean 4 | Real but scoped to specific subsystems |
| **Economic primitives** | Budgets, settlement hooks, and insurance-linked framing in the security path | Mixed: some pieces shipped, broader market story is a strategic bet |
| **Cross-protocol lineage** | One evidence model spanning MCP, A2A, ACP, and future native/API surfaces | Strong thesis; ACP completion and HTTP/native packaging still needed |

The adjacent comparison set is broader than one product. Runtime governance
toolkits, policy engines, API-security platforms, and observability systems all
cover part of this landscape. ARC's claim is the fusion of deterministic
enforcement, signed portable evidence, delegation lineage, and economic
controls -- not that no adjacent system exists.

---

## 4. The Priority Stack

Three tiers, ordered by impact and dependency.

### Tier 1: Do Now

These items unblock adoption and close the most visible gaps in the current
shipping surface.

| Item | Rationale | Crate |
|------|-----------|-------|
| ACP kernel integration | Promote arc-acp-proxy from unsigned audit entries to full signed receipts via injected kernel service | `arc-acp-proxy` |
| MCP proxy DX polish | The repo already ships `arc mcp serve` and `arc mcp serve-http`; Tier 1 work is simplifying naming, defaults, and docs further, potentially including an `arc proxy` alias | `arc-cli` |
| Unified runtime config (proposed) | Single `arc.yaml` that configures MCP, A2A, and ACP edges with shared policy | `arc-cli` |
| Symlink fix | Workspace symlink resolution for monorepo consumers | `arc-cli` |

**Why Tier 1 first:** The ACP proxy currently generates unsigned audit entries.
Promoting those to signed ARC receipts completes the three-protocol attestation
story. The wrapped MCP edge already exists; the near-term DX work is making the
current CLI easier to adopt and documenting proposed future entry points
honestly.

**Runtime-security framing:** Tier 1 is about making deterministic governance
and signed observability easy to adopt. It is intentionally not framed as full
dynamic or intent-aware governance on day one.

### Tier 2: Build Next

These items extend the protocol surface and complete the compliance story.

| Item | Rationale | Crate |
|------|-----------|-------|
| A2A edge crate | Bidirectional bridging: expose ARC tools as A2A Agent Cards | `arc-a2a-edge` (new) |
| ACP edge crate | Bidirectional bridging: expose ARC tools as ACP capabilities | `arc-acp-edge` (new) |
| MCP adapter completion | Close coverage from 14 tests to 80+, covering streaming, error paths, and edge cases | `arc-mcp-adapter` |
| Compliance certificates | Session-scoped, single-artifact proof bundles for auditors (SOC 2, HIPAA, EU AI Act) | `arc-core` |

**Why Tier 2 second:** Edge symmetry means every protocol gets both inbound
adaptation (consume external tools) and outbound exposure (publish ARC tools).
This is what makes ARC a hub, not just a consumer. Compliance certificates
are the artifact that enterprise security and legal teams actually want to see.

### Tier 3: Strategic Bets

These items create new market categories or defensible network effects.

| Item | Rationale | Crate / Surface |
|------|-----------|-----------------|
| Capability attenuation SDK | Programmatic sub-agent delegation with provable subset guarantees | `arc-core` |
| Receipt dashboard expansion | The dashboard ships today; the strategic work is adding cross-protocol traces, compliance views, and certificate inspection | `arc-cli/dashboard` |
| OpenAI function calling adapter | Fourth protocol edge, capturing the OpenAI ecosystem | `arc-openai-adapter` (new) |
| WASM guard runtime | Custom guards authored in any language compiled to WASM, sandboxed execution | `arc-guards` |
| Kubernetes admission controller | Enforce ARC capability policies at pod deployment time | `arc-k8s` (new) |

**Why Tier 3 last:** These are force multipliers that assume Tier 1 and Tier 2
are complete. The WASM guard runtime and K8s controller extend ARC into
infrastructure-level enforcement. The OpenAI adapter captures a major remaining
agent ecosystem. The dashboard work here is expansion of an existing operator
surface, not net-new UI creation.

### Cross-Language Packaging Constraint

The kernel can remain Rust-first. The adoption surface cannot.

ARC's current shipping story is strongest where the Rust CLI can wrap a known
protocol edge directly. That is valuable, but it is not enough to win ordinary
API developers or mixed-language platform teams. The complementary adoption
track is defined in `HTTP-FRAMEWORK-INTEGRATION-STRATEGY.md`:

- zero-code sidecar / reverse-proxy onboarding
- OpenAPI-driven manifest and policy generation
- Python first, TypeScript second, Go third for native packaging
- thin framework wrappers over shared substrate adapters

This is not optional DX polish. It is the packaging path that keeps ARC from
being a strong kernel with weak reach.

---

## 5. ARC's Differentiation Features

These features are where ARC appears differentiated today or where it is making
explicit strategic bets. Some are shipped. Some are in progress. Some are
research horizon.

### 5.1 Capability Delegation with Attenuation (Shipped)

When Agent A delegates a capability to Agent B, the delegated token is a
provable subset of the parent token. Delegation can narrow scope, reduce
invocation limits, shorten time windows, and tighten parameter constraints.
Delegation cannot amplify. This is not a convention. It is a structural
property proven in Lean 4 (P1: Capability Monotonicity).

Sub-agent tokens carry their full ancestry. Any verifier can walk the
delegation chain and confirm that every hop only narrowed authority.

### 5.2 Usage-Bounded Tokens (Shipped)

Capability tokens carry invocation limits per grant. The kernel's BudgetStore
enforces limits atomically: try_increment either succeeds or denies. Budget
records travel with the capability through delegation, and attenuated tokens
inherit the tighter of the parent's remaining budget or the delegated budget.

Planned extensions:
- **Data volume limits:** cap bytes read/written per grant, not just invocation count
- **Time + usage composition:** "100 invocations OR 24 hours, whichever comes first"
- **Monetary budget enforcement:** per-grant spending ceilings in denominated currency, enforced through the arc-link oracle runtime

### 5.3 Capability Attestation Chaining (Shipped)

Receipts hash-chain within sessions. Each receipt references the hash of the
previous receipt in the session, creating an ordered, tamper-evident sequence.
A gap in the chain is detectable. A reordering is detectable. The chain is
the foundation for session compliance certificates.

### 5.4 Session Compliance Certificates (In Progress)

A session compliance certificate is a single artifact that proves:
- Every tool invocation in the session was authorized by a valid capability token
- Every guard in the pipeline evaluated and produced a signed decision
- No receipt in the chain was tampered with or reordered
- The session stayed within its budget, time, and scope constraints

One artifact. One verification. Auditor-ready. The certificate references the
receipt chain root hash and the capability token IDs, so a verifier can
reconstruct the full evidence independently.

### 5.5 Zero-Knowledge Capability Proofs (Research Horizon: 2027-2028)

Prove that an agent holds a capability token with sufficient scope to perform
an action, without revealing the token itself, the issuer, or the full scope.
This enables privacy-preserving capability verification for cross-organization
agent collaboration where neither party wants to disclose their internal
authorization structure.

The research direction is ZK-SNARKs over the capability token structure, with
the kernel as the trusted prover and external verifiers checking the proof
without seeing the witness.

### 5.6 Multi-Party Capability Approval (Planned)

N-of-M signing for high-stakes capabilities. A capability token for
"transfer funds > $10,000" requires signatures from 3 of 5 designated
approvers before the kernel accepts it. The approval set is encoded in the
token itself, and the kernel validates the threshold before any guard runs.

This maps directly to enterprise approval workflows: dual control for
financial operations, committee approval for infrastructure changes, and
multi-department sign-off for cross-functional agent deployments.

---

## 6. The Protocol-Agnostic Tool Store

The three-adapter architecture creates a natural opportunity: a tool store
where publishers register once and ARC automatically exposes the tool through
every protocol edge.

### Publish Once, Expose Everywhere

A tool author writes a tool, signs a manifest, and registers it with ARC.
The MCP edge exposes it as an MCP tool. The A2A edge publishes it in an
Agent Card. The ACP edge makes it available to coding agents. One tool
definition, three protocol surfaces, zero additional work for the author.

### Federated Capability Exchange

Organizations running ARC can federate capability tokens across organizational
boundaries. Delegation chains span federation boundaries. The receipt chain
captures the full cross-org lineage. Federation trust is explicit, bounded,
and auditable -- not implicit or ambient.

### Discovery API and Revenue Model

A unified discovery surface spans all three protocols: query by tool name,
capability scope, or protocol preference. The marketplace model follows
naturally: ARC-mediated billing where every invocation produces a receipt
carrying financial metadata. The receipt chain is the settlement evidence.
The billing ledger is not a separate system. It is the receipt log.

This is a strategic thesis, not a present-day claim that a multi-protocol tool
store or liability-linked billing surface is already implemented.

The reason this matters to runtime security is simple: if tools and skills can
be invoked through multiple protocols or through native APIs, security
architecture cannot stop at MCP chokepoints alone.

The same principle applies to HTTP/OpenAPI surfaces. Spec-driven import is a
useful governance wedge, but route publication should be curated rather than
treated as a naive 1:1 "every endpoint becomes a tool" rule.

---

## 7. Developer Experience Roadmap

Five phases, each building on the last. The goal is to take ARC from "powerful
but requires expertise" to "secure any agent in one command." The phases below
explicitly distinguish shipped surfaces from proposed next steps.

### Phase 1: Wrapped MCP Edge Commands (Shipped, DX polish next)

Current shipped surface:

```
arc mcp serve --policy <policy.yaml> --server-id <id> <command>...
```

and, for hosted HTTP:

```bash
arc mcp serve-http --policy <policy.yaml> --server-id <id> --listen <addr> <command>...
```

These commands already wrap an MCP server subprocess, interpose the ARC
kernel, and produce signed receipts for every tool call. The next DX step is
to simplify naming, defaults, and documentation further, potentially including
an `arc proxy` alias.

This is the **adoption wedge**, not the architectural boundary. ARC should win
initial deployment through wrapped MCP edges while building toward broader
protocol and native-surface coverage.

### Phase 2: `arc.yaml` Unified Runtime Config (Proposed)

One configuration file that defines all three protocol edges, shared policy,
capability authorities, and receipt storage:

```yaml
edges:
  mcp:
    servers:
      - name: database
        command: "npx @db/mcp-server"
  a2a:
    agents:
      - url: "https://agent.example.com"
  acp:
    agent:
      command: "claude-code"
      workspace: "/home/user/project"
policy:
  guards: [forbidden-path, shell-command, egress-allowlist]
receipts:
  store: sqlite
  path: "./arc-receipts.db"
```

Status note: this is a design proposal. The repo currently supports `arc_yaml`
as a policy format, but does not currently ship an `arc start --config arc.yaml`
runtime command.

### Phase 3: Guard SDK

Custom guards in Rust or any language that compiles to WASM. A guard is a
pure function: it receives the tool call context and returns allow or deny
with evidence. The SDK provides the trait, the WASM runtime provides the
sandbox, and the kernel provides the integration.

### Phase 3.5: Behavioral and Intent Signals (Research / Design)

ARC should explicitly research which live signals are useful for runtime risk
evaluation without introducing a false sense of precision:

- workflow drift from the initial session objective
- unusual tool sequencing or data-volume changes
- cross-tool exfiltration patterns
- mismatch between declared task intent and observed side effects
- escalation triggers for human approval

The important discipline is to treat these as inputs to optional governance
layers, not as magic "understanding" that replaces deterministic controls.

### Phase 4: Receipt Dashboard Expansion (Base Surface Shipped)

The receipt dashboard already exists as an operator-facing UI. The expansion
work is cross-protocol trace visualization, compliance certificate inspection,
and richer non-receipt summaries. The dashboard reads from the receipt store
and presents data that is already there -- it does not introduce new data
collection.

### Phase 5: Hosted Managed Service

ARC-as-a-service with per-receipt pricing. Organizations that do not want to
operate the kernel, receipt store, or control plane can use the hosted service.
The trust model is preserved: the managed kernel signs receipts with keys the
customer controls, so the hosted service cannot forge receipts. Key custody,
verifier onboarding, and trust-root distribution are specified separately in
`TRUST-MODEL-AND-KEY-MANAGEMENT.md`.

---

## 8. Enterprise Go-to-Market

Four concentric rings, each capturing a different buyer.

These rings are strategic assumptions about adoption order. They are not
presented here as externally validated market research.

### Ring 1: Open-Source Adoption (Developers)

ARC is open source and free. Developers adopt it because `arc mcp serve` /
`arc mcp serve-http` are the fastest current way to add authorization and audit
to an MCP server. A future `arc proxy` alias may compress that further. The
receipt log is local SQLite. No account, no sign-up, no cloud dependency.

### Ring 2: Enterprise SIEM Integration (Security Teams)

`arc-siem` exports receipt data to Splunk, Datadog, Elastic, and any SIEM
that accepts structured events. Security teams adopt ARC because it gives
them the agent audit trail they cannot get from any other source. The
integration is the wedge into enterprise procurement.

But SIEM export alone is not the runtime strategy. Post-hoc monitoring without
pre-execution enforcement is still reactive.

### Ring 3: Managed Receipt Analytics (Compliance Teams)

Compliance teams need artifacts, not dashboards. Session compliance
certificates, receipt chain exports, and EU AI Act Article 19 traceability
reports are the artifacts ARC produces natively. Managed analytics packages
these artifacts with retention policies, automated report generation, and
regulator-ready formatting.

### Ring 4: Liability Market Integration (Insurance Industry)

ARC receipts are actuarial data. The behavioral metrics computed from the
receipt log -- reliability, compliance rate, scope discipline, delegation
hygiene -- are the inputs an underwriter needs to price agent liability
coverage. Per-session pricing, capability-scoped coverage, and receipt-backed
claims adjudication could create a new category: parametric agent insurance.
This is a long-term strategic bet, not a claim that product-market fit is
already proven.

---

## 9. Integration Roadmap

Planned integrations, ordered by expected adoption impact.

| Integration | Description | Status |
|-------------|-------------|--------|
| **OpenAI function calling adapter** | Wrap OpenAI-style function calls through the ARC kernel | Planned |
| **HTTP/OpenAPI sidecar** | Reverse-proxy adoption path for any documented API, with manifest generation from OpenAPI and `x-arc-*` policy hints | Proposed |
| **Python / TypeScript / Go substrate SDKs** | Multi-language middleware and wrapper packages around the Rust kernel | Planned |
| **LangChain / LlamaIndex wrappers** | Python packages that inject ARC authorization into existing agent frameworks | Planned |
| **Kubernetes admission controller** | Enforce ARC capability policies at pod deployment, reject workloads without valid tokens | Planned |
| **WASM guard runtime** | Execute custom guards compiled to WASM in a sandboxed runtime | Planned |
| **HSM integration** | Hardware Security Module support for kernel signing keys (PKCS#11, AWS CloudHSM, Azure HSM) | Planned |
| **TEE / confidential computing** | Run the ARC kernel inside a Trusted Execution Environment (Intel SGX, AMD SEV, ARM CCA) | Research |
| **SCIM provisioning** | Sync agent identities and capability grants from enterprise identity providers | Planned |
| **OpenTelemetry collector** | Export receipt data as OTel spans for existing observability infrastructure | Planned |

These integrations matter partly because agent execution is already moving
beyond MCP-specific surfaces. ARC's protocol-agnostic story gets stronger as it
secures a wider share of actual runtime behavior.

---

## 10. Cross-Adapter Test Coverage

Current state and targets for the four protocol surfaces.

| Adapter | Tests (Current) | Grade | Target | Target Grade |
|---------|-----------------|-------|--------|--------------|
| `arc-mcp-adapter` | 14 | C | 80+ | A |
| `arc-a2a-adapter` | 56 | A- | 60+ | Maintain |
| `arc-acp-proxy` | 129 | A | 130+ | Maintain |
| `arc-mcp-edge` | 42 | B+ | 60+ | A- |

Counts reflect `#[test]` functions in each crate's source tree. For line-level
coverage metrics, see CI reports.

The MCP adapter is the oldest crate and has the weakest coverage relative to
its surface area. The gap is concentrated in streaming, error propagation,
resource template resolution, nested flows, and OAuth token refresh. Closing
to 80+ tests is a Tier 2 priority. The A2A and ACP crates demonstrate that
thorough adapter coverage is achievable; the MCP adapter needs the same
treatment.

---

## 11. The Architecture Debate (Resolved)

Three architectural questions arose during the multi-protocol expansion. All
three are now resolved with clear rationale.

### ACP Proxy: Boundary Proxy, Not Tool Server

The ACP proxy sits at the boundary between the editor client and the ACP agent.
It is not a tool server. It does not implement tools. It intercepts JSON-RPC
messages, enforces capability-based access control, and generates audit entries.

The kernel is injected as a service, not embedded as a library. This means the
proxy can run alongside an ARC kernel that is already managing MCP and A2A
edges, producing receipts into the same log. The alternative -- making the ACP
proxy a standalone tool server -- would have created a second receipt log and a
second policy evaluation path, violating the single-kernel invariant.

Note: `arc-acp-proxy` and `arc-acp-edge` serve opposite directions.
The proxy is an inbound adapter (intercepts an existing ACP session for
security enforcement). The edge is an outbound adapter (exposes ARC
tools to ACP editors as if they were native ACP capabilities). The
"not a tool server" characterization applies to the proxy only.

### Unified Trait: Lightweight Metadata, Not Behavioral Abstraction

The three adapters (MCP, A2A, ACP) share a common trait surface for metadata:
tool names, descriptions, input schemas, and capability requirements. They do
not share a behavioral abstraction. Each protocol has distinct transport
semantics (stdio pipes, HTTP streaming, JSON-RPC bidirectional) that would be
distorted by a forced common interface.

The shared surface is intentionally thin: enough to support cross-protocol
discovery and the tool store, not so thick that protocol-specific behavior
leaks through an inappropriate abstraction.

### Edge Symmetry: Bidirectional Bridging for All Three Protocols

Every protocol gets two crate surfaces:

| Protocol | Inbound (consume external) | Outbound (expose ARC tools) |
|----------|---------------------------|----------------------------|
| MCP | `arc-mcp-adapter` | `arc-mcp-edge` |
| A2A | `arc-a2a-adapter` | `arc-a2a-edge` (Tier 2) |
| ACP | `arc-acp-proxy` | `arc-acp-edge` (Tier 2) |

Inbound adapters wrap external protocol servers as ARC tool servers. Outbound
edges expose ARC-native tools through the external protocol's wire format.
Bidirectional bridging is what makes ARC a protocol hub rather than a
protocol consumer. An ARC-native tool registered once is discoverable and
invocable from MCP clients, A2A agents, and ACP editors simultaneously.

---

## The Strategic Thesis

ARC's near-term protocol bet centers on MCP, A2A, and ACP, but the broader
strategic view is that agent execution will remain protocol-mixed: MCP, A2A,
ACP, native APIs, and framework-level tool surfaces will coexist.
None of these surfaces natively solve authorization, attestation, or non-
repudiation, because those are not their jobs.

ARC is the system that aims to sit across those surfaces and answer the
questions that matter after the agent acts: was it authorized, what did it
cost, can you prove it, and who is liable if it went wrong?

The receipt log is the asset. Every signed receipt makes the dataset larger,
the compliance story stronger, and the operational evidence richer. The
protocol adapters are the distribution mechanism. The kernel is the trust
anchor. Liability-market applications are a long-term strategic extension if
the security and compliance layers prove valuable first.

ARC does not compete with agent protocols. It makes them safe to use for
things that matter.
