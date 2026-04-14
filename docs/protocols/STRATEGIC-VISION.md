# ARC Protocol Stack: Strategic Vision

**Date:** 2026-04-13
**Status:** Active strategy document
**Scope:** Cross-protocol position, priority stack, novel security features, long-term roadmap

---

## 1. The One-Sentence Vision

ARC is the comptroller of the agent economy -- the only system providing
cryptographically signed, cross-protocol attestation of what AI agents actually
did, across MCP, A2A, and ACP, with a full liability market for pricing the
residual risk.

---

## 2. The Protocol Landscape (April 2026)

Three protocols now dominate agent infrastructure. Each solves one problem
well. None solves the problem that matters most.

### MCP: Agent-to-Tool (Anthropic)

97M+ downloads. The de facto standard for how LLMs call tools. Defines tool
schemas, resources, prompts, sampling, and completions over stdio or HTTP+SSE.
OAuth 2.1 support added in the 2026 spec revision. Broad adoption: Cursor,
Windsurf, Claude Desktop, VS Code, and the growing registry ecosystem.

MCP is a tool-calling wire format. It explicitly defers authorization to the
application layer. OpenTelemetry logging provides observability, not proof.
There are no capability tokens, no delegation chains, no signed receipts, and
no revocation semantics.

### A2A: Agent-to-Agent (Google / Linux Foundation)

Google donated A2A to the Linux Foundation in June 2025. 150+ launch partners.
v1.0 shipped with JWS-signed Agent Cards (RFC 7515), task lifecycle streaming,
and DNS/HTTP discovery.

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

Every enterprise deploying agents at scale will use all three protocols. MCP
for tool access. A2A for multi-agent coordination. ACP for developer-facing
agent integration. The three protocols are complementary, not competitive.

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

### Signed Receipts Across All Three Protocols

The receipt log is protocol-agnostic. An MCP tool call, an A2A task
delegation, and an ACP filesystem write all produce the same `ArcReceipt`
structure: signed, timestamped, capability-bound, and append-only. Nested
operations produce parent-child receipt chains that preserve the full lineage
across protocol boundaries.

### The Receipt Log as the Deepest Moat

The receipt log is not just an audit trail. It is a billing ledger, a
compliance record, a behavioral dataset, and an underwriting input -- all from
one data structure. Every receipt that flows through ARC deepens the dataset
that no competitor can replicate without first building the authorization and
attestation layer that produces it.

### ARC vs. Microsoft AGT

Microsoft's Agent Governance Toolkit provides policy enforcement for agent
systems within the Azure ecosystem. AGT enforces policies. ARC is designed to
enforce policies and produce cryptographic proof that the enforcement happened.
The distinction is fundamental: policy enforcement without signed evidence is
an assertion. Policy enforcement with signed evidence is auditable evidence.

Cross-protocol signed receipts are fully shipped for MCP and A2A adapters.
ACP proxy kernel integration is Tier 1 priority (see ACP-KERNEL-INTEGRATION.md).

### What ARC Has That Nobody Else Does

| Capability | ARC | Everyone Else |
|------------|-----|---------------|
| **Capability tokens** | Attenuated, time-bounded, subject-bound, revocable, formally verified (Lean 4 P1) | No protocol-level equivalent |
| **Guard pipeline** | 7 composable, fail-closed guards with signed evidence capture | Application-level guardrails without attestation |
| **Receipt signing** | Every outcome (allow, deny, cancel, incomplete) signed by the kernel | Mutable logs or no logging at all |
| **Merkle commitment** | Append-only receipt log with checkpoint publication | No tamper-evident ordering guarantees |
| **Liability market** | Receipts feed actuarial data for per-session agent insurance pricing | No connection between security controls and insurance |
| **Cascade revocation** | Delegation-chain-aware, formally proven (Lean 4 P2) | No revocation or best-effort propagation |
| **Cross-protocol attestation** | MCP + A2A + ACP through one kernel | Single-protocol or no attestation |

---

## 4. The Priority Stack

Three tiers, ordered by impact and dependency.

### Tier 1: Do Now

These items unblock adoption and close the most visible gaps in the current
shipping surface.

| Item | Rationale | Crate |
|------|-----------|-------|
| ACP kernel integration | Promote arc-acp-proxy from unsigned audit entries to full signed receipts via injected kernel service | `arc-acp-proxy` |
| Drop-in proxy binary | `arc proxy` CLI that wraps any MCP server in one command, zero config | `arc-cli` |
| Unified config | Single `arc.yaml` that configures MCP, A2A, and ACP edges with shared policy | `arc-cli` |
| Symlink fix | Workspace symlink resolution for monorepo consumers | `arc-cli` |

**Why Tier 1 first:** The ACP proxy currently generates unsigned audit entries.
Promoting those to signed ARC receipts completes the three-protocol attestation
story. The proxy binary and unified config are the developer experience surface
that makes adoption frictionless.

### Tier 2: Build Next

These items extend the protocol surface and complete the compliance story.

| Item | Rationale | Crate |
|------|-----------|-------|
| A2A edge crate | Bidirectional bridging: expose ARC tools as A2A Agent Cards | `arc-a2a-edge` (new) |
| ACP edge crate | Bidirectional bridging: expose ARC tools as ACP capabilities | `arc-acp-edge` (new) |
| MCP adapter completion | Close coverage from 13 tests to 80+, covering streaming, error paths, and edge cases | `arc-mcp-adapter` |
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
| Receipt analytics dashboard | Web UI for exploring receipt chains, compliance status, and cost attribution | `arc-dashboard` (new) |
| OpenAI function calling adapter | Fourth protocol edge, capturing the OpenAI ecosystem | `arc-openai-adapter` (new) |
| WASM guard runtime | Custom guards authored in any language compiled to WASM, sandboxed execution | `arc-guards` |
| Kubernetes admission controller | Enforce ARC capability policies at pod deployment time | `arc-k8s` (new) |

**Why Tier 3 last:** These are force multipliers that assume Tier 1 and Tier 2
are complete. The WASM guard runtime and K8s controller extend ARC into
infrastructure-level enforcement. The OpenAI adapter captures the largest
remaining agent ecosystem. The dashboard is the product surface that makes
receipts visible to non-technical stakeholders.

---

## 5. Novel Security Features

These features differentiate ARC from every other system in the agent security
landscape. Some are shipped. Some are in progress. Some are research horizon.

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

---

## 7. Developer Experience Roadmap

Five phases, each building on the last. The goal is to take ARC from "powerful
but requires expertise" to "secure any agent in one command."

### Phase 1: `arc proxy` CLI Binary

Wrap any existing MCP server in ARC security with a single command:

```
arc proxy --server "npx my-mcp-server" --policy default
```

The proxy spawns the MCP server as a subprocess, interposes the ARC kernel,
and produces signed receipts for every tool call. No code changes to the MCP
server. No configuration beyond the command line.

### Phase 2: `arc.yaml` Unified Config

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

### Phase 3: Guard SDK

Custom guards in Rust or any language that compiles to WASM. A guard is a
pure function: it receives the tool call context and returns allow or deny
with evidence. The SDK provides the trait, the WASM runtime provides the
sandbox, and the kernel provides the integration.

### Phase 4: Receipt Analytics Dashboard

Web UI for exploring receipt chains, visualizing delegation trees, tracking
budget consumption, and generating compliance reports. The dashboard reads
from the receipt store and presents the data that is already there -- it does
not introduce new data collection.

### Phase 5: Hosted Managed Service

ARC-as-a-service with per-receipt pricing. Organizations that do not want to
operate the kernel, receipt store, or control plane can use the hosted service.
The trust model is preserved: the managed kernel signs receipts with keys the
customer controls, so the hosted service cannot forge receipts.

---

## 8. Enterprise Go-to-Market

Four concentric rings, each capturing a different buyer.

### Ring 1: Open-Source Adoption (Developers)

ARC is open source and free. Developers adopt it because `arc proxy` is the
fastest way to add authorization and audit to any MCP server. The on-ramp is
a single CLI command. The receipt log is local SQLite. No account, no
sign-up, no cloud dependency.

### Ring 2: Enterprise SIEM Integration (Security Teams)

`arc-siem` exports receipt data to Splunk, Datadog, Elastic, and any SIEM
that accepts structured events. Security teams adopt ARC because it gives
them the agent audit trail they cannot get from any other source. The
integration is the wedge into enterprise procurement.

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
claims adjudication create a new category: parametric agent insurance.

---

## 9. Integration Roadmap

Planned integrations, ordered by expected adoption impact.

| Integration | Description | Status |
|-------------|-------------|--------|
| **OpenAI function calling adapter** | Wrap OpenAI-style function calls through the ARC kernel | Planned |
| **LangChain / LlamaIndex wrappers** | Python packages that inject ARC authorization into existing agent frameworks | Planned |
| **Kubernetes admission controller** | Enforce ARC capability policies at pod deployment, reject workloads without valid tokens | Planned |
| **WASM guard runtime** | Execute custom guards compiled to WASM in a sandboxed runtime | Planned |
| **HSM integration** | Hardware Security Module support for kernel signing keys (PKCS#11, AWS CloudHSM, Azure HSM) | Planned |
| **TEE / confidential computing** | Run the ARC kernel inside a Trusted Execution Environment (Intel SGX, AMD SEV, ARM CCA) | Research |
| **SCIM provisioning** | Sync agent identities and capability grants from enterprise identity providers | Planned |
| **OpenTelemetry collector** | Export receipt data as OTel spans for existing observability infrastructure | Planned |

---

## 10. Cross-Adapter Test Coverage

Current state and targets for the four protocol surfaces.

| Adapter | Tests (Current) | Grade | Target | Target Grade |
|---------|-----------------|-------|--------|--------------|
| `arc-mcp-adapter` | 13 | C | 80+ | A |
| `arc-a2a-adapter` | 55 | A- | 60+ | Maintain |
| `arc-acp-proxy` | 129 | A | 130+ | Maintain |
| `arc-mcp-edge` | 41 | B+ | 60+ | A- |

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

The agent economy will be built on MCP, A2A, and ACP. All three will succeed.
None of them will solve authorization, attestation, or non-repudiation,
because those are not their jobs.

ARC is the system that sits across all three and answers the questions that
matter after the agent acts: was it authorized, what did it cost, can you
prove it, and who is liable if it went wrong?

The receipt log is the asset. Every signed receipt makes the dataset larger,
the compliance story stronger, the underwriting data richer, and the moat
deeper. The protocol adapters are the distribution mechanism. The kernel is
the trust anchor. The liability market is the endgame.

ARC does not compete with agent protocols. It makes them safe to use for
things that matter.
