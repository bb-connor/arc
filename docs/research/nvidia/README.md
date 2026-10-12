# NVIDIA stack research: integrate, evolve, compete, build alongside

Date: 2026-09-29. NVIDIA announced the platform on 2026-09-28; sources were read on 2026-09-28 and 2026-09-29 UTC.

This set assesses how Chio should relate to NVIDIA's agent safety stack. On 2026-09-28 NVIDIA announced the Open Agent Safety Platform: OpenShell, an Apache-2.0 agent runtime (VERIFIED, OpenShell@acbac9c [`LICENSE`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/LICENSE)), and Sentry, a reference design for an out-of-band watchdog on BlueField-4 data processing units (VERIFIED, [NVIDIA press release, 2026-09-28](https://nvidianews.nvidia.com/news/open-agent-safety-platform)). The documents record what NVIDIA shipped, designed or only announced, what Chio has today, where the two overlap, how Chio would connect, who else competes, and a dated plan in four directions: integrate, evolve, compete and build alongside. This page gives the answer, the stack, the open decisions and a map of the set, for Chio maintainers and the founder.

## How to read the status labels

Statements about NVIDIA, OpenShell, the Open Delegation & Identity Standard (ODIS) draft, partners and standards carry a status label the first time they appear in a section. Statements about Chio carry the repository's claim-boundary labels. A label is never upgraded.

| Label | Applies to | Meaning |
|---|---|---|
| VERIFIED | NVIDIA and others | Primary source read on 2026-09-28 to 2026-09-29; some repository states are dated 2026-09-29 UTC. "VERIFIED as X's statement" means X said it; the claim itself is not confirmed. |
| VERIFIED, local test | NVIDIA and others | Behavior observed in the local test of OpenShell v0.1.2 on 2026-09-29, described in [spike/README.md](spike/README.md). |
| REPORTED | NVIDIA and others | Secondary source, not independently confirmed. |
| INFERRED | NVIDIA, others, and recommendations about Chio | Our reasoning from cited evidence. Ratings, estimates and recommendations are INFERRED. |
| PROPOSED | NVIDIA and others | A design, draft, reference design, RFC, open issue or announced plan that is not built. |
| qualified | Chio | Named in [`QUALIFICATION.md`](../../../docs/release/QUALIFICATION.md) or approved with scope in [`CLAIM_REGISTRY.md`](../../../docs/reference/CLAIM_REGISTRY.md). |
| shipped | Chio | Code on `main` that builds and has tests, outside the qualified boundary. |
| test only | Chio | Code on `main` whose only callers are tests, fixtures or offline tools. Documents [02](02-chio-today.md), [04](04-integration-design.md) and [07](07-ideas-backlog.md) write test-only. |
| branch only | Chio | Code on an unmerged branch: draft PR #1160 or PR #1156. Documents [02](02-chio-today.md), [04](04-integration-design.md) and [07](07-ideas-backlog.md) write unmerged. |
| design doc | Chio | A design, proposal, specification draft or paper with no implementation. |
| roadmap | Chio | Stated direction with no design behind it. Every plan task, demo, date and estimate is roadmap. |

"Not documented" means the sources read say nothing on the point. Plan IDs (LW, D30, D60, D90, Q2, L) name tasks in [06-strategy-and-roadmap.md](06-strategy-and-roadmap.md), and F-1 to F-17 name the founder decisions listed below. Day 1 of the plan is 2026-09-30, and Q2 means days 91 to 180 (2026-12-29 to 2027-03-28), not a calendar quarter.

## The answer in one page

### Positioning

Chio should enter NVIDIA's stack as the delegated-authority and evidence layer behind OpenShell's extension seams, not as a kernel above the runtime (INFERRED). The kernel framing in the current README, "The kernel your agents answer to" ([`README.md:16`](../../../README.md)), collides with NVIDIA's Secure Agent Workspace (SAW) reference design (INFERRED). SAW defines an agent's authority as a subset of its sponsor's permissions, "never a separate authority" (VERIFIED, [SAW enterprise tool access model, last updated 2026-06-28](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/enterprise-tool-access-model.html)). Microsoft already calls its toolkit's policy engine "the kernel for AI agents" (VERIFIED, [Microsoft open source blog, 2026-04-02](https://opensource.microsoft.com/blog/2026/04/02/introducing-the-agent-governance-toolkit-open-source-runtime-security-for-ai-agents/)). The recommended category sentence (roadmap):

> Chio is the delegated-authority and evidence layer for agent runtimes. It carries authority your organization grants as a capability that can only narrow. It checks each request to an endpoint bound to Chio against that capability's arguments, call counts, expiry and budget, at the runtime's own enforcement point. It signs a receipt that an auditor, and in the cross-organization tier a counterparty, can verify later against a published key. It does not isolate agents, hold their credentials, issue identities or watch the model path.

Each clause becomes true at a different milestone, so public copy uses an interim form until Q2 (roadmap; [06](06-strategy-and-roadmap.md) section 3). The proposed tagline is "Authority that only narrows. Evidence that travels." (roadmap)

### Division of labor

| Function | Holder | Chio's part |
|---|---|---|
| Isolation, egress and L7 policy | OpenShell: Landlock and seccomp, with every outbound connection through its proxy (VERIFIED, OpenShell@acbac9c [`docs/security/best-practices.mdx:31-42`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/security/best-practices.mdx?plain=1#L31-L42)) | None. The ADR-0023 candidate would freeze `chio-cage` and `chio-secret-broker` (both branch only) and the six-host launchers (for Claude Code, Codex, Cursor, Hermes, Pi and OpenClaw) on the OpenShell path (roadmap). |
| Identity issuance | Entra Agent ID, Okta, IBM Verify, Google Agent Identity and SPIFFE (VERIFIED as their published scope: [Microsoft Learn, 2026-06-15](https://learn.microsoft.com/en-us/entra/agent-id/identity-platform/what-is-agent-id); [Okta developer guide, read 2026-09-28](https://developer.okta.com/docs/guides/ai-agent-token-exchange/authserver/main/); [IBM community blog, 2026-09-01](https://community.ibm.com/community/user/blogs/dinesh-jain/2026/09/01/ibm-agent-identity-public-preview); [Google Cloud Agent Identity, updated 2026-09-28](https://docs.cloud.google.com/agent-builder/agent-engine/agent-identity); further sources in [05](05-competitive-analysis.md)). ODIS, an unapproved draft of the Coalition for Secure AI (CoSAI) by three NVIDIA authors (VERIFIED, ODIS@148dc41 [`RFCs/ODIS.md:2-4`](https://github.com/cosai-oasis/ws4-odis/blob/148dc4187139a41325e3c6d6e7533d956bd33144/RFCs/ODIS.md?plain=1#L2-L4)), specifies where delegated authority comes from (PROPOSED). | Consumes identities as the originating grant (Q2-01, roadmap). Issues none. |
| Per-request authority: arguments, counts, expiry, budget | Not in OpenShell. Its MCP rules match method and tool name only: "Tool arguments are not matched" (VERIFIED, [`docs/how-it-works/policies/schema.mdx:347`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/how-it-works/policies/schema.mdx?plain=1#L347)) | Middleware decision and signed receipt (D30-07, roadmap) |
| Control-plane binding | OpenShell gateway, extensible through interceptors under the accepted RFC 0010 (VERIFIED, [`rfc/0010-gateway-interceptors/README.md:4`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/rfc/0010-gateway-interceptors/README.md?plain=1#L4)) | Interceptor binds each sandbox to a capability (D60-06 shadow, D90-01 fail_closed; roadmap) |
| Audit record | OpenShell's unsigned, opt-in Open Cybersecurity Schema Framework (OCSF) JSONL (VERIFIED, [`docs/observability/ocsf-json-export.mdx:12-28`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/observability/ocsf-json-export.mdx?plain=1#L12-L28)) | Signed receipts (qualified) joined to that record (D90-03, roadmap) |
| Model path and hardware | Sentry on BlueField-4, an optional reference design (VERIFIED as NVIDIA's description, [NVIDIA developer blog, 2026-09-28](https://developer.nvidia.com/blog/nvidia-open-agent-safety-platform-a-reference-for-continuous-in-silicon-agent-monitoring/); the capability is PROPOSED) | None until NVIDIA publishes an interface (F-14) |

### Three integration mechanisms

1. **Supervisor middleware** (`openshell.middleware.v1`). For each allowed HTTP/1.x request to an included host, OpenShell calls an external gRPC service after its own policy check and before credential injection. The call passes headers and a body of up to 4 MiB (VERIFIED, OpenShell@acbac9c [`proto/supervisor_middleware.proto:15-35`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/proto/supervisor_middleware.proto#L15-L35), [`:108-128`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/proto/supervisor_middleware.proto#L108-L128)). NVIDIA labels it a research preview (VERIFIED, [`examples/supervisor-middleware-content-guard/README.md:9`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/examples/supervisor-middleware-content-guard/README.md?plain=1#L9)), and [#3307 (opened 2026-09-14)](https://github.com/NVIDIA/OpenShell/issues/3307) proposes replacing the unary request call without an adapter (PROPOSED). Chio builds `chio-openshell-middleware` as a preview over a shared decision core, `chio-pep-core` (D30-06, D30-07; roadmap). A Python prototype failed closed at this hook and added 3.6 ms p50 at 1 KB, measured on one host over plaintext gRPC, not a product number (VERIFIED, local test).
2. **Gateway interceptor** (`openshell.gateway_interceptor.v1`). It can intercept 25 unary control-plane RPCs (VERIFIED, [`crates/openshell-gateway-interceptors/src/routes.rs:17-43`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/crates/openshell-gateway-interceptors/src/routes.rs#L17-L43)). Middleware `config` sits inside OpenShell's deterministic policy hash (VERIFIED, [`crates/openshell-core/src/policy_identity.rs:134-177`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/crates/openshell-core/src/policy_identity.rs#L134-L177)), so a binding written there ties a sandbox's policy to a Chio capability (INFERRED). Middleware cannot refuse `on_error: fail_open`, because `ValidateConfigRequest` carries only `config` and `middleware_name` (INFERRED from the VERIFIED schema at [`proto/supervisor_middleware.proto:92-97`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/proto/supervisor_middleware.proto#L92-L97)). Chio builds `chio-openshell-interceptor`, which writes the binding and enforces fail_closed: shadow in D60-06, fail_closed in D90-01 (roadmap).
3. **OCSF join.** OpenShell keeps its OCSF record as the three most recent daily files (VERIFIED, [`docs/observability/ocsf-json-export.mdx:60-63`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/observability/ocsf-json-export.mdx?plain=1#L60-L63)). No OCSF event carried the middleware's `request_id`, and only a deny reason code carried a receipt reference (VERIFIED, local test). Chio labels OCSF class 3002 as Authorization today (shipped, [`crates/observability/chio-siem/src/ocsf.rs:4`](../../../crates/observability/chio-siem/src/ocsf.rs#L4)). It stops that mislabel in D30-05, emits OCSF 1.9 API Activity 6003 with the delegation object (D60-02), and collects OpenShell's record and joins it to receipts (D90-03) (roadmap). The join is exact on denials and a correlation by sandbox and time on allows (roadmap).

### Two things only Chio has, relative to NVIDIA's stack

1. **Authority as a signed artifact that can only narrow, spend included.** Attenuation is qualified with bounded Lean and executable-test evidence ([`CLAIM_REGISTRY.md:70`](../../../docs/reference/CLAIM_REGISTRY.md)), and cost caps can only narrow under delegation (qualified, [`QUALIFICATION.md:328`](../../../docs/release/QUALIFICATION.md); variants in [`attenuation.rs:196-209`](../../../crates/core/chio-core-types/src/capability/attenuation.rs#L196-L209)). SAW names a signed delegation record with no wire format or signature algorithm (VERIFIED, [SAW overview, last updated 2026-06-28](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/what-is-secure-agent-workspace.html)). ODIS mandates no carrier or signature and defers the economic layer as FW-04 (VERIFIED, ODIS@148dc41 [`RFCs/ODIS.md:1153-1156`](https://github.com/cosai-oasis/ws4-odis/blob/148dc4187139a41325e3c6d6e7533d956bd33144/RFCs/ODIS.md?plain=1#L1153-L1156)). Caveats: offline lineage covers one hop ([`attenuation.rs:301-306`](../../../crates/core/chio-core-types/src/capability/attenuation.rs#L301-L306)), two argument matchers pass if any leaf matches ([`request_matching.rs:429`](../../../crates/kernel/chio-kernel/src/request_matching.rs#L429), [`:1286-1300`](../../../crates/kernel/chio-kernel/src/request_matching.rs#L1286-L1300)), and remote budget stores are advisory ([`budget.rs:137-160`](../../../crates/platform/chio-control-plane/src/trust_control/service_runtime/budget.rs#L137-L160)) (all shipped).
2. **Per-decision evidence a party outside the gateway can check.** Chio signs local receipts and checkpoints (qualified, [`QUALIFICATION.md:67-74`](../../../docs/release/QUALIFICATION.md)). Denied calls also get signed receipts (shipped, [`deny_responses.rs:227-228`](../../../crates/kernel/chio-kernel/src/kernel/responses/deny_responses.rs#L227-L228)). OpenShell's record is unsigned, Sentry's attested telemetry has no published format or signer, and draft RFC 0011 lists cross-gateway federation as a non-goal (VERIFIED, [NVIDIA developer blog, 2026-09-28](https://developer.nvidia.com/blog/nvidia-open-agent-safety-platform-a-reference-for-continuous-in-silicon-agent-monitoring/); OpenShell@acbac9c [`rfc/0011-multi-player-design/README.md:55-58`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/rfc/0011-multi-player-design/README.md?plain=1#L55-L58); the RFC's design is PROPOSED; further evidence in [03](03-overlap-matrix.md) sections 4, 5 and 7). Caveats: `chio evidence verify` checks signatures and consistency and pins no trust roots (shipped, [`receipt.rs:195-200`](../../../crates/products/chio-cli/src/cli/types/receipt.rs#L195-L200)). Receiver-owned admission, which a counterparty would run, is installed only by the loopback harness (test only, [`kernel.rs:422`](../../../crates/kernel/chio-runtime-harness/src/kernel.rs#L422)). Three outcome states are D30-09 (roadmap).

Other vendors also ship both. Microsoft's Agent Governance Toolkit (AGT) combines cost budgets with cross-organization federation (VERIFIED, AGT [`agentmesh/governance/budget.py`](https://github.com/microsoft/agent-governance-toolkit/blob/main/agent-governance-python/agent-mesh/src/agentmesh/governance/budget.py) and [`agentmesh/governance/federation.py`](https://github.com/microsoft/agent-governance-toolkit/blob/main/agent-governance-python/agent-mesh/src/agentmesh/governance/federation.py), main, read 2026-09-29).

### The biggest threat

The biggest threat is NVIDIA's Agent Policy Fabric (APF) (INFERRED). A job post plans signed policy bundles, a Runtime Policy Verifier and revocation checks. It also plans subject binding to attested runtime context and projection into OpenShell policy (VERIFIED as the text of [NVIDIA job post JR2019848, posted 2026-06-22](https://jobs.nvidia.com/careers/job/893395763513); the scope is PROPOSED). That is most of single-organization authority, on the interceptor seam Chio would use (INFERRED). A prototype issuer, `apf-bundle-issuer`, is public in the ODIS contract harness (VERIFIED, ODIS@148dc41 [`contract-harness/README.md:163`](https://github.com/cosai-oasis/ws4-odis/blob/148dc4187139a41325e3c6d6e7533d956bd33144/contract-harness/README.md?plain=1#L163)). NemoClaw admits one external component, and its `--apf-interceptor` mode already holds it (VERIFIED, [NemoClaw external components, pinned c97172c](https://github.com/NVIDIA/NemoClaw/blob/c97172ca1ae7cd63993b5ae04051146183d37fca/docs/deployment/register-external-component.mdx)). APF's openness and dates are not documented. APF as the default interceptor, expiring grants ([#2881, opened 2026-08-21](https://github.com/NVIDIA/OpenShell/issues/2881)), OCSF correlation fields ([#2640, opened 2026-08-06](https://github.com/NVIDIA/OpenShell/issues/2640)) and the #3307 hook (all PROPOSED) would remove the low-cost single-organization wedges within two to four calendar quarters (INFERRED). The counter is to verify alongside APF, accept `odis.bundle.v1` harness grants and APF digests as evidence-only roots, and differentiate on lineage depth, fleet budgets, three-state receipts and counterparty verification (roadmap). A kill-or-continue review on 2027-03-26 tests whether the relying-party and cross-organization seats convert (roadmap).

### The first demonstration

Demo A, "right tool, wrong arguments", is due by 2026-10-29 with a fallback of 2026-11-10 (roadmap). Claude Code 2.1.284, Codex 0.158.0 and, if its MCP client negotiates a supported revision, Hermes would run in OpenShell v0.1.2 sandboxes on the Docker driver, against an MCP server in front of an internal ticketing or data API (roadmap). It would first show that OpenShell forwards any arguments to an allowed MCP tool, as its documentation states (VERIFIED, OpenShell@acbac9c [`docs/how-it-works/policies/schema.mdx:347`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/how-it-works/policies/schema.mdx?plain=1#L347)). With Chio bound, the same call would be denied before credential injection (roadmap). Invocations would be counted, the grant would expire, OpenShell would refuse to forward when the middleware is killed, and each decision would get a three-state receipt (roadmap). It needs the MCP edge fixes (D30-03) and D30-06 to D30-09 (roadmap). Receipt verification would cover signatures and consistency only until D90-02, and no budget hold would appear until Q2-04 (roadmap). A launch-week field note on OpenShell behaviors, with no latency figures, comes first, by 2026-10-04 (LW-02).

## Stack diagram

The target layout from [06](06-strategy-and-roadmap.md) section 3. Chio trust-control exists today (shipped; its receipts and checkpoints are qualified). Every other Chio box, and every plan ID, is roadmap. The status of the OpenShell and Sentry rows is given below the diagram.

```text
ORGANIZATION A (operator)                                            ORGANIZATION B (counterparty, Q2)
+------------------------------------------------------------+       +--------------------------------------+
| ENTERPRISE IDENTITY (consumed; Chio issues none)           |       | IdP of B (any)                       |
|   Entra Agent ID, Okta ID-JAG, IBM Verify, Keycloak,       |       |                                      |
|   SPIFFE JWT-SVIDs -> originating_authorization_ref        |       |                                      |
+------------------------------------------------------------+       +--------------------------------------+
| CHIO TRUST-CONTROL (issuer, revocation, budgets,           |       | CHIO RELYING-PARTY VERIFIER (D90-02) |
|   receipts, checkpoints; single writer today;              |  <->  |   verifies a presented single-hop    |
|   Vault transit signer in Q2-03; companion in Q2-01)       |       |   chain offline; signs its receipt   |
+------------------------------------------------------------+       +--------------------------------------+
| OPENSHELL GATEWAY (control plane)                          |       CHIO DECISION CORE (chio-pep-core)
|   Chio gateway interceptor (RFC 0010): shadow in D60,      |       one evaluate-and-receipt path:
|   fail_closed in D90; writes binding_revision into         |         - OpenShell middleware (D30)
|   network_middlewares.config, inside the policy hash       |         - relying-party verifier (D90)
+------------------------------------------------------------+         - Envoy ext_authz (Q2-07)
| OPENSHELL SUPERVISOR (data plane, outside workload)        |
|   L4 + L7 policy -> CHIO SUPERVISOR MIDDLEWARE (preview)   |
|   sees: request_id, sandbox_id, headers, body <= 4 MiB     |
|   misses: tls: skip, HTTP/2, opaque TCP, binary            |
|   WebSocket, originating process (None today)              |
|   -> credential placeholder substitution -> egress         |
|   writes OCSF 1.8 JSONL inside the sandbox (unsigned,      |
|   opt-in; gateway sink on Windows MXC only)                |
|   -> Chio collector (D90-03)                               |
+------------------------------------------------------------+
| SANDBOX (Landlock + seccomp; Docker, Podman, K8s, VM)      |
|   Claude Code, Codex, Hermes, Pi, OpenClaw                 |
|   harness hooks fail open: coverage, never a boundary      |
|   stdio MCP, shell, local files: not visible to Chio       |
+------------------------------------------------------------+
| INFRASTRUCTURE: Sentry on BlueField-4 (reference           |
|   design, optional); the artifact its DOCA gateway         |
|   verifies is unpublished; Chio's only planned route       |
|   is projection into OpenShell policy (D90-01)             |
+------------------------------------------------------------+
```

Status: the OpenShell details are VERIFIED at OpenShell@acbac9c, for example [`proto/supervisor_middleware.proto:583-598`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/proto/supervisor_middleware.proto#L583-L598) and [`docs/observability/ocsf-json-export.mdx:60-69`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/observability/ocsf-json-export.mdx?plain=1#L60-L69); [01](01-nvidia-stack.md) sections 2 to 4 source the rest. The Sentry row is NVIDIA's description (VERIFIED, [NVIDIA developer blog, 2026-09-28](https://developer.nvidia.com/blog/nvidia-open-agent-safety-platform-a-reference-for-continuous-in-silicon-agent-monitoring/)), and the capability is PROPOSED. In the diagram, ID-JAG is the Identity Assertion JWT Authorization Grant, MXC is Microsoft Execution Containers, and DOCA is NVIDIA's software platform for BlueField data processing units.

## Decisions the founder must make

The recommendations are ours (INFERRED). Reasons and dependencies are in [06](06-strategy-and-roadmap.md) section 14.

| # | Decision | Recommendation | Reversible |
|---|---|---|---|
| F-1 | Publication boundary for this set | Keep [05](05-competitive-analysis.md), [06](06-strategy-and-roadmap.md), [07](07-ideas-backlog.md) and other go-to-market material in a private repository. Publish [01](01-nvidia-stack.md), [03](03-overlap-matrix.md) and [04](04-integration-design.md) after legal review and an editorial review, and [02](02-chio-today.md) as a known-limitations register after each claim in it is checked against the code. | No, once published |
| F-2 | Write and adopt the ADR-0023 candidate, which freezes runtime enforcement work on the OpenShell path | Yes, in the first week. Record the freeze on PR #1160, PR #1156, the five plugin repositories and `chio-bridge`. | Yes |
| F-3 | The plan: product-wedge discipline, two ring-fenced engineers, the cut scope | Yes | Yes |
| F-4 | A go-to-market owner separate from the engineers | Yes, by 2026-09-30 | Yes |
| F-5 | Open-core boundary (ADR-0037 candidate) | Verifiers and adapters free under Apache-2.0; services priced | Yes |
| F-6 | Day-90 revenue proof | Two paid vendor design partnerships and one non-production bank or insurer letter of intent. No production-affecting bank criterion. | Yes |
| F-7 | Packaging split and NVIDIA Inception | Feature-gate the web3 crates (Q2-10), then request a written Inception ruling. Decide the healthcare track in writing within 30 days, in shadow mode with no protected health information (PHI). | Partly (feature gates yes; ruling request and repository split no) |
| F-8 | Trust sprint and stop list before tier-2 outreach | Yes, with a phrase gate on every public surface | Partly (edits yes; reputation no) |
| F-9 | Launch-week posture | A field note and three vendor-neutral OpenShell issues, no product announcement. The founder approves each post. | No, once posted |
| F-10 | Receipt privacy | Write and adopt the ADR-0036 candidate now. No personal data or PHI on the OpenShell path until commitment mode (Q2-13). | Yes |
| F-11 | AWS track | Customer-hosted Chio behind AgentCore Gateway, or park it. No hosted service before SOC 2, a data processing agreement (DPA) and a business associate agreement (BAA). | Yes |
| F-12 | ODIS engagement | Publish a role-capability statement pinned to 148dc41, then the field map and attenuation profile. Contribute issue-first. Never claim conformance. | Yes |
| F-13 | Legal groundwork before offers and contributions (D30-13) | Yes | No, once specifications are contributed (patent posture) |
| F-14 | Sentry, DOCA and BlueField | No code before NVIDIA publishes an interface; take NVIDIA evidence through the Cloud Native Computing Foundation (CNCF) Confidential Containers Trustee | Yes |
| F-15 | Co-signer custody | Backbay never hosts both co-signers. Treaty lanes (Chio's cross-organization federation lanes) enter the bounded release gate with the two-keys wording ("two distinct configured keys signed the same predicate"), and the relay or mTLS lane lands before 2026-12-31. | Yes |
| F-16 | Kill-or-continue on 2027-03-26 | Hold it for the relying-party and cross-organization seats | Yes |
| F-17 | Portfolio boundary, written by day 14 | Chio owns delegated authority and evidence. Backbay's Clawdstrike owns sensing, EDR (endpoint detection and response), response and any Sentry or DOCA detection work. HushSpec, published at [backbay-labs/hush](https://github.com/backbay-labs/hush/tree/6ca599ca8322a7cae6050086718ed5f3417c97e1), is the policy specification. | Yes |

## Document map

| File | What it answers | Read it when |
|---|---|---|
| [01-nvidia-stack.md](01-nvidia-stack.md) | What NVIDIA announced, shipped and designed: OpenShell, Sentry, SAW, ODIS, the Alliance, attestation, partners, critiques, and what is not documented | You need a fact about the NVIDIA side |
| [02-chio-today.md](02-chio-today.md) | What Chio has today for an NVIDIA integration, with claim-boundary labels, paths and limits, and where Chio's documents disagree with its code | Before any statement about Chio |
| [03-overlap-matrix.md](03-overlap-matrix.md) | How NVIDIA's artifacts and Chio relate on each dimension: superset, equivalent, complementary or absent | Deciding whether to build, integrate or cede a capability |
| [04-integration-design.md](04-integration-design.md) | Designs for the middleware, the interceptor, OCSF export, verifier families, Sentry, ODIS, deployment, demonstrations and upstream asks | Building or reviewing an OpenShell adapter |
| [05-competitive-analysis.md](05-competitive-analysis.md) | Who else sells delegated authority for agents, where Chio wins and should not compete, and the verdict on the positioning thesis | Preparing positioning, discovery or a competitor response |
| [06-strategy-and-roadmap.md](06-strategy-and-roadmap.md) | Positioning, the four directions, customers, standards, the phased plan with exit criteria, ADR candidates, risks and founder decisions | Planning, approving or sequencing work |
| [07-ideas-backlog.md](07-ideas-backlog.md) | Every idea considered, by I-number, with effort, impact and status, rejected ideas included | Looking up a backlog item or reopening a rejected idea |
| [08-sources.md](08-sources.md) | Every source with its date, status and the documents that use it, plus the upstream pins | Checking a citation or re-verifying a fact |
| [spike/README.md](spike/README.md) | The local test of OpenShell v0.1.2: what ran, the files, how to run it again, results and limits | Reproducing a "VERIFIED, local test" statement |

## Method and sources

The set rests on sources read on 2026-09-28 and 2026-09-29 UTC, most of them primary, on the Chio repository, and on one local test of OpenShell v0.1.2 run on 2026-09-29. [08-sources.md](08-sources.md) lists every source with its date and status. OpenShell is cited at [`acbac9cb795094986cbab016bfd0352d980b17f6`](https://github.com/NVIDIA/OpenShell/tree/acbac9cb795094986cbab016bfd0352d980b17f6) on `main`, 13 commits after the v0.1.2 tag (`6648bd0`, release published 2026-09-28) (VERIFIED). The local test ran the v0.1.2 release, not the pinned commit. ODIS is cited at [`148dc4187139a41325e3c6d6e7533d956bd33144`](https://github.com/cosai-oasis/ws4-odis/tree/148dc4187139a41325e3c6d6e7533d956bd33144) (2026-09-08). NemoClaw is pinned at `c97172c`, NeMo Relay at `db4c6c5`, hermes-agent at `39faafb`, HushSpec at `6ca599c` and the OCSF schema at release `v1.9.0`. Chio paths refer to `main` at `f5566d9a76` (2026-09-03). Branch-only code names draft PR #1160 (`f928453692`) or PR #1156 (`7059c71ca8`).

## How to keep the set current

| Trigger | Re-verify | Update |
|---|---|---|
| Each OpenShell release. The project targets a release every Tuesday when there are changes and qualification passes (VERIFIED, [`docs/about/support-matrix.mdx:22-24`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/about/support-matrix.mdx?plain=1#L22-L24)). | The middleware and interceptor protos, the interceptable RPC list, MCP rules and `mcp.versions` in `schema.mdx`, the OCSF export page, `architecture/sandbox-limits.md`, and whether OpenShell populates `RequestContext.originating_process` (set to `None` at every call site at the pin) or adds policy version and hash to `RequestContext`. Re-run [spike/](spike/README.md) against the release. | The OpenShell pin across the set, listed in [08](08-sources.md); the tables in [04](04-integration-design.md) sections A and B |
| A state change on #3307, PR #3450, #2881, #2640, #2025, #2109, PR #2168, #1055, #3224, #3817 or #2565 | Issue text, labels and linked pull requests | [01](01-nvidia-stack.md) section 4; [05](05-competitive-analysis.md) section 3; [06](06-strategy-and-roadmap.md) sections 6 and 13 |
| Any public APF RFC, repository or specification, or a NemoClaw change to external components | Scope, openness, bundle format and which seam it uses | [05](05-competitive-analysis.md) section 3; [06](06-strategy-and-roadmap.md) section 6; the inputs to F-16 |
| New commits on `cosai-oasis/ws4-odis`, or a decision on ODIS issues #21 and #22 | Delegation Record fields, FW-01, FW-04 and the conformance text; move the pin | [01](01-nvidia-stack.md) section 7; [03](03-overlap-matrix.md) sections 2 and 3; [04](04-integration-design.md) section F |
| Each DOCA release. DOCA 3.6 LTS (October 2026) and 4.0 (January 2027) are scheduled (PROPOSED, [DOCA 3.5.0 changes and new features, updated 2026-09-02](https://networking-docs.nvidia.com/doca/archive/3-5-0/changes-and-new-features)). | Whether a gateway interface, signer or record format for Sentry is published | [01](01-nvidia-stack.md) section 5; [04](04-integration-design.md) section E; F-14 |
| A new OCSF schema release or MCP revision | API Activity 6003 and the delegation object; the MCP revisions OpenShell parses | [03](03-overlap-matrix.md) section 9; [04](04-integration-design.md) section C |
| Merges to Chio `main` that touch cited paths, and each phase exit (2026-10-29, 2026-11-28, 2026-12-28) | Labels in [02](02-chio-today.md) against `QUALIFICATION.md` and `CLAIM_REGISTRY.md`; the exit criteria in [06](06-strategy-and-roadmap.md) | [02](02-chio-today.md); [06](06-strategy-and-roadmap.md); statuses in [07](07-ideas-backlog.md) |
| Every 90 days | Competitor states: Microsoft AGT and Entra Agent ID, AWS AgentCore, Okta, Tigera Lynx | [05](05-competitive-analysis.md) |
