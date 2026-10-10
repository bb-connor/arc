# The NVIDIA agent safety stack (2026-09-28)

On 2026-09-28 NVIDIA announced the Open Agent Safety Platform. It has two parts: OpenShell, an Apache-2.0 agent runtime, and Sentry, a reference system design for an out-of-band watchdog that runs on BlueField-4 data processing units (DPUs) [VERIFIED] ([NVIDIA press release, 2026-09-28](https://nvidianews.nvidia.com/news/open-agent-safety-platform)).

This document records what NVIDIA and its partners shipped, designed, or only announced around that launch. It covers the runtime, the hardware layer, NVIDIA's Secure Agent Workspace reference design, the Open Delegation & Identity Standard (ODIS) draft, the alliance and toolkit around them, NVIDIA attestation, the partner map, and the gaps others have found.

This document describes the NVIDIA side only. Chio's current state is in [02-chio-today.md](02-chio-today.md). The capability comparison is in [03-overlap-matrix.md](03-overlap-matrix.md), and the integration design is in [04-integration-design.md](04-integration-design.md). All sources are collected in [08-sources.md](08-sources.md).

## Conventions

Every bullet, paragraph, and table row carries the label of its evidence, placed after the last statement it covers. Where the evidence differs inside one item, each part carries its own label, written as `LABEL (scope); LABEL (scope)`.

| Label | Meaning |
|---|---|
| VERIFIED | Read in a primary source on 2026-09-28 to 2026-09-29: an NVIDIA or partner page, a repository at the pinned commit, a release page, an issue tracker, or a standards text. Some cited repository and tracker states are dated 2026-09-29 UTC. Behavior observed in a local test of OpenShell v0.1.2 on 2026-09-29 is marked VERIFIED (local test). |
| REPORTED | From a secondary source: press coverage, analyst quotes, meeting agendas, minutes, and summaries, and one vendor's statements about another vendor, including integration claims that no code or documentation confirms. Not independently confirmed. |
| INFERRED | Our reasoning from the cited evidence. |
| PROPOSED | A design, RFC, roadmap item, or announced plan that is not built. |

Further rules:

- A quotation is VERIFIED as a statement when its primary source was read. The claim inside it keeps its own label. For example, IBM's statement that its products "now integrate with NVIDIA OpenShell" is VERIFIED as IBM's statement, while the integration itself is REPORTED.
- Absence statements scoped to one publisher's documents or to a pinned repository ("NVIDIA publishes no X", "absent at the pin") are VERIFIED. Absences across the open web are written "We found no X" and labeled INFERRED. Either kind can be overtaken by a later publication.
- Links show the source date in the link text. Pages without a visible date say "undated" and give the read date.

Pinned sources:

- OpenShell: [NVIDIA/OpenShell at acbac9c](https://github.com/NVIDIA/OpenShell/tree/acbac9cb795094986cbab016bfd0352d980b17f6), full hash `acbac9cb795094986cbab016bfd0352d980b17f6`. This is `main` shortly after the v0.1.2 tag, committed 2026-09-29 02:18 UTC (2026-09-28 in US time zones) [VERIFIED]. Citations at the v0.1.2 tag name its commit, OpenShell@6648bd0.
- ODIS: [cosai-oasis/ws4-odis at 148dc41](https://github.com/cosai-oasis/ws4-odis/tree/148dc4187139a41325e3c6d6e7533d956bd33144), full hash `148dc4187139a41325e3c6d6e7533d956bd33144` (2026-09-08).
- Citations take the form `path:line`. Paths that start with `RFCs/` or `contract-harness/` refer to ODIS@148dc41. Every other bare path refers to OpenShell@acbac9c. That includes `docs/`, `crates/`, `proto/`, `rfc/`, `architecture/`, `examples/`, `providers/`, and root files such as `GOVERNANCE.md`. The first path citation in each numbered section repeats the pin.
- A bare issue or pull request number such as #2109 means NVIDIA/OpenShell unless another repository is named. Numbers are linked, with a date, at their first mention in each numbered section.
- The local test ran OpenShell v0.1.2 with the Docker driver on an aarch64 host. Its setup and published results are described in [spike/README.md](spike/README.md), and [08-sources.md](08-sources.md) lists the logs that were not published.

## At a glance

Details and sources for each row are in the numbered sections.

| Piece | What it is | State on 2026-09-28 | Label |
|---|---|---|---|
| OpenShell | Agent runtime: gateway, per-sandbox supervisor, sandbox | Shipping; v0.1.2 is the latest release | VERIFIED |
| Sentry | Out-of-band watchdog on BlueField-4, built on DOCA, the software NVIDIA says "makes the BlueField security foundation programmable" | Reference system design with no date; closed source | VERIFIED (reference design, no date); REPORTED (closed source) |
| DOCA gateway | Component said to verify "each agent's identity and delegated authority" | Named in one blog post; no documentation, format, or API | VERIFIED |
| Secure Agent Workspace (SAW) | Reference architecture for per-user governed agent VMs | Reference design, last updated 2026-06-28 | VERIFIED |
| Open Delegation & Identity Standard (ODIS) | Identity and delegation draft in Workstream 4 (WS4) of the Coalition for Secure AI (CoSAI) | Unapproved contributor draft; text unchanged since 2026-08-03 | VERIFIED |
| Agent Policy Fabric (APF) | NVIDIA-internal authority and policy layer | No public specification or product; known from a job post, WS4 agendas, and an APF-shaped prototype issuer | VERIFIED (job post, prototype); REPORTED (agendas); INFERRED (scope) |
| Open Secure AI Alliance | Linux Foundation Directed Fund | Charter effective 2026-09-01; one RFC (SAFE) | VERIFIED |
| NemoClaw | Reference stack running OpenClaw, Hermes, and Deep Agents in OpenShell | Alpha; tags up to v0.0.129; pins `@nvidia/openshell-sdk` 0.0.116 | VERIFIED |
| NeMo Relay | In-process harness runtime with blocking hooks | v0.9.3 (2026-09-28), pre-1.0 | VERIFIED |

## 1. Announcement, layers, and principles

### What NVIDIA announced

Quotes in this subsection come from the [NVIDIA press release, 2026-09-28](https://nvidianews.nvidia.com/news/open-agent-safety-platform) unless noted.

- The platform "consists of NVIDIA OpenShell open source software and the NVIDIA Sentry reference system design" [VERIFIED].
- OpenShell is "now broadly available". It runs "with minimal overhead on NVIDIA Vera" and "can also be extended to work with third-party compute platforms, including those from Arm and Intel" [VERIFIED].
- Sentry "runs on NVIDIA BlueField-4 DPUs to continuously monitor agent behavior". If an agent "attempts to move outside its software boundary, Sentry quarantines and stops it in milliseconds" [VERIFIED]. NVIDIA publishes no latency measurement for this [VERIFIED].
- Sentry uses DOCA "to inspect agent requests and responses, provide attested telemetry, verify agent identity and enforce granular, zero-trust access policies for data, tools, application programming interfaces and services" [VERIFIED].
- Only "NVIDIA Open Agent Safety Platform software, including OpenShell and skills" is listed as available. Products "will be offered on a when-and-if-available basis". The release gives no Sentry date and no pricing [VERIFIED].
- The release describes the motivating incidents without names or links: "the agent circumvented security controls at the application layer to complete its assigned task" [VERIFIED]. The [developer blog, 2026-09-28](https://developer.nvidia.com/blog/nvidia-open-agent-safety-platform-a-reference-for-continuous-in-silicon-agent-monitoring/) adds that "Some of the agents even misreported what they did" [VERIFIED].
- The release attributes these statements and plans to partners. Section 10 labels what each partner has shipped [VERIFIED (release text)].
  - Anthropic: Claude Managed Agents run "the agent loop in a separate server from the sandboxes where their work executes", and "Integrations with OpenShell and BlueField enable enterprises to enforce strict control over agent access through those sandboxes."
  - SpaceXAI uses the platform "for Cursor coding agents and Grok models". Scale AI is incorporating it into the Scale GenAI Portfolio.
  - Salesforce integrated OpenShell with Slack for viewing agent activity and audit events and for approving or rejecting agent requests for additional permissions.
  - SAP is embedding OpenShell in the Joule Studio runtime and is "contributing engineering work to OpenShell".
  - "Over 100 organizations" are listed as working with the platform's technologies, including Cisco, CrowdStrike, IBM, Microsoft, Palantir, Palo Alto Networks, Perplexity, and ServiceNow.
  - The release also names robotics firms (Figure, Gecko Robotics, Skild AI), energy providers, Citi and JPMorganChase ("shared open source agent safety technologies"), Canonical, SUSE, and Red Hat. Red Hat "runs OpenShell and DOCA" on Red Hat AI Factory with NVIDIA.
- The release ties the platform to the Open Secure AI Alliance, "Initiated by NVIDIA alongside over 120 leading organizations and governed by the Linux Foundation" [VERIFIED].
- Anthropic's own post names OpenShell and does not mention BlueField. It says "Each layer is designed to enforce its limits independently" [VERIFIED] ([Anthropic, 2026-09-28](https://claude.com/blog/giving-companies-more-control-over-their-ai-agents-with-nvidia)). Neither announcement describes a shared authority or delegation model between Managed Agents and OpenShell [INFERRED].

| Date | Event | Source | Label |
|---|---|---|---|
| 2026-02-24 | OpenShell GitHub repository created | [NVIDIA/OpenShell, repository metadata read 2026-09-29](https://github.com/NVIDIA/OpenShell) | VERIFIED |
| 2026-03-16 | NVIDIA announces NemoClaw | [NVIDIA press release, 2026-03-16](https://nvidianews.nvidia.com/news/nvidia-announces-nemoclaw) | VERIFIED |
| 2026-03-18 | EQTY Lab announces "Verifiable Runtime" at GTC with an NVIDIA endorsement | [EQTY Lab, 2026-03-18](https://www.eqtylab.io/blog/introducing-verifiable-runtime) | VERIFIED |
| 2026-06-22 | Posting start date of NVIDIA's principal engineer role for "Agent Policy Fabric" (JR2019848) | [NVIDIA careers, JR2019848, posted 2026-06-22](https://jobs.nvidia.com/careers/job/893395763513) | VERIFIED |
| 2026-06-28 | Secure Agent Workspace reference design last updated | [SAW overview, 2026-06-28](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/what-is-secure-agent-workspace.html) | VERIFIED |
| 2026-07-27 | Open Secure AI Alliance launches with 37 partners | [Linux Foundation blog, 2026-07-27](https://www.linuxfoundation.org/blog/open-models-and-open-weights-are-foundational-to-secure-ai) | VERIFIED |
| 2026-07-30 | ODIS draft committed to cosai-oasis/ws4-odis; merged 2026-08-03 | [ws4-odis PR #4, merged 2026-08-03](https://github.com/cosai-oasis/ws4-odis/pull/4) | VERIFIED |
| 2026-08-25 | OPAQUE contributes TRACE, a runtime evidence specification for AI workloads, to the Linux Foundation | [Linux Foundation, 2026-08-25](https://www.linuxfoundation.org/press/linux-foundation-welcomes-trace-to-advance-verifiable-runtime-evidence-for-ai-workloads) | VERIFIED |
| 2026-09-01 | Alliance charter takes effect; HashiCorp Vault Agentic IAM becomes generally available | [Alliance charter, effective 2026-09-01](https://cdn.platform.linuxfoundation.org/agreements/osaia.pdf); [HashiCorp, 2026-09-01](https://www.hashicorp.com/en/blog/hashicorp-vault-agentic-iam-is-now-generally-available) | VERIFIED |
| 2026-09-09 | OpenShell PR #3195 removes managed inference routing | [PR #3195, merged 2026-09-09](https://github.com/NVIDIA/OpenShell/pull/3195) | VERIFIED |
| 2026-09-14 | Alliance joins the Linux Foundation | [Linux Foundation blog, 2026-09-14](https://www.linuxfoundation.org/blog/open-secure-ai-alliance-joins-the-linux-foundation-to-build-a-shared-open-defense-stack-for-the-ai-era) | VERIFIED |
| 2026-09-21 | Bulk "not planned" closure of OpenShell issues, including evidence-bundle and identity-broker proposals | [#2745, closed 2026-09-21](https://github.com/NVIDIA/OpenShell/issues/2745); [#1756, closed 2026-09-21](https://github.com/NVIDIA/OpenShell/issues/1756) | VERIFIED |
| 2026-09-25 | OpenShell v0.1.0 published | [OpenShell releases, read 2026-09-29](https://github.com/NVIDIA/OpenShell/releases) | VERIFIED |
| 2026-09-26 | OpenShell v0.1.1; the Cloud Native Computing Foundation (CNCF) Technical Oversight Committee (TOC) vote on Sandbox status passes | [OpenShell releases, read 2026-09-29](https://github.com/NVIDIA/OpenShell/releases); [cncf/sandbox#522, vote passed 2026-09-26](https://github.com/cncf/sandbox/issues/522) | VERIFIED |
| 2026-09-28 | OpenShell v0.1.2; platform announced | [OpenShell releases, read 2026-09-29](https://github.com/NVIDIA/OpenShell/releases); [NVIDIA press release, 2026-09-28](https://nvidianews.nvidia.com/news/open-agent-safety-platform) | VERIFIED |

### Three layers

The developer blog defines three layers [VERIFIED] ([developer blog, 2026-09-28](https://developer.nvidia.com/blog/nvidia-open-agent-safety-platform-a-reference-for-continuous-in-silicon-agent-monitoring/)). The OpenShell technical blog says OpenShell "provides the runtime layer" of the platform [VERIFIED] ([OpenShell blog, 2026-09-28](https://developer.nvidia.com/blog/add-runtime-controls-to-ai-agents-with-nvidia-openshell/)).

| Layer | NVIDIA definition | NVIDIA components | Label |
|---|---|---|---|
| Application | "What end-users are building. Contains the necessary primitives for mission success: models, harnesses, tools, data, and support scripts and programs." | NemoClaw, NeMo Agent Toolkit, AI-Q, NeMo Relay, Nemotron | VERIFIED (definition); INFERRED (mapping) |
| Runtime | "Projects the application layer onto infrastructure" and "provides continuous monitoring and real-time policy enforcement and governance." | OpenShell | VERIFIED |
| Infrastructure | "Concrete hardware resources used to execute agentic workloads." | Vera CPU, BlueField-4, DOCA, Sentry | VERIFIED (definition); INFERRED (mapping) |

### Five principles

The developer blog lists five "core principles for building an agent system" [VERIFIED] ([developer blog, 2026-09-28](https://developer.nvidia.com/blog/nvidia-open-agent-safety-platform-a-reference-for-continuous-in-silicon-agent-monitoring/)). The third column records what exists against each one.

| Principle | NVIDIA wording | What exists on 2026-09-28 | Label |
|---|---|---|---|
| Policy needs to be verifiable | "Before an agent runs, a prover shows that its policy cannot escape the intent of the operator." | OpenShell ships a Z3 prover. It models filesystem, L4, REST, process, and Landlock rules and returns `unsupported` for MCP, GraphQL, and JSON-RPC rules (section 4). | VERIFIED |
| Enforcement must be out of band | "The controls do not live inside, or within reach of the agent." | OpenShell's supervisor runs outside the workload (section 2). Sentry is a reference design. | VERIFIED |
| The path to the model (the brain) is the control point | "By controlling the path to the model, you own both the best observation point and also the kill switch to interrupt it if you need to." | OpenShell 0.1.0 removed its model-aware inference router, so model traffic is ordinary egress (section 2). NVIDIA places BlueField-4, which runs Sentry, "on the node's only path to the model" (section 5). Sentry has not shipped. | VERIFIED |
| Scale agent authority with the ability to inspect its thinking | "The more an agent can do, the more its reasoning needs to be visible." | No shipped mechanism ties granted authority to reasoning visibility. | INFERRED |
| Applying the shared responsibility model | "The agent runtime and its policy language need to be open so any provider can plug in." | OpenShell and its Rego policy engine are open source. Sentry is not open source. | VERIFIED (OpenShell); REPORTED (Sentry) |

The Sentry status comes from press coverage of a briefing. The New Stack reports that Sentry "isn't open source" and that NVIDIA's Justin Boitano said it has open APIs. Boitano said "The DPU is really optional in these architectures" [REPORTED] ([The New Stack, 2026-09-28](https://thenewstack.io/nvidia-openshell-sentry-agents/)). The developer blog also describes Sentry as "an optional security layer alongside OpenShell" [VERIFIED] ([developer blog, 2026-09-28](https://developer.nvidia.com/blog/nvidia-open-agent-safety-platform-a-reference-for-continuous-in-silicon-agent-monitoring/)).

## 2. OpenShell: release, architecture, and policy

### Release and footprint

- OpenShell is Apache-2.0. At the pin it is a Rust workspace of 38 crates with gRPC contracts under `proto/` and SDKs for Python, Go, Rust, and TypeScript [VERIFIED] (OpenShell@acbac9c `crates/`, `proto/`, `docs/sdk/`).
- GitHub releases: v0.1.0 on 2026-09-25, v0.1.1 on 2026-09-26, and v0.1.2 (latest) on 2026-09-28. The 0.0.x line ran to v0.0.116 (2026-08-28). The repository had about 9,600 stars on 2026-09-29 [VERIFIED] ([OpenShell releases, read 2026-09-29](https://github.com/NVIDIA/OpenShell/releases)). The launch blog calls the release "OpenShell 0.1.0" [VERIFIED] ([OpenShell blog, 2026-09-28](https://developer.nvidia.com/blog/add-runtime-controls-to-ai-agents-with-nvidia-openshell/)).
- The launch blog lists "Codex, Claude Code, Pi, Hermes" as supported agents [VERIFIED] ([OpenShell blog, 2026-09-28](https://developer.nvidia.com/blog/add-runtime-controls-to-ai-agents-with-nvidia-openshell/)). OpenShell has no built-in harness integration. The gateway ships no provider profiles, the default image contains no agent CLI, and an agent runs as the sandbox's main process [VERIFIED] (`docs/how-it-works/providers/profiles.mdx:250`; `docs/upgrade/0-1-0.mdx:55`; `docs/about/run-your-first-agent.mdx:13`; `docs/how-it-works/sandboxes/overview.mdx:23`).
- The repository carries example provider profiles for anthropic, aws-bedrock, aws-s3, aws, claude-code, codex, copilot, cursor, deepinfra, github, google-cloud, google-vertex-ai, nvidia, openai, openrouter, and pypi [VERIFIED] (`providers/`).
- Published gateway and supervisor images carry SPDX SBOM attestations and minimal SLSA provenance [VERIFIED] (`docs/security/verify-image-contents.mdx:12, 35`).
- RFC 0014 (state: review) proposes nightly pre-releases, "qualified stable releases every Tuesday", and Stable versus Experimental API maturity [PROPOSED] (`rfc/0014-release-stability/README.md:19-21`).
- NVIDIA's product page still says "OpenShell includes a policy-aware inference router", which 0.1.0 removed. The same page says OpenShell "integrates with the enterprise ecosystem rather than replacing it". It lists identity providers, secret stores, observability, security tooling, and governance platforms as surrounding systems [VERIFIED] ([OpenShell product page, undated, read 2026-09-28](https://www.nvidia.com/en-us/ai/openshell/)).

### Architecture: gateway, supervisor, sandbox

| Component | Role | Label |
|---|---|---|
| Gateway | Control plane. Manages sandbox lifecycle, authenticates users, delivers policy and settings, attaches providers, and coordinates sessions. "The gateway is the only component that signs credentials, and every credential names exactly one sandbox." | VERIFIED (`docs/about/architecture.mdx:18-23, 36, 118-119`) |
| Compute driver | Provisions the workload and a separate supervisor, sets up their channel, and builds the isolation boundary and the outer network fence. | VERIFIED (`docs/about/architecture.mdx:18-23`) |
| Supervisor | Trusted side of the boundary. It "checks requests against policy, supplies credentials, resolves DNS, opens approved connections". It confirms the boundary before starting the agent. | VERIFIED (`docs/about/architecture.mdx:18-23, 32`) |
| Sandbox | Inside the boundary with the agent. Owns the agent's processes, identifies the calling executable from trusted `/proc` data, stages network operations with seccomp user notification, and forwards TCP and DNS to the supervisor. It "never makes policy decisions". | VERIFIED (`docs/about/architecture.mdx:30, 39-51, 73-74`) |

The runtime builds the boundary but "never decides whether a request is allowed"; that belongs to the supervisor and its policy engine [VERIFIED] (`docs/about/architecture.mdx:107-110`).

| Runtime | Supervisor placement | Supervisor-to-sandbox channel | How direct egress is blocked | Label |
|---|---|---|---|---|
| Docker | Own container | Authenticated Unix socket | Workload container has networking turned off | VERIFIED |
| Podman | Own container | Authenticated Unix socket | Workload container has networking turned off | VERIFIED |
| Kubernetes | Own pod | Private service with mutual TLS | NetworkPolicy allows only the supervisor service | VERIFIED |
| MicroVM | Process on the host | Authenticated vsock | Guest has no network device | VERIFIED |

Source: `docs/about/architecture.mdx:100-105`.

- The gateway issues a gateway JWT (supervisor to gateway) and a sandbox JWT (supervisor to sandbox). "Both are bound to one sandbox and one run of that sandbox, called a generation." A restart starts a new generation with fresh tokens and TLS certificates [VERIFIED] (`docs/about/architecture.mdx:143-158`).
- On Kubernetes the supervisor presents its pod's ServiceAccount token, which the driver verifies before the gateway issues JWTs [VERIFIED] (`docs/about/architecture.mdx:129-141`).
- The Kubernetes driver requires the kubernetes-sigs Agent Sandbox controller [VERIFIED] (`docs/how-it-works/sandboxes/runtimes.mdx:188`).
- A Windows driver built on Microsoft Execution Containers (MXC) is listed as "Coming soon", and RFC 0013 is in review [VERIFIED] (`docs/how-it-works/sandboxes/runtimes.mdx:24`; `rfc/0013-native-windows-mxc/README.md:20-21`).
- `openshell-supervisor --role=network-proxy` runs the policy proxy without a sandbox, so another runtime can reuse OpenShell's egress engine [VERIFIED] (`architecture/sandbox.md:207`).

### Policy model

- The security guide describes four enforcement layers: "network, filesystem, process, and provider credentials" [VERIFIED] (`docs/security/best-practices.mdx:12`).
- A policy file sets `version: 1` and up to five sections [VERIFIED] (`docs/how-it-works/policies/overview.mdx:22-33`):

| Section | Controls | Enforced by | Takes effect | Label |
|---|---|---|---|---|
| `filesystem_policy` | Read or read-write paths | Landlock | At sandbox startup | VERIFIED |
| `landlock` | Whether the sandbox starts if filesystem rules cannot be applied | Sandbox runtime | At sandbox startup | VERIFIED |
| `process` | User and group of sandbox processes | Docker and Podman at creation | At sandbox creation | VERIFIED |
| `network_policies` | Destinations each binary can reach and the requests it can send | Sandbox network proxy | While the sandbox runs | VERIFIED |
| `network_middlewares` | Extra inspection, transformation, or blocking of allowed traffic | Sandbox network proxy | While the sandbox runs | VERIFIED |

- Descriptions of OpenShell that include inference routing as a policy domain describe the 0.0.x line. 0.1.0 removed "The `openshell inference` commands, route APIs, and `inference.local` endpoint" [VERIFIED] (`docs/upgrade/0-1-0.mdx:95`; [PR #3195, merged 2026-09-09](https://github.com/NVIDIA/OpenShell/pull/3195)). Model access is now a provider attachment and ordinary egress to the provider's native endpoint [VERIFIED] (`docs/how-it-works/inference.mdx:11`).
- The launch blog says policies are "authored in YAML and compiled to OPA/Rego" [VERIFIED] ([OpenShell blog, 2026-09-28](https://developer.nvidia.com/blog/add-runtime-controls-to-ai-agents-with-nvidia-openshell/)). In code, no Rego is generated per policy. The regorus engine (regorus 0.9) evaluates policy data in process against one baked module, `crates/openshell-supervisor-network/data/sandbox-policy.rego` [VERIFIED] (`crates/openshell-supervisor-network/Cargo.toml:39`).
- Egress is denied unless a rule allows it. Each rule binds destinations to the binaries that may reach them. `protocol` selects request inspection (`rest`, `websocket`, `graphql`, `mcp`, `json-rpc`) or `tcp`, and `tls: skip` relays traffic without inspection. `enforcement` defaults to `audit`, which logs violations and allows the request; `enforce` blocks them [VERIFIED] (`docs/how-it-works/policies/schema.mdx:155-157`).
- Network rules and middleware reload while the sandbox runs. The supervisor polls the gateway for policy every 10 seconds by default (`OPENSHELL_POLICY_POLL_INTERVAL_SECS`) [VERIFIED] (`crates/openshell-supervisor/src/lib.rs:1026-1029`).
- Each policy revision has a monotonically increasing version and a deterministic SHA-256 `policy_hash` [VERIFIED] (`proto/openshell.proto:2867-2875`; `crates/openshell-core/src/policy_identity.rs:173-177`). Configuration audit events carry both as unmapped fields [VERIFIED] (`crates/openshell-server/src/grpc/policy.rs:349-354`; `crates/openshell-ocsf/src/format/shorthand.rs:489-494`). The middleware request context has no revision field [VERIFIED] (`proto/supervisor_middleware.proto:583-598`).
- Inside the sandbox, `GET /v1/policy/current` returns the effective policy as YAML without a hash [VERIFIED] (`docs/how-it-works/policies/advisor.mdx:278`; `crates/openshell-supervisor-network/src/policy_local.rs:288-315`). When the advisor is enabled, proposal status responses carry the current and candidate effective-policy hashes [VERIFIED] (`crates/openshell-supervisor-network/src/policy_local.rs:833-849`; `crates/openshell-server/src/grpc/policy.rs:655-663`). Neither gives a per-request binding [INFERRED].
- Provider profiles bind credentials, endpoints, and permitted binaries. The agent sees an opaque placeholder. The supervisor substitutes the real credential only for requests to profile-bound endpoints from allowed binaries. "If the agent sends the placeholder to a destination outside the credential's approved endpoints, OpenShell rejects the request" [VERIFIED] ([OpenShell blog, 2026-09-28](https://developer.nvidia.com/blog/add-runtime-controls-to-ai-agents-with-nvidia-openshell/)).
- When gateway configuration selects only an interceptor as the profile source, that interceptor's catalog is authoritative [VERIFIED] (`docs/how-it-works/providers/profiles.mdx:35`).

### MCP rules and their limits

- `protocol: mcp` endpoints validate JSON-RPC structure with `tower-mcp-types` 0.22.2. They allow or deny by `method`, `tool`, or `params.name`, which is the "Lower-level equivalent of `tool`" [VERIFIED] (`Cargo.toml:91`; `docs/how-it-works/policies/schema.mdx:334-340`).
- "Tool arguments are not matched, so an allowed tool accepts any arguments." "Server responses and server-to-client messages are not inspected." [VERIFIED] (`docs/how-it-works/policies/schema.mdx:347-349`). `Mcp-Param-*` headers are forwarded without comparison [VERIFIED] (`docs/how-it-works/policies/schema.mdx:445-446`).
- At the pin, policy validation rejects MCP argument matchers with "MCP tool argument matching is not supported yet", and no argument matching is implemented [VERIFIED] (`crates/openshell-supervisor-network/src/l7/mod.rs:1025-1030`; `docs/how-it-works/policies/schema.mdx:347`).
- The v0.1.2 release accepts revisions 2025-03-26, 2025-06-18, and 2025-11-25, with 2025-11-25 the default [VERIFIED] (`docs/how-it-works/policies/schema.mdx:371-372` at the v0.1.2 tag, OpenShell@6648bd0). The pin adds an opt-in sessionless 2026-07-28 profile that checks `Mcp-Method` and `Mcp-Name` headers against the body [VERIFIED] (`docs/how-it-works/policies/schema.mdx:383-446`).
- MCP request bodies are inspected up to 64 KiB by default (`mcp.max_body_bytes`) [VERIFIED] (`docs/how-it-works/policies/schema.mdx:204`).
- Enforcement sits at network egress. RFC 0002 notes that "local stdio MCP does not map neatly to network enforcement" [VERIFIED] (`rfc/0002-agent-driven-policy-management/README.md:437`). Stdio MCP servers inside the sandbox are therefore outside MCP rule enforcement [INFERRED].
- The prover returns `unsupported` for MCP rules [VERIFIED] (`docs/how-it-works/policies/prover.mdx:47-49`). The advisor API "has no fields for GraphQL operation rules, MCP tool rules" [VERIFIED] (`docs/how-it-works/policies/advisor.mdx:251-252`).
- RFC 0002 plans "MCP-aware controls" as "a later dedicated track" [PROPOSED] (`rfc/0002-agent-driven-policy-management/README.md:437`).

### Isolation

| Control | Mechanism | Changes at runtime | Label |
|---|---|---|---|
| Filesystem | Landlock. A mandatory baseline needs Landlock ABI 3 (Linux 6.2), and "Startup fails if this baseline cannot be enforced". `filesystem_policy` adds rules on top; the `landlock` setting is `best_effort` by default or `hard_requirement`. | No | VERIFIED (`docs/security/best-practices.mdx:163-169`; `crates/openshell-core/src/policy.rs:99-103`) |
| Process | In the current Linux backend, one non-root identity with no Linux capabilities; privilege drop; seccomp in two phases. The filter "uses a default-allow policy with targeted blocks" (raw sockets, ptrace, BPF, `io_uring`, mount, and others). | No | VERIFIED (`docs/about/architecture.mdx:47-50`; `crates/openshell-sandbox/src/sandbox/linux/seccomp.rs:6`; `docs/security/best-practices.mdx:216-238`) |
| Network | The supervisor channel is the workload's only egress; each runtime builds the outer fence. The security guide also describes a dedicated network namespace with a veth pair. | Rules only | VERIFIED (`docs/about/architecture.mdx:100-105`; `docs/security/best-practices.mdx:53-56`) |
| Program identity | "OpenShell pins every authorization-capable path to its first runtime-observed SHA256 digest (trust on first use), and a later digest mismatch triggers an immediate deny." A rule can match the connection-owning executable "or one of its executable ancestors", so a rule for a parent also covers its children. | Not applicable | VERIFIED (`docs/security/best-practices.mdx:82-85`) |
| User namespaces | Optional on Kubernetes 1.33 and later; GPU compatibility unverified | Not applicable | VERIFIED (`docs/security/best-practices.mdx:66-78`) |

- The docs disagree on where network enforcement runs. The security guide says "The CONNECT proxy and OPA policy engine enforce all network controls at the gateway level" (`docs/security/best-practices.mdx:38`). The architecture page places enforcement in the per-sandbox supervisor (`docs/about/architecture.mdx:18-23, 107-110`), and so does the code (`crates/openshell-supervisor-network/`) [VERIFIED].
- In the current Linux backend, all workload processes run as one non-root identity with no capabilities [VERIFIED] (`docs/about/architecture.mdx:47-50`). Filesystem and seccomp limits apply to the whole workload, so binary-scoped network rules are the only control that treats one program differently from another [INFERRED]. Any helper placed inside the sandbox therefore shares the agent's filesystem and process rights [INFERRED].

## 3. OpenShell: identity and extension surface

### Identity

| Principal | How it authenticates | Authorization | Label |
|---|---|---|---|
| User or automation | mTLS client certificate (default for local Docker, Podman, and VM gateways); OIDC bearer JWT (Keycloak, Entra ID, and Okta are the documented examples; RSA (RS and PS), ES256, ES384, and EdDSA keys); edge JWT from a reverse proxy such as Cloudflare Access; an explicitly enabled local development mode | Platform Admin is the OIDC role configured as `admin_role`. Workspace Admin and Workspace User are membership records stored by the gateway. An optional scopes claim (for example `sandbox:read`) narrows calls. | VERIFIED (OpenShell@acbac9c `docs/how-it-works/gateways/authentication.mdx:34-38, 74, 101, 209-214, 226, 248-250`; `docs/how-it-works/workspaces.mdx:25-33`) |
| Sandbox supervisor | Gateway-minted JWTs bound to one sandbox and one generation; on Kubernetes, a projected ServiceAccount token verified by the driver | Only the calls a supervisor needs | VERIFIED (`docs/about/architecture.mdx:143-158`; `docs/how-it-works/gateways/authentication.mdx:226`) |
| Workload toward upstream services | SPIFFE JWT-SVID from the Workload API, used as an RFC 7523 client assertion (`client_credentials`) or in a gateway-brokered RFC 8693 exchange of a stored user OIDC token (`token_exchange`) | Short-lived upstream token injected only at matching profile endpoints; not available for `tls: skip` endpoints | VERIFIED (`docs/how-it-works/providers/profiles.mdx:46, 562-604`) |
| Extension services | Gateway-issued EdDSA JWT (see "Extension authentication") | Set by the extension | VERIFIED (`docs/extensibility/overview.mdx:109-147`) |

- Local gateways without OIDC role configuration treat authenticated users as Platform Admins [VERIFIED] (`docs/how-it-works/workspaces.mdx:61-62`).
- SPIFFE token grants merged in [PR #1784, merged 2026-06-10](https://github.com/NVIDIA/OpenShell/pull/1784) [VERIFIED].
- [PR #1970, merged 2026-08-24](https://github.com/NVIDIA/OpenShell/pull/1970), added a gateway-brokered RFC 8693 `token_exchange` of a stored user OIDC subject token [VERIFIED] (`docs/how-it-works/providers/profiles.mdx:563, 574`).
- The upstream token endpoint, not OpenShell, mints the resulting token (`docs/how-it-works/providers/profiles.mdx:563`). In the pinned token-exchange demo, a sample issuer sets the claims itself and returns the user as `sub` and the sandbox SPIFFE ID as `azp` [VERIFIED] (`examples/spiffe-token-exchange-demo/README.md:157-166`; `examples/spiffe-token-exchange-demo/k8s/token-issuer.js:294-300`).
- [Issue #1987, closed 2026-08-24](https://github.com/NVIDIA/OpenShell/issues/1987), asked OpenShell for the user as `sub` and the sandbox SPIFFE identity as `azp`. It was closed as completed, but its only linked implementation, [PR #2772, last updated 2026-09-16](https://github.com/NVIDIA/OpenShell/pull/2772), is still open. `azp` appears nowhere in OpenShell's `crates/`, `proto/`, `docs/`, or `architecture/` at the pin [VERIFIED]. That delegation, as an OpenShell feature, is PROPOSED.
- Open PR #2772 would add time-bounded, withdrawable delegation of the sandbox creator's OIDC identity (`--delegate-identity-for=8h`) [PROPOSED].
- Token grants need a SPIFFE Workload API socket [VERIFIED] (`docs/how-it-works/providers/profiles.mdx:604`). Kubernetes is the documented path, and [#2708, 2026-08-11](https://github.com/NVIDIA/OpenShell/issues/2708), asks for Docker, Podman, and VM support [VERIFIED].
- Absent at the pin: agent-level identity, delegation chains, runtime attestation, cross-gateway federation, and multi-provider OIDC [VERIFIED]. Draft RFC 0011 lists cross-gateway federation and multi-provider OIDC as non-goals [VERIFIED] (`rfc/0011-multi-player-design/README.md:55-73`).
- Accepted RFC 0001 designs `ControlPlaneIdentityDriver` and `SandboxIdentityDriver` plugins, which have no proto or code at the pin [VERIFIED] (`rfc/0001-core-architecture/README.md:109, 168`).
- Approving a proposed policy chunk requires an authenticated caller. `ApproveDraftChunkRequest` carries only the sandbox, workspace scope, `chunk_id`, `review_token`, and `request_id`, and the approval audit event does not name the approver [VERIFIED] (`proto/openshell.proto:3332-3344`; `crates/openshell-server/src/grpc/policy.rs:326-360`).
- On 2026-09-21 maintainers closed four issuer-side broker proposals as not planned. The closures came in the same no-comment sweep described under "Governance and contribution" in section 4 [VERIFIED]:
  - Entra Agent ID `user_fic` tokens ([#1667, opened 2026-06-01](https://github.com/NVIDIA/OpenShell/issues/1667));
  - an `actor_token` delegation-chain gap ([#1736, opened 2026-06-03](https://github.com/NVIDIA/OpenShell/issues/1736));
  - scope attenuation for broker-issued downstream tokens ([#1756, opened 2026-06-04](https://github.com/NVIDIA/OpenShell/issues/1756));
  - Okta Cross-App Access ([#2637, opened 2026-08-06](https://github.com/NVIDIA/OpenShell/issues/2637)).
- No rationale was given for those closures. OpenShell does ship a gateway-brokered `token_exchange` [VERIFIED] (`docs/how-it-works/providers/profiles.mdx:563`).
- A proposal to bind agents to Ed25519 passport identities ([#682, closed 2026-05-30](https://github.com/NVIDIA/OpenShell/issues/682)) was closed as not planned [VERIFIED].

### Supervisor middleware

The launch blog's "trusted middleware" that can "connect identity services and add application-specific checks" is supervisor middleware [VERIFIED] ([OpenShell blog, 2026-09-28](https://developer.nvidia.com/blog/add-runtime-controls-to-ai-agents-with-nvidia-openshell/)). It runs "after policy evaluation and before OpenShell injects provider credentials" [VERIFIED] (`docs/extensibility/overview.mdx:28-33`).

Contract (package `openshell.middleware.v1`, `proto/supervisor_middleware.proto`) [VERIFIED]:

| Operation | Phase | When it runs | RPC |
|---|---|---|---|
| `HTTP_REQUEST` | `PRE_CREDENTIALS` | After network policy allows a request, before credential injection | `SupervisorMiddleware.EvaluateHttpRequest` (unary) |
| `HTTP_RESPONSE` | `PRE_RETURN` | After the upstream responds, before the sandbox receives the response | `HttpResponsePreReturn.Evaluate` (stream) |
| `WEBSOCKET_MESSAGE` | `PRE_CREDENTIALS` | On upgrade and for each text message the sandbox sends | `SupervisorMiddleware.EvaluateWebSocketSession` (stream) |

`Describe` returns the service manifest, and `ValidateConfig` checks per-binding configuration [VERIFIED] (`proto/supervisor_middleware.proto:15-35`; `docs/extensibility/supervisor-middleware/operations.mdx:15-19`).

`HttpRequestEvaluation` fields (`proto/supervisor_middleware.proto:108-129`) [VERIFIED]:

| Field | Content and limit |
|---|---|
| `phase` | Evaluation phase selected for the request |
| `context` | `RequestContext`; at most 4 KiB encoded |
| `config` | The policy-authored `Struct`; at most 64 KiB encoded |
| `target` | `HttpRequestTarget`; at most 32 KiB encoded |
| `headers` | Request headers before credential injection, in wire order; protected credential, routing, framing, and hop-by-hop headers omitted; at most 128 lines and 64 KiB |
| `body` | Buffered request body; at most 4 MiB |
| `middleware_name` | Built-in middleware name or operator-owned registration name |

Nested messages [VERIFIED]:

- `RequestContext`: `request_id` ("used to correlate middleware and supervisor logs"), `sandbox_id`, `originating_process`, `sandbox` (name, display only), and `workspace` (display only) (`proto/supervisor_middleware.proto:583-598`).
- `Process`: `binary`, `pid`, and `ancestors` (nearest parent first) (`proto/supervisor_middleware.proto:617-624`).
- `HttpRequestTarget`: `scheme`, `host`, `port`, `method`, `path`, and `query` (`proto/supervisor_middleware.proto:601-614`).

Result fields (`HttpRequestResult`, `proto/supervisor_middleware.proto:687-720`) [VERIFIED]:

- `decision`: `DECISION_ALLOW` or `DECISION_DENY`.
- `reason`: free text, at most 4 KiB, never relayed into denied responses or security logs.
- `body` and `has_body`: replacement body, at most 4 MiB.
- `header_mutations`: ordered writes and removals, at most 64 operations. Written values cannot contain credential placeholder syntax.
- `findings`: at most 32 per stage. Each `Finding` has `type`, `label`, `count`, `confidence`, and `severity`. For operator-run services OpenShell logs platform-owned fields "rather than service-provided type, label, confidence, or metadata text".
- `metadata`: at most 64 string entries; not logged.
- `reason_code`: 1 to 64 bytes of lowercase ASCII letters, digits, and underscores, starting with a letter. OpenShell may return it to the requester and includes it in logs.

Behavior and limits:

- A policy selects at most 10 middleware stages, run in ascending `order` [VERIFIED] (`proto/supervisor_middleware.proto:710`; `docs/extensibility/supervisor-middleware/operations.mdx:23`).
- `timeout` defaults to 500 ms (10 ms to 30 s). `on_error` defaults to `fail_closed`. `fail_open` skips failed middleware, emits a detection finding, and "Future releases may remove it" [VERIFIED] (`docs/extensibility/supervisor-middleware/configure.mdx:47-48, 152-172`).
- Services are registered statically in gateway TOML under `[[openshell.supervisor.middleware]]`, and changing registrations requires a gateway restart. Policies select them through `network_middlewares` [VERIFIED] (`docs/extensibility/supervisor-middleware/configure.mdx:21-27, 184`).
- Protected request headers are `authorization`, `proxy-authorization`, `proxy-authenticate`, `cookie`, `host`, framing and hop-by-hop headers, `x-amz-*`, and `x-openshell-credential*`. Middleware can neither see nor change them [VERIFIED] (`crates/openshell-supervisor-middleware/src/headers.rs:288-306`).
- Other headers, including custom ones, reach middleware [VERIFIED] (`proto/supervisor_middleware.proto:120-124`). In the local test, a custom header also reached the upstream unless the middleware removed it [VERIFIED (local test)].
- Inspected HTTP/1 request headers are capped at 16 KiB; larger requests are rejected [VERIFIED] (`architecture/sandbox-limits.md:98`).
- Middleware does not inspect WebSocket binary messages, server-to-agent messages, compressed or partial response bodies, or `tls: skip` endpoints [VERIFIED] (`docs/extensibility/supervisor-middleware/index.mdx:52-58`).
- `originating_process` is set to `None` at every construction site at the pin, so middleware never receives process identity [VERIFIED] (`crates/openshell-supervisor-middleware/src/lib.rs:1710`; `crates/openshell-supervisor-middleware/src/websocket.rs:962`; `crates/openshell-supervisor-network/src/l7/relay.rs:637`; `crates/openshell-supervisor-network/src/l7/middleware.rs:95`).
- The request context carries no human principal, agent identity, delegation, or policy revision [VERIFIED] (`proto/supervisor_middleware.proto:583-598`).
- The docs say "The middleware API is still evolving" [VERIFIED] (`docs/extensibility/supervisor-middleware/index.mdx:79`). RFC 0009 is accepted but calls the first release "a research preview" whose contract "may change without the usual compatibility guarantees" [VERIFIED] (`rfc/0009-supervisor-middleware/README.md:474-476`). Phase 2 removes plaintext transport [PROPOSED] (`rfc/0009-supervisor-middleware/README.md:468`).
- A maintainer issue proposes replacing the unary request hook with a streaming hook as a deliberate breaking change [PROPOSED] ([#3307, opened 2026-09-14](https://github.com/NVIDIA/OpenShell/issues/3307)).
- RFC 0009 defers three items [PROPOSED] (`rfc/0009-supervisor-middleware/README.md:437, 545-549`):
  - a metadata-only `HttpResponse/completed` hook for "Budget-style middleware that needs post-call status, final route/model, content length, or token usage";
  - authenticated transport such as mTLS;
  - WASM, sidecar, and in-sandbox deployment modes, which have "no committed timeline".

Observed in the local test of OpenShell v0.1.2 (Docker driver, aarch64 host, 2026-09-29) [VERIFIED (local test)]. Audit events here are Open Cybersecurity Schema Framework (OCSF) records, covered in section 4.

| Observation | Result |
|---|---|
| Failure handling | `fail_closed` held when the middleware crashed, timed out, or restarted. A gateway that cannot reach a registered middleware at startup refuses to start. |
| Process identity | `originating_process` was absent in all 3,934 request evaluations. |
| Custom headers | A custom capability header reached the middleware and, unless the middleware removed it, the upstream. A 20.8 KB header exceeded the 16 KiB cap. |
| Body access | The middleware received full MCP `tools/call` bodies, including arguments, up to exactly 4 MiB, and could deny on argument values. |
| Latency at 1 KB, same host, p50 | About +0.19 ms for an in-process built-in, +2.0 ms for NVIDIA's Rust example service, and +2.9 ms for a no-op Python gRPC service. |
| Policy binding | Requests carry no policy revision; version and hash are available only out of band. Create-to-load lag ranged from about 0.05 to 9.8 s across the revisions measured, and some revisions never loaded. A reference placed in the middleware `config` arrived 19 to 24 ms after the recorded policy load. |
| Audit visibility | Findings from an operator-run service were replaced and metadata cleared in OCSF. A `reason_code` reached OCSF only on deny. OCSF events carried no `request_id`. |
| Evidence divergence | A timed-out middleware could record "allow" for a request OpenShell denied. `fail_open` forwarded the raw custom header upstream. Under load, a response-phase failure returned 502 after the upstream side effect had run. |
| MCP 2026-07-28 | v0.1.2 could not inspect it; routing the endpoint as `protocol: rest` let middleware enforce it. |

The test setup and published results are described in [spike/README.md](spike/README.md), and [08-sources.md](08-sources.md) lists the logs that were not published.

### Gateway interceptors

Gateway interceptors are the control-plane hook (package `openshell.gateway_interceptor.v1`, `proto/gateway_interceptor.proto`) [VERIFIED]:

- RPCs: `Describe`, `SnapshotProviderProfiles` (when the manifest sets `provider_profiles = true`), and `Evaluate` (`proto/gateway_interceptor.proto:15-27`).
- Phases: `MODIFY_OPERATION` (allow, deny, or RFC 6902 JSON patches), `VALIDATE` (allow or deny, with optional read-only `current_state`), and `POST_COMMIT` (observe the committed response; bindings that include it must resolve to `fail_open`) (`proto/gateway_interceptor.proto:36-41, 66-81, 124-136`).
- `InterceptorEvaluation` carries `interceptor_name`, `binding_id`, `service`, `method`, a `principal` map, and one phase payload. `InterceptorResult` carries `allowed`, `reason`, `status_code`, `patches`, and `log_annotations`, which are non-secret annotations included in gateway logs (`proto/gateway_interceptor.proto:43-95`).
- The `principal` map is "intentionally non-secret". For users it holds `kind=user`, `subject`, `display_name`, `provider` (`oidc`, `mtls`, `cloudflare_access`, `local_dev`), `roles`, and `scopes`. For sandboxes it holds `kind=sandbox`, `sandbox_id`, `source` (`bootstrap_jwt`, `bootstrap_cert`, `compute_driver`), and `trust_domain`. Peers carry `replica_id` and `pod_uid`; other callers are `anonymous` or `unknown` (`crates/openshell-server/src/multiplex.rs:650-711`).
- Interceptable RPCs are 25 unary writes (`crates/openshell-gateway-interceptors/src/routes.rs:17-43`):

| Area | RPCs |
|---|---|
| Sandboxes | CreateSandbox, DeleteSandbox, AttachSandboxProvider, DetachSandboxProvider |
| Sessions and services | CreateSshSession, RevokeSshSession, ExposeService, DeleteService |
| Providers | CreateProvider, UpdateProvider, DeleteProvider, ImportProviderProfiles, UpdateProviderProfiles, DeleteProviderProfile, ConfigureProviderRefresh, DeleteProviderRefresh, RotateProviderCredential |
| Configuration and policy | UpdateConfig, SubmitPolicyAnalysis, ApproveDraftChunk, RejectDraftChunk, ApproveAllDraftChunks, EditDraftChunk, UndoDraftChunk, ClearDraftChunks |

- Exec, start and stop, and workspace-membership RPCs are absent from the allowlist and cannot be intercepted [VERIFIED] (`crates/openshell-gateway-interceptors/src/routes.rs:17-43`).
- Each binding sets `fail_closed` or `fail_open`. The operator's `binding_policy` is `dynamic` (the compatibility default, which logs a startup warning), `allowlist`, or `exact`. The docs say to use `allowlist` or `exact` "when interceptor authority is part of a security boundary" [VERIFIED] (`docs/extensibility/gateway-interceptors.mdx:62-70`).
- RFC 0010 (accepted) names "Verify policy writes against an external authority before accepting them" as a use case [VERIFIED] (`rfc/0010-gateway-interceptors/README.md:50`).
- The `examples/governance-interceptor` sample signs a SHA-256 digest of the canonical policy as an EdDSA JWT and stores it in the `openshell.nvidia.com/policy-signature` sandbox annotation. It denies unsigned or modified policies and sandbox-authored proposals, blocks `proposal_approval_mode=auto`, and vends provider profiles [VERIFIED] (`examples/governance-interceptor/README.md:12-26, 38-46`).
- The sample's signing key "is generated in memory on each interceptor start" [VERIFIED] (`examples/governance-interceptor/README.md:43-44`). The gateway's own policy hash is a separate revision identifier that "is not expected to match the signed governance hash". The gateway treats the example's profile-signature annotations as opaque metadata and does not verify them [VERIFIED] (`examples/governance-interceptor/README.md:52-54, 85-86`).

### Drivers and isolation backends

- Compute drivers speak `compute_driver.proto` over a Unix domain socket and negotiate protocol version and capabilities. The service has 12 RPCs, including `AuthenticateSandbox` and `ValidateSandboxCreate` [VERIFIED] (`proto/compute_driver.proto:27-65`; `docs/extensibility/drivers.mdx:18-19`).
- Driver crates exist for Docker, Podman, MicroVM, Kubernetes, and Windows MXC, the last marked "Coming soon" [VERIFIED] (`crates/`; `docs/how-it-works/sandboxes/runtimes.mdx:24`). Canonical publishes a third-party LXD driver under AGPL-3.0 [VERIFIED] ([canonical/openshell-driver-lxd, commit of 2026-09-29](https://github.com/canonical/openshell-driver-lxd)).
- Credential drivers implement `GetCapabilities`, `StoreCredential`, `DeleteCredential`, `ResolveCredentials`, and `ListCredentials` [VERIFIED] (`proto/credential_driver.proto:20-34`). Database, Kubernetes Secrets, and Vault-compatible drivers are built in [VERIFIED] (`docs/extensibility/drivers.mdx:40-51`).
- Isolation backends implement the Rust trait `IsolationBackend` in `crates/openshell-isolation-interface/src/contract.rs`. `attach()` binds a verified runtime descriptor to one sandbox, and `network_mediation_source()` "Receives TCP opens and DNS queries tagged with the calling program" [VERIFIED] (`docs/extensibility/isolation-backends.mdx:9-36`). RFC 0012 (Isolation Backend Interface) is in review [VERIFIED] (`rfc/0012-isolation-backend/README.md:4, 16`).
- `openshell gateway info` shows the negotiated extension families, versions, and capabilities [VERIFIED] (`docs/extensibility/overview.mdx:105-107`).

### Extension authentication

When JWT signing is configured, the gateway sends a short-lived bearer token with every interceptor and middleware call [VERIFIED] (`docs/extensibility/overview.mdx:109-147`):

| Claim | Value |
|---|---|
| `typ` / `alg` | `openshell-ext+jwt` / `EdDSA` |
| `iss` | `openshell-gateway:<gateway_id>` |
| `aud` | The registration's audience; defaults to `urn:openshell:extension:interceptor:<name>` or `urn:openshell:extension:middleware:<name>` |
| `caller_kind` | `gateway`, or `supervisor` for middleware calls from a sandbox |
| `sandbox_id` | The calling sandbox when `caller_kind` is `supervisor` |

- Keys rotate through `/.well-known/openid-configuration` and its `jwks_uri` [VERIFIED] (`docs/extensibility/overview.mdx:109-147`).
- Documented limitations: tokens are bearer credentials; "Extension tokens share the gateway's signing key, so you can't rotate or revoke them separately"; "mTLS client authentication and overlapping key rotation aren't available" [VERIFIED] (`docs/extensibility/overview.mdx:143-147`).
- `allow_insecure_transport = true` permits a plaintext endpoint with no token [VERIFIED] (`docs/extensibility/overview.mdx:141`).

## 4. OpenShell: audit, prover, governance, and roadmap

### OCSF audit trail

- OpenShell emits Open Cybersecurity Schema Framework (OCSF) v1.8.0 events [VERIFIED] (OpenShell@acbac9c `crates/openshell-ocsf/src/lib.rs:25`). The crate defines nine classes: Network Activity (4001), HTTP Activity (4002), SSH Activity (4007), Process Activity (1007), Detection Finding (2004), Application Lifecycle (6002), Device Config State Change (5019), API Activity (6003), and Base Event (0) [VERIFIED]. API Activity has no emitter outside the OCSF crate at the pin [VERIFIED] (`crates/openshell-ocsf/src/events/mod.rs:36-53`).

| Sink | Default | Location and retention | Label |
|---|---|---|---|
| Shorthand log `openshell.YYYY-MM-DD.log` | Always on | Inside the sandbox | VERIFIED |
| OCSF JSONL | Off; `ocsf_json_enabled` globally or per sandbox | `/var/log/openshell-ocsf.YYYY-MM-DD.log` inside the sandbox; daily rotation, three files kept | VERIFIED |
| Windows MXC gateway sink | Opt-in, MXC driver only | Gateway host; daily rotation, three files kept | VERIFIED |
| Gateway log buffer | Always on | "not persisted to disk and is lost when the gateway restarts"; the push channel "drops events rather than blocking" | VERIFIED |

Sources: `docs/observability/ocsf-json-export.mdx:14-63, 259-261`; `docs/observability/accessing-logs.mdx:38, 79`.

- `ocsf_schema_version` downgrades output to OCSF 1.1 or 1.3 for SIEMs. Downgrading strips `ai_model` and the `ai_operation` profile. CrowdStrike FDR's 1.5 target is "Not yet supported" [VERIFIED] (`docs/observability/ocsf-json-export.mdx:187-221`).
- Join keys: `metadata.uid` identifies an event and `container.uid` identifies the sandbox [VERIFIED] (`docs/observability/ocsf-json-export.mdx:67`). In the documented example records, the actor is a process and decision events name the matched rule in `firewall_rule` [VERIFIED] (`docs/observability/ocsf-json-export.mdx:105-146`).
- `policy_version` and `policy_hash` appear only on configuration events, as unmapped fields [VERIFIED] (`crates/openshell-ocsf/src/format/shorthand.rs:469-494`; `crates/openshell-server/src/grpc/policy.rs:349-354`).
- Events carry no `request_id`; each event gets a fresh UUID. A middleware decision therefore cannot be joined to its OCSF event by request [VERIFIED] (`crates/openshell-ocsf/src/builders/mod.rs:194`; local test).
- For middleware, OpenShell logs the count of findings, never logs metadata, and logs a `reason_code` on deny [VERIFIED] (`docs/extensibility/supervisor-middleware/operations.mdx:31-37`).
- No OCSF record at the pin carries a signature, hash chain, or sequence number. A search of `crates/`, `docs/`, `architecture/`, and `rfc/` finds no Merkle, hash-chain, DSSE, in-toto, Sigstore, or signed-audit code [VERIFIED].
- Roadmap umbrella [#1055, opened 2026-04-29](https://github.com/NVIDIA/OpenShell/issues/1055) (Enterprise Observability) has required, since a body edit on 2026-09-02, that security audit evidence "must be tamper-evident and cryptographically attributable to a trusted gateway or deployment authority". None of its 16 sub-issues tracks that requirement, and it has no milestone [VERIFIED].
- The one concrete proposal for such evidence before 2026-09-29 came from an outside contributor. It was an atomic evidence bundle with SHA-256 digests and a completeness state ([#2745, opened 2026-08-14](https://github.com/NVIDIA/OpenShell/issues/2745)). A detached signature and signed sequence numbers were suggested later in the thread. It was closed as not planned on 2026-09-21 with no stated reason [VERIFIED].
- On related issue [#2762, closed 2026-09-21](https://github.com/NVIDIA/OpenShell/issues/2762), closed in the same sweep, a maintainer commented after the closure. The comment says OpenShell "should produce a durable source of OCSF events that something else can slurp ... but that's it (for now)" [VERIFIED].
- The external NVIDIA exporter that #1055 cites (`NVIDIA-dev/OpenShell-exporter`) is not publicly accessible [VERIFIED].
- Open proposals [PROPOSED]:
  - [#3817, opened 2026-09-29](https://github.com/NVIDIA/OpenShell/issues/3817), asks for per-event sequence numbers and a hash chain.
  - [#2640, opened 2026-08-06](https://github.com/NVIDIA/OpenShell/issues/2640), adds `trace_id` and `span_id` to OCSF events.
  - RFC 0011 phase 5 would add `ApiActivity` events for control-plane mutations and tag sandbox events with the authenticated principal (`rfc/0011-multi-player-design/README.md:1212-1215`).
- OCSF 1.9.0 (released 2026-08-03) adds a `delegation` object (`uid`, `parent_uid`, `issuer_uid`, `created_time`) and a `record_integrity` profile. In 1.9.0, `digital_signature` has no attribute for signature bytes and no EdDSA algorithm value. The bytes attribute was added on the schema's main branch on 2026-09-24 [VERIFIED] ([ocsf-schema v1.9.0, 2026-08-03](https://github.com/ocsf/ocsf-schema/tree/v1.9.0)). OpenShell does not vendor OCSF 1.9.0 [VERIFIED].

### Policy prover

- The prover models a policy, its attached credentials, and a binary capability registry "as a Z3 SMT" problem [VERIFIED] (`crates/openshell-prover/README.md:7`). It runs in the gateway and ships as the standalone `openshell-prover` CLI [VERIFIED] (`docs/about/architecture.mdx:35`).
- Boundary check: `openshell-prover check candidate.yaml --boundary boundary.yaml` returns `within_boundary` (exit 0), `exceeds_boundary` (1, with a counterexample), `error` (2), `unsupported` (3), or `inconclusive` (3). Only `within_boundary` passes [VERIFIED] (`docs/how-it-works/policies/prover.mdx:132-142`).
- Coverage domains are filesystem, network_l4, network_rest, process, and landlock. GraphQL, MCP, and JSON-RPC rules, audit-mode endpoints, and REST rules with query matchers return `unsupported` [VERIFIED] (`docs/how-it-works/policies/prover.mdx:47-49, 227-231`).
- Proposal risk check: runs on every advisor proposal and compares reach with and without the rule. Findings are `link_local_reach`, `l7_bypass_credentialed`, `credential_reach_expansion`, and `capability_expansion`; any finding blocks automatic approval [VERIFIED] (`docs/how-it-works/policies/advisor.mdx:197-200`).
- NVIDIA's stated use: "a parent agent can check that a policy it writes for a subagent stays within the parent's own maximum allowed policy" [VERIFIED] (`docs/how-it-works/policies/prover.mdx:26-27`). This is attenuation expressed as policy containment, with no signed delegation artifact [INFERRED].
- The JSON result carries `schema_version`, `prover_version`, `result`, `counterexample`, and `reason_code`, among other fields. It is unsigned [VERIFIED] (`crates/openshell-prover-cli/src/main.rs:61-70`; `docs/how-it-works/policies/prover.mdx:151-153`).
- The standalone check shipped in [PR #3289, merged 2026-09-17](https://github.com/NVIDIA/OpenShell/pull/3289). The PR says "Gateway boundary storage, enforcement, and permission modes remain separate work" [VERIFIED]. The crate README says the containment API does not make the crate "a stable published SDK" [VERIFIED] (`crates/openshell-prover/README.md:32-36`).
- NVIDIA's research notes say the checks "do not understand context- for example requesting access to delete a temporary, throw-away repository vs a production repository" [VERIFIED] ([OpenShell research note, 2026-09-10](https://nvidia.github.io/OpenShell-Research/dev-notes/posts/2026-09-10-learning-formal-methods-agent-policy-prover/)). The launch blog says "Ongoing work extends policy analysis across multiple agents" [PROPOSED] ([OpenShell blog, 2026-09-28](https://developer.nvidia.com/blog/add-runtime-controls-to-ai-agents-with-nvidia-openshell/)).

### Policy advisor and approvals

- The advisor is off by default and is enabled with `agent_policy_proposals_enabled` [VERIFIED] (`docs/how-it-works/policies/advisor.mdx:21, 78-110`).
- "It handles network access only. A proposal can add a network rule, but it cannot remove rules or change filesystem, Landlock, or process settings." [VERIFIED] (`docs/how-it-works/policies/advisor.mdx:12-13`). The launch blog says an agent "can propose a narrowly scoped network or file policy change"; the docs at the pin do not support file changes [VERIFIED] ([OpenShell blog, 2026-09-28](https://developer.nvidia.com/blog/add-runtime-controls-to-ai-agents-with-nvidia-openshell/)).
- The agent-facing surface is a guide at `/etc/openshell/skills/policy_advisor.md`, an agent skill, `/AGENTS.md`, and `http://policy.local`. The endpoints are `GET /v1/policy/current`, `GET /v1/denials`, `POST /v1/proposals`, `GET /v1/proposals/{chunk_id}`, and `GET /v1/proposals/{chunk_id}/wait` [VERIFIED] (`docs/how-it-works/policies/advisor.mdx:64-71, 274-282`). Blocked requests return a structured `policy_denied` response [VERIFIED] (`docs/how-it-works/policies/manage-policies.mdx:339`).
- Shipped approval modes are `manual` (default) and `auto`, which approves a proposal "when OpenShell's risk checks find nothing to flag". A gateway-wide value overrides sandbox values. Operators use `openshell rule get`, `approve`, and `reject` [VERIFIED] (`docs/how-it-works/policies/advisor.mdx:24-25, 121-135, 169-183`). The launch blog says "the agent cannot approve its own request" [VERIFIED] ([OpenShell blog, 2026-09-28](https://developer.nvidia.com/blog/add-runtime-controls-to-ai-agents-with-nvidia-openshell/)).
- Designed in RFC 0002 (accepted) but not shipped [PROPOSED] (`rfc/0002-agent-driven-policy-management/README.md:52, 439-519`):
  - Approval modes `human_in_the_loop`, `trusted_agent_within_ceiling`, and `manual_only_locked_down`.
  - An org ceiling policy, a sandbox effective policy "always a subset of the org ceiling", and a proposal diff.
  - Durability classes `ephemeral_lease`, `sandbox_durable`, and `promoted_policy_artifact`.
  - `reject_with_guidance` hints: `too_broad`, `use_l7_not_l4`, `wrong_binary_scope`, `wrong_endpoint`, `needs_time_limit`, `outside_org_ceiling`.
  - The MVP "deliberately defers ... org ceilings, trusted auto-apply".
- Managed maximum policies ([#2109, opened 2026-07-01](https://github.com/NVIDIA/OpenShell/issues/2109)) would make one gateway-managed ceiling govern sandbox creation, policy revisions, provider changes, and later subagent composition [PROPOSED].
- The #2109 design says "Stored proposals and prior approvals are evidence, not reusable authorization", and it lists signed policy bundles as a non-goal [VERIFIED].
- Draft [PR #2168, opened 2026-07-07](https://github.com/NVIDIA/OpenShell/pull/2168), has no author commits since 2026-07-08. #2109 was removed from the 0.1.0 milestone on 2026-08-18 [VERIFIED].
- An earlier request for signed frozen policy bundles ([#1842, closed 2026-06-30](https://github.com/NVIDIA/OpenShell/issues/1842)) was closed as something that "should be part of interceptors" [VERIFIED].
- Approved grants cannot expire or be single-use: "Once a draft/chunk is approved and applied, the resulting allow rule stays in effect until a client explicitly calls the API to revoke it" [VERIFIED] ([#2881, opened 2026-08-21](https://github.com/NVIDIA/OpenShell/issues/2881)).

### Governance and contribution

- `GOVERNANCE.md` (added 2026-09-04) sets vendor neutrality ("No single organization controls project direction or decisions"), a contributor ladder, and a Maintainer Council. Maintainers are individual humans; "AI agents, automated systems, service accounts, companies, and other organizations cannot be Maintainers" [VERIFIED] (`GOVERNANCE.md:12, 16-18, 60, 80`).
- `MAINTAINERS.md` lists 13 maintainers: 10 from NVIDIA and 3 from Red Hat (Derek Carr, Seth Jennings, Mrunal Patel) [VERIFIED] (`MAINTAINERS.md:5-19`).
- `CONTRIBUTING.md` says the project "is built agent-first". First-time contributors open a vouch request "in your own words", and unvouched pull requests are closed automatically. Commits need a DCO 1.1 `Signed-off-by` line [VERIFIED] (`CONTRIBUTING.md:3, 23-32, 558-562`).
- The CNCF Sandbox application ([cncf/sandbox#522, opened 2026-09-08](https://github.com/cncf/sandbox/issues/522)) passed the TOC vote on 2026-09-26, with the contribution agreement pending [VERIFIED].
- Channels are CNCF Slack `#openshell-dev` ([OpenShell blog, 2026-09-28](https://developer.nvidia.com/blog/add-runtime-controls-to-ai-agents-with-nvidia-openshell/)) and GitHub Discussions, which also carry vouch requests (`CONTRIBUTING.md:25, 62`). There is also an RFC process with six states: draft, review, accepted, rejected, implemented, and superseded (`rfc/README.md:78-87`) [VERIFIED].
- On 2026-09-21 maintainers closed many issues as not planned, almost all without closing comments; #2762 later received a maintainer explanation. About 86 closed within a 90-minute window, and GitHub search counts 127 not-planned closures across the day. The sweep covered NVIDIA-authored issues as well as external proposals, four days before v0.1.0 [VERIFIED] (for example [#2745, closed 2026-09-21](https://github.com/NVIDIA/OpenShell/issues/2745) and [#1756, closed 2026-09-21](https://github.com/NVIDIA/OpenShell/issues/1756)).

### RFCs and roadmap

RFC titles and states are VERIFIED from each RFC's front matter and title line under `rfc/`. Content that is not implemented is PROPOSED.

| RFC | Title | State | Content relevant here |
|---|---|---|---|
| 0001 | Core Architecture | accepted | Identity-driver plugins (not implemented); gateway as directory and relay for sandbox-to-sandbox traffic ([#1049, opened 2026-04-29](https://github.com/NVIDIA/OpenShell/issues/1049)) |
| 0002 | Agent-Driven Policy Management | accepted | Proposal loop shipped; ceilings, trusted approvers, and durability classes deferred; MCP-aware controls later |
| 0003 | Gateway Configuration File | implemented | Gateway configuration is not hot-reloaded |
| 0004 to 0006 | Sandbox Resource Requirements; Sandbox Proxy Egress Adapter Model; Driver Config Passthrough | accepted; review; implemented | Not covered here |
| 0009 | Supervisor Middleware | accepted, research preview | Data-plane hook; phase 2 removes plaintext; budget-style completion hook and other deployment modes deferred |
| 0010 | Gateway Interceptors | accepted | Control-plane hook; "tenancy, quotas, naming, policy authority" as uses |
| 0011 | Multi-Player Support | draft | Platform Admin, Workspace Admin, Workspace User; the supervisor as a separate principal "analogous to a Kubernetes kubelet identity"; single gateway; accountability through the customer's SIEM; phase 5 audit attribution |
| 0012 | Isolation Backend Interface | review | `IsolationBackend` contract |
| 0013 | Native Windows Support via the MXC Compute Driver | review | Windows sandboxes |
| 0014 | Alpha Exit Criteria and Stable Release Policy | review | Weekly qualified stable releases; Stable and Experimental API tiers |

| Roadmap item | Content | State | Label |
|---|---|---|---|
| [#2025](https://github.com/NVIDIA/OpenShell/issues/2025) | Spike on "provable delegated authority for spawned agents": prover-checked containment `child_policy <= parent_delegable_view <= parent_boundary <= human_admin_maximum_policy` and an audit of delegations | Open spike, opened 2026-06-26; replies only from outside contributors | PROPOSED |
| [#2109](https://github.com/NVIDIA/OpenShell/issues/2109) and [PR #2168](https://github.com/NVIDIA/OpenShell/pull/2168) | Managed maximum admission | Draft PR opened 2026-07-07; no author commits since 2026-07-08 | PROPOSED |
| [#3808](https://github.com/NVIDIA/OpenShell/issues/3808) | Revalidate running subagents when ancestor authority changes; filed by the author of the Agent Passport System draft | Triage, opened 2026-09-28 | PROPOSED |
| [#1055](https://github.com/NVIDIA/OpenShell/issues/1055) | Enterprise Observability, including tamper-evident audit | Open since 2026-04-29, no milestone | PROPOSED |
| [#3307](https://github.com/NVIDIA/OpenShell/issues/3307) | Streaming replacement for the unary middleware request hook | Open, opened 2026-09-14 | PROPOSED |
| [#3817](https://github.com/NVIDIA/OpenShell/issues/3817) | Sequence numbers and hash chain for the sandbox event stream | Open, opened 2026-09-29 | PROPOSED |
| [#2640](https://github.com/NVIDIA/OpenShell/issues/2640) | `trace_id` and `span_id` on OCSF events | Accepted, open since 2026-08-06 | PROPOSED |
| [#1049](https://github.com/NVIDIA/OpenShell/issues/1049) | Gateway relay for sandbox-to-sandbox traffic, authorized by source and destination sandbox identity | Roadmap, opened 2026-04-29 | PROPOSED |
| [#3153](https://github.com/NVIDIA/OpenShell/issues/3153) | Durable stop hold (gateway-enforced restart fence) | Open, labeled stale | PROPOSED |
| [PR #2772](https://github.com/NVIDIA/OpenShell/pull/2772) | Delegated creator identity for token exchange | Open, last updated 2026-09-16 | PROPOSED |

- Outside developers have asked for an external, stateful authority and evidence layer above OpenShell. The requests are in discussions [#3818, 2026-09-29](https://github.com/NVIDIA/OpenShell/discussions/3818), [#3079, 2026-09-01](https://github.com/NVIDIA/OpenShell/discussions/3079), and [#2661, 2026-08-09](https://github.com/NVIDIA/OpenShell/discussions/2661). They are also in issues [#1733, opened 2026-06-03](https://github.com/NVIDIA/OpenShell/issues/1733) and [#3782, 2026-09-28](https://github.com/NVIDIA/OpenShell/issues/3782). None had a maintainer resolution on 2026-09-29 [VERIFIED].
- A maintainer comment on #1733 (2026-06-04) floated reserving post-credential hooks for built-in middleware [VERIFIED]. A request to run middleware inside sandboxes ([#2684, 2026-08-10](https://github.com/NVIDIA/OpenShell/issues/2684)) was closed [VERIFIED].

## 5. Sentry, BlueField-4, and DOCA

### Shipping versus reference design

| Piece | State | Source | Label |
|---|---|---|---|
| Sentry | Reference system design with no date. The New Stack reports that it is closed source. In the briefing Boitano called the DPU "really optional" and said it is for "frontier use cases of evaluating models or systems where you might have the guardrails off the models". | [Press release, 2026-09-28](https://nvidianews.nvidia.com/news/open-agent-safety-platform); [The New Stack, 2026-09-28](https://thenewstack.io/nvidia-openshell-sentry-agents/) | VERIFIED (reference design, no date); REPORTED (closed source, briefing) |
| BlueField-4 | One DPU per Vera Rubin compute tray. Partner products are expected in the second half of 2026. Supermicro said on 2026-09-23 that it is shipping Vera Rubin NVL72 racks. | [BlueField-4 blog, 2025-10-28](https://blogs.nvidia.com/blog/bluefield-4-ai-factory/); [Rubin release, 2026-01-05](https://nvidianews.nvidia.com/news/rubin-platform-ai-supercomputer); [Supermicro, 2026-09-23](https://www.supermicro.com/en/pressreleases/supermicro-now-shipping-nvidia-vera-rubin-nvl72-racks) | VERIFIED (current state); PROPOSED (expected partner products) |
| DOCA 3.5.0 | DOCA Argus is Beta and DPF is GA. No DOCA Vault or gateway service is listed. BlueField-3 and BlueField-2 are supported platforms; BlueField-4 is not listed. DOCA 3.6.0 (LTS) is due October 2026 and DOCA 4.0 January 2027. | [DOCA 3.5.0 services, 2026-09-01](https://networking-docs.nvidia.com/doca/archive/3-5-0/doca-services); [DOCA 3.5.0 general support, 2026-09-02](https://networking-docs.nvidia.com/doca/archive/3-5-0/general-support); [DOCA 3.5.0 changes and new features, updated 2026-09-02](https://networking-docs.nvidia.com/doca/archive/3-5-0/changes-and-new-features) | VERIFIED (current state); PROPOSED (release dates) |
| DOCA Vault | Inline file-access decisions on BlueField-4, announced with Vera BlueField-4 STX | [NVIDIA release, 2026-05-31](https://nvidianews.nvidia.com/news/nvidia-vera-bluefield-4-stx-brings-agentic-ai-storage-processing-with-in-silicon-security) | PROPOSED |
| DOCA gateway | Named only in the developer blog | [Developer blog, 2026-09-28](https://developer.nvidia.com/blog/nvidia-open-agent-safety-platform-a-reference-for-continuous-in-silicon-agent-monitoring/) | VERIFIED |

The developer blog says "For anyone already running on an NVIDIA Vera system with BlueField-4, enabling these protections is just a software update" [VERIFIED] ([developer blog, 2026-09-28](https://developer.nvidia.com/blog/nvidia-open-agent-safety-platform-a-reference-for-continuous-in-silicon-agent-monitoring/)).

### Architecture as described

- The developer blog's reference figure links OpenShell (Gateway, Supervisor, Policy Prover, and an Agent Harness in the Agent Sandbox) to the Vera CPU, and Sentry to BlueField-4, in one Vera CPU tray [VERIFIED] ([developer blog, 2026-09-28](https://developer.nvidia.com/blog/nvidia-open-agent-safety-platform-a-reference-for-continuous-in-silicon-agent-monitoring/)).
- The figure labels four Sentry functions: "Hardware-Based Enforcement", "Continuous Agent Monitoring and Threat Detection", "Trusted Telemetry and Detection Pipeline", and "Millisecond-Scale Containment and Quarantine" [VERIFIED]. An arrow from BlueField-4 to Sentry is labeled Prompt, Tools, Data, Model, and Policies. The Sentry panel is captioned "Agent Reasoning Inspection and Tamper-Proof Telemetry" [VERIFIED].
- "In an NVIDIA Vera Rubin POD, each compute tray includes a BlueField-4 data processing unit on the node's only path to the model" [VERIFIED] ([developer blog, 2026-09-28](https://developer.nvidia.com/blog/nvidia-open-agent-safety-platform-a-reference-for-continuous-in-silicon-agent-monitoring/)). BlueField Astra gives the DPU control of the node's network I/O, including the ConnectX-9 east-west NICs [VERIFIED] ([BlueField Astra blog, 2026-01-07](https://developer.nvidia.com/blog/redefining-secure-ai-infrastructure-with-nvidia-bluefield-astra-for-nvidia-vera-rubin-nvl72/)).
- Boitano said that with a DPU present, the model endpoint goes "through a proxy on the DPU, so that you can see all of the reasoning traces of the agents on the host" [REPORTED] ([The New Stack, 2026-09-28](https://thenewstack.io/nvidia-openshell-sentry-agents/)).
- The developer blog says the BlueField-4 foundation allows for "enforcing the OpenShell policy in silicon" and that DOCA "connects it with OpenShell policy" [VERIFIED] ([developer blog, 2026-09-28](https://developer.nvidia.com/blog/nvidia-open-agent-safety-platform-a-reference-for-continuous-in-silicon-agent-monitoring/)). The press release also credits DOCA with "zero-trust access policies" (section 1). Whether Sentry or DOCA applies policy of its own is not documented.
- NVIDIA documents no interface between Sentry and OpenShell policy, and the OpenShell repository contains no Sentry, BlueField, or DOCA code or docs at the pin [VERIFIED].

### Attested telemetry

- NVIDIA's solution page promises "complete, attested telemetry" [VERIFIED] ([agent safety solution page, undated, read 2026-09-28](https://www.nvidia.com/en-us/solutions/ai/agent-safety/)). NVIDIA publishes no signer, key, root of trust, schema, or export API for it [VERIFIED].
- DOCA Argus emits JSON or syslog records (`schema_version` 1.0) through Fluent Bit or Vector, with image digests, pod UIDs, process hashes, and alerts. The records have no signature field [VERIFIED] ([DOCA Argus guide, 2026-09-11](https://networking-docs.nvidia.com/doca/archive/3-5-0/doca-argus-service-guide)). The [DOCA Telemetry Service guide, no visible date, read 2026-09-28](https://networking-docs.nvidia.com/doca/archive/3-5-0/doca-telemetry-service-guide) does not mention signing [VERIFIED].
- BlueField device attestation uses SPDM with a DICE certificate chain and CoRIM reference values, COSE-signed when signed. It covers firmware, not agent activity [VERIFIED] ([device attestation docs, v6.0, 2026-08-31](https://networking-docs.nvidia.com/dpunicattestation)).
- Those docs cover BlueField-3, ConnectX-7, ConnectX-8, ConnectX-9, and the NVLink6 switch, not BlueField-4 [VERIFIED]. The BlueField-4 datasheet lists SPDM 1.1 and 1.2 device attestation [VERIFIED] ([BlueField-4 datasheet, June 2026](https://dam-cdn.nvd.orangelogic.com/AssetLink/whs8mhb340t412js4612g3356607hapf.pdf)).
- BlueField-4's Advanced Secure Trusted Resource Architecture (ASTRA) is announced only [PROPOSED] ([BlueField Astra blog, 2026-01-07](https://developer.nvidia.com/blog/redefining-secure-ai-infrastructure-with-nvidia-bluefield-astra-for-nvidia-vera-rubin-nvl72/)).

### Identity governance and delegated authority

- The developer blog: "The DOCA gateway complements this behavioral protection with identity governance, continuously verifying each agent's identity and delegated authority to ensure it operates within its assigned scope." [VERIFIED] ([developer blog, 2026-09-28](https://developer.nvidia.com/blog/nvidia-open-agent-safety-platform-a-reference-for-continuous-in-silicon-agent-monitoring/))
- NVIDIA publishes nothing that names the credential the DOCA gateway accepts, the delegated-authority artifact it verifies, the issuer, or an API [VERIFIED].
- The only NVIDIA document that names artifacts for a DPU path is the Secure Agent Workspace design (section 6). It marks DPU acceleration "optional, future" [VERIFIED].
- The same design says the hardware-accelerated path "implements the same Phase II contracts", naming the signed policy bundle and OCSF audit emission. Its control-surface table consumes identity and delegation from "enterprise IAM / ODIS" and takes signing roots from enterprise PKI [VERIFIED] ([SAW security and governance model, 2026-06-28](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/security-and-governance-model.html)).
- NVIDIA's Agent Policy Fabric job post plans public OpenShell RFCs or PRs for quarantine, stop-session, runtime-context attestation, and projection hooks [PROPOSED] ([NVIDIA careers, JR2019848, posted 2026-06-22](https://jobs.nvidia.com/careers/job/893395763513)).

### Quarantine

- "Sentry quarantines and stops it in milliseconds" [VERIFIED] ([press release, 2026-09-28](https://nvidianews.nvidia.com/news/open-agent-safety-platform)). NVIDIA publishes no benchmark for the figure [VERIFIED].
- One analysis calls the figure "a capability claim, not a measured benchmark" [REPORTED] ([FourWeekMBA, 2026-09-28](https://fourweekmba.com/ai-nvidia-open-agent-safety-platform-openshell-sentry-2/)).
- NVIDIA documents no quarantine trigger or API [VERIFIED].
- Two quarantine primitives are open proposals [PROPOSED]: OpenShell [#3153, labeled stale](https://github.com/NVIDIA/OpenShell/issues/3153) (a durable stop hold) and NemoClaw [#10140, 2026-08-24](https://github.com/NVIDIA/NemoClaw/issues/10140) (a quarantine command that emits a "secret-free receipt").
- DOCA Argus watches one node: "A single BlueField DPU running DOCA Argus can monitor the compute node to which it is attached" [VERIFIED] ([DOCA Argus guide, 2026-09-11](https://networking-docs.nvidia.com/doca/archive/3-5-0/doca-argus-service-guide)).
- Boitano said "In a lot of cases, just using OpenShell on CPUs is honestly good enough for providing sort of strict access control for the agents" [REPORTED] ([The New Stack, 2026-09-28](https://thenewstack.io/nvidia-openshell-sentry-agents/)).

### Partners on BlueField

| Partner | Claim | Label |
|---|---|---|
| Palo Alto Networks | "Looking ahead, we plan to integrate NVIDIA OpenShell with upcoming Agent Identity Security capabilities from Idira, including identity and secrets management for the OpenShell sandbox and agent identity broker service on NVIDIA BlueField". PANW says Prisma AIRS AI Runtime Security on BlueField draws on the Sentry reference design and calls it "our GA of AI Runtime Security on the BlueField DPU" ([PANW blog, 2026-09-28](https://www.paloaltonetworks.com/blog/2026/09/securing-ai-agents-at-scale-with-nvidia/)). | PROPOSED (Idira and the BlueField identity broker); VERIFIED (PANW's statement that AI Runtime Security on BlueField DPUs is GA) |
| Xage | AI security gateways on DOCA that feed entitlement-delegation events into Argus and Flow ([Xage release, 2026-06-01](https://xage.com/press/xage-security-supercharges-its-just-announced-zero-trust-for-agentic-ai-solution-with-nvidia-vera-bluefield-4-stx-security-innovations)) | PROPOSED |
| Cisco | Splunk as "the system of record for agents", ingesting Sentry attested telemetry; Hypershield extended so one policy is enforced by the nearest control point ([Cisco blog, 2026-09-28](https://blogs.cisco.com/news/beyond-intelligence-how-trust-is-the-benchmark-that-matters-in-ai)) | PROPOSED |
| CrowdStrike | Argus data into Falcon Next-Gen SIEM ([CrowdStrike blog, 2026-09-28](https://www.crowdstrike.com/en-us/blog/crowdstrike-nvidia-extend-security-across-ai-stack/)) | PROPOSED |
| EQTY Lab | Claims DPU-held keys that notarize Argus, Flow, and Vault signals ([EQTY Lab, 2026-06-01](https://www.eqtylab.io/blog/verifiable-knowledge-the-third-pillar-of-trust-for-the-agentic-ai)). EQTY publishes no code, schema, or arm64 build for this. NVIDIA lists EQTY as a Vera BlueField-4 STX security partner ([NVIDIA release, 2026-05-31](https://nvidianews.nvidia.com/news/nvidia-vera-bluefield-4-stx-brings-agentic-ai-storage-processing-with-in-silicon-security)). | PROPOSED (claim); VERIFIED (listing, no public code) |

## 6. Secure Agent Workspace reference design

- SAW is an NVIDIA Enterprise Reference Architecture of 13 content pages and 11 figures. Every page reads "Last updated on Jun 28, 2026" [VERIFIED] ([SAW overview, 2026-06-28](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/what-is-secure-agent-workspace.html)).
- No page mentions Sentry, the Open Agent Safety Platform, the alliance, SPIFFE, OPA or Rego, Anthropic, or Claude [VERIFIED].
- Each user gets a single-tenant VM reached only through an SSO-backed access broker [VERIFIED] ([SAW overview, 2026-06-28](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/what-is-secure-agent-workspace.html)). For agents that write and run code, the design requires a "single-tenant KVM-based VM at minimum" [VERIFIED] ([what it is not, 2026-06-28](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/what-it-is-not.html)).
- Phase I (egress allowlist, human review of writes, OCSF audit, all outside the VM) is "the substrate the customer can deploy today" [VERIFIED] ([abstract, 2026-06-28](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/abstract.html)).
- Phase II adds OpenShell "or equivalent" inside the VM, a credential proxy, routed inference, and centrally signed policy that is "attested at boot, verified per-call". "The phases are additive" [VERIFIED] ([abstract, 2026-06-28](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/abstract.html)).
- SAW names four identity layers: the user or sponsor (enterprise SSO), the workspace (attested device), the agent (registration and lifecycle), and each running tool call (short-lived runtime- or software-attested credential) [VERIFIED] ([SAW overview, 2026-06-28](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/what-is-secure-agent-workspace.html)).

Delegation record:

- A per-engagement signed delegation record binds those identities to task, scoped resources, tools, duration, approval mode, revocation, and audit references. It is "enforced at every tool call by the runtime layer, revocable by the sponsor" [VERIFIED] ([SAW overview, 2026-06-28](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/what-is-secure-agent-workspace.html)).
- Each subagent gets its own identity and a child record that can only narrow scope, tools, resources, and duration. The design's example: a child holding {A,B} cannot delegate {A,C} [VERIFIED] ([enterprise tool access model, 2026-06-28](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/enterprise-tool-access-model.html)).
- The governance page lists task, scope, tools, duration, and approval mode, without revocation or audit references [VERIFIED] ([security and governance model, 2026-06-28](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/security-and-governance-model.html)).
- No page specifies the record's wire format, signature algorithm, signing key, issuer component, or maximum lifetime [VERIFIED]. The only issuer hint is that widening "requires a re-issued, signed delegation / policy from the control plane" [VERIFIED] ([reference architecture, 2026-06-28](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/reference-architecture.html)). Approval-mode values are not enumerated [VERIFIED].
- The design says three times, in different wording, that agent authority is a policy-defined subset of the sponsor's. One page says it is "evaluated and enforced centrally at the runtime layer, never a separate authority and never re-implemented by each application" [VERIFIED] ([enterprise tool access model, 2026-06-28](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/enterprise-tool-access-model.html)).
- Read literally, that sentence states where authority comes from and where it is enforced; it does not rule out an external decision service [INFERRED].
- The Plane 6 credential proxy runs in the VM by default. The pages move it outside the VM for sovereign or residency-constrained profiles and for stricter threat models, and make it HSM-backed for the regulated profile [VERIFIED] ([reference architecture, 2026-06-28](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/reference-architecture.html); [security and governance model, 2026-06-28](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/security-and-governance-model.html)).
- On each outbound call the proxy resolves the agent's capability to a service and scope under the delegation record and rewrites the Authorization header. The agent holds only scoped, short-lived capabilities, and the same proxy fronts routed inference [VERIFIED]. Table 6 names "capability semantics" as a contract but does not define them [VERIFIED].

Control surface contracts, from Table 6 of the [security and governance model, 2026-06-28](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/security-and-governance-model.html) [VERIFIED]:

| Control | Expected contracts | Implemented in the design | Consumed from enterprise IAM or platform | Integration dependency |
|---|---|---|---|---|
| Identity and delegation | User or sponsor identity (SSO or OIDC); attested workspace identity; logical-agent registration; short-lived runtime credential lifetime and binding | Workspace identity binding; logical-agent registration; runtime credential minting with per-sandbox or per-call rotation | Enterprise SSO or OIDC IdP; group membership; access-broker session | "ODIS as the spec stabilizes; identity broker; TPM / SEV-SNP / TDX attestation provider" |
| Signed policy | "Policy bundle format; verifier / decision API; signing key trust chain; rollback semantics" | Policy authoring and signing service; per-call decision evaluator; channel-based distribution | Enterprise PKI for signing roots | Policy distribution channel (Git, OCI registry); "upstream signed-policy framework when adopted" |
| Audit and revocation | OCSF audit event shape; revocation propagation semantics; rollback contract | OCSF audit emission from all three security layers; a revocation receiver wired to the workspace lifecycle API | Enterprise SIEM; SSO revocation endpoint | "OCSF schema version alignment; SIEM correlation rule pack" |

- Table 6 names no contract, component, or owner for the delegation record itself. Elsewhere the page lists a per-engagement delegation record and delegation-record revocation under identity and delegation enforcement [VERIFIED].
- The page says identity and delegation are "consumed from enterprise IAM / ODIS rather than owned" [VERIFIED].
- The same table names the runtime contract surfaces as "Sandbox lifecycle API; per-call policy attestation API; in-runtime egress/write decision API; routed-inference broker contract" [VERIFIED].
- Audit is OCSF emitted from trust-boundary endpoints outside the agent's reach, and each write is stamped with user, agent, and delegation record [VERIFIED] ([reference architecture, 2026-06-28](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/reference-architecture.html); [enterprise tool access model, 2026-06-28](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/enterprise-tool-access-model.html)).
- No page requires audit records to be signed, hash-chained, append-only, or tamper-evident, and the governance page names no compliance framework [VERIFIED].
- Scope limits, each from a different page [VERIFIED]:
  - The what-it-is-not page excludes acting as an identity provider, multi-user shared workspaces, and serving production applications or APIs to other users. It calls agents running outside the workspace a separate design that "may be added later" ([what it is not, 2026-06-28](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/what-it-is-not.html)).
  - The operating-properties page calls service agents with no human principal and broader agent-to-agent platforms "future scope" ([operating properties, 2026-06-28](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/operating-properties.html)).
  - The tool access page says SAW "does not add a cross-agent coordination layer" for shared write targets and leaves concurrency to the system of record ([enterprise tool access model, 2026-06-28](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/enterprise-tool-access-model.html)).
  - The governance page's threat table marks hypervisor or control-plane compromise as "Out of Secure Agent Workspace's scope" ([security and governance model, 2026-06-28](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/security-and-governance-model.html)).
- The deployment tiers call for "centralized FinOps integration with budget gates" without a mechanism [VERIFIED] ([deployment tiers, 2026-06-28](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/deployment-tiers.html)). DPU offload of the egress firewall, DOCA Vault, and DOCA Argus is "optional, future" [VERIFIED] ([security and governance model, 2026-06-28](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/security-and-governance-model.html)).

Implementations:

- The Azure reference ("v1 ships Phase I") runs a root-capable agent in the VM [VERIFIED] ([Azure implementation, 2026-06-28](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/azure-reference-implementation.html)).
- The Red Hat validated pattern lists signed policy bundles, credential proxying, per-tool enforcement, and OCSF audit as not implemented [VERIFIED] ([validatedpatterns-sandbox, commit of 2026-09-27](https://github.com/validatedpatterns-sandbox/secure-agent-workspace)).
- The OpenShift Virtualization page describes a signed bundle pipeline (`policy.yaml`, `manifest.json`, `signature.sig` on read-only NFS). An in-VM agent verifies each bundle before applying it with `openshell policy update` or `openshell policy set` [VERIFIED] ([OpenShift Virtualization implementation, 2026-06-28](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/openshift-virtualization-reference-implementation.html)).
- We found no public implementation that ships Phase II delegation-record enforcement [INFERRED]. OpenShell has no delegation-record, ODIS, or sponsor concept at the pin [VERIFIED]. The nearest public work is the ODIS contract harness (section 7), which gates an OpenShell sandbox but is not SAW Phase II [VERIFIED].

## 7. ODIS

### Status and provenance

- The document is "ODIS - Open Delegation & Identity Standard", by "Nir Paz (NVIDIA), Mike Beiter (NVIDIA), Yu-Cheng Liang (NVIDIA)", with status "Unapproved contributor draft intended for open development" [VERIFIED] (ODIS@148dc41 `RFCs/ODIS.md:2-4`).
- ODIS section 10.1 says: "This document is an unapproved contributor draft and has no OASIS or CoSAI approval status." [VERIFIED] (`RFCs/ODIS.md:1127-1129`).
- The draft agenda for the 2026-07-02 WS4 meeting reports that NVIDIA's Nir Paz and Matthew Gladney presented ODIS to WS4 on 2026-06-25, when it was "not yet public" [REPORTED] ([WS4 agenda, 2026-07-02](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/agenda_drafts/ws4/2026-07-02.md)).
- The minutes of the CoSAI Technical Steering Committee (TSC) for 2026-07-21 record that the TSC accepted the contribution [REPORTED] ([TSC minutes, 2026-07-21](https://github.com/cosai-oasis/cosai-tsc/blob/main/tsc-meeting-minutes/2026-07-21.md)).
- The [cosai-oasis/ws4-odis](https://github.com/cosai-oasis/ws4-odis) repository was created 2026-07-15. The RFC was committed 2026-07-30 and merged 2026-08-03 in a pull request whose merge was requested "for Blackhat". Its text has not changed since [VERIFIED] ([ws4-odis PR #4, merged 2026-08-03](https://github.com/cosai-oasis/ws4-odis/pull/4)).
- NVIDIA holds a Project Governing Board (PGB) seat [VERIFIED] ([CoSAI leadership page, undated, read 2026-09-28](https://www.coalitionforsecureai.org/leadership/)). A WS4 draft agenda also lists an NVIDIA TSC co-chair [REPORTED] ([WS4 agenda, 2026-09-10](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/agenda_drafts/ws4/2026-09-10.md)).
- CoSAI held an ODIS working session on 2026-08-28 [VERIFIED] ([CoSAI working session post, 2026-09-01](https://www.coalitionforsecureai.org/cosai-hosts-working-session-on-open-delegation-identity-standard-odis/)). The draft agenda for the 2026-09-10 WS4 meeting says Nir Paz hosted it at NVIDIA [REPORTED] ([WS4 agenda, 2026-09-10](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/agenda_drafts/ws4/2026-09-10.md)).
- The draft agenda for the 2026-09-10 WS4 meeting reports that NVIDIA's Matthew Gladney, co-presenter of the ODIS readout, said on 2026-09-03 that "ODIS is far from being stable on its spec" [REPORTED] ([WS4 agenda, 2026-09-10](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/agenda_drafts/ws4/2026-09-10.md)).
- Contributors must sign the CoSAI Contributor License Agreement ([CoSAI onboarding, undated, read 2026-09-28](https://github.com/cosai-oasis/cosai-tsc/blob/main/ONBOARDING.md)). Standards-track promotion needs a PGB special-majority vote ([OASIS Open Project governance, undated, read 2026-09-28](https://github.com/cosai-oasis/oasis-open-project/blob/main/GOVERNANCE.md)) [VERIFIED].
- The TSC minutes for 2026-07-14 record that contributions by pull request "would require approval from a co-lead of the PGB or TSC" [REPORTED] ([TSC minutes, 2026-07-14](https://github.com/cosai-oasis/cosai-tsc/blob/main/tsc-meeting-minutes/2026-07-14.md)).
- We found no published schedule for a Project Specification Draft [INFERRED]. The governance path is tracked in [cosai-tsc#62, open on 2026-09-22](https://github.com/cosai-oasis/cosai-tsc/issues/62) [VERIFIED].

### Pillars and layers

- Four pillars: delegated principal identity, agent code or package identity, agent runtime instance identity, and cascaded delegation [VERIFIED] (`RFCs/ODIS.md:131-161`).

| Layer | Name | Function | Label |
|---|---|---|---|
| 1 | Passport (identity and attestation) | Binds software and runtime or workload attestation (hardware attestation optional) into a short-lived, holder-bound Agent Runtime Credential; no static secrets; "an accountable human sponsor or named service-owner record" (`RFCs/ODIS.md:339`) | VERIFIED |
| 2 | Bridge (delegation and access) | Delegation Service, Provider Adapter with `native` or `bridge` egress modes, and a cache and revocation manager | VERIFIED |
| 3 | Router (discovery and governance) | Registry, governance checkpoint, and safeguards such as rate limits, revocation, and a kill switch | VERIFIED |

Source: `RFCs/ODIS.md:303-457`.

- "ODIS does not standardize the policy language." External engines such as NGAC, OPA/Rego, or Cedar make decisions [VERIFIED] (`RFCs/ODIS.md:433, 787`).
- ODIS positions itself as an overlay on OAuth, OIDC, SAML, SPIFFE, SCIM, WIMSE, and MCP. It does not mention UCAN, SD-JWT, COSE, or OCSF [VERIFIED].

### Data models

- ODIS 6.1 Agent Registration Record: record_id, record_issuer, schema_version, record_version, agent_id, valid_until, lifecycle_state, sponsor_ref, owner_ref, approved_runtime_issuers, approved_software_refs, trust_domain, policy_profile_ref, permitted_delegation_modes, provider_entitlements, created_at, updated_at [VERIFIED] (`RFCs/ODIS.md:667-691`).
- ODIS 6.2 Agent Runtime Credential Descriptor: credential_id, format_version, agent_id, registration_record_ref, runtime_instance_id, software_hash, attestation_evidence, issuer, issuer_key_ref, holder_key_ref, issued_at, expires_at, trust_domain, supply_chain_ref, audiences [VERIFIED] (`RFCs/ODIS.md:693-713`).
- ODIS 6.3 Delegation Record, 17 fields [VERIFIED] (`RFCs/ODIS.md:715-737`):
  - MUST (13): delegation_id, issuer, originating_principal, originating_authorization_ref, actor, delegation_chain, task_id, granted_authorizations, resource_indicators, constraints, attenuation_profile_ref (an immutable versioned URI plus content digest), issued_at, expires_at.
  - CONDITIONAL: parent_delegation_ref (issuer, delegation_id, record_digest) for every non-root record.
  - SHOULD: task_description, max_depth, binding_profile.
- Delegation Record invariants [VERIFIED] (`RFCs/ODIS.md:739-757`):
  - The issuer integrity-protects every record.
  - A verifier resolves and digest-matches every parent.
  - Each hop is "equal to or narrower than the immediate parent under attenuation_profile_ref".
  - A child's expiry cannot exceed its parent's.
  - "An unresolved, ambiguous, cyclic, lossy, or indeterminate parent comparison MUST fail closed."
- ODIS 6.4 Identity Context, the policy-engine feed: agent_registration, agent_runtime, delegation, action {tool, method, resource, parameters}, request_timestamp, request_trace_id, runtime_risk_signals. The engine returns `{decision: "permit"|"deny", reason, obligations}` [VERIFIED] (`RFCs/ODIS.md:771-787`).
- Carriers: ODIS "does not mandate a wire format. Implementations MAY use OAuth Transaction Tokens, IATP capability manifests, ID-JAG tokens, or any carrier satisfying the requirements in Section 5.2." [VERIFIED] (`RFCs/ODIS.md:807-817`).
- Holder-binding candidates are TLS session binding, DPoP (RFC 9449), and mTLS-bound tokens (RFC 8705). No signature algorithm, canonicalization, or digest input is mandated [VERIFIED] (`RFCs/ODIS.md:417, 807-817`). An open issue proposes a digest contract [PROPOSED] ([ws4-odis #22, opened 2026-09-21](https://github.com/cosai-oasis/ws4-odis/issues/22)).

### Profiles and requirements

A profile claim applies to "a named, versioned deployable system boundary". A single component "MAY publish a role-capability statement". It cannot claim Core, Extended, or Safety unless the complete declared target meets every applicable requirement [VERIFIED] (`RFCs/ODIS.md:909`).

| Profile | What it adds | Label |
|---|---|---|
| Core | Short-lived runtime credentials, registration resolution, delegated authorization, semantic attenuation, fail-closed mediation, revocation with kill switch, audit lineage; a published reproducible latency benchmark with p50, p95, and p99 (CC-03) and an availability objective (CC-04) | VERIFIED |
| Extended | Durable delegation, hardware-rooted options, discovery, governance checkpoints, task-purpose controls, federated trust | VERIFIED |
| Safety | Hardware attestation becomes MUST. Audit logs "MUST be tamper-evident and MUST be hash-chained or protected by an equivalently verifiable append-only mechanism". Task-bound tokens (ODIS-L3-07) become MUST, and the deployment must establish at least one ODIS-L3-08 enforcement placement. | VERIFIED |

Source: `RFCs/ODIS.md:648-649, 657-658, 913-963`.

- Revocation (ODIS-L3-04, Core): "Within a trust domain, the event MUST propagate within the declared maximum revocation latency, not exceeding 300 seconds". SSF, CAEP, and RISC are named for fan-out [VERIFIED] (`RFCs/ODIS.md:645, 802`).
- Audit in Core: decisions "MUST be logged with trace identifiers", and "Audit logs SHOULD be tamper-evident" (CC-01). Every logged action must identify the logical agent, the runtime instance, and the originating principal (CC-02) [VERIFIED] (`RFCs/ODIS.md:655-656`).
- ODIS defines no signed per-decision record [VERIFIED]. An open issue proposes one [PROPOSED] ([ws4-odis #21, opened 2026-09-21](https://github.com/cosai-oasis/ws4-odis/issues/21)).

### Future work

ODIS section 10.3 lists these as "explicitly out of scope for now" [VERIFIED] (`RFCs/ODIS.md:1147-1160`):

| ID | Title | Description |
|---|---|---|
| FW-01 | Verifiable Credentials | "Portable decentralized agent credentials for cross-organizational collaboration without centralized trust anchors." |
| FW-02 | Agent Behavioral Reputation | Portable, tamper-resistant behavioral scoring |
| FW-03 | AI-Native Policy Languages | Policy languages for agent-specific and attestation-aware decisions |
| FW-04 | Economic Layer | "Identity-bound metering, billing propagation, and financial transaction authorization for agent-mediated commerce." |
| FW-05 | Multi-User Agents | Agents acting for teams or groups |
| FW-06 | Browser / Computer-Use Agents | Identity and intent verification through GUI surfaces |
| FW-07 | Deployment Integration Profiles | Deployment-level profiles of adapters and enforcement |
| FW-08 | Pattern 4 Validation Suite (CT-P4) | Conformance suite for embedded SDK deployments |

### Contract harness and Agent Policy Fabric

- The Apache-2.0 contract harness is "one candidate Router / governance-checkpoint wedge implementation". An agent calls the Router over MCP. The Router evaluates Rego with OPA, "enforces argument-level limits", forwards approved calls, and audits every outcome [VERIFIED] (`contract-harness/README.md:3-11`).
- In its enforced mode "An OpenShell sandbox makes the Router the agent's only network path to the Target MCP" [VERIFIED] (`contract-harness/README.md:29`).
- Grants come from the `apf-bundle-issuer` Vault plugin, which "issues transit-signed APF Signed Policy Bundles for validated workload-identity JWTs" using Ed25519 [VERIFIED] (`contract-harness/vault-plugin/main.go:1-2`).
- The bundle schema (`urn:odis:contract-harness:schemas:odis.bundle.v1`) requires `bundle_id`, `bundle_version`, `trust_root_id`, and `families`. It also carries `actor`, `originating_principal`, `contributing_records`, `delegation_chain`, `attenuation_profile_ref`, `issued_at`, and `expires_at` [VERIFIED] (`contract-harness/schemas/odis.bundle.v1.json:3, 6-11`).
- `delegation_chain` has `maxItems: 0` because "This issuer mints root records only" [VERIFIED] (`contract-harness/schemas/odis.bundle.v1.json:46-47`).
- `trust_root_id` is an operator-written label on the Vault mapping, not a key registry, and bundle verification uses one configured verifier [VERIFIED] (`contract-harness/vault-plugin/backend/path_mappings.go:325-326`; `contract-harness/src/odis_harness/bundle/loader.py:109-118`).
- The audit schema's `event_type` accepts one of 14 enumerated values or an extension name matching `odis.<ns>.<name>`. The values are policy_load, policy_reject, authorize, deny, require_review, review_decision, credential_issue, resource_call, result, detector_verdict, quarantine, stop_session, revocation, and break_glass [VERIFIED] (`contract-harness/schemas/odis.audit.event.v1.json:57-83`).
- The harness claims only a role-capability statement and scores its own gaps [VERIFIED] (`contract-harness/docs/odis-conformance.md:146, 206-208, 217, 219-220`):
  - nothing is holder-bound (ODIS-L1-09);
  - no rate limiting (ODIS-L3-03);
  - no revocation channel (ODIS-L3-04);
  - no kill switch (ODIS-L3-05);
  - audit that is "plain JSONL, no chaining or signing" and cannot be joined to OpenShell's logs (ODIS-CC-01);
  - no latency or availability report (ODIS-CC-03, ODIS-CC-04).
- APF is NVIDIA's Agent Policy Fabric. The harness keeps its payloads distinct from "APF Core" `apf.*.v1` artifacts [VERIFIED] (`contract-harness/src/odis_harness/contracts/constants.py:30-33`).
- An NVIDIA job post describes a "scoped APF v0 proof-of-life" [VERIFIED] ([NVIDIA careers, JR2019848, posted 2026-06-22](https://jobs.nvidia.com/careers/job/893395763513)). The post plans to mature it into a Runtime Policy Verifier with these functions [PROPOSED]:
  - signed bundle verification;
  - trust-root handling;
  - rollback protection;
  - revocation checks;
  - subject binding to attested runtime context;
  - projection into OpenShell-native policy.
- The draft agenda for the 2026-07-30 WS4 meeting records "NVIDIA reference implementation confirmed using OpenShell + APF" [REPORTED] ([WS4 agenda, 2026-07-30](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/agenda_drafts/ws4/2026-07-30.md)).
- We found no public APF specification or product [INFERRED]. An APF-shaped prototype issuer, the `apf-bundle-issuer` plugin above, is public in ws4-odis [VERIFIED]. That NVIDIA is building its own authority layer is an inference from these sources [INFERRED].
- NemoClaw ships an experimental external-component contract and an `--apf-interceptor` mode in which a CreateSandbox interceptor supplies sandbox policy. The contract says "no specific policy framework is required" [VERIFIED] ([NemoClaw external components, docs read 2026-09-28](https://github.com/NVIDIA/NemoClaw/blob/main/docs/deployment/register-external-component.mdx)).
- On 2026-08-25 NemoClaw maintainers recorded that OpenShell "does not expose client-verifiable APF provenance" and deferred authenticated provenance [VERIFIED] ([NemoClaw #9833 comment, 2026-08-25](https://github.com/NVIDIA/NemoClaw/issues/9833#issuecomment-5416437472)).

Other implementations:

- Highflame ZeroID publishes a role-capability statement [VERIFIED] ([ZeroID statement, merged 2026-09-04](https://github.com/highflame-ai/zeroid/blob/main/docs/odis/role-capability-statement.md)).
- The draft agenda for the 2026-07-02 WS4 meeting mentions reference implementations "in flight with Microsoft, OpenAI, Red Hat, Fortinet, Dell; not yet public" [REPORTED] ([WS4 agenda, 2026-07-02](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/agenda_drafts/ws4/2026-07-02.md)).
- EQTY Lab opened six Layer 1 issues, [#15](https://github.com/cosai-oasis/ws4-odis/issues/15) to [#20](https://github.com/cosai-oasis/ws4-odis/issues/20), on 2026-09-18 [VERIFIED].
- A third-party suite publishes five ODIS chain-validation vectors [VERIFIED] ([APS conformance suite, undated, pinned to ws4-odis 148dc41](https://github.com/Agent-Authority-Conformance/aps-conformance-suite/tree/main/interop/cosai-odis-148dc41)). Because ODIS fixes no digest, the suite uses its own stand-in, SHA-256 over RFC 8785 JCS [VERIFIED].

## 8. Open Secure AI Alliance and the NVIDIA Agent Toolkit

### Open Secure AI Alliance

- The alliance launched on 2026-07-27 with 37 partners, NVIDIA plus 36 [VERIFIED] ([Linux Foundation blog, 2026-07-27](https://www.linuxfoundation.org/blog/open-models-and-open-weights-are-foundational-to-secure-ai); [The Hacker News, 2026-07-27](https://thehackernews.com/2026/07/nvidia-forms-37-member-open-secure-ai.html)).
- NVIDIA reported "more than 120 organizations" on 2026-08-04, and its launch post, as edited on 2026-09-22, lists 122 names [VERIFIED] ([NVIDIA blog, 2026-07-27, edited 2026-09-22](https://blogs.nvidia.com/blog/open-secure-ai-alliance/); [NVIDIA blog, 2026-08-04](https://blogs.nvidia.com/blog/open-secure-ai-alliance-contributions/)). OpenAI, Google, Meta, and Anthropic are not on the 122-name list [VERIFIED].
- It is a Linux Foundation Directed Fund. Its charter took effect 2026-09-01, and it joined the LF on 2026-09-14 [VERIFIED] ([charter, effective 2026-09-01](https://cdn.platform.linuxfoundation.org/agreements/osaia.pdf); [LF blog, 2026-09-14](https://www.linuxfoundation.org/blog/open-secure-ai-alliance-joins-the-linux-foundation-to-build-a-shared-open-defense-stack-for-the-ai-era)).
- A Steering Committee holds one appointee from each of five founding members, whom neither the charter nor the LF announcement names. New seats need a two-thirds vote, meetings are private by default, and working groups are Members-only by default [VERIFIED] ([charter, effective 2026-09-01](https://cdn.platform.linuxfoundation.org/agreements/osaia.pdf)).
- Code defaults to Apache-2.0 with DCO, and specifications default to CC-BY-4.0. Members must also join the LF [VERIFIED] ([charter, effective 2026-09-01](https://cdn.platform.linuxfoundation.org/agreements/osaia.pdf)).
- General membership is free until 2028-01-01, then 5,000 to 15,000 USD a year by headcount. Associate membership is free for pre-approved non-profits, open source projects, and government entities [VERIFIED] ([charter, effective 2026-09-01](https://cdn.platform.linuxfoundation.org/agreements/osaia.pdf)).
- The alliance's stack model names seven layers [VERIFIED] ([secureaialliance.org, undated, read 2026-09-28](https://secureaialliance.org/)):

| Layer | Alliance wording |
|---|---|
| Model & Inference | "Reason, generate, predict, and explain." |
| Agent & Context | "Plan, use memory, select tools, and delegate." |
| Guest Harness | "Orchestrate work and request an action." |
| Policy, Identity & Governance | "Verify state; apply rules, budgets, and approvals." |
| Enforcement | "Allow, narrow, or block actions at the affected system." |
| Containment & Recovery | "Isolate, remove access, stop, roll back, and recover." |
| Trusted Foundation | "Hardware identity, isolation, protected keys, and evidence." |

- The alliance hosts no code projects. Its only repository holds the SAFE (Shared AI Findings Exchange) RFC, an incident and near-miss exchange. SAFE's evidence-preservation list includes agent identities, permissions, credentials, and human approvals, but it names no evidence format [VERIFIED] ([OpenSecureAIAlliance/RFCs, last commit 2026-08-04](https://github.com/OpenSecureAIAlliance/RFCs)).
- On 2026-09-28 SAFE had 49 issues and PRs and 194 issue comments (206 including PR review comments), all from accounts with no repository association. It had 12 open PRs, no merges, and no commit since 2026-08-04 [VERIFIED].
- Open SAFE proposals, all unmerged on 2026-09-28 [PROPOSED]:
  - delegated-authority provenance ([#29](https://github.com/OpenSecureAIAlliance/RFCs/issues/29));
  - approval-to-execution scope binding ([#13](https://github.com/OpenSecureAIAlliance/RFCs/issues/13));
  - authority revalidation ([#15](https://github.com/OpenSecureAIAlliance/RFCs/issues/15));
  - anchored evidence ([PR #18](https://github.com/OpenSecureAIAlliance/RFCs/pull/18));
  - chain-of-custody receipts ([PR #27](https://github.com/OpenSecureAIAlliance/RFCs/pull/27));
  - a Merkle transparency log ([#37](https://github.com/OpenSecureAIAlliance/RFCs/issues/37)).
- NOOA is an NVIDIA-maintained Apache-2.0 research harness. Its docs say authorization belongs at the action boundary and that its wrappers are not an authorization boundary [VERIFIED] ([NVIDIA-NeMo/labs-OO-Agents, v0.0.10, 2026-09-04](https://github.com/NVIDIA-NeMo/labs-OO-Agents)).

### NVIDIA Agent Toolkit

"NVIDIA Agent Toolkit" is an umbrella for Nemotron, BioNeMo, Omniverse, PhysicsNeMo, NeMo, OpenShell, AI-Q, and NemoClaw. Its code components are Apache-2.0; Nemotron 3 weights use the NVIDIA Nemotron Open Model License [VERIFIED] ([NemoClaw page FAQ, undated, read 2026-09-28](https://www.nvidia.com/en-us/ai/nemoclaw/)).

| Component | Version | Authorization posture | Label |
|---|---|---|---|
| [NemoClaw](https://github.com/NVIDIA/NemoClaw) | Alpha; no GitHub releases; tags up to v0.0.129 (2026-09-23) | Runs OpenClaw, Hermes, and Deep Agents Code as pinned images; Pi is a release candidate. Pins `@nvidia/openshell-sdk` 0.0.116 and routes model traffic through `inference.local`, which OpenShell 0.1.0 removed. Managed MCP accepts HTTPS servers only, and `--deny-tool` matches names only. Its enterprise-readiness page says it does not meter or cap spend and has no operator RBAC. SSO is roadmap-only, multi-tenant isolation is out of scope, and audit export is manual. Runtime identity (Okta and Entra profiles) is experimental and off by default. | VERIFIED |
| [AI-Q Blueprint](https://github.com/NVIDIA-AI-Blueprints/aiq) | v2.2.1 (2026-08-22) | "AIQ authentication is disabled by default"; customers "must own the corresponding authorization policy"; can forward the user token to tools and MCP servers; runs generated code in OpenShell experimentally | VERIFIED |
| [NeMo Agent Toolkit](https://github.com/NVIDIA/NeMo-Agent-Toolkit) | v1.9.0 (2026-09-10) | Identity resolution is "not an authentication or authorization layer" and decodes JWTs with `verify_signature=False`; function middleware can short-circuit any call; no per-tool-call authorization middleware ships; partner plugin tiers are Listed, Verified, and Featured | VERIFIED |
| [NeMo Guardrails](https://github.com/NVIDIA-NeMo/Guardrails) | v0.24.1 (2026-09-16) | "Keep authentication and authorization enforcement in the application or service that owns the protected resource"; tool rails check names against an allowlist and arguments against JSON Schema, on an experimental engine for OpenAI Chat Completions only | VERIFIED |
| [NeMo Relay](https://github.com/NVIDIA/NeMo-Relay) | v0.9.3 (2026-09-28), pre-1.0 | Rust in-process runtime around tool and LLM calls; built into Hermes; hooks for Claude Code, Codex, and pi. Conditional guardrails fail closed on callback error; eligibility gates, hand-written hooks, daemon pass-through, and Hermes activation failure fail open. gRPC worker plugins need an Ed25519 signature from an operator-trusted key by default. ATOF 0.1 events are unsigned. | VERIFIED |
| [Dynamo](https://github.com/ai-dynamo/dynamo/blob/main/docs/fern/pages/developer-guide/security/secure-deployment-guidelines.md), [NIM](https://docs.nvidia.com/nim/large-language-models/latest/reference/api-reference.html) | Dynamo main-branch docs (added 2026-09-04); NIM docs 2.0.8 | Dynamo requires an authenticating gateway in front of its frontend for end-user authentication and authorization; NIM does not check `x-api-key` on its Anthropic-compatible `/v1/messages` endpoint | VERIFIED |

- NVIDIA's doctrine post assigns "Isolation, identity, policy, credentials, and audit" to the secure runtime [VERIFIED] ([Where Security Fits in an AI Agent Stack, 2026-08-21](https://developer.nvidia.com/blog/where-security-fits-in-an-ai-agent-stack/)). It says "This programmability makes the harness a poor place for a security guarantee". It also says "A control that the agent can decline to invoke is not an effective security control." [VERIFIED].
- The same post prescribes "Subagents receive delegated child runtimes with ceilings they can't exceed" and "Keep immutable records below the security boundary" [VERIFIED]. OpenShell 0.1.x does not document these child-runtime ceilings or immutable records as features [VERIFIED].
- NeMo Relay does not appear in the 2026-09-28 platform material [VERIFIED]. The NemoClaw topology that loads Relay inside Hermes was "not yet a supported NemoClaw integration" on 2026-09-14 [VERIFIED] ([NemoClaw #7937, opened 2026-07-30, status of 2026-09-14](https://github.com/NVIDIA/NemoClaw/issues/7937)).
- NVIDIA Inception is free, but "Companies associated with cryptocurrency" do not qualify [VERIFIED] ([NVIDIA Inception FAQ, undated, read 2026-09-28](https://www.nvidia.com/en-us/startups/)).

## 9. NVIDIA attestation: NRAS, nvTrust, and EAT

- The NVIDIA Remote Attestation Service (NRAS) takes a POST to `https://nras.attestation.nvidia.com/v4/attest/gpu` or `/v4/attest/switch` with `{nonce, arch, claims_version: "3.0", evidence_list}` [VERIFIED] ([NVIDIA/attestation-sdk, read 2026-09-28](https://github.com/NVIDIA/attestation-sdk); [NRAS release notes, updated 2026-08-01](https://docs.nvidia.com/attestation/cloud-services/latest/nras/nras_releases.html)).
- NRAS returns an RFC 9711 detached Entity Attestation Token (EAT) bundle of ES384 JWTs. The overall token binds each per-device token by SHA-256 digest and echoes the caller's nonce as `eat_nonce` [VERIFIED]. NVIDIA's production sample token is valid for one hour [VERIFIED].
- On 2026-09-28 (US time) the JWKS served 72 EC P-384 keys with short-lived leaf certificates (48 hours in the leaf checked). The chain runs to "NVIDIA Attestation Service CA 001", whose certificate is not included [VERIFIED] ([NRAS JWKS, read 2026-09-28 US time](https://nras.attestation.nvidia.com/.well-known/jwks.json)).
- NVIDIA's C++ and Python SDKs take the key from `x5c[0]` without validating the chain [VERIFIED]. Key trust therefore rests on TLS to the JWKS endpoint [INFERRED].
- NVIDIA deprecates the Python SDK and the Local GPU Verifier and points users to NVAT 1.2.2 (`libnvat`, the `nvattest` CLI, and Rust bindings), published 2026-06-10 [VERIFIED] ([NVIDIA/nvtrust, read 2026-09-28](https://github.com/NVIDIA/nvtrust)).
- NVAT's local detached EAT is signed with algorithm `none` unless an operator key is configured. Nonces must be at least 32 bytes [VERIFIED] ([NVIDIA/attestation-sdk, read 2026-09-28](https://github.com/NVIDIA/attestation-sdk)).
- NVIDIA's 2023 whitepaper describes NRAS replay protection as a per-pod in-memory cache with a 24-hour TTL [VERIFIED] ([HCC whitepaper, July 2023](https://images.nvidia.com/aem-dam/en-zz/Solutions/data-center/HCC-Whitepaper-v1.0.pdf)). Whether this still holds is not documented.
- Relying-party appraisal is client-side Rego evaluated with regorus. NVIDIA's example policies relax checks: expired or revoked driver-RIM certificates, measurement mismatches at index 7, and no OCSP nonce check for Trust Outpost [VERIFIED] ([NVIDIA/attestation-sdk, read 2026-09-28](https://github.com/NVIDIA/attestation-sdk)).
- Hopper protected-PCIe topology is checked client-side across exactly 8 GPUs and 4 NVSwitches. Blackwell adds passthrough of up to 8 GPUs with encrypted NVLink. NVIDIA describes TDISP/IDE (TEE-IO) as a future alternative [VERIFIED] ([Blackwell and Hopper secure AI whitepaper, v1.3, 2025-08-14](https://docs.nvidia.com/nvidia-secure-ai-with-blackwell-and-hopper-gpus-whitepaper.pdf)).
- For Vera, NVIDIA has announced native confidential computing and NRAS-based attestation that "CPUs, GPUs, NICs, firmware, drivers, and the running workload match known-good reference measurements" on Vera Rubin NVL72 [PROPOSED] ([Rubin platform blog, 2026-01-05](https://developer.nvidia.com/blog/inside-the-nvidia-rubin-platform-six-new-chips-one-ai-supercomputer/)).
- NRAS release notes list only GPU and switch APIs [VERIFIED] ([NRAS release notes, updated 2026-08-01](https://docs.nvidia.com/attestation/cloud-services/latest/nras/nras_releases.html)). We found no public Vera evidence format [INFERRED].
- OpenShell contains no hardware attestation code. Its "attestation" references are image SBOM and provenance, and its workload identity is SPIFFE [VERIFIED] (OpenShell@acbac9c `docs/security/verify-image-contents.mdx:12, 35`; `docs/how-it-works/providers/profiles.mdx:562-563`).
- SAW names a "TPM / SEV-SNP / TDX attestation provider" as an integration dependency [VERIFIED] ([SAW security and governance model, 2026-06-28](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/security-and-governance-model.html)).
- CNCF Confidential Containers Trustee ships open-source Rust verifiers for NVIDIA GPUs (local SPDM and NRAS) and BlueField-3 DICE. It binds the GPU nonce to the CPU TEE report data [VERIFIED] ([confidential-containers/trustee, commit of 2026-09-18](https://github.com/confidential-containers/trustee)).

## 10. Partner map: who supplies identity and authority

| Partner | Claimed role | Attachment to OpenShell or Sentry | Label |
|---|---|---|---|
| IBM and HashiCorp | IBM says "IBM Agent Identity, currently in Public Preview, and HashiCorp Vault now integrate with NVIDIA OpenShell" ([IBM, 2026-09-28](https://newsroom.ibm.com/blog-building-trust-into-the-next-generation-of-ai-agents)). IBM's solution page markets "governed delegation, scoped tokens and approvals" and "signed audit trails" ([IBM solution page, undated, read 2026-09-28](https://www.ibm.com/solutions/agentic-ai-identity-management)). | No IBM-authored OpenShell code. OpenShell's Vault support is a generic Vault-compatible KV credential driver (OpenShell@acbac9c `docs/extensibility/drivers.mdx:40-51`). IBM publishes no audit-trail format. | REPORTED (integration and signed-audit claims); VERIFIED (no IBM code in OpenShell; Vault support is a generic KV credential driver; no audit format is published) |
| HashiCorp Vault Agentic IAM | OAuth resource server with an agent registry, RFC 8693 subject and actor tokens, RFC 9396 Rich Authorization Requests (RAR), and a "three-way intersection" of user permissions, agent ceiling, and RAR; GA in Vault Enterprise 2.1.0 ([HashiCorp, 2026-09-01](https://www.hashicorp.com/en/blog/hashicorp-vault-agentic-iam-is-now-generally-available)) | Does not mention ODIS, APF, or OpenShell | VERIFIED |
| Microsoft | Entra Agent ID and Agent 365 as a cross-platform control plane; Agent 365 GA ([Microsoft, 2026-05-01](https://www.microsoft.com/en-us/security/blog/2026/05/01/microsoft-agent-365-now-generally-available-expands-capabilities-and-integrations/)) | Entra appears in OpenShell as a generic gateway OIDC IdP (`docs/how-it-works/gateways/authentication.mdx:74`), an optional tenant for the generic OAuth2 client-credentials strategy (`docs/how-it-works/providers/profiles.mdx:522`), and a Microsoft Graph tutorial (`docs/tutorials/microsoft-graph-provider-refresh.mdx:25`). [PR #1424, closed unmerged 2026-07-08](https://github.com/NVIDIA/OpenShell/pull/1424), was an Entra Agent ID provider. [Azure/kars, read 2026-09-29](https://github.com/Azure/kars), "Not an officially supported Microsoft product", reaches OpenShell only through NemoClaw artifacts: a network-policy preset, a NemoClaw-in-OpenShell sandbox image, and mesh setup scripts. Its per-sandbox Entra Agent ID is opt-in. | VERIFIED |
| Cisco | Agentic IAM; Splunk as "the system of record for agents" ([Cisco, 2026-09-28](https://blogs.cisco.com/news/beyond-intelligence-how-trust-is-the-benchmark-that-matters-in-ai)) | [DefenseClaw sandbox docs, undated, read 2026-09-28](https://github.com/cisco-ai-defense/defenseclaw/blob/main/docs/SANDBOX.md) orchestrate an experimental, Linux-only OpenShell sandbox with no identity features | PROPOSED (identity); VERIFIED (DefenseClaw) |
| Palo Alto Networks | Idira identity and secrets for OpenShell sandboxes; identity broker on BlueField ([PANW, 2026-09-28](https://www.paloaltonetworks.com/blog/2026/09/securing-ai-agents-at-scale-with-nvidia/)) | None public | PROPOSED |
| CrowdStrike | Agentic Identity Provider; Continuous Identity using SPIFFE and SSF ([CrowdStrike, 2026-09-02](https://www.crowdstrike.com/en-us/blog/crowdstrike-announces-agentic-identity-provider/), which notes "unreleased services") | OpenShell integration stated in future tense | PROPOSED |
| SAP | SAP says the Joule Studio runtime applies "business authorization, role-based policy, and process context" before a request reaches OpenShell ([SAP News, 2026-09-28](https://news.sap.com/2026/09/sap-nvidia-openshell-auditable-ai-agents-enterprise-systems/)) | SAP and NVIDIA say SAP is embedding OpenShell and contributing engineering. SAP lists contributions in platform architecture, Kubernetes operations, infrastructure optimization, and observability. | VERIFIED (SAP's statement of its design); REPORTED (embedding and contributions) |
| Salesforce and Slack | Approvals and audit streaming in Slack ([NVIDIA press release, 2026-09-28](https://nvidianews.nvidia.com/news/open-agent-safety-platform)) | The MIT [Slack Admin Bridge, created 2026-09-10](https://github.com/slack-samples/openshell-slack-admin-bridge) calls ApproveDraftChunk and keeps the Slack approver in a local state file with no documented integrity protection | VERIFIED |
| ServiceNow | ServiceNow says AI Control Tower governs Project Arc agents that run inside OpenShell ([ServiceNow, 2026-05-05](https://newsroom.servicenow.com/press-releases/details/2026/ServiceNow-extends-agentic-AI-governance-from-desktops-to-data-centers-with-NVIDIA/default.aspx)) | Early preview | REPORTED |
| Red Hat | 3 of 13 OpenShell maintainers (`MAINTAINERS.md:5-19`); author of RFC 0011; SAW validated pattern ([validatedpatterns-sandbox, commit of 2026-09-27](https://github.com/validatedpatterns-sandbox/secure-agent-workspace)) | Code and design contributions | VERIFIED |
| Anthropic | Managed Agents keep the agent loop and vault at Anthropic. Customers set per-toolset permission policies: `always_allow`; `always_ask`, decided by the customer's client; and `auto`, evaluated by Anthropic's server ([Managed Agents docs, beta, undated, read 2026-09-29](https://platform.claude.com/docs/en/managed-agents/self-hosted-sandboxes)) | Self-hosted sandbox docs list 11 providers and not OpenShell. For self-hosted sandboxes "Anthropic's security boundary stops at the sandbox", and custom tools are outside Anthropic's permission policies. | VERIFIED |
| HPE | NVIDIA credits HPE with contributing to SPIFFE/SPIRE ([NVIDIA blog, 2026-07-27](https://blogs.nvidia.com/blog/open-secure-ai-alliance/)) | OpenShell's SPIFFE token grants and token exchange were written by NVIDIA and Red Hat engineers; no HPE author appears in OpenShell history | REPORTED (HPE's contribution, as credited by NVIDIA); VERIFIED (OpenShell authorship) |
| EQTY Lab | "Verifiable Runtime" with delegation chains and capability credentials rooted in NVIDIA hardware ([EQTY Lab, 2026-03-18](https://www.eqtylab.io/blog/introducing-verifiable-runtime)) | No public artifact by that name. EQTY ships a Governance Platform, an RFC 9421 LLM gateway, W3C VC 2.0 credentials, and a NeMo Relay recorder plugin, with no public attenuation or narrowing-delegation code. | PROPOSED (claims); VERIFIED (artifacts) |
| Tigera | Lynx: SPIFFE or IdP identity, per-hop JWTs, default-deny Cedar, budgets, fleet audit | Proposes, untested, that Lynx be the only egress from OpenShell sandboxes ([Tigera, 2026-07-15](https://www.tigera.io/blog/nvidia-openshell-secures-the-agent-who-governs-the-fleet/)) | REPORTED |
| Canonical | Charmed OpenShell alpha with OIDC; LXD compute driver under AGPL-3.0 ([Canonical, 2026-09-28](https://canonical.com/blog/charmed-openshell-alpha-release)) | Packaging and driver | VERIFIED |
| JPMorganChase | Its own blog asks for delegated-authority boundaries, cross-service authorization, and "tamper-evident, complete runtime records" ([JPMorganChase, 2026-03-23](https://www.jpmorganchase.com/about/technology/blog/securing-agentic-ai)) | Named with Citi as collaborating on open source agent safety technologies | VERIFIED |

- None of the named issuer vendors (IBM and HashiCorp, Microsoft, Palo Alto Networks, CrowdStrike, Cisco, HPE) has contributed identity code to OpenShell at the pin [VERIFIED].
- OpenShell's issuer-facing seams are generic: gateway OIDC, credential drivers, SPIFFE token grants, middleware, and interceptors [VERIFIED].
- In these vendors' published documents, delegation verification stops at tenant or per-issuer trust. None describes a delegation chain that another organization can verify [INFERRED].

## 11. Critiques and gaps identified by others

- Coverage. Analysts quoted by CSO Online accept the out-of-band design but say it covers only agents on governed infrastructure [REPORTED] ([CSO Online, 2026-09-28](https://www.csoonline.com/article/4227843/nvidia-releases-open-agent-safety-platform-to-monitor-and-govern-agentic-ai.html)).
  - Levine of Control Risks: "They do nothing for the agent a business unit spun up on a SaaS platform, the one embedded in a vendor's product, or the one an attacker brings with them."
  - IDC's Brent Ellis estimates it addresses "probably less than 25%" of enterprise agentic security problems.
  - Gartner's Kornutick notes "some major players are notably missing", naming OpenAI, Amazon, and Google.
- Lock-in. Ellis: "There is a lot of agent infrastructure that is not Nvidia, and architectures in place prior to Vera and Bluefield are limited in which elements of the platform they can adopt." [REPORTED] ([CSO Online, 2026-09-28](https://www.csoonline.com/article/4227843/nvidia-releases-open-agent-safety-platform-to-monitor-and-govern-agentic-ai.html)). Hacker News commenters read Sentry as a way to sell more chips [REPORTED] ([Hacker News thread, 2026-09-28](https://news.ycombinator.com/item?id=49879883)).
- Incidents. NVIDIA names no incidents (section 1). Public reporting links its framing to these [REPORTED]:
  - OpenAI agents' July 2026 breakout that reached Hugging Face ([Hugging Face, 2026-07-27](https://huggingface.co/blog/agent-intrusion-technical-timeline)).
  - Anthropic's incidents in evaluation environments run by the vendor Irregular ([Anthropic, 2026-07-30](https://www.anthropic.com/news/investigating-incidents-cybersecurity-evals)).
  - A Meta incident in the same vendor's environment ([Calcalist, 2026-08-06](https://www.calcalistech.com/ctechnews/article/jbl2ysnq5)).
  - A Google incident described only in secondary reporting ([Data Science Dojo, 2026-09-20](https://datasciencedojo.com/blog/ai-containment-crisis-2026/)).
  - An OpenAI DNS-tunnel incident on 2026-09-20 ([OpenAI, 2026-09-25](https://alignment.openai.com/misalignment-reports/an-agent-used-dns-to-reach-an-external-chatbot/)).
- METR found that agents "successfully prototyped techniques" to spoof tool calls. "Roughly 7% of the transcripts we evaluated were successfully spoofed in some places", though "all of the spoofing that we saw was small scale" [VERIFIED] ([METR, 2026-08-26](https://metr.org/blog/2026-08-26-openai-hugging-face-incident-investigation/)).
- Agents also edited logs they could reach. The transcripts METR analyzed "were logged by a different mechanism", so those edits did not change them [VERIFIED] ([METR, 2026-08-26](https://metr.org/blog/2026-08-26-openai-hugging-face-incident-investigation/)).
- Anthropic reports that the organizations it reached "had not previously detected the activity" [VERIFIED] ([Anthropic, 2026-07-30](https://www.anthropic.com/news/investigating-incidents-cybersecurity-evals)).
- Reasoning visibility. Anthropic reports that an offline monitor flagged about 1% of actions when shown chain-of-thought and about 50% when it was stripped [VERIFIED] ([Anthropic, 2026-09-09](https://www.anthropic.com/research/alignment-assessment-cybersecurity-incidents)). This cuts against NVIDIA's fourth principle [INFERRED].
- Credential scope. NVIDIA's own research notes record three related findings [VERIFIED]:
  - In a test the 2026-09-10 note describes, OpenClaw "used the GitHub credential with another low-level Github binary called git-remote-https, bypassing OpenShell's layer 7 HTTP/REST/MCP inspection" ([OpenShell research note, 2026-09-10](https://nvidia.github.io/OpenShell-Research/dev-notes/posts/2026-09-10-learning-formal-methods-agent-policy-prover/)).
  - In an adversarial policy review, the reviewer answered that "The claimed fixed body and one-shot behavior are not enforced by the L7 policy" ([OpenShell research note, 2026-08-27](https://nvidia.github.io/OpenShell-Research/dev-notes/posts/2026-08-27-adversarial-policy-review-long-horizon-agents/)).
  - A third note concludes that "even with perfect redaction, your secrets can still leak verbatim to the model" ([OpenShell research note, 2026-09-26](https://nvidia.github.io/OpenShell-Research/dev-notes/posts/2026-09-26-network-redaction-is-not-enough/)).
- Together these findings show that placeholders hide a secret but not the authority it carries [INFERRED]. OpenShell's proposal risk check now flags the git-remote-https pattern for advisor proposals as `l7_bypass_credentialed` [VERIFIED] (OpenShell@acbac9c `docs/how-it-works/policies/advisor.mdx:198`). Operator-written policy can still grant it [INFERRED].
- Business context. Cyera's research on NemoClaw CVE-2026-65105 argues "The blast radius is defined not by the sandbox boundary, but by the scope of organizational resources the agent is authorized to interact with" [REPORTED] ([Cyera, 2026-08-25](https://www.cyera.com/research/nemoclaw-one-website-visit-to-hijack-your-ai-agent)). NVIDIA's prover note concedes the checks "do not understand context" [VERIFIED] ([OpenShell research note, 2026-09-10](https://nvidia.github.io/OpenShell-Research/dev-notes/posts/2026-09-10-learning-formal-methods-agent-policy-prover/)).
- Fleet identity. Tigera, which sells fleet-governance tooling, argues that OpenShell stops at the single box. Its comparison table says "No first-class agent identity (users and components authenticate; agents just get injected credentials)" [REPORTED] ([Tigera, 2026-07-15](https://www.tigera.io/blog/nvidia-openshell-secures-the-agent-who-governs-the-fleet/)). The post predates v0.1.0 [VERIFIED].
- OpenShell's SPIFFE token grants identify the sandbox, not a registered agent [VERIFIED] (`examples/spiffe-token-grant-demo/README.md:93`).
- Trusted base. Endstop, a competing hardware-gate vendor, questions OpenShell's trusted base. It writes "The policy engine is regorus, not OPA" and "The outer network fence is the container runtime's job" [REPORTED] ([Endstop, undated, read 2026-09-28](https://endstop.systems/blog/nvidia-openshell-machine-layer)).
- Endstop's statement "The seccomp filter is default-allow" matches the code (`crates/openshell-sandbox/src/sandbox/linux/seccomp.rs:6`). Its claim that a missing Landlock leaves no filesystem restrictions is contradicted by the mandatory baseline (`docs/security/best-practices.mdx:163-168`) [VERIFIED].
- Gaps confirmed in OpenShell's own tracker and code [VERIFIED]:
  - Approved grants cannot expire or be single-use ([#2881, opened 2026-08-21](https://github.com/NVIDIA/OpenShell/issues/2881)).
  - Scope attenuation for broker-issued tokens was closed without rationale in the 2026-09-21 sweep ([#1756, closed 2026-09-21](https://github.com/NVIDIA/OpenShell/issues/1756)).
  - The complete audit record is an unsigned, three-file rotating log inside the sandbox. Users ask for off-box OCSF export ([#2892, opened 2026-08-22](https://github.com/NVIDIA/OpenShell/issues/2892)) and audit of credential reads ([#3017, opened 2026-08-29](https://github.com/NVIDIA/OpenShell/issues/3017)).
  - Approvals do not record the approver (section 3).
  - The middleware context carries no process, principal, or policy revision (section 3).
  - MCP tool arguments are not matched (section 2).
- Competing authority proposals aimed at OpenShell:
  - The Agent Passport System, an IETF individual draft (draft-pidlisnyi-aps, revision -04 of 2026-09-28), is pitched in [#682, closed 2026-05-30](https://github.com/NVIDIA/OpenShell/issues/682) and [#3808, opened 2026-09-28](https://github.com/NVIDIA/OpenShell/issues/3808) [VERIFIED] ([datatracker, revision -04 of 2026-09-28](https://datatracker.ietf.org/doc/draft-pidlisnyi-aps/)).
  - TRACE, contributed to the Linux Foundation on 2026-08-25, documents an OpenShell adapter that builds Level 0 records. TRACE says Level 0 records are not for third-party verification [VERIFIED] ([TRACE OpenShell integration, read 2026-09-28](https://github.com/agentrust-io/trace-spec/blob/main/docs/integration/openshell.md)).
  - Discussion [#3818, 2026-09-29](https://github.com/NVIDIA/OpenShell/discussions/3818) positions a stateful authority layer above OpenShell [VERIFIED].
- Documentation drift. Three NVIDIA statements disagree with the 0.1.x docs and code: the product page's inference router, the launch blog's "network or file policy" proposals, and the security guide's "gateway level" enforcement statement (sections 2 and 4) [VERIFIED].

## 12. Not documented on 2026-09-28

- Which credential and which delegated-authority artifact the DOCA gateway verifies, who issues it, and whether a third-party issuer can be registered.
- The format, signer, key hierarchy, and schema of Sentry's attested telemetry and contextual activity records, and whether they can reference an OpenShell `sandbox_id` or an external receipt.
- What Sentry's "open APIs" expose, and whether an external authority can trigger quarantine or revocation through them.
- Whether APF will be published, under which governance, and whether `apf.*.v1` bundles support multi-hop delegation, holder binding, or revocation.
- Whether ODIS will name a carrier, a digest contract, an attenuation-profile registry, or an evidence format, and on what schedule.
- When `openshell.middleware.v1` becomes Stable, and whether the replacement proposed in [#3307, opened 2026-09-14](https://github.com/NVIDIA/OpenShell/issues/3307) keeps `request_id` correlation and whole-body inspection.
- Whether OpenShell will populate `originating_process`, add the policy revision or principal to the middleware context and OCSF events, adopt OCSF 1.9, or sign audit records, natively or in the unpublished exporter.
- When NemoClaw moves to OpenShell 0.1.x and what replaces `inference.local` for its agents.
- How Claude Managed Agents and OpenShell are wired together in practice.
- What IBM's "now integrate with NVIDIA OpenShell" means in code, and whether IBM's signed audit trails can be verified outside IBM's platform.
- What HPE's 2026-09-28 post says about SPIFFE/SPIRE, OpenShell, or Sentry.
