# Integration designs: Chio inside and beside the NVIDIA stack

This document specifies how Chio would connect to NVIDIA's agent safety stack. It covers the two OpenShell extension points relevant to an external authority: supervisor middleware and gateway interceptors. OpenShell also documents drivers and isolation backends (VERIFIED, [`docs/extensibility/overview.mdx:26-51`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/extensibility/overview.mdx?plain=1#L26-L51)). The document also covers a receipt metadata family with Open Cybersecurity Schema Framework (OCSF) export, verifier families for NVIDIA and OpenShell evidence, Sentry as a sensor provider, the Open Delegation & Identity Standard (ODIS), deployment shapes, demonstrations, and upstream engagement. For each design it gives the mechanism, the contracts and fields, what Chio has today with repository paths, the new work, effort, risks, and open questions. Every design here is PROPOSED. None is built.

The NVIDIA side is described in [01-nvidia-stack.md](01-nvidia-stack.md), Chio's current state in [02-chio-today.md](02-chio-today.md), the field-level comparison in [03-overlap-matrix.md](03-overlap-matrix.md), competitors in [05-competitive-analysis.md](05-competitive-analysis.md), sequencing and dated effort in [06-strategy-and-roadmap.md](06-strategy-and-roadmap.md), candidate ideas in [07-ideas-backlog.md](07-ideas-backlog.md), and sources in [08-sources.md](08-sources.md). [README.md](README.md) indexes the set.

The designs keep one division of labor. OpenShell stays the enforcement point in every design below. Chio supplies the authority decision, the delegation chain and signed evidence through OpenShell's published hooks. No design or upstream ask needs OpenShell core to sign Chio data or adopt a Chio format. Chio references travel only in generic fields that OpenShell already has, named in designs A to C, and each ask in section I is a generic field that any external authority could use (PROPOSED).

NVIDIA's Secure Agent Workspace (SAW) reference design treats authorization as "the per-engagement delegation record", "a policy-defined subset of the end-user's permissions". SAW says authorization is "evaluated and enforced centrally at the runtime layer, never a separate authority and never re-implemented by each application" (VERIFIED, [SAW enterprise tool access model, last updated 2026-06-28](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/enterprise-tool-access-model.html)). Read literally, this rules out a separately held authority (INFERRED). The designs fit it only where the runtime layer invokes Chio's decision and each root capability carries a grant from the enterprise identity provider (IdP) (INFERRED). Q2-01 adds that grant (roadmap, ADR-0028 candidate). Until then, Chio-issued roots are a separate authority in SAW's terms (INFERRED).

## Scope, pins, and labels

### Pinned sources

| Source | Pin | Citation form |
|---|---|---|
| OpenShell | `main` at `acbac9cb`, committed 2026-09-29 02:18 UTC (2026-09-28 in US time zones), 13 commits after the v0.1.2 tag `6648bd0` (VERIFIED) | Upstream `path:line` at [the commit](https://github.com/NVIDIA/OpenShell/tree/acbac9cb795094986cbab016bfd0352d980b17f6) |
| ODIS | Commit `148dc418` of `cosai-oasis/ws4-odis`, dated 2026-09-08 | Upstream `path:line` at [the commit](https://github.com/cosai-oasis/ws4-odis/tree/148dc4187139a41325e3c6d6e7533d956bd33144) |
| Chio | `main` at `f5566d9a76` | `path:line`, linked relative to the repository root |
| OCSF | [ocsf-schema v1.9.0](https://github.com/ocsf/ocsf-schema/tree/v1.9.0), released 2026-08-03 | Object and profile names |
| Local test | OpenShell v0.1.2 on the Docker driver, one aarch64 host, run on 2026-09-29, with a Python prototype middleware | Artifacts under `spike/`, described in [spike/README.md](spike/README.md); findings without a published log say "local test" |

Dates are UTC. An issue or pull request number without a repository name refers to NVIDIA/OpenShell. A bare `path:line` refers to OpenShell at `acbac9cb`, except paths under `RFCs/` or `contract-harness/`, which refer to ODIS at `148dc418`. Chio paths are linked with `../../../`, and `spike/` paths are the local-test artifacts next to this document.

The local test ran v0.1.2, while OpenShell line numbers below are for `acbac9cb`. The 13 commits between them include MCP inspection and sandbox restart-policy changes (VERIFIED, GitHub comparison read 2026-09-29). The difference that affects these designs is MCP revision 2026-07-28 (INFERRED). In the local test, v0.1.2 rejected 2026-07-28 requests with a 400, while the pinned schema accepts that revision when an endpoint lists it in `mcp.versions` (VERIFIED, local test; [`docs/how-it-works/policies/schema.mdx:383-386`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/how-it-works/policies/schema.mdx?plain=1#L383-L386)).

### Labels

Status labels for statements about NVIDIA, OpenShell, ODIS, partners and standards:

| Label | Meaning |
|---|---|
| VERIFIED | Primary source read on 2026-09-28 to 2026-09-29; some repository states are dated 2026-09-29 UTC. "VERIFIED, local test" marks behavior observed in the local test of OpenShell v0.1.2 on 2026-09-29, described in [spike/README.md](spike/README.md). A quotation is VERIFIED as a statement when its source was read; the claim inside it keeps its own label. |
| REPORTED | Secondary source, such as press coverage or a meeting agenda, not independently confirmed. |
| INFERRED | Our reasoning from the cited evidence. Effort figures are INFERRED. |
| PROPOSED | A design or plan that is not built. Every design in this document carries it, as does NVIDIA or partner work that is only announced. |

Claim-boundary labels for statements about Chio, as [02-chio-today.md](02-chio-today.md) uses them:

| Label | Meaning |
|---|---|
| qualified | Named in the bounded release gate or the evidence matrix of `docs/release/QUALIFICATION.md`, or approved with scope in `docs/reference/CLAIM_REGISTRY.md`. |
| shipped | Code on `main` that builds and has tests, outside the qualified boundary. |
| test-only | Code on `main` with no production caller: its only callers are tests, fixtures or offline tools. |
| unmerged | Code that exists only on an unmerged branch. |
| design doc | A design, proposal, specification draft or paper with no implementation. |
| roadmap | Planned Chio work, scheduled in [06-strategy-and-roadmap.md](06-strategy-and-roadmap.md). |

A label is never upgraded. A label follows the last statement it covers and covers the statements before it in the same paragraph, bullet or table row, back to the previous label. A label in the sentence that introduces a table covers the rows that carry none of their own. Each design section opens with PROPOSED, which covers its design statements. A fact keeps the label from its first appearance in a section, and later mentions in that section do not repeat it.

### Effort, plan ids, and prototype caveats

- Effort is in engineer-weeks (ew) and is an estimate (INFERRED). Figures match sections 4, 5 and 10 of [06-strategy-and-roadmap.md](06-strategy-and-roadmap.md). "Founder" means founder time rather than engineering. M and L are relative sizes, medium and large, that the roadmap does not convert to engineer-weeks.
- Task ids follow that roadmap. Day 1 is 2026-09-30. D30, D60 and D90 name the three 30-day phases, and Q2 means days 91 to 180 (2026-12-29 to 2027-03-28), not a calendar quarter. L-nn ids are later work that a named trigger starts, not a date.
- The roadmap plans three demonstrations in its section 7. Demo A shows argument checks at the middleware ("right tool, wrong arguments"). Demo B shows twenty workers under one sponsor with one revocation. Demo C shows the auditor and the counterparty. Design H maps them to the demonstrations here.
- Latency figures come from a Python prototype on one host. They say nothing about a Rust implementation.
- NVIDIA labels the middleware contract a research preview (VERIFIED, [`examples/supervisor-middleware-content-guard/README.md:9`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/examples/supervisor-middleware-content-guard/README.md?plain=1#L9)), and [#3307, opened 2026-09-14](https://github.com/NVIDIA/OpenShell/issues/3307) proposes a breaking replacement of its request hook (VERIFIED). Every design that touches the contract carries a migration cost (INFERRED).

## The designs at a glance

| Design | OpenShell or NVIDIA surface | Chio role | Window | Effort |
|---|---|---|---|---|
| A. Supervisor middleware | `openshell.middleware.v1` at HTTP_REQUEST/PRE_CREDENTIALS and HTTP_RESPONSE/PRE_RETURN | Per-call authority decision and outcome-bound receipt | D30-06 and D30-07, preview | 5 to 7 ew for a qualified v0 |
| B. Gateway interceptor | `openshell.gateway_interceptor.v1` on 25 interceptable RPCs | Binds a capability ceiling to sandbox policy; control-plane receipts; approvals | Shadow D60-06; fail_closed D90-01 | 7 to 10 ew with policy projection |
| C. Receipt metadata and OCSF | Request, sandbox and policy identifiers; OpenShell OCSF 1.8 events | `runtime_binding` block, OCSF 1.9 export, collector and join verifier | D30-05, D30-09, D60-02, D90-03 | 4 to 6 ew; receipt states 1.25 ew |
| D. Verifier families | Gateway extension JWT; NVIDIA Remote Attestation Service (NRAS) tokens; BlueField Device Identifier Composition Engine (DICE) evidence | Evidence classes for workload identity and hardware attestation | JWT with A; NRAS on partner demand (L-07) | JWT inside A; L-07 M to L |
| E. Sentry as a sensor provider | Sentry reference design; DOCA Argus, a host-monitoring service in NVIDIA's DOCA software for BlueField | Out-of-band observer in sensor-grounded admission | No data processing unit (DPU) code until an interface exists (L-08) | Founder; 0.25 ew observer statement |
| F. ODIS | ODIS sections 6.3 and 8.2 | Role-capability statement, carrier map, companion record | D30-11 to Q2-12 | Founder; 3 ew in Q2-01 |
| G. Deployment shapes | Docker driver, Kubernetes and Helm, OpenShift | Wrapper, edge, middleware, cluster | D60-01 and D60-03 | 3 to 4 ew |
| H. Demonstrations | OpenShell v0.1.2 sandboxes | Minimal, middleware, cross-organization | Days 1 to 90 | Inside A to C |
| I. Engagement | OpenShell issues, Coalition for Secure AI (CoSAI) Workstream 4 (WS4), Open Secure AI Alliance, OCSF | Upstream asks tied to A to F | Tiers in [06-strategy-and-roadmap.md](06-strategy-and-roadmap.md), section 9 | Founder |

Every Chio role in this table is PROPOSED, and every window and effort is roadmap. The OpenShell, NRAS, BlueField, DOCA Argus and ODIS surfaces are VERIFIED as documented at the pins or on the pages cited in each design. Sentry is a reference design that NVIDIA announced without an availability date (PROPOSED).

## Building blocks the designs share

| Block | New work (roadmap) | Chio today | Used by |
|---|---|---|---|
| `chio-pep-core` | A decision-core trait extracted from `EnvoyKernel` and implemented once over the kernel's mediated path. It does not use `HttpAuthority`. | `EnvoyKernel` is a trait with no shipped implementation ([`crates/protocol/chio-envoy-ext-authz/src/service.rs:22-28`](../../../crates/protocol/chio-envoy-ext-authz/src/service.rs#L22-L28)). The mediated path is built at [`crates/products/chio-api-protect/src/proxy/mediated.rs:102`](../../../crates/products/chio-api-protect/src/proxy/mediated.rs#L102). `HttpAuthority` rejects any token carrying an attenuation proof ([`crates/platform/chio-http-core/src/authority.rs:1250-1254`](../../../crates/platform/chio-http-core/src/authority.rs#L1250-L1254)) and grants a 60-second capability with no constraints (`authority.rs:36, 57-68`) (shipped). | A, G |
| Field-scoped constraints and an MCP/JSON-RPC mapper | JSON-pointer argument constraints with all-occurrences semantics (ADR-0027 candidate) | `RegexMatch` passes if any string leaf matches, and `Custom` if any nested object matches. Deferred constraints return true at argument matching and are left to downstream guards, which apply only where installed ([`crates/kernel/chio-kernel/src/request_matching.rs:429, 457, 465-468`](../../../crates/kernel/chio-kernel/src/request_matching.rs#L429)) (shipped). | A, B |
| Outcome-bound receipts | Three states: denied before forward, forwarded (answered, or response withheld), and unknown after deadline. Adds `ToolOrigin::RuntimeForwarded` (ADR-0025 candidate). | Three origins: CallerExecuted, HostExecutedProviderReported and HostExecutedUnmediated ([`crates/core/chio-core-types/src/receipt/kinds.rs:107-112`](../../../crates/core/chio-core-types/src/receipt/kinds.rs#L107-L112)) (shipped) | A, C |
| `runtime_binding` metadata key | A reserved receipt metadata block for host-runtime identifiers | The reserved-key table it joins, at [`spec/PROTOCOL.md:1074-1093`](../../../spec/PROTOCOL.md?plain=1#L1074-L1093) (shipped) | A, B, C |
| Trust-root resolver | Hosted validation of delegated chains with ancestor snapshots in trust-control, per-sandbox subject keys, and presentation by reference through `x-chio-capability-ref` (ADR-0026 candidate) | Trust-root validation rejects attenuated chains longer than one link ([`crates/core/chio-core-types/src/capability/attenuation.rs:301-306`](../../../crates/core/chio-core-types/src/capability/attenuation.rs#L301-L306)) (shipped) | A, B, F |
| Observer statement | `chio.observer-statement.v1`: loss and coverage counters per sandbox and window, signed by a collector key distinct from the kernel receipt key. It can only tighten admission. | None | C, E |
| Relying-party verifier | A `--treaty-store` flag on `chio mcp serve-http` and `chio api protect` that installs the runtime admission hook | Only the runtime loopback harness (`chio-runtime-harness`, behind `chio runtime loopback`) and a bench fixture install the hook, into a single slot. No serving path does ([`crates/kernel/chio-runtime-harness/src/kernel.rs:422-429`](../../../crates/kernel/chio-runtime-harness/src/kernel.rs#L422-L429); [`crates/kernel/chio-kernel/src/kernel/kernel_struct.rs:602`](../../../crates/kernel/chio-kernel/src/kernel/kernel_struct.rs#L602)) (shipped). | F, H |

## A. OpenShell supervisor middleware

PROPOSED. `chio-openshell-middleware` is a Rust service that implements OpenShell's supervisor middleware contract as a thin shim over `chio-pep-core`. It decides each HTTP request that OpenShell's network rules already allow, before OpenShell injects credentials, and it settles the receipt when the response returns.

### Mechanism

1. The operator registers the service in gateway TOML and restarts the gateway ([`docs/extensibility/supervisor-middleware/configure.mdx:17-33, 184`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/extensibility/supervisor-middleware/configure.mdx?plain=1#L17-L33)). The gateway does not start if a registered service is unavailable (`configure.mdx:63`) (VERIFIED).
2. Sandbox policy attaches the service under `network_middlewares`, with `on_error: fail_closed` and the authority hosts in `endpoints.include` (VERIFIED, [`docs/how-it-works/policies/schema.mdx:479-509`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/how-it-works/policies/schema.mdx?plain=1#L479-L509)). Design B inserts and protects this entry.
3. For each allowed HTTP/1.x request to an included host, the supervisor calls `EvaluateHttpRequest` at HTTP_REQUEST/PRE_CREDENTIALS (VERIFIED, [`proto/supervisor_middleware.proto:15-35`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/proto/supervisor_middleware.proto#L15-L35)). Chio parses the request, evaluates the bound capability, signs a receipt, and returns allow or deny.
4. For an allowed request, the supervisor sends a response preflight at HTTP_RESPONSE/PRE_RETURN that carries the same `request_id` (VERIFIED, `supervisor_middleware.proto:169-203`). Chio returns `inspect` in headers-only mode, sets its receipt header on the response, and settles the receipt outcome.

Registration uses the documented fields. The local test used the same fields over plaintext (VERIFIED, local test; [`spike/gateway/gateway.toml`](spike/gateway/gateway.toml) lines 13-18).

```toml
[[openshell.supervisor.middleware]]
name = "chio"
grpc_endpoint = "https://chio-mw.example:27601"
tls_ca_cert_path = "/etc/openshell/chio-ca.pem"
max_payload_bytes = 4194304
timeout = "500ms"
```

The policy stanza below is what design B writes. Middleware runs in ascending `order` (VERIFIED, `schema.mdx:481`), so `order: 1000` places Chio after any transforming middleware, and Chio decides on the bytes that will be forwarded (INFERRED).

```yaml
network_middlewares:
  chio:
    middleware: chio
    order: 1000
    on_error: fail_closed
    endpoints:
      include: ["tickets.internal.example"]
    config:
      chio:
        binding_revision: "<trust-control binding revision>"
        capability_id: "<root capability id>"
        ceiling_digest: "<sha256 of the projected ceiling>"
```

### Contracts and fields

What Chio receives in `HttpRequestEvaluation`, with the limits that message states (VERIFIED, `supervisor_middleware.proto:108-128`):

| Field | Content | Limit | Chio use |
|---|---|---|---|
| `context.request_id` | A new UUID v4 per request ([`crates/openshell-supervisor-network/src/l7/relay.rs:1198`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/crates/openshell-supervisor-network/src/l7/relay.rs#L1198)); links the request and response evaluations (`supervisor_middleware.proto:170-172`) | Context 4 KiB | Receipt key; joins the two phases |
| `context.sandbox_id` | Sandbox UUID, the same value OpenShell writes to OCSF `container.uid` ([`crates/openshell-ocsf/src/builders/mod.rs:207`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/crates/openshell-ocsf/src/builders/mod.rs#L207)) | | Subject binding and SIEM join |
| `context.originating_process` | Documented as "when available" (`supervisor_middleware.proto:583-598`), and set to `None` at all four production call sites ([`crates/openshell-supervisor-middleware/src/lib.rs:1710`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/crates/openshell-supervisor-middleware/src/lib.rs#L1710), `websocket.rs:962`, `crates/openshell-supervisor-network/src/l7/middleware.rs:95`, `l7/relay.rs:637`) | | Not used |
| `context.sandbox`, `context.workspace` | Display values only | | Copied as display fields, never as identity |
| `config` | The stanza's `config` object | 64 KiB | `binding_revision`, `capability_id`, `ceiling_digest` |
| `target` | Scheme, host, port, method, path and query (`supervisor_middleware.proto:601-614`) | 32 KiB | REST tool mapping. The local test saw `scheme` "https" for plaintext upstreams, so Chio does not rely on the scheme (VERIFIED, local test). |
| `headers` | End-to-end request headers, protected headers omitted | 128 lines, 64 KiB | MCP headers and `x-chio-capability-ref` |
| `body` | Request body | 4 MiB | JSON-RPC parsing and argument constraints |

Middleware cannot write or remove protected request headers, which include `authorization`, `proxy-authorization`, `cookie`, `host`, `x-amz-*` and `x-openshell-credential*` (VERIFIED, [`crates/openshell-supervisor-middleware/src/headers.rs:243, 288-306`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/crates/openshell-supervisor-middleware/src/headers.rs#L288-L306)). In the local test, `Authorization`, `Cookie`, `Proxy-Authorization`, `x-amz-*` and `x-openshell-credential*` headers were also hidden from middleware and still forwarded upstream (VERIFIED, local test).

What Chio returns in `HttpRequestResult` (VERIFIED, `supervisor_middleware.proto:687-720`, or the local test where a row says so):

| Field | OpenShell behavior | Chio value |
|---|---|---|
| Decision | Allow or deny | From `chio-pep-core` |
| `reason` | Never relayed (lines 690-692) | Empty |
| `reason_code` | At most 64 bytes matching `^[a-z][a-z0-9_]*$` (lines 715-719). On deny it appears in OCSF `status_detail` and in the 403 body; on allow it is accepted and logged nowhere (VERIFIED, local test). | `chio_` plus the first 59 hex characters of the receipt id |
| Header mutations | End-to-end headers only (lines 697-704) | Remove `x-chio-capability-ref` and any legacy `x-chio-capability-token` |
| Findings | For operator-run services, OpenShell replaces type, label and confidence with platform-owned values (lines 705-711) | One finding per deny, useful only as a count |
| Metadata | Cleared for operator-run services (VERIFIED, local test) | None |

Receipt ids are 64-character SHA-256 hex strings ([`crates/core/chio-core-types/src/receipt/body.rs:240-244`](../../../crates/core/chio-core-types/src/receipt/body.rs#L240-L244)) (shipped). A 59-character prefix carries 236 bits and fits the 64-byte limit with the `chio_` prefix. In the local test, the deny event carried `status_detail` "middleware_denied:chio-authority:chio_a63e59a962e322e0ee96aecbe3305ace" (VERIFIED, local test; [`spike/results/ocsf.jsonl`](spike/results/ocsf.jsonl)). The prototype used 32 hex characters ([`spike/middleware/chio_mw.py`](spike/middleware/chio_mw.py)), and the Chio finding it returned appeared in OCSF only as "chio-spike.finding" titled "External middleware finding" (VERIFIED, local test).

**Response header.** On allow, Chio answers the response preflight with `inspect` in the headers-only body mode and a header mutation that sets `x-openshell-middleware-chio-receipt: <receipt id>` on the response. OpenShell always offers headers-only mode and accepts response header mutations (VERIFIED, `supervisor_middleware.proto:191-202, 256-265`). RFC 0009 limits external header writes to the `x-openshell-middleware-` namespace ([`rfc/0009-supervisor-middleware/README.md:289, 528`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/rfc/0009-supervisor-middleware/README.md?plain=1#L528)). The code accepts any end-to-end name on requests and responses (tests at `headers.rs:605` and `headers.rs:622`) (VERIFIED). Chio uses the reserved namespace so that later enforcement of the RFC does not break it. The prototype wrote `x-chio-receipt-id` onto the request instead, which reached the upstream rather than the agent (VERIFIED, local test).

**Capability presentation.** The agent carries no token. Design B writes `capability_id` and `binding_revision` into the policy-authored `config`, which arrives with every request and is covered by OpenShell's deterministic policy hash (VERIFIED, [`crates/openshell-core/src/policy_identity.rs:135-177`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/crates/openshell-core/src/policy_identity.rs#L135-L177)). Chio resolves the bound capability in trust-control and checks the extension JWT's `sandbox_id` claim against `context.sandbox_id` and the binding (design D). An optional `x-chio-capability-ref` header selects an already-bound narrower child, for example one issued to a subagent, and is always stripped. Tokens are not carried inline. OpenShell caps the request header block at 16 KiB (VERIFIED, [`architecture/sandbox-limits.md:98`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/architecture/sandbox-limits.md?plain=1#L98)). A 40-link delegation-chain token measured 20.8 KB, and under `fail_open` a custom capability header reached the upstream (VERIFIED, local test).

**Tool-call parsing.** The mapper reads `method`, `params.name` and `params.arguments` from the JSON-RPC body and maps `tools/call` to a Chio tool grant. A tool grant carries `server_id`, `tool_name`, constraints and `max_invocations` ([`crates/core/chio-core-types/src/capability/scope.rs:95-118`](../../../crates/core/chio-core-types/src/capability/scope.rs#L95-L118)) (shipped).

- A batch is denied if any call in it is denied, matching OpenShell's own MCP rule (VERIFIED, `schema.mdx:348`).
- OpenShell denies MCP request bodies above `mcp.max_body_bytes`, 65536 by default (VERIFIED, `schema.mdx:204`; local test). Design B raises it to 4194304, the middleware body limit, as the local test's [`spike/policies/chio_mcpbig.yaml`](spike/policies/chio_mcpbig.yaml) did.
- The MCP 2026-07-28 revision requires the `Mcp-Method` and `Mcp-Name` request headers (VERIFIED, [MCP 2026-07-28 changelog, revision 2026-07-28](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2026-07-28/changelog.mdx)). Chio denies a request whose headers disagree with its body. The pinned schema accepts 2026-07-28 only when it is listed in `mcp.versions` (VERIFIED, `schema.mdx:383-386`). The v0.1.2 release rejected it with a 400, and routing the MCP URL as `protocol: rest` let the prototype enforce 2026-07-28 `tools/call` (VERIFIED, local test). That workaround turns off OpenShell's own MCP rules (INFERRED), so no design here uses it.
- Compressed request bodies are opaque to middleware (VERIFIED, RFC 0009 line 536). Chio denies a compressed body on a bound host.
- REST calls map to `http.<method>.<path>` with a body hash, as the Envoy adapter does today ([`crates/protocol/chio-envoy-ext-authz/src/translate.rs:346-349, 368-370`](../../../crates/protocol/chio-envoy-ext-authz/src/translate.rs#L346-L349)) (shipped).

**Outcomes.** A signed allow stays provisional until its outcome is known.

| Outcome | Condition | Evidence Chio holds |
|---|---|---|
| `denied_before_forward` | Chio denied | Its signed deny; the 403 and OCSF `status_detail` carry the code |
| `forwarded_answered` | Chio allowed, and a PRE_RETURN preflight arrived with the same `request_id` | Response status and headers from the preflight |
| `forwarded_response_withheld` | Chio or a later stage blocked delivery at PRE_RETURN | The upstream request has already run: "blocking its response does not reject or roll back that request" (VERIFIED, `supervisor_middleware.proto:237-239`) |
| `unknown_after_deadline` | Chio allowed, and no preflight arrived before the deadline | Never recorded as "not executed" |

The local test showed why one allow receipt is not enough. Of 79 requests the prototype allowed, 74 produced a response preflight with a matching `request_id`. The other 5 had timed out, were denied by OpenShell and never reached the upstream, yet carried signed allow receipts (VERIFIED, local test). With 120 concurrent requests to a prototype service that took 400 ms, 30 returned 502 from a response-phase failure after the upstream side effect had run (VERIFIED, local test). The likely cause is the prototype's shared 32-thread pool starving response preflights, not an OpenShell load limit (INFERRED). What matters for the design is that a response-phase failure can follow an upstream side effect.

Monetary budgets do not apply in v0. OpenShell performs the forward, so Chio cannot measure realized cost (INFERRED). The kernel's unmeasured-cost path reverses the charge and records `cost_charged` 0 ([`crates/kernel/chio-kernel/src/kernel/validation.rs:1919-1946`](../../../crates/kernel/chio-kernel/src/kernel/validation.rs#L1919-L1946)) (shipped). The kernel also enforces invocation counts and expiry at decision time (shipped), so v0 keeps both. Cost mode is Q2-04 (roadmap).

### Latency in the local test

Latency on the guarded host, all on one machine (VERIFIED, local test; [`spike/results/bench2.jsonl`](spike/results/bench2.jsonl)):

| Variant | Implementation | 1 KB p50 (ms) | 1 KB p99 (ms) | 64 KiB p50 (ms) | 1 MiB p50 (ms) |
|---|---|---|---|---|---|
| none | No middleware | 1.703 | 2.747 | 2.040 | 4.938 |
| regex | Built-in `openshell/regex`, in process | 1.896 | 3.212 | 2.188 | No comparable figure |
| cg | NVIDIA's Rust content-guard example | 3.747 | 6.685 | 4.606 | Not run |
| null | No-op Python gRPC service | 4.566 | 9.103 | 4.803 | 9.027 |
| chioA | Chio Python prototype | 5.338 | 10.477 | 6.436 | 16.838 |

Runs used 1,000 requests at 1 KB, 300 at 64 KiB and 100 at 1 MiB. At 1 MiB the regex built-in returned 51 responses with status 403 and 49 dropped connections. Over no middleware, the prototype adds 3.6 ms at p50 and 7.7 ms at p99 at 1 KB, and 11.9 ms at p50 at 1 MiB. A no-op Python service alone adds 2.9 ms at 1 KB, so most of the prototype's cost is the Python gRPC service rather than Chio's checks (INFERRED).

### Chio today and new work

| Piece | Today | Status of today's piece | New work |
|---|---|---|---|
| Envoy ext_authz adapter | The ext_authz translation strips `authorization` and `x-chio-capability-token` (`crates/protocol/chio-envoy-ext-authz/src/translate.rs:255`), hashes bodies and names REST tools `http.<method>.<path>`. `EnvoyKernel` is a trait with no shipped implementation ([`crates/protocol/chio-envoy-ext-authz/README.md:33-35`](../../../crates/protocol/chio-envoy-ext-authz/README.md?plain=1#L33-L35)). | shipped; library only | Extract `chio-pep-core` |
| Mediated kernel path | `build_mediation_kernel` in API protect (`crates/products/chio-api-protect/src/proxy/mediated.rs:102`) | shipped | The decision core behind the shim |
| `HttpAuthority` | 60-second grant with no constraints; rejects attenuation proofs (`crates/platform/chio-http-core/src/authority.rs:36, 1250-1254`) | shipped | Not used |
| Argument constraints | Any-leaf and any-object matching. Deferred constraints return true at argument matching and are left to downstream guards, which apply only where installed (`crates/kernel/chio-kernel/src/request_matching.rs:429, 457, 465-468`). | shipped | JSON-pointer constraints: 2 ew, then 1.5 ew (roadmap) |
| Receipt header | `x-chio-receipt-id` in `chio-tower` ([`crates/protocol/chio-tower/src/service.rs:169, 205`](../../../crates/protocol/chio-tower/src/service.rs#L169)) | shipped | Response header in the reserved namespace |
| Receipt origin | CallerExecuted, HostExecutedProviderReported and HostExecutedUnmediated. The production coupling gate requires CallerExecuted and `RedactionMode::None` ([`crates/kernel/chio-kernel/src/receipt_support/coupling.rs:33-39`](../../../crates/kernel/chio-kernel/src/receipt_support/coupling.rs#L33-L39); `docs/reference/CLAIM_REGISTRY.md:67`). | Origins shipped; coupling gate qualified | RuntimeForwarded and outcome states: 1.25 ew (D30-09), plus a TLA+ model in D60-01 (2 ew including the CI lane) (roadmap) |
| Prototype | `spike/middleware/chio_mw.py`: Ed25519 verification through the Python SDK, a `path_prefix` constraint, a fixed demo signing key | test-only | Replaced by the Rust service |

### Research-preview caveats

- NVIDIA's example says "Supervisor middleware is a research preview. Its policy and service contracts may change without compatibility guarantees" (VERIFIED, [`examples/supervisor-middleware-content-guard/README.md:9`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/examples/supervisor-middleware-content-guard/README.md?plain=1#L9)). The docs add "Expect to update your service when you upgrade OpenShell" (VERIFIED, [`docs/extensibility/supervisor-middleware/index.mdx:77-81`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/extensibility/supervisor-middleware/index.mdx?plain=1#L77-L81)).
- [#3307](https://github.com/NVIDIA/OpenShell/issues/3307), opened 2026-09-14 and open on 2026-09-29, proposes replacing the unary request hook with a streaming contract. It says a unary compatibility adapter is not a requirement (VERIFIED). [PR #3450](https://github.com/NVIDIA/OpenShell/pull/3450), created 2026-09-18, tracks the same change (VERIFIED). [#2565, opened 2026-07-30](https://github.com/NVIDIA/OpenShell/issues/2565), "Stabilize public API, SDK, and extension contracts for 0.1.0", is open, and RFC 0014 on release stability is in review (VERIFIED, [`rfc/0014-release-stability/README.md:4`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/rfc/0014-release-stability/README.md?plain=1#L4)).
- The middleware therefore sits behind a transport-neutral trait over a normalized request with an explicit body-complete flag, so the streaming hook is an adapter change. Losing `request_id` linkage, `reason_code` or response header writes in a future contract is a stop-ship condition.
- Registration is static and needs a gateway restart (`configure.mdx:184`), while stanza changes apply live (VERIFIED, [`docs/how-it-works/policies/manage-policies.mdx:186-196`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/how-it-works/policies/manage-policies.mdx?plain=1#L186-L196)).

### Effort, risks, and open questions

Effort is 5 to 7 ew for a qualified v0 in D30-06 and D30-07, plus weekly release upkeep and one budgeted migration when #3307 lands (roadmap). It depends on `chio-pep-core`, field-scoped constraints and outcome-bound receipts.

| Risk | Effect | Mitigation |
|---|---|---|
| Contract churn | The request shim is rewritten | Transport-neutral trait; weekly release tracking; one budgeted migration |
| `on_error: fail_open` | Requests skip Chio; the local test saw a custom capability header reach the upstream (VERIFIED, local test) | `ValidateConfigRequest` carries only `config` and `middleware_name` (VERIFIED, `supervisor_middleware.proto:92-97`), so the middleware cannot refuse it (INFERRED); design B enforces fail_closed |
| Chio outage | fail_closed blocks all bound traffic, and a gateway with an unreachable registration does not start (VERIFIED, `configure.mdx:63`) | Co-located replicas; a tested break-glass gateway configuration with no Chio registration |
| Coverage | HTTP/2, HTTP/3, opaque TCP, `tls: skip`, binary WebSocket messages and server-to-client WebSocket messages are outside the hook (RFC 0009 lines 162, 524). Binary WebSocket messages pass even under fail_closed (line 533), and fail_closed cannot apply to `tls: skip` (`schema.mdx:494-496`) (VERIFIED). | On `protocol: mcp` authority hosts OpenShell refuses h2c and WebSocket upgrades (VERIFIED, `manage-policies.mdx:343`; `schema.mdx:155`). Invariant 4 rejects `tls: skip`, `protocol: tcp`, `protocol: websocket` and protocol-less rules on authority hosts. HTTP/2 over TLS and HTTP/3 remain untested; see the bypass table in design G. |
| Identity | Process data is optional context, not a per-request identity (VERIFIED, RFC 0009 line 530), so middleware can tell sandboxes apart but not the processes inside one (INFERRED) | Bind to the sandbox; a broker outside the sandbox gives each subagent its own sandbox |
| Extension token | Bearer token, one shared gateway signing key, no mTLS client authentication, and tokens are reused (VERIFIED, [`docs/extensibility/overview.mdx:131, 143-147`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/extensibility/overview.mdx?plain=1#L143-L147)) | Private network and private CA; the JWT counts only as asserted evidence (design D) |
| Latency | The prototype adds 3.6 ms at p50 and 7.7 ms at p99 (VERIFIED, local test) | Rust service; publish Rust numbers only |

The fail_closed default held in the local test. After the middleware was killed, the first 403 `middleware_failed` came 0.14 s later. During the roughly 12-second outage, 59 requests were denied and none were allowed. The first 200 came 0.26 s after the restart, with no gateway restart (VERIFIED, local test). [`spike/q7_restart.sh`](spike/q7_restart.sh) drove the run, and [`spike/results/q7_restart_events.txt`](spike/results/q7_restart_events.txt) records the kill and restart times that bound the 12-second window. A service slower than the 500 ms timeout got 403 `middleware_failed` at 505 to 513 ms (VERIFIED, local test).

Open questions:

- Whether the contract that replaces the unary hook keeps `request_id` linkage, `reason_code`, whole-body mode and response header writes.
- Whether OpenShell will enforce the `x-openshell-middleware-` namespace for writes, or log a `reason_code` on allow.
- Whether HTTP/2 over TLS or HTTP/3 traffic to an included host can bypass the hook in practice. RFC 0009 says the proxy's TLS termination pins ALPN to `http/1.1` (line 162), and OpenShell refuses h2c and upgrades on MCP endpoints (VERIFIED). The local test tried none of these.
- How 2026-07-28 traffic behaves at `acbac9cb` when listed in `mcp.versions`. The local test ran v0.1.2 only.

## B. Gateway interceptor

PROPOSED. `chio-openshell-interceptor` implements `openshell.gateway_interceptor.v1` (VERIFIED, [`proto/gateway_interceptor.proto:15-27`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/proto/gateway_interceptor.proto#L15-L27)). It binds a Chio capability's ceiling to a sandbox's OpenShell policy at creation, keeps the design A stanza present and fail_closed, validates each RPC that could widen a bound sandbox's reach, and records signed control-plane receipts. It also lets a Chio approval service approve policy proposals as an external approver.

### Mechanism

The gateway runs interceptors after authentication in a fixed order: authenticate, decode and omit secrets, `modify_operation`, `validate`, the gateway handler, then `post_commit` ([`docs/extensibility/gateway-interceptors.mdx:28-42`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/extensibility/gateway-interceptors.mdx?plain=1#L28-L42)). `modify_operation` may allow, deny or return RFC 6902 JSON patches. `validate` may allow or deny. `post_commit` only observes and adds log annotations. A patched operation still passes the gateway's own validation (line 40). Each evaluation names the RPC and carries a non-secret principal map for the authenticated caller (`gateway_interceptor.proto:43-64`) (VERIFIED).

| Mode | Phases | Failure policy | Use |
|---|---|---|---|
| Shadow | `validate` and `post_commit` | fail_open | Logs would-deny verdicts and receipts without enforcing (D60-06) |
| Enforcing | `modify_operation` and `validate`, plus `post_commit` for receipts | fail_closed; `post_commit` bindings fail_open | Projects, protects and denies (D90-01) |
| Validate-and-receipt | `validate` and `post_commit`, no patches | fail_closed | Deployments whose policy is signed before it reaches the gateway, such as SAW on OpenShift. `chio policy project --openshell` (roadmap) writes the stanza into the bundle before signing. |

**CreateSandbox.** The RPC requires bearer authentication, scope `sandbox:write` and workspace role user (VERIFIED, [`proto/openshell.proto:48-54`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/proto/openshell.proto#L48-L54)). Its request carries the sandbox spec with policy, labels, annotations and an optional `request_id` for at-most-once admission (VERIFIED, `openshell.proto:1252-1274`).

1. `modify_operation`: the caller names the root capability in a CreateSandbox annotation (`openshell.proto:1260-1261`). Chio verifies the chain in trust-control, checks the principal against the capability's subject, projects the capability's ceiling into OpenShell network rules, and patches in the design A stanza with a fresh `binding_revision`. Rules the projection cannot express are dropped and listed in a loss report. Dropping a rule only narrows (INFERRED).
2. `validate`: Chio recomputes the ceiling from the final prepared request and denies on any difference.
3. `post_commit`: Chio records the new sandbox id against `binding_revision` and completes a signed control-plane receipt keyed by the CreateSandbox `request_id`. Bindings that include `post_commit` must resolve to fail_open (VERIFIED, `gateway_interceptor.proto:131-135`), so a missed call leaves the binding unattached. The middleware then attaches it on the first request by `binding_revision` and records that in the receipt.

**Why the binding lives in policy.** `modify_operation` and `validate` run before the handler creates the sandbox, so they cannot key a registry on a sandbox id (INFERRED from the phase order). The stanza's `config` is inside OpenShell's policy hash (VERIFIED, `crates/openshell-core/src/policy_identity.rs:135-177`), so a binding change also changes the hash that GetSandboxPolicyStatus reports (INFERRED). In the local test, a reference in middleware config reached requests 19 ms and 24 ms after the supervisor loaded each new revision (VERIFIED, local test). The supervisor polls every 10 s by default (VERIFIED, [`crates/openshell-supervisor/src/lib.rs:1026-1029`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/crates/openshell-supervisor/src/lib.rs#L1026-L1029)). Two revisions went to superseded without ever loading (VERIFIED, local test; [`spike/results/q5_policy_list.json`](spike/results/q5_policy_list.json), driven by [`spike/q5_switch.sh`](spike/q5_switch.sh)). A reconciler compares trust-control bindings with WatchSandbox and ListSandboxPolicies output, the APIs the prototype queried in [`spike/middleware/policy_identity.py`](spike/middleware/policy_identity.py). It flags any bound sandbox whose loaded policy lacks the current `binding_revision`.

**Registration** adapts the documented example (VERIFIED, `gateway-interceptors.mdx:77-95`). `binding_policy = "exact"` requires the configured RPCs and phases to match the manifest exactly, which the docs recommend when interceptor authority is part of a security boundary (VERIFIED, lines 64-70). The manifest declares `post_commit` bindings with `failure_policy` fail_open. The configuration lists every binding in the table below; two are shown.

```toml
[[openshell.gateway.interceptors]]
name               = "chio"
grpc_endpoint      = "https://chio-interceptor.example:18081"
tls_ca_cert_path   = "/etc/openshell/chio-ca.pem"
order              = 20
failure_policy     = "fail_closed"
binding_policy     = "exact"
timeout            = "500ms"
max_patches        = 32

[[openshell.gateway.interceptors.bindings]]
rpc    = "openshell.v1.OpenShell/CreateSandbox"
phases = ["modify_operation", "validate"]

[[openshell.gateway.interceptors.bindings]]
rpc    = "openshell.v1.OpenShell/UpdateConfig"
phases = ["modify_operation", "validate"]
```

### Contracts and fields

The 25 interceptable RPCs are listed at [`crates/openshell-gateway-interceptors/src/routes.rs:17-43`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/crates/openshell-gateway-interceptors/src/routes.rs#L17-L43) (VERIFIED). Chio binds the ones below. The Reason column cites OpenShell at the pin (VERIFIED); the invariants themselves are PROPOSED.

| # | Invariant for a bound sandbox | RPCs and phase | Reason |
|---|---|---|---|
| 1 | The Chio stanza is present with `on_error: fail_closed` | CreateSandbox, UpdateConfig: `modify_operation`, `validate` | Middleware cannot see `on_error` (design A) |
| 2 | `binding_revision`, `capability_id` and `ceiling_digest` change only through Chio | UpdateConfig: `validate` | Keeps the policy hash and the binding in step |
| 3 | Rules for authority hosts stay inside the projected ceiling | CreateSandbox, UpdateConfig: `validate` | OpenShell matches MCP method and tool name, never arguments (`schema.mdx:347`) |
| 4 | No `tls: skip`, `protocol: tcp`, `protocol: websocket` or protocol-less rule reaches an authority host | CreateSandbox, UpdateConfig: `validate` | `tls: skip` and TCP traffic are outside the hook, binary WebSocket messages pass even under fail_closed, and a protocol-less endpoint relays non-HTTP traffic uninspected (RFC 0009 lines 524, 533; `docs/how-it-works/policies/network-rules.mdx:105-108`) |
| 5 | Merge operations Chio cannot recompute are denied | UpdateConfig: `validate` | `current_state` is not populated (`gateway-interceptors.mdx:171`); merge operations at `openshell.proto:2687-2688` |
| 6 | Writes carry `expected_resource_version` | UpdateConfig: `validate` | Optimistic concurrency (`openshell.proto:2689-2694`) |
| 7 | Proposals are never auto-approved, and chunk edits stay inside the ceiling | SubmitPolicyAnalysis, UpdateConfig and the six draft-chunk RPCs: `validate` | SubmitPolicyAnalysis carries sandbox-proposed chunks (`openshell.proto:643-644`), and approved chunks widen policy |
| 8 | Only the Chio approval service approves chunks that touch authority hosts | ApproveDraftChunk, ApproveAllDraftChunks: `validate` | `ApproveDraftChunkRequest` has no approver field (`openshell.proto:3332-3344`) |
| 9 | Provider changes add no credentialed reach to an authority host outside the ceiling | AttachSandboxProvider and the provider and provider-profile RPCs: `validate` | Credentials are injected after middleware runs |
| 10 | Every allowed write yields a control-plane receipt | All bound RPCs: annotation at `modify_operation`, completion at `post_commit` | UpdateConfig annotations are stored immutably with the revision (`openshell.proto:2695-2701`) |

For invariant 10, Chio adds its decision receipt id as an annotation at `modify_operation`, so OpenShell stores it with the revision. At `post_commit`, Chio completes the receipt with the committed revision identifiers where the response carries them, as ApproveDraftChunk's does (VERIFIED, `openshell.proto:3346-3351`).

StopSandbox, StartSandbox, ExecSandbox, ExecSandboxInteractive and ForwardTcp are not interceptable, because they are absent from the allowlist (`routes.rs:17-43`). Each needs only bearer authentication with scope `sandbox:write` and workspace role user, the same authorization as CreateSandbox (`openshell.proto:181-186, 190-194, 253-258, 262-267, 273-277`). New RPCs stay non-interceptable until added to the allowlist (`gateway-interceptors.mdx:170`) (VERIFIED). The invariants therefore trust every workspace principal with `sandbox:write`, not only the gateway administrator. A process started through ExecSandbox still sends its traffic through the supervisor, so its calls to authority hosts still reach the middleware (INFERRED). Changing a registration takes a gateway TOML edit and a restart (VERIFIED, `gateway-interceptors.mdx:102`), which only the gateway's operator can do (INFERRED).

Interceptors never see fields marked secret (VERIFIED, `gateway-interceptors.mdx:122`). Provider-profile snapshots answer `ProviderProfileSnapshotRequest {}`, which carries no fields (VERIFIED, `gateway_interceptor.proto:34`). Any profiles Chio vends are therefore gateway-wide, not per sandbox (INFERRED).

**Signed policy.** NVIDIA's governance example supplies each new sandbox's policy at CreateSandbox, adds an `openshell.nvidia.com/policy-signature` annotation used to verify it, denies unsigned, stale or modified policies for every caller, denies sandbox-authored proposals, and blocks `proposal_approval_mode=auto` (VERIFIED, [`examples/governance-interceptor/README.md:8-26`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/examples/governance-interceptor/README.md?plain=1#L8-L26)). Its signatures are EdDSA JWTs over a `sha256:v2` digest that the example owns independently of the gateway, whose policy hash "is a separate operational revision identifier" (VERIFIED, lines 38-54). A Chio patch would turn a signed policy into a modified one (INFERRED). Where policy is signed upstream, Chio therefore runs in validate-and-receipt mode, the stanza is written before signing, and receipts record both the signed digest and the gateway hash.

**Approvals.** RFC 0002, whose state is accepted, says OpenShell "should support at least three approval modes": `human_in_the_loop`, `trusted_agent_within_ceiling` and `manual_only_locked_down`. In the second, "A trusted external agent may apply changes automatically when validation and prover checks confirm the proposal stays within an org or user-defined maximum" (VERIFIED, [`rfc/0002-agent-driven-policy-management/README.md:4, 459-466`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/rfc/0002-agent-driven-policy-management/README.md?plain=1#L459-L466)). OpenShell ships different modes. `proposal_approval_mode` accepts only `manual`, the default, and `auto`, which approves only proposals whose prover delta is empty; other values are rejected (VERIFIED, [`crates/openshell-core/src/settings.rs:87-107`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/crates/openshell-core/src/settings.rs#L87-L107)). The trusted external approver is therefore a role Chio plays by calling ApproveDraftChunk under its own principal, not a shipped OpenShell mode (INFERRED). Which identities may act as trusted external approvers is an open question in the RFC (VERIFIED, line 720). OpenShell's prover reports MCP and GraphQL rules as unsupported (VERIFIED, [`docs/how-it-works/policies/prover.mdx:48-49, 231`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/how-it-works/policies/prover.mdx?plain=1#L48-L49)). For MCP rules, Chio's ceiling check is therefore the only containment check (INFERRED).

1. The agent proposes a rule, and invariant 7 computes whether the chunk stays inside the ceiling.
2. Inside the ceiling, the Chio approval service may approve in the role RFC 0002 gives a trusted external agent. Outside it, a human approves in Chio's approval flow after an IdP login.
3. The service calls ApproveDraftChunk under its own gateway principal, which invariant 8 alone admits.
4. The `post_commit` receipt binds the approver, `chunk_id`, and the returned `policy_version` and `policy_hash`.

The approver's evidence class is "IdP-authenticated principal, attested by the Chio approval service", or "bridge-attested" when the approval arrives through a chat bridge such as Slack. Today the API protect sidecar signs approval tokens ([`crates/products/chio-api-protect/src/proxy/approval.rs:235-237`](../../../crates/products/chio-api-protect/src/proxy/approval.rs#L235-L237)) (shipped). The IdP-bound approval service is Q2-02 (roadmap).

**Containment order.** Revocation runs in three steps. Trust-control revokes, and the middleware denies the next call. UpdateConfig removes the rules, effective after the supervisor's next poll. A workspace principal with `sandbox:write` runs StopSandbox, which Chio cannot intercept. A fail_closed interceptor blocks UpdateConfig while Chio is down, so during an outage only the StopSandbox step works (INFERRED).

### Chio today and new work

| Piece | Today | Status of the piece |
|---|---|---|
| Interceptor service | None | roadmap |
| Policy projection (`chio-openshell-policy`) | None. `chio-policy` accepts HushSpec 0.1.0 only ([`crates/guards/chio-policy/src/version.rs:3-5`](../../../crates/guards/chio-policy/src/version.rs#L3-L5)) (shipped). | roadmap |
| Approval tokens | Signed by the API protect sidecar | shipped |
| Kubernetes admission webhook | Never reads `DelegationChain` ([`sdks/k8s/webhooks/capability.go:25`](../../../sdks/k8s/webhooks/capability.go#L25)) and never patches ([`sdks/k8s/webhooks/server.go:150-152`](../../../sdks/k8s/webhooks/server.go#L150-L152)) | shipped |
| Remote budgets | Report `AdvisoryPosthoc` and refuse family limits ([`crates/platform/chio-control-plane/src/trust_control/service_runtime/budget.rs:137-160`](../../../crates/platform/chio-control-plane/src/trust_control/service_runtime/budget.rs#L137-L160)), so deciders stay co-located and single-writer | shipped |

### Effort, risks, and open questions

Effort is 7 to 10 ew including `chio-openshell-policy`: shadow mode in D60-06, fail_closed in D90-01 (roadmap).

| Risk | Effect | Mitigation |
|---|---|---|
| Gateway coupling | fail_closed blocks writes during a Chio outage. The gateway does not start without the service, and registration is static (VERIFIED, `gateway-interceptors.mdx:98, 102`). | A dedicated gateway per governed tenant and a tested break-glass configuration |
| NemoClaw slot | NemoClaw's experimental external-component contract v1 admits one registered host component, on a Unix socket with fixed bindings: CreateSandbox `modify_operation` and `validate`, and UpdateConfig `validate`. It permits no `post_commit`, network endpoint or TLS field, and middleware connections arrive only with version 2. `--apf-interceptor` selects that component's CreateSandbox policy for fresh providerless onboarding, and a generic component can implement it (VERIFIED, [NemoClaw external components, main, read 2026-09-29](https://github.com/NVIDIA/NemoClaw/blob/main/docs/deployment/register-external-component.mdx)). | A Chio interceptor can fill the v1 slot for validation only, without `post_commit` receipts or design A, and would compete for it with an Agent Policy Fabric (APF) component (INFERRED). The full design waits until NemoClaw qualifies its version 2 declaration, which it recognizes but says not to rely on in an installed release (VERIFIED). |
| Agent Policy Fabric | An NVIDIA job post plans a Runtime Policy Verifier with projection into OpenShell-native policy, and public OpenShell RFCs or PRs for projection hooks (VERIFIED as the post's text; the plan is PROPOSED, [NVIDIA careers JR2019848, created 2026-06-12, posting start 2026-06-22](https://jobs.nvidia.com/careers/job/893395763513)) | Keep the interceptor thin and the authority logic in trust-control |
| Field-name drift | RFC 0010 names `audit_annotations = 6` ([`rfc/0010-gateway-interceptors/README.md:252`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/rfc/0010-gateway-interceptors/README.md?plain=1#L252)), while the proto has `log_annotations = 5` (`gateway_interceptor.proto:93-94`) (VERIFIED) | Build against the proto and pin per release |
| Gateway-wide providers | A provider-profile change affects every sandbox (INFERRED) | Deny any change that widens a bound sandbox |

Open questions:

- The annotation key and value format for the capability reference at CreateSandbox.
- Whether the sandbox id is absent from CreateSandbox at `modify_operation` and `validate`, as inferred; this is untested.
- Whether gateway TOML can set a per-binding failure policy, or only the manifest can.
- Whether OpenShell will add approver identity to draft-chunk approvals, which RFC 0002 leaves open.

## C. Receipt metadata family and OCSF export

PROPOSED. Receipts from designs A and B carry a reserved `runtime_binding` block, schema `chio.runtime-binding.v1`, with the host runtime's identifiers. A collector preserves OpenShell's own OCSF events, and an exporter emits Chio decisions as OCSF 1.9 events that a SIEM can join to them.

### Mechanism

Protocol section 6.4 reserves top-level metadata keys that only the kernel writes. A colliding key from caller or hook metadata is rejected, so a verifier can treat a block under a reserved key as kernel-authored and covered by the receipt signature ([`spec/PROTOCOL.md:1074-1093`](../../../spec/PROTOCOL.md?plain=1#L1074-L1093)) (shipped). `runtime_binding` joins that table (roadmap). Fields that OpenShell supplies with each request are signed into the receipt. Fields that exist only out of band, or only after OCSF collection, are signed later by the collector into Chio checkpoints, together with the collected OCSF events and WatchSandbox output.

The Source column names OpenShell fields at the pin (VERIFIED); the evidence classes are PROPOSED.

| Field | Source | Known at | Evidence class |
|---|---|---|---|
| `runtime` | Constant `openshell` | Signing | None; a configured constant |
| `gateway_id` | Extension JWT `iss`, `openshell-gateway:<gateway_id>` ([`docs/extensibility/overview.mdx:111-118`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/extensibility/overview.mdx?plain=1#L111-L118)) | Signing | asserted by an authenticated gateway caller |
| `request_id`, `sandbox_id` | `RequestContext`, with `sandbox_id` checked against the JWT claim | Signing | asserted by an authenticated gateway caller |
| `sandbox_name`, `workspace` | `RequestContext` display values | Signing | display only |
| `binding_revision`, `capability_id`, `ceiling_digest` | Stanza `config` | Signing | verified against trust-control |
| `outcome` | One of design A's four outcomes | PRE_RETURN or deadline | observed for `denied_before_forward` and `unknown_after_deadline`; asserted by an authenticated gateway caller for `forwarded_answered` and `forwarded_response_withheld` |
| `policy_version`, `policy_hash` | `configuration_admission` in GetSandbox or WatchSandbox status ([`proto/openshell.proto:2847-2855`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/proto/openshell.proto#L2847-L2855)) | After load, out of band | observed |
| Generation | Not available per request. The session token is bound to the sandbox UUID, runtime generation, authorization epoch and token lineage (`openshell.proto:830-832`). `main_process_instance_id` identifies the supervisor instance tied to the main process and lets the gateway reject stale exit reports after a restart (lines 1173-1175). | Out of band | observed |
| `ocsf_uid` | OCSF `metadata.uid`, a new UUID v4 per event (`crates/openshell-ocsf/src/builders/mod.rs:194`) | After collection | observed, in the checkpoint |

Chio's lineage schema defines three classes: asserted is caller-supplied, observed is local kernel runtime truth, and verified is signed or proof-checked ([`crates/observability/chio-lineage/schemas/lineage-graph.v1.json:27-28`](../../../crates/observability/chio-lineage/schemas/lineage-graph.v1.json#L27-L28)) (shipped). Calling OpenShell's collected events observed widens that definition, so the protocol must state the wider meaning before any receipt uses it (INFERRED).

### SIEM join

OpenShell's trail is opt-in OCSF 1.8.0 JSONL at `/var/log/openshell-ocsf.YYYY-MM-DD.log`, with three files kept ([`docs/observability/ocsf-json-export.mdx:58-63`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/observability/ocsf-json-export.mdx?plain=1#L58-L63)). It is enabled per sandbox with `openshell settings set my-sandbox --key ocsf_json_enabled --value true` (line 25). The gateway's log buffer is not persisted, and its push channel drops events ([`docs/observability/accessing-logs.mdx:38, 79`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/observability/accessing-logs.mdx?plain=1#L38)). OpenShell defines nine classes, API Activity 6003 among them ([`crates/openshell-ocsf/src/events/mod.rs:35-54`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/crates/openshell-ocsf/src/events/mod.rs#L35-L54)) (VERIFIED).

The join cases use OpenShell's event fields at the pin (VERIFIED), with local-test results where a row says so:

| Case | Join | Exactness |
|---|---|---|
| Deny | HTTP Activity 4002 `status_detail` `middleware_denied:<config key>:chio_<59 hex>` to the receipt id prefix | Exact |
| Allow | `container.uid` equal to `sandbox_id`, plus destination, path and a time window | Correlation only. None of 959 middleware `request_id` values appeared in the 58 OCSF events from the same window (VERIFIED, local test). |
| Policy change | `configuration_admission.policy_hash` to the revision holding the receipt's `binding_revision` | Exact after load |
| Finding | Detection Finding 2004 with uid `<registration name>.finding` and a count | Count only |
| Unreceipted forward | An allowed request on a bound host with no receipt in the window | Flagged by the join verifier |

Events can be dropped before collection and carry no sequence number (VERIFIED), so loss is reported as a lower bound of detected gaps. An open request asks OpenShell to hash-chain its events (VERIFIED, [#3817, opened 2026-09-29](https://github.com/NVIDIA/OpenShell/issues/3817)). The claim is "tamper-evident after signing, correlated with OpenShell events by sandbox and time, linked exactly on denials by reason code". OpenShell's own events become tamper-evident only from collection onward (INFERRED).

### OCSF 1.9 export of Chio decisions

Today `chio-siem` maps receipts to OCSF 1.3.0 class 3002 and labels it "Authorization" ([`crates/observability/chio-siem/src/ocsf.rs:46-52`](../../../crates/observability/chio-siem/src/ocsf.rs#L46-L52)) (shipped). OCSF defines 3002 as Authentication (VERIFIED, [OCSF 1.3.0 Authentication, no visible date](https://schema.ocsf.io/1.3.0/classes/authentication)). The mapper copies tool parameters into `api.request.data` (`ocsf.rs:147-149`) and `raw_data` (`ocsf.rs:189-191`) (shipped). The only exporter an operator binary wires is the webhook ([`crates/products/chio-wall/src/commands.rs:1199-1214`](../../../crates/products/chio-wall/src/commands.rs#L1199-L1214)) (shipped). The relabel is D30-05 (roadmap). The target is API Activity 6003 with the `ai_operation` and `record_integrity` profiles. The OCSF field names below are VERIFIED in 1.9.0, and the mapping is PROPOSED:

| OCSF 1.9 field | Chio source |
|---|---|
| `class_uid` 6003, `status`, `status_detail` | Verdict, outcome and deny `reason_code` |
| `metadata.uid`, `metadata.version` | Receipt id; "1.9.0" |
| `api.service.name`, `api.operation` | `server_id` and tool name |
| `container.uid` | `sandbox_id`, the value OpenShell's events carry |
| `policy.uid` | Chio policy hash |
| `ai_operation.delegation`: `uid` (required), `parent_uid`, `issuer_uid`, `created_time` | Capability id, parent capability id, issuer key, `issued_at` |
| `ai_operation.ai_agent` | Capability subject |
| `record_integrity.attestation_list[]`: `authority_uid`, `chain_uid`, `fingerprint`, `prev_event`, `signatures`, `uid` | Exporter key id, receipt log id, fingerprint of the event's canonical serialization, previous exported event, exporter signature, attestation id |
| `unmapped.chio` | `runtime_binding` and the receipt signature |

OCSF 1.9.0's `digital_signature` object has no field for signature bytes and no EdDSA `algorithm_id` (VERIFIED). [PR #1709](https://github.com/ocsf/ocsf-schema/pull/1709), merged 2026-09-24 after the 1.9.0 release, adds a Base64 `value` field, but no released schema carries it and no EdDSA value exists (VERIFIED). The Ed25519 receipt signature therefore travels in `unmapped` until a release includes `value` and an EdDSA `algorithm_id`. OpenShell's own exporter strips `ai_model`, `container` and the `ai_operation` profile when downgrading to OCSF 1.1 or 1.3 (VERIFIED, `ocsf-json-export.mdx:203-221`). Chio would ship 1.9, 1.3 and 1.1 golden files and state what each loses. Enforcement events would carry argument commitments rather than argument values, with a per-tenant `raw_data` switch (D60-02, roadmap).

### Effort, risks, and open questions

Effort is 4 to 6 ew for the relabel (D30-05), export (D60-02), collector and join verifier (D90-03), and the Kubernetes collector with a SIEM rule pack (Q2-08). The receipt states and `runtime_binding` take 1.25 ew (D30-09), and the collector's observer statement 0.25 ew (roadmap).

- Allow joins stay correlation-only until OpenShell carries a request identifier in OCSF. [#2640, opened 2026-08-06](https://github.com/NVIDIA/OpenShell/issues/2640), proposes trace and span ids (VERIFIED).
- A SIEM that ingests OpenShell events downgraded to OCSF 1.1 or 1.3 loses `container`, and with it the allow join on `container.uid` (INFERRED from `ocsf-json-export.mdx:205`).
- Rotation keeps three daily files, so the collector must copy each file before it rotates out. It should run far more often, because the gateway's buffer and push channel lose events (INFERRED).
- Receipts and events can hold personal data. The ADR-0036 candidate settles receipt privacy in days 1 to 30 (roadmap; [06-strategy-and-roadmap.md](06-strategy-and-roadmap.md), section 12).

Open questions:

- Which OCSF class should carry capability issuance and revocation events.
- Whether `main_process_instance_id` maps one to one to the credential generation.
- Whether the agent process can write the OCSF JSONL path under each driver.

## D. Verifier families

PROPOSED. Chio's runtime attestation appraisal accepts four verifier families: AzureMaa, AwsNitro, GoogleAttestation and EnterpriseVerifier ([`crates/core/chio-core-types/src/runtime_attestation.rs:12-30`](../../../crates/core/chio-core-types/src/runtime_attestation.rs#L12-L30)) (shipped). A trust rule maps a schema and verifier pair to an effective tier, with a maximum evidence age, allowed attestation types and required assertions ([`crates/core/chio-core-types/src/capability/trust_policy.rs:21-34`](../../../crates/core/chio-core-types/src/capability/trust_policy.rs#L21-L34)) (shipped). Enterprise-verifier evidence is accepted by schema and normalized ([`crates/economy/chio-appraisal/src/appraisal.rs:739-746`](../../../crates/economy/chio-appraisal/src/appraisal.rs#L739-L746)) (shipped). JWK resolution accepts RSA keys only ([`crates/platform/chio-control-plane/src/attestation/verification.rs:1166-1174`](../../../crates/platform/chio-control-plane/src/attestation/verification.rs#L1166-L1174)) (shipped). This design adds NVIDIA-side sources, each with a stated evidence class.

What each source proves is VERIFIED from the sources cited in this section; the evidence classes and paths are PROPOSED.

| Source | What it proves | Chio evidence class | Path |
|---|---|---|---|
| Gateway extension JWT | An authenticated gateway caller asserted a sandbox id | Asserted by an authenticated gateway caller | Checked per call in design A |
| NRAS Entity Attestation Token (EAT) appraised by CNCF Trustee | GPU measurements at a nonce | Verified only once Chio supplies the nonce at admission; caller-asserted until then | EnterpriseVerifier (L-07) |
| BlueField-3 DICE evidence appraised by Trustee | DPU firmware measurements | Verified device firmware, not agent activity | EnterpriseVerifier (L-07) |
| DOCA Argus records | Nothing cryptographic | Asserted | Design E |
| Sentry "attested telemetry" | Not documented | Asserted until a signer and schema are published | Design E |

### Gateway JWT as workload identity evidence

The gateway sends a short-lived bearer token with each extension call. Its `typ` is "openshell-ext+jwt" and its `alg` EdDSA. `iss` is `openshell-gateway:<gateway_id>`, and `aud` defaults to `urn:openshell:extension:middleware:<name>`. `caller_kind` is gateway or supervisor, and `sandbox_id` names the calling sandbox for supervisor calls (VERIFIED, [`docs/extensibility/overview.mdx:111-129`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/extensibility/overview.mdx?plain=1#L111-L129)). The docs say to take keys from the gateway operator and to fetch rotated keys from the gateway's OpenID configuration over TLS (line 122). With `allow_insecure_transport`, no token is sent (line 141) (VERIFIED).

Chio pins the operator-supplied keys, requires `caller_kind` supervisor on request evaluations, and records `gateway_id`, `sandbox_id` and `caller_kind` as asserted evidence. The token is not a SPIFFE identity, and it does not identify the sending process (INFERRED from its claims). Chio's workload identity parses SPIFFE URIs ([`crates/core/chio-core-types/src/capability/workload_identity.rs:146-150`](../../../crates/core/chio-core-types/src/capability/workload_identity.rs#L146-L150)) (qualified). Chio refuses to serve a bound gateway that uses insecure transport. The new work is an OKP (Ed25519) key resolver, inside design A's effort.

OpenShell's SPIFFE token grants exchange a JWT-SVID at a configured `token_endpoint` and inject the result (VERIFIED, [`docs/how-it-works/providers/profiles.mdx:554-606`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/how-it-works/providers/profiles.mdx?plain=1#L554-L606)). Chio's shipped v1 contract does not claim OAuth authorization-server product status before an accepted ADR defines it ([`spec/PROTOCOL.md:110, 116`](../../../spec/PROTOCOL.md?plain=1#L110-L116)) (shipped). A Chio token endpoint therefore waits for that ADR.

### NVIDIA GPU attestation

The NVIDIA Remote Attestation Service (NRAS) takes a POST to `/v4/attest/gpu` and returns an RFC 9711 detached EAT bundle of ES384 JWTs. The overall token binds each device token by SHA-256 and echoes the caller's nonce as `eat_nonce` (VERIFIED, [NVIDIA/attestation-sdk, read 2026-09-28](https://github.com/NVIDIA/attestation-sdk); [NRAS release notes, updated 2026-08-01](https://docs.nvidia.com/attestation/cloud-services/latest/nras/nras_releases.html)). On 2026-09-28 the NRAS JWKS served 72 EC P-384 keys with short-lived leaf certificates, 48 hours in the leaf checked (VERIFIED, [NRAS JWKS, read 2026-09-28](https://nras.attestation.nvidia.com/.well-known/jwks.json)). NVIDIA's SDKs take the key from `x5c[0]` without validating the chain (VERIFIED, attestation-sdk). CNCF Confidential Containers Trustee ships open-source verifiers for NVIDIA GPUs (local SPDM and NRAS) and BlueField-3 DICE, and binds the GPU nonce to the CPU TEE report data (VERIFIED, [confidential-containers/trustee, commit of 2026-09-18](https://github.com/confidential-containers/trustee)).

Chio builds no `nvidia_nras` family first. Trustee appraises, and its result enters as `chio.runtime-attestation.enterprise-verifier.json.v1` under a trust rule that names the Trustee verifier, a tier, a maximum age and the assertions a partner requires. No statement that a call "ran on an attested GPU" is made until Chio invokes the verifier at admission with its own nonce. That replaces today's caller-asserted `evidence_sha256` (shipped) and is L-07, sized M to L. Trust in NRAS keys rests on TLS to the JWKS endpoint (INFERRED from the SDK behavior), and NVIDIA publishes no Vera evidence format (VERIFIED).

### BlueField and Sentry

BlueField device attestation uses SPDM with a DICE certificate chain and CoRIM reference values, COSE-signed when signed, and it covers firmware, not agent activity. NVIDIA's device attestation docs cover BlueField-3 but not BlueField-4 (VERIFIED, [device attestation docs, v6.0, 2026-08-31](https://networking-docs.nvidia.com/dpunicattestation)). The BlueField-4 datasheet lists "Device attestation (SPDM 1.1/1.2)" (VERIFIED, [BlueField-4 datasheet, June 2026](https://dam-cdn.nvd.orangelogic.com/AssetLink/whs8mhb340t412js4612g3356607hapf.pdf)), and BlueField-4 attestation rests only on that datasheet bullet. NVIDIA publishes no signer, key, root of trust, schema or export API for Sentry's "attested telemetry" (VERIFIED). DOCA Argus records have no signature field (VERIFIED, [DOCA Argus guide, 2026-09-11](https://networking-docs.nvidia.com/doca/archive/3-5-0/doca-argus-service-guide)). NVIDIA's pages name no credential or delegated-authority artifact that the DOCA gateway verifies (VERIFIED). BlueField-3 device evidence can take the Trustee path above. Everything from Sentry enters as asserted evidence (design E), and no DPU code is written until NVIDIA publishes an interface (L-08).

Open questions:

- How Trustee's appraisal output maps into the enterprise-verifier schema; its output format is not among the sources cited here.
- Which artifact the DOCA gateway verifies, and whether an external issuer can be registered with it.

## E. Sentry as a sensor provider kind

PROPOSED. Sensor-grounded admission conditions a receipt on a signed attestation of the kernel's sensing posture. For each registered provider it records the installed, active, healthy and degraded flags, degradation reasons, and dropped-event and deadline-miss counts, plus a clock record ([`docs/papers/sensor-grounded-admission/lean/SensorGroundedAdmission.lean:63-101`](../../../docs/papers/sensor-grounded-admission/lean/SensorGroundedAdmission.lean#L63-L101)) (design doc). This design adds an out-of-band infrastructure observer, such as Sentry on BlueField-4, as a provider kind with its own signer.

### What NVIDIA documents

- Sentry is a BlueField-4 reference system design. NVIDIA's release says that "if an AI agent attempts to move outside its software boundary, Sentry quarantines and stops it in milliseconds" (VERIFIED, [NVIDIA press release, 2026-09-28](https://nvidianews.nvidia.com/news/open-agent-safety-platform)). The New Stack reports that Sentry is not open source and that NVIDIA's Justin Boitano said it "has open APIs" (REPORTED, [The New Stack, 2026-09-28](https://thenewstack.io/nvidia-openshell-sentry-agents/)). NVIDIA's pages read on 2026-09-28 and 2026-09-29 publish no benchmark, quarantine trigger, API documentation or availability date for Sentry (VERIFIED).
- In a Vera Rubin POD the DPU sits "on the node's only path to the model", and NVIDIA describes "enforcing the OpenShell policy in silicon" without a documented interface (VERIFIED, [NVIDIA developer blog, 2026-09-28](https://developer.nvidia.com/blog/nvidia-open-agent-safety-platform-a-reference-for-continuous-in-silicon-agent-monitoring/)).
- Justin Boitano said "The DPU is really optional in these architectures" and aimed Sentry at "frontier use cases" such as model evaluation and red teaming (REPORTED, [The New Stack, 2026-09-28](https://thenewstack.io/nvidia-openshell-sentry-agents/)).
- DOCA Argus monitors only the node its DPU serves (VERIFIED, [DOCA Argus guide, 2026-09-11](https://networking-docs.nvidia.com/doca/archive/3-5-0/doca-argus-service-guide)), and design D lists what is not documented about its records.

### Chio today

- `ProviderKind` is a closed enum of eight kinds: kernelCallout, networkFlow, signatureDrift, supplyChainGuard, behavioralTelemetry, agentApi, honeyToken and other (`SensorGroundedAdmission.lean:63-72`). Sentry would have to be `other` or `networkFlow` (design doc).
- `ProviderRecord` holds the provider id and kind, the four flags, degradation reasons and the two counts (lines 76-86). `SensorAttestation` holds the provider list and the clock (lines 98-101) (design doc).
- The attestation is signed by the same key that signs the receipt body, and the paper leaves the audit channel unspecified ([`docs/papers/sensor-grounded-admission/sections/03-substrate.tex:53`](../../../docs/papers/sensor-grounded-admission/sections/03-substrate.tex#L53)). A lie becomes detectable only when "an out-of-band sensor-coverage auditor disagrees" ([`sections/10-conclusion.tex:8`](../../../docs/papers/sensor-grounded-admission/sections/10-conclusion.tex#L8)). The four theorems compile without `sorry` ([`lean/STATUS.md`](../../../docs/papers/sensor-grounded-admission/lean/STATUS.md)), and no crate implements the model (design doc).
- Chio's security design lets only events from configured internal detector keys or verified Chio receipts trigger automatic response, and keeps unsigned and external events advisory ([`docs/superpowers/specs/2026-07-09-security-folder-design.md:52`](../../../docs/superpowers/specs/2026-07-09-security-folder-design.md?plain=1#L52)) (design doc).

### Design

1. Add a provider kind for an out-of-band infrastructure observer and a per-record signer, so an observer's record is never signed by the kernel key.
2. An observer record carries its own clock and observation window, names the node or sandbox it covers, and binds to the receipt subject digest.
3. Observer input only tightens. A degraded or missing required observer moves a decision toward partition-contingency admission or refusal, never the reverse. Records that are unsigned, or signed by a key the operator did not configure, stay advisory.
4. An observer record of a call on a bound host with no matching Chio receipt is the signed disagreement the paper describes (INFERRED). The join verifier from design C reports it.
5. Until NVIDIA publishes a Sentry signer and schema, the slot is filled by the collector's `chio.observer-statement.v1` over OpenShell's OCSF trail, which reports loss and coverage per sandbox and window under the collector key.

A Sentry record would need a documented format, a signer certified to a hardware endorsement key, freshness bound to the receipt subject digest, and an independent clock (INFERRED). NVIDIA documents none of these, and no documented Sentry field maps to a `ProviderRecord` field (VERIFIED).

### Effort, risks, and open questions

- Effort: moving the Lean model into the proof root is small, and binding sensor state into Rust receipts is large (INFERRED). The observer statement is 0.25 ew, and the tighten-only rule 1 to 1.5 ew (Q2-16, roadmap). There is no Sentry code until L-08.
- Admission would run through the runtime admission hook ([`crates/kernel/chio-kernel/src/kernel/mod.rs:151-157`](../../../crates/kernel/chio-kernel/src/kernel/mod.rs#L151-L157)) (shipped). The relying-party verifier needs the same single slot, so the two must compose (INFERRED).
- NVIDIA's developer blog describes the DOCA gateway as "continuously verifying each agent's identity and delegated authority" (VERIFIED, [NVIDIA developer blog, 2026-09-28](https://developer.nvidia.com/blog/nvidia-open-agent-safety-platform-a-reference-for-continuous-in-silicon-agent-monitoring/)). Unless it consumes Chio tokens or receipts, it overlaps Chio's core role (INFERRED).
- Partners may define signed DPU telemetry first. EQTY Lab says its notary takes "Argus telemetry, Flow's network policy context, Vault's file-access policy decisions" and that "Each event is hashed, signed by keys held inside the DPU's trust domain" (VERIFIED as EQTY's statement, [EQTY Lab, 2026-06-01](https://www.eqtylab.io/blog/verifiable-knowledge-the-third-pillar-of-trust-for-the-agentic-ai)). EQTY publishes no code, schema or evidence type for it (VERIFIED), so the capability is announced only (PROPOSED).
- Open questions: the Sentry record format, signer and clock, and whether Sentry quarantine events reach third parties at all.

## F. ODIS

PROPOSED. Chio publishes an ODIS role-capability statement pinned to `148dc418`, a field-by-field carrier map, an attenuation profile at an immutable URI with a digest, and a companion record for the Delegation Record fields that Chio lacks. Chio does not claim ODIS conformance.

ODIS is an "Unapproved contributor draft" by three NVIDIA authors ([`RFCs/ODIS.md:2-4`](https://github.com/cosai-oasis/ws4-odis/blob/148dc4187139a41325e3c6d6e7533d956bd33144/RFCs/ODIS.md?plain=1#L2-L4)) with "no OASIS or CoSAI approval status" (lines 1127-1129) (VERIFIED). Matthew Gladney (NVIDIA), who co-presented the ODIS readout, said on 2026-09-03 that ODIS is "far from being stable on its spec" (REPORTED, [WS4 agenda draft, 2026-09-10](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/agenda_drafts/ws4/2026-09-10.md)).

### Role-capability statement

A profile claim applies to "a named, versioned deployable system boundary", and a component on its own may publish only a role-capability statement (VERIFIED, lines 909, 1030). A `key_custody` of process-memory cannot support a Core, Extended or Safety claim without a CT-P4 suite version and a passing test log (VERIFIED, line 1032). CT-P4 is the companion validation suite for embedded-SDK deployments, which ODIS lists as future work (VERIFIED, line 1160). The declaration template is section 8.2 (lines 967-1016).

The Field column follows that template (VERIFIED); the values are PROPOSED.

| Field | Chio value | Basis |
|---|---|---|
| `claim_type`, `profile` | role-capability; profile omitted | Line 1024 |
| `layers_implemented` | L2, L3 | Delegation and governance-checkpoint roles, per the layer map below |
| `delegation_wire_format` | other | `chio.capability.v1` is none of the named carriers |
| `token_binding_method` | other | `chio.dpop_proof.v1` is Chio's own format, not RFC 9449 ([`docs/adr/ADR-0007-dpop-binding-format.md:14-21`](../../../docs/adr/ADR-0007-dpop-binding-format.md?plain=1#L14-L21)) (shipped) |
| `presenter_profile` | gateway | Designs A and G |
| `key_custody` | process-memory | Remote signers for HTTP and Vault Transit exist, but only the hosted cognition-market profile wires them ([`crates/trust/chio-signing-remote/src/lib.rs:102, 263`](../../../crates/trust/chio-signing-remote/src/lib.rs#L102)) (shipped) |
| `policy_engine` | other | Chio's own evaluator |
| `maximum_revocation_latency_seconds` | Not yet measured. ODIS caps it at 300 seconds, and its template takes an integer from 1 through 300 (lines 645, 1006). | Measured across 20 sandboxes in Demo B (Q2) |
| `ct_p4_suite_version`, `test_log_ref` | Omitted | No CT-P4 suite exists (line 1160) |

### Layer map

The ODIS columns are VERIFIED at lines 303-457; the Relation column is INFERRED.

| ODIS layer | Function | Chio today | Relation |
|---|---|---|---|
| L1 Passport | Short-lived, holder-bound Agent Runtime Credential; software and runtime attestation; accountable human sponsor | Agent Passport: a `did:chio` identity plus a signed reputation credential ([`README.md:365-374`](../../../README.md?plain=1#L365-L374)); runtime attestation appraisal (both shipped) | Different object, same name |
| L2 Bridge | Delegation Service; Provider Adapter in native or bridge egress mode; cache and revocation | Capabilities with delegation links ([`crates/core/chio-core-types/src/capability/attenuation.rs:64-92`](../../../crates/core/chio-core-types/src/capability/attenuation.rs#L64-L92)); an attenuation proof covers at most one link (`attenuation.rs:301-306`) (shipped) | Partial: at least four MUST fields missing, plus the parent record digest for non-root records |
| L3 Router | Registry, governance checkpoint, rate limits, revocation, kill switch | Kernel mediation and signed receipts. `emergency_stop` is kernel-wide and in memory, sits behind a static admin token, and signs no record of engage or resume ([`crates/kernel/chio-kernel/src/kernel/construction.rs:1570-1586`](../../../crates/kernel/chio-kernel/src/kernel/construction.rs#L1570-L1586); [`crates/platform/chio-http-core/src/routes.rs:90-93`](../../../crates/platform/chio-http-core/src/routes.rs#L90-L93)) (shipped) | Partial: no cascading kill switch |

A Delegation Record must carry `originating_principal`, `originating_authorization_ref`, `task_id` and `attenuation_profile_ref` among its minimum fields. A non-root record must also carry `parent_delegation_ref`, which holds a record digest (VERIFIED, ODIS-L2-05 at line 626; section 6.3). Chio's capability token has none of the four ([`crates/core/chio-core-types/src/capability/token.rs:120-161`](../../../crates/core/chio-core-types/src/capability/token.rs#L120-L161)), and its delegation links carry no parent record digest (`attenuation.rs:64-92`) (shipped). A signed `chio.delegation-context.v1` companion, digest-bound to the root capability, carries them (Q2-01, 3 ew, roadmap).

The design publishes `chio.attenuation-profile.v1` at an immutable, versioned URI, as ODIS-L2-06 requires (VERIFIED, line 627). Its digest is SHA-256, which Chio chooses because ODIS names no digest algorithm (VERIFIED, [ws4-odis #22, opened 2026-09-21](https://github.com/cosai-oasis/ws4-odis/issues/22)). The profile cites the bounded Lean model of capability monotonicity (D90-07, roadmap).

### Conformance target with OpenShell

A candidate target is one OpenShell release (gateway and supervisors) plus the Chio middleware, interceptor and trust-control, with an IdP. Before it could support any profile claim, it would need the following (ODIS requirements VERIFIED at the lines cited):

- key custody other than process memory, or a passing CT-P4 suite (line 1032);
- holder binding, since OpenShell extension tokens are bearer tokens (VERIFIED, [`docs/extensibility/overview.mdx:145`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/extensibility/overview.mdx?plain=1#L145));
- a measured revocation latency within 300 s (ODIS-L3-04, line 645) and a kill switch that cascades to sessions and cached tokens (ODIS-L3-05, line 646);
- delivery of the section 6.4 identity-context object to a policy decision point (ODIS-L3-06, line 647);
- published latency and availability reports (ODIS-CC-03 and CC-04, lines 657-658).

Provider Adapter modes map onto the designs: Chio middleware in front of a target is bridge mode, and a resource owner running Chio's verifier (design H3) is native mode (INFERRED). ODIS-L2-15 permits native mode only when the target itself validates the credential and the active Delegation Record (VERIFIED, line 636).

NVIDIA's contract harness is the nearest comparison. Inside an OpenShell sandbox, it makes a Router gated by Open Policy Agent (OPA) the agent's only network path to the target MCP server ([`contract-harness/README.md:29`](https://github.com/cosai-oasis/ws4-odis/blob/148dc4187139a41325e3c6d6e7533d956bd33144/contract-harness/README.md?plain=1#L29)). Its bundles are root-only: `delegation_chain` has `maxItems` 0 ([`contract-harness/schemas/odis.bundle.v1.json:44-48`](https://github.com/cosai-oasis/ws4-odis/blob/148dc4187139a41325e3c6d6e7533d956bd33144/contract-harness/schemas/odis.bundle.v1.json#L44-L48)). It claims only a role-capability statement (VERIFIED). In this design the relying-party verifier (D90-02) accepts `odis.bundle.v1` grants as evidence of originating authorization, never as Chio authority.

### Naming collision

"Passport" names three different things. Chio's Agent Passport (`chio.agent-passport.v1`, [`spec/PROTOCOL.md:3818`](../../../spec/PROTOCOL.md?plain=1#L3818)) is a portable reputation credential (shipped). ODIS Layer 1 is "The Passport (Identity & Attestation)" (VERIFIED, line 303). A third-party "Agent Passport System" was pitched to OpenShell in [#3808, opened 2026-09-28](https://github.com/NVIDIA/OpenShell/issues/3808) (VERIFIED). In standards contexts Chio says "portable trust credential", keeps `chio.agent-passport.v1` on the wire, and maps it to ODIS `holder_key_ref`, not `agent_id`.

Effort is founder time for the statement (D30-11), carrier map (D60-08) and attenuation profile (D90-07), plus 3 ew for the companion in Q2-01 (roadmap). Open questions: whether ODIS adopts a digest contract ([ws4-odis #22, opened 2026-09-21](https://github.com/cosai-oasis/ws4-odis/issues/22)) and a signed per-decision record ([ws4-odis #21, opened 2026-09-21](https://github.com/cosai-oasis/ws4-odis/issues/21)), and whether a CT-P4 suite will exist.

## G. Deployment shapes

PROPOSED. Four shapes, from the least enforcement to the most. The measure for each is what an agent inside the sandbox can reach without a Chio decision.

| Shape | Where Chio runs | Chio parts | Status |
|---|---|---|---|
| G1. MCP wrapper in the sandbox | `chio mcp serve` wraps a stdio MCP server inside the sandbox image | `mcp serve` with `--preset code-agent` and `--server-id` ([`crates/products/chio-cli/src/cli/types/runtime.rs:645-687`](../../../crates/products/chio-cli/src/cli/types/runtime.rs#L645-L687)) | shipped |
| G2. Chio edge as the only tool egress | `chio mcp serve-http` outside the sandbox; OpenShell policy allows only the edge for tool traffic | `serve-http` with `--policy`, `--server-id`, `--listen` (default 127.0.0.1:8931) and `CHIO_AUTH_TOKEN` (`runtime.rs:690-732`) | shipped; interop fixes are roadmap |
| G3. Middleware and interceptor | Designs A and B beside the gateway | Rust services | roadmap |
| G4. Kubernetes with Helm beside OpenShell | Chio services as cluster workloads next to OpenShell's Kubernetes driver | Helm post-renderer, charts for OpenShift restricted-v2, trust-control on a block volume | roadmap |

**G1.** The Chio README documents the Claude Code line and a Hermes configuration ([`README.md:263-293`](../../../README.md?plain=1#L263-L293)), and the code-agent preset grants only the fs, shell and git server ids (lines 295-296) (shipped). Inside OpenShell, the wrapper is one more process within the boundary, and stdio traffic between two local processes never reaches OpenShell's network rules (INFERRED). The agent can also act without the wrapper through its own shell and file tools (INFERRED). NVIDIA's guidance says "A control that the agent can decline to invoke is not an effective security control" (VERIFIED, [Where Security Fits in an AI Agent Stack, 2026-08-21](https://developer.nvidia.com/blog/where-security-fits-in-an-ai-agent-stack/)). Chio's own registers agree. `ASSUME-SUBPROCESS-ISOLATION` is an audited assumption of the claim registry ([`docs/reference/CLAIM_REGISTRY.md:50`](../../../docs/reference/CLAIM_REGISTRY.md?plain=1#L50)), and the release risk register lists sidecar bypass as an open HIGH risk ([`docs/release/RISK_REGISTER.md:11`](../../../docs/release/RISK_REGISTER.md?plain=1#L11)) (qualified). G1 yields evidence for mediated calls, not a boundary (INFERRED).

**G2.** OpenShell makes the supervisor the workload's only egress. On Docker and Podman the workload has networking off, on Kubernetes a NetworkPolicy admits only the supervisor service, and VMs get no network device (VERIFIED, [`docs/about/architecture.mdx:100-105`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/about/architecture.mdx?plain=1#L100-L105)). The local test saw the workload container in network mode `none` behind a supervisor proxy. Its policy allowed the edge on port 27607 as `chio_edge` ([`spike/policies/chioA.yaml`](spike/policies/chioA.yaml)) (VERIFIED, local test). Neither Claude Code 2.1.284 nor Codex 0.158.0 completed discovery against the edge in the local test. Claude Code timed out on `tools/list` because the edge answers `notifications/initialized` with a 200 SSE `roots/list` request instead of 202 ([`crates/protocol/chio-mcp-remote/src/remote_mcp/http_service.rs:390-427`](../../../crates/protocol/chio-mcp-remote/src/remote_mcp/http_service.rs#L390-L427)). Codex initialized with 2025-06-18, which the edge rejects because it accepts only 2025-11-25 ([`crates/protocol/chio-mcp-edge/src/runtime.rs:81-82`](../../../crates/protocol/chio-mcp-edge/src/runtime.rs#L81-L82)) (VERIFIED, local test; the edge code is shipped). The fix is D30-03, 1.25 ew (roadmap).

**G3.** Designs A and B. The bypass surface shrinks to traffic outside the hook's scope. Invariant 4 keeps `tls: skip`, TCP, WebSocket and protocol-less rules off authority hosts. OpenShell refuses h2c and upgrades on MCP endpoints (VERIFIED, [`docs/how-it-works/policies/manage-policies.mdx:343`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/how-it-works/policies/manage-policies.mdx?plain=1#L343)). HTTP/2 over TLS and HTTP/3 remain untested.

**G4.** OpenShell's chart renders no middleware or interceptor section in its gateway configuration (VERIFIED, [`deploy/helm/openshell/templates/gateway-config.yaml`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/deploy/helm/openshell/templates/gateway-config.yaml)), so Chio would ship a post-renderer. The chart requires a Container Network Interface (CNI) plugin that enforces NetworkPolicy, warning that "Without enforcement, sandbox workloads may connect directly and bypass supervisor network policy". It also needs the Agent Sandbox custom resource definitions and controller (VERIFIED, [`deploy/helm/openshell/README.md:130-139`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/deploy/helm/openshell/README.md?plain=1#L130-L139)). On OpenShift, the 5.14 kernel of Red Hat Enterprise Linux CoreOS (RHCOS) starts sandboxes in a legacy read-only mode. Isolation is unchanged, some mediated socket operations fail closed, and outbound workloads run unchanged (VERIFIED, [`docs/kubernetes/openshift.mdx:22-34`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/kubernetes/openshift.mdx?plain=1#L22-L34)). Trust-control keeps its state in SQLite stores in WAL mode, and Chio's deployment guide says WAL is not safe over NFS, Amazon EFS or Azure Files ([`deploy/README.md:65-66`](../../../deploy/README.md?plain=1#L65-L66)) (shipped). In G4, trust-control therefore runs as a single replica on a block volume until a PostgreSQL store exists (roadmap; [06-strategy-and-roadmap.md](06-strategy-and-roadmap.md), section 4). Packaging is 3 to 4 ew (D60-01, D60-03, roadmap).

### Bypass analysis

OpenShell behavior in the table is VERIFIED where a cell cites it; the classifications are INFERRED.

| Path to a tool without a Chio decision | G1 wrapper | G2 edge | G3 and G4 middleware |
|---|---|---|---|
| Local effects through the agent's own shell or file tools | Open | Open | Open; Chio governs remote tools only |
| Direct HTTP to a tool host | Open if policy allows the host | Closed: only the edge is allowed | Decided by Chio for included hosts |
| A tool host missing from `endpoints.include` | Not applicable | Closed unless allowed | Open; the interceptor projects every authority host into the list |
| `tls: skip`, `protocol: tcp`, `protocol: websocket` or protocol-less rules to a tool host | Open if allowed | Closed unless allowed | Rejected on authority hosts by invariant 4 |
| h2c or a WebSocket upgrade to a `protocol: mcp` or `json-rpc` endpoint | Refused by OpenShell | Refused by OpenShell | Refused by OpenShell (VERIFIED, `manage-policies.mdx:343`) |
| HTTP/2 over TLS or HTTP/3 to a tool host | Open if allowed | Closed unless allowed | Outside the hook; RFC 0009 says TLS termination pins ALPN to `http/1.1` (VERIFIED, [`rfc/0009-supervisor-middleware/README.md:162`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/rfc/0009-supervisor-middleware/README.md?plain=1#L162)); not tested |
| Compressed request body | Not applicable | Not tested | Denied on bound hosts |
| `on_error: fail_open` | Not applicable | Not applicable | Denied by invariant 1 |
| Credentials that OpenShell injects for a provider | Not governed | Not governed | Injected after Chio's decision; invariant 9 limits provider changes |
| NetworkPolicy not enforced on Kubernetes | Open | Open | Open; enforcement is a G4 prerequisite |
| Workspace-user lifecycle and exec RPCs: StopSandbox, StartSandbox, ExecSandbox, ExecSandboxInteractive, ForwardTcp | Trusted | Trusted | Trusted and not interceptable. Any workspace principal with `sandbox:write` can call them (VERIFIED, cited in design B). Commands they start still egress through the supervisor (INFERRED). |
| Administrator registration changes in gateway TOML, applied by restart | Trusted | Trusted | Trusted and not interceptable |
| Gateway or supervisor compromise | Out of scope | Out of scope | Out of scope |

## H. Demonstrations

PROPOSED. Three demonstrations, smallest first. Commands and configuration come from OpenShell's documentation, Chio's README and the local test, and names in angle brackets are placeholders. H2 is Demo A in [06-strategy-and-roadmap.md](06-strategy-and-roadmap.md), and H3 is the counterparty part of its Demo C.

### H1. Minimal: a coding agent in OpenShell with the Chio MCP wrapper

It shows signed receipts for MCP calls from Claude Code or Hermes running in an OpenShell sandbox, with no OpenShell extension. It does not show a boundary (G1).

1. Build an image with the agent, the `chio` binary and the MCP server preinstalled, since OpenShell denies egress that policy does not allow (INFERRED). Start it the documented way, `openshell sandbox create --from registry.example.com/your-org/claude-agent:latest -- claude` (VERIFIED, [`docs/how-it-works/sandboxes/overview.mdx:20`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/how-it-works/sandboxes/overview.mdx?plain=1#L20)). The Claude Code provider profile's smoke test is `openshell sandbox create --provider <name> -- claude -p 'reply with OK'` (VERIFIED, [`providers/claude-code.yaml`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/providers/claude-code.yaml)).
2. Inside the sandbox, register the wrapper as the Chio README does ([`README.md:265-269`](../../../README.md?plain=1#L265-L269)) (shipped):

   ```bash
   claude mcp add fs -- chio --receipt-db ./chio.db mcp serve --preset code-agent --server-id fs -- npx -y @modelcontextprotocol/server-filesystem .
   ```

3. Turn on OpenShell's OCSF export with `openshell settings set my-sandbox --key ocsf_json_enabled --value true` (VERIFIED, [`docs/observability/ocsf-json-export.mdx:25`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/observability/ocsf-json-export.mdx?plain=1#L25)).
4. Make an in-scope call and an out-of-scope call, then verify the exported evidence on a second machine with `chio evidence verify --input` ([`crates/products/chio-cli/src/cli/types/receipt.rs:195-199`](../../../crates/products/chio-cli/src/cli/types/receipt.rs#L195-L199)) (shipped). This checks signatures and internal consistency only. Trust-bundle verification arrives with D90-02 (roadmap).

For Hermes, its own MCP configuration points at the wrapper. The README's Hermes example gives `command` as a list (`README.md:277-291`), and whether Hermes accepts that form is unconfirmed. The `chio-hermes` plugin is not used. It gates only `chio_*` tools ([`sdks/python/chio-hermes/src/chio_hermes/hooks.py:51-55`](../../../sdks/python/chio-hermes/src/chio_hermes/hooks.py#L51-L55)), and its id-only path always raises `ChioDeniedError` ([`sdks/python/chio-sdk-python/src/chio_sdk/client.py:463-490`](../../../sdks/python/chio-sdk-python/src/chio_sdk/client.py#L463-L490)) (shipped). Codex is left out because it initializes with 2025-06-18, which Chio's MCP edge rejects over HTTP (VERIFIED, local test). The stdio wrapper uses the same negotiation, so it rejects 2025-06-18 too ([`crates/protocol/chio-mcp-edge/src/runtime/jsonrpc.rs:68-84`](../../../crates/protocol/chio-mcp-edge/src/runtime/jsonrpc.rs#L68-L84)) (shipped). Running the stdio wrapper inside an OpenShell sandbox has not been tested.

### H2. Middleware: right tool, wrong arguments

It shows that OpenShell forwards any arguments to an allowed MCP tool, because "Tool arguments are not matched, so an allowed tool accepts any arguments" (VERIFIED, [`docs/how-it-works/policies/schema.mdx:347`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/how-it-works/policies/schema.mdx?plain=1#L347)). It also shows Chio denying out-of-scope arguments before credential injection, counting invocations, expiring grants, failing closed and signing outcome-bound receipts. It runs Claude Code 2.1.284, Codex 0.158.0 and, if its MCP client negotiates a supported revision, Hermes. They run in OpenShell v0.1.2 sandboxes on the Docker driver, against an MCP server in front of an internal ticketing or data API. It uses `protocol: mcp` only.

Configuration from the local test (VERIFIED, local test):

- Registration: [`spike/gateway/gateway.toml`](spike/gateway/gateway.toml) lines 13-18, or the TLS form in design A.
- Policy: [`spike/policies/chioA.yaml`](spike/policies/chioA.yaml) allows `initialize`, `notifications/initialized`, `tools/list`, `ping` and `tools/call` for `file_read`, denies `tools/call` for `delete_resource`, and attaches the middleware with `on_error: fail_closed` to `host.openshell.internal` (lines 172-188). Codex also needs `mcp.versions: ["2025-06-18", "2025-11-25"]`, as in [`spike/policies/clients_B.yaml`](spike/policies/clients_B.yaml) lines 183-188.
- Apply: `openshell policy set <sandbox> --policy <file> --wait` (VERIFIED, [`docs/how-it-works/policies/manage-policies.mdx:159`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/docs/how-it-works/policies/manage-policies.mdx?plain=1#L159)).
- Traffic: `openshell sandbox exec -n <sandbox> --no-tty --timeout 290 -- python3 <path>/probe2.py bench ...`, as in [`spike/bench_all.sh`](spike/bench_all.sh), with the client in [`spike/client/probe2.py`](spike/client/probe2.py).

Steps:

1. Show the policy and the line "Tool arguments are not matched".
2. Forward a forbidden argument without Chio.
3. Deny it with Chio: a 403 with a `chio_` code in OCSF `status_detail`, and a `denied_before_forward` receipt.
4. Allow an in-scope call: the receipt header on the response, no Chio header upstream, and `forwarded_answered` at PRE_RETURN.
5. Exceed `max_invocations`, then pass expiry.
6. Kill the middleware: OpenShell refuses to forward, and the in-flight call ends as `unknown_after_deadline`.
7. Run `chio evidence verify` on a second machine, which checks signatures and consistency only.
8. Show the latency and coverage tables.

No budget hold appears, because cost mode is Q2-04 (roadmap). The demo makes no claim about the incident in NVIDIA's policy-prover post. That write went through `git-remote-https`, outside the L7 path that Chio uses (VERIFIED, [OpenShell research note, 2026-09-10](https://nvidia.github.io/OpenShell-Research/dev-notes/posts/2026-09-10-learning-formal-methods-agent-policy-prover/)). [06-strategy-and-roadmap.md](06-strategy-and-roadmap.md), section 3, lists the claims this rules out.

### H3. Cross-organization: verification at the resource owner's door

It shows a resource owner verifying an agent operator's delegation and receipts at its own door. Organization A runs agents as in H2. Organization B fronts one MCP server with `chio api protect --treaty-store` or `chio mcp serve-http --treaty-store`. The `--treaty-store` flag is roadmap (D90-02), and it verifies the presented chain and receipts under B's own trust roots. The shipped flags of `serve-http` are listed in design G. The global `--receipt-db` and `--authority-seed-file` options are at [`crates/products/chio-cli/src/cli/types.rs:120, 128`](../../../crates/products/chio-cli/src/cli/types.rs#L120) (shipped).

1. In-scope calls return a receipt id.
2. Out-of-scope arguments are denied before dispatch.
3. After A revokes, the new epoch denies the next call without B contacting A.

Around it, Demo C hash-chains the collected OpenShell OCSF and WatchSandbox output into Chio checkpoints and exports OCSF 1.9 to a SIEM. It also shows the interceptor rejecting `tls: skip` on an authority host, and an allow event with no receipt in the join verifier's report.

The chain still roots in A's issuer key, and A signs the epoch. The claim is therefore verification "without trusting the operator's runtime, gateway or logs", not without trusting the operator. A bilateral co-signed receipt appears only if a real second operator holds its own keys. Otherwise it is labeled "two configured keys under one custodian". In the first 90 days H3 runs in a relying-party form that needs no second organization ([06-strategy-and-roadmap.md](06-strategy-and-roadmap.md), section 1).

## I. Engagement

PROPOSED. These are the upstream asks the designs depend on, filed through each venue's own process. Tiers and timing follow section 9 of [06-strategy-and-roadmap.md](06-strategy-and-roadmap.md). Every post discloses the Backbay affiliation, and nothing is posted under the founder's GitHub account without the founder's approval.

### OpenShell

New features start as feature-request issues. An RFC is written only when maintainers decide an issue needs one, and maintainers assign the number and the `needs-rfc` label (VERIFIED, [`rfc/README.md:3-16`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/rfc/README.md?plain=1#L3-L16)). Pull requests from unvouched contributors are closed automatically, and vouch requests must be written by hand (VERIFIED, [`CONTRIBUTING.md:23-32`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/CONTRIBUTING.md?plain=1#L23-L32)). The maintainers are 10 NVIDIA and 3 Red Hat engineers (VERIFIED, [`MAINTAINERS.md`](https://github.com/NVIDIA/OpenShell/blob/acbac9cb795094986cbab016bfd0352d980b17f6/MAINTAINERS.md)). The RFCs to file therefore start as issues.

The Evidence column cites OpenShell facts that designs A to C label; the asks are PROPOSED.

| Ask | Design | Evidence | Form |
|---|---|---|---|
| Populate `RequestContext.originating_process`, or document it as unavailable | A, D | `None` at four call sites | Issue with a patch outline |
| Carry `policy_version` and `policy_hash` in `RequestContext` | A, C | Out of band only, behind a 10 s poll | Issue |
| Put `request_id` and an external decision reference on OCSF HTTP Activity | C | No request id in OCSF; builds on #2640 | Issue |
| An observe binding keyed by `request_id` that reports the operation outcome | A, C | Asked in [#1733, opened 2026-06-03, closed](https://github.com/NVIDIA/OpenShell/issues/1733) and [#3782, opened 2026-09-28](https://github.com/NVIDIA/OpenShell/issues/3782) (VERIFIED) | Issue |
| Pass `on_error` and `endpoints` to `ValidateConfig` | A, B | `supervisor_middleware.proto:92-97` | Issue |
| Populate `current_state`, and reconcile `audit_annotations` with `log_annotations` | B | `gateway-interceptors.mdx:171`; RFC 0010 line 252 | Issue |
| Record approver identity on draft-chunk approvals | B | RFC 0002 line 720 | Comment where maintainers direct |
| Keep `request_id` linkage, `reason_code`, whole-body mode up to 4 MiB, the fail_closed default and the header-write scope, and declare stability under RFC 0014 | A | #3307, #2565 | Comments |
| Fail-closed middleware conformance tests | A | Local test cases | Pull request |

No design or ask needs OpenShell core to sign Chio data or adopt a Chio format. Chio references travel only in OpenShell's existing generic fields, and the asks are generic fields any external authority could use. Third parties already ask for an external authority and evidence layer in discussions [#3818, created 2026-09-29](https://github.com/NVIDIA/OpenShell/discussions/3818), [#3079, created 2026-09-01](https://github.com/NVIDIA/OpenShell/discussions/3079) and [#2661, created 2026-08-09](https://github.com/NVIDIA/OpenShell/discussions/2661) (VERIFIED). Chio replies only on #3079 and #2661, after D30-02, and not in competitors' threads.

### CoSAI Workstream 4

Contributions to the Coalition for Secure AI (CoSAI) need its Contributor License Agreement (CLA) (VERIFIED, [CoSAI onboarding, no visible date](https://github.com/cosai-oasis/cosai-tsc/blob/main/ONBOARDING.md)). Pull requests would require approval from a co-lead of the Project Governing Board (PGB) or the Technical Steering Committee (TSC) (REPORTED, [TSC minutes, 2026-07-14](https://github.com/cosai-oasis/cosai-tsc/blob/main/tsc-meeting-minutes/2026-07-14.md)). Counsel reads the CLA before the company signs it.

The sequence is the role-capability statement v0 (D30-11), the carrier map (D60-08), the attenuation profile (D90-07), the companion (Q2-01), and results on the ODIS-ATT test vectors, failures included (Q2-12). The Agent Passport System (APS) conformance suite publishes those vectors against ODIS `148dc418` (VERIFIED, [APS ODIS interop vectors, no visible date](https://github.com/Agent-Authority-Conformance/aps-conformance-suite/tree/main/interop/cosai-odis-148dc41)). Contributions are issue-first: a digest profile using JSON Canonicalization Scheme (JCS, RFC 8785) and SHA-256, with cross-language vectors, on #22, and co-authorship rather than a counter-proposal on #21.

### Open Secure AI Alliance

The Open Secure AI Alliance is a Linux Foundation Directed Fund. General membership is free until 2028-01-01, and associate membership is free for pre-approved open source projects (VERIFIED, [Open Secure AI Alliance charter, effective 2026-09-01](https://cdn.platform.linuxfoundation.org/agreements/osaia.pdf)). Its stack model lists "Policy, Identity & Governance" and "Enforcement" as separate layers (VERIFIED, [secureaialliance.org, read 2026-09-28](https://secureaialliance.org/)). That is the same split these designs keep between Chio and OpenShell (INFERRED). The alliance's only repository holds the Shared AI Findings Exchange (SAFE) RFC, an incident-exchange proposal with no merges and no commit since 2026-08-04 (VERIFIED, [OpenSecureAIAlliance/RFCs, read 2026-09-29](https://github.com/OpenSecureAIAlliance/RFCs)). Chio enrolls at no cost and later opens one SAFE pull request with a delegated-authority provenance profile. The profile answers proposals #29, #13 and #15 and includes an evidence-minimization section.

### OCSF

Once D60-02 ships, Chio emits OCSF 1.9 events that validate against the 1.9.0 schema (design C, roadmap). Chio comments on [issue #1640, opened 2026-05-19](https://github.com/ocsf/ocsf-schema/issues/1640) with the call-time enforcement semantics that [PR #1665, merged 2026-07-24](https://github.com/ocsf/ocsf-schema/pull/1665), left out. That PR says it "does not address enforcement" (VERIFIED). Chio also proposes an EdDSA `algorithm_id` and a non-X.509 key descriptor as a follow-up to merged [PR #1709, 2026-09-24](https://github.com/ocsf/ocsf-schema/pull/1709).
