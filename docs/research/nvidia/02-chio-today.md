# Chio's existing surface for an NVIDIA integration

This document inventories the parts of Chio that an integration with NVIDIA's agent safety stack would build on. For each Chio subsystem it records what exists, its claim-boundary status, where it lives in the repository, and the limits that a design or a public statement must respect. The NVIDIA side is described in [01-nvidia-stack.md](01-nvidia-stack.md). Field-level comparisons are in [03-overlap-matrix.md](03-overlap-matrix.md). Integration mechanisms are in [04-integration-design.md](04-integration-design.md).

NVIDIA terms used below:

- On 2026-09-28 NVIDIA announced the Open Agent Safety Platform, which consists of OpenShell open source software and the Sentry reference system design (VERIFIED, [NVIDIA newsroom, 2026-09-28](https://nvidianews.nvidia.com/news/open-agent-safety-platform)). OpenShell provides a runtime boundary for AI agents (VERIFIED, same source).
- Sentry is described as an out-of-band watchdog that runs on BlueField-4 DPUs (data processing units) and is built on NVIDIA DOCA software (PROPOSED, same source).
- NemoClaw is an open source reference stack that runs OpenClaw, Hermes, and LangChain Deep Agents Code inside OpenShell sandboxes (VERIFIED, [NVIDIA/NemoClaw README, read 2026-09-29](https://github.com/NVIDIA/NemoClaw)).
- The Secure Agent Workspace (SAW) is an NVIDIA reference design (VERIFIED, [SAW documentation, last updated 2026-06-28](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/what-is-secure-agent-workspace.html)).
- ODIS (Open Delegation & Identity Standard) is a delegation and identity draft developed in the CoSAI Workstream 4 repository `cosai-oasis/ws4-odis`. Its front matter lists three NVIDIA authors and the status "Unapproved contributor draft intended for open development" (VERIFIED, [`RFCs/ODIS.md:2-4` at 148dc418](https://github.com/cosai-oasis/ws4-odis/blob/148dc4187139a41325e3c6d6e7533d956bd33144/RFCs/ODIS.md?plain=1#L2-L4)).

Five facts frame the rest of the document.

- The qualified core is signed authority and signed evidence. The only ship-facing claim covers "recursive delegated-authority admission backed by ancestor capability snapshots" and "signed local receipts and checkpoints" (**qualified**; [QUALIFICATION.md](../../../docs/release/QUALIFICATION.md) lines 67-74). Attenuation-only delegation is approved with scope as P1 (**qualified**; [CLAIM_REGISTRY.md](../../../docs/reference/CLAIM_REGISTRY.md) line 70). Runtime-attestation appraisal is qualified in six evidence-matrix rows (QUALIFICATION.md lines 364-369). Receipts co-signed by two organizations are **shipped** but sit outside the bounded gate.
- On the general mediation path Chio does not confine agents or tool servers. Its only OS sandboxes are two cognition-market harnesses (section 6). Isolation is an audited assumption, `ASSUME-SUBPROCESS-ISOLATION`, not a Chio control (**qualified** as an assumption; CLAIM_REGISTRY.md line 50).
- Chio is not a control point on the model inference path. Its provider adapters sit in that path as opaque pass-through clients that use a provider key supplied by the embedding process and evaluate only tool-use blocks (**shipped**; section 7).
- At `f5566d9a76` no tracked file mentions OpenShell, NemoClaw, BlueField, DOCA, or ODIS. NVIDIA appears only in four files of the sensor-grounded-admission paper: its bibliography, a research note, and two sections (`docs/papers/sensor-grounded-admission/`).
- Several shipped surfaces have no production caller, and several documents describe behavior the code does not have. Section 15 lists each document that disagrees with the code.

## Conventions

### Status labels

Chio statements carry one of these labels.

| Label | Meaning |
| --- | --- |
| qualified | Named in the bounded release gate or the evidence matrix of `docs/release/QUALIFICATION.md`, or approved with scope in `docs/reference/CLAIM_REGISTRY.md`. |
| shipped | Code on main that builds and has tests, outside the qualified boundary. |
| test-only | Code on main with no production caller: its only callers are tests, fixtures, or offline proof tools. |
| unmerged | Code that exists only on an unmerged branch (PR #1160 or PR #1156). |
| design doc | A design, proposal, specification draft, or paper with no implementation. |
| roadmap | Stated direction in a document, with no design behind it. |

`qualified`, `shipped`, `design doc`, and `roadmap` are the repository's claim-boundary labels. `test-only` and `unmerged` narrow `shipped`: test-only code is on main but no product path calls it, and unmerged code is not on main. Where parts of one component differ, each part carries its own label. Statements of absence, registry facts, and quotations of repository wording carry no label.

Statements about NVIDIA, OpenShell, ODIS, partners, or standards carry one of these labels the first time they appear in a section.

| Label | Meaning |
| --- | --- |
| VERIFIED | Primary source read on 2026-09-28 to 2026-09-29; some repository states are dated 2026-09-29 UTC. Behavior observed in the local test of OpenShell v0.1.2 on 2026-09-29 is marked VERIFIED, local test. |
| REPORTED | Secondary source, not independently confirmed. |
| INFERRED | Our reasoning from verified facts. |
| PROPOSED | A design, draft specification, or reference design that is not built. The text itself was read in the primary source. |

Facts about a design document itself (its status, authors, date, scope, or omissions) are VERIFIED. What the document says a system will do is PROPOSED.

### Numbering

- P1 to P10 are the ten formal properties bound in `formal/proof-manifest.toml:158-171` and approved with scope in `docs/reference/CLAIM_REGISTRY.md:70-79`. P1 is capability attenuation, P2 presented revocation coverage, P3 fail-closed evaluation, and P10 report truthfulness.
- M0 to M11 are the milestones of the security launch ledger on PR #1160 (`docs/security/launch-status.md:35-48` on that branch).

### Sources and paths

- `path:line` citations are relative to the repository root and refer to main at `f5566d9a76` (2026-09-03). Links into the repository are relative to this file; `../../../` reaches the repository root from `docs/research/nvidia/`.
- `QUALIFICATION.md:N` and "row N" mean line N of `docs/release/QUALIFICATION.md`, where each evidence-matrix row sits on one line. `CLAIM_REGISTRY.md:N` means line N of `docs/reference/CLAIM_REGISTRY.md`.
- Branch citations name the branch. Draft PR #1160 is `origin/integration/process-security-m4` at `f928453692` (2026-09-26, 681 commits ahead of main). PR #1156 is `origin/codex/required-agent-integrations-20260909` at `7059c71ca8` (2026-09-10).
- Upstream sources are cited by their own repository path at a pinned commit, prefixed with the project name:
  - OpenShell at `acbac9cb795094986cbab016bfd0352d980b17f6` of [NVIDIA/OpenShell](https://github.com/NVIDIA/OpenShell/tree/acbac9cb795094986cbab016bfd0352d980b17f6), committed 2026-09-29 02:18 UTC.
  - ODIS at `148dc4187139a41325e3c6d6e7533d956bd33144` of [cosai-oasis/ws4-odis](https://github.com/cosai-oasis/ws4-odis/tree/148dc4187139a41325e3c6d6e7533d956bd33144), committed 2026-09-08.
  - HushSpec at `6ca599ca8322a7cae6050086718ed5f3417c97e1` of [backbay-labs/hush](https://github.com/backbay-labs/hush/tree/6ca599ca8322a7cae6050086718ed5f3417c97e1), committed 2026-09-23.
- Release-facing wording is governed by `docs/reference/CLAIM_REGISTRY.md` and `docs/release/QUALIFICATION.md`. A third file, `spec/registries/claim-registry.v1.json`, lists 83 claims, all marked `enforced`, including 8 `claim.swarm.*`, 7 `claim.runtime.*`, and 4 `claim.agent_web.*` rows. It also holds a separate `proposed_claims` list of three entries (line 689). `CLAIM_REGISTRY.md` does not reference that file, so its rows license no release-facing wording.

## 1. Runtime attestation appraisal and verifier families

Chio ships two attestation stacks (**shipped**). Only the appraisal boundary feeds authority decisions; the TEE quote verifiers do not.

### Appraisal boundary

- Four verifier families sit in a closed enum: `AzureMaa`, `AwsNitro`, `GoogleAttestation`, and `EnterpriseVerifier`, each keyed by a schema string such as `chio.runtime-attestation.azure-maa.jwt.v1` (`crates/core/chio-core-types/src/runtime_attestation.rs:12-30`). Normalizing Azure, Nitro, and Google evidence into one appraisal shape without widening above `attested` is **qualified** (row 365). The enterprise-verifier family is **shipped**. The spec calls its bridge locally qualified (`spec/PROTOCOL.md:2988-2990`), but no evidence-matrix row names it (section 15).
- Evidence is one normalized statement: `RuntimeAttestationEvidence { schema, verifier, tier, issued_at, expires_at, evidence_sha256, runtime_identity?, workload_identity?, claims? }`, valid while `issued_at <= now < expires_at`. Tiers order as `none < basic < attested < verified`, and `basic` has no producer (**shipped**; `crates/core/chio-core-types/src/capability/runtime_attestation.rs:14-55`).
- Operators rebind a `{schema, verifier}` pair to an effective tier with `extensions.runtime_assurance.trusted_verifiers` rules in policy (`crates/guards/chio-policy/src/models/extensions.rs:381-409`). A rule can bound evidence age, allowed attestation types, and required assertions. Load-time validation rejects empty fields, zero ages, and duplicate bindings (**qualified**, row 366; `crates/guards/chio-policy/src/validate.rs:524-567`).
- With no trust rules configured, evidence is recorded as not locally accepted at tier `none` (**shipped**; `crates/economy/chio-appraisal/src/appraisal.rs:824-835`). With rules configured, evidence that matches no rule is rejected (`crates/core/chio-core-types/src/capability/runtime_attestation.rs:225-228`). The kernel then denies the whole governed request, even when no grant requires a tier (**qualified**, row 366; `crates/kernel/chio-kernel/src/receipt_support/receipt_metadata.rs:203-212`; `crates/kernel/chio-kernel/src/kernel/governed_validation.rs:1372-1373`).
- The kernel denies a governed call when the accepted tier is below a grant's `MinimumRuntimeAssurance` constraint or below the autonomy tier's floor. Delegated execution needs `attested` and Autonomous needs `verified` (**qualified**, row 349; `crates/kernel/chio-kernel/src/kernel/governed_validation.rs:314`). Capability issuance clamps scope per tier and appends the constraint to economically sensitive grants (**shipped**; `crates/platform/chio-control-plane/src/issuance/scope.rs:47`).
- The accepted tier, verifier family, verifier, evidence digest, and SPIFFE workload identity are written to `governed_transaction.runtime_assurance` in the signed receipt. Evidence that was not accepted is omitted (**qualified**, row 364; `crates/core/chio-core-types/src/receipt/governance.rs:34`).
- The hosted MCP edge can bind a session to an attestation digest (header `x-chio-runtime-attestation-sha256`, OAuth parameter `chio_sender_attestation_sha256`). This is qualified only when paired with DPoP or mTLS, "without widening authority from attestation alone" (**qualified**, row 333; `crates/protocol/chio-mcp-remote/src/remote_mcp/session_core.rs:96-99`).
- SPIFFE is the only workload-identity scheme, with `Uri`, `X509Svid`, and `JwtSvid` credential kinds (**qualified**, row 364; `crates/core/chio-core-types/src/capability/workload_identity.rs:9-21,150`).
- Signed appraisal reports, import of signed appraisal results under explicit local policy, verifier descriptors, reference-value sets, and trust bundles are **qualified** (rows 367-369; `spec/PROTOCOL.md:2988-2994`). Reference values are metadata only: nothing compares admission-time measurements against an active reference set.

### What admission verifies

- The kernel and the issuance path consume the normalized evidence the caller carries. They match schema and verifier strings against a trust rule, read required assertions from the same caller-supplied claims, and copy `evidence_sha256` without recomputing it (**shipped**; `crates/core/chio-core-types/src/capability/runtime_attestation.rs:123-229`).
- The bridges that verify vendor signatures live in `crates/platform/chio-control-plane/src/attestation.rs` and `crates/platform/chio-control-plane/src/attestation/`. The Azure MAA JWT, Google Confidential VM JWT, and AWS Nitro COSE bridges are **qualified** as library verification (row 365). The Ed25519 enterprise-envelope bridge is **test-only**. None of the four has a production caller outside that module and its tests.
- The JWT bridges resolve only RSA keys from a JWKS (`crates/platform/chio-control-plane/src/attestation/verification.rs:1169-1172`).
- Admission therefore does not re-verify vendor signatures. Accepted evidence is trusted through operator policy unless the operator runs a bridge upstream.

### TEE quote verification

- `chio-attest-verify` defines a `QuoteVerifier` trait with Intel TDX, AMD SEV-SNP, and AWS Nitro backends that bind a quote's report data to `SHA256(kernel_pk || receipt_root)` (`crates/trust/chio-attest-verify/src/lib.rs:340`; `crates/trust/chio-attest-verify/src/quote.rs:162`). The trait and types always compile. The three backends compile only with the non-default `tee-quotes` feature (**shipped** as an opt-in feature; `crates/trust/chio-attest-verify/src/lib.rs:33-53`; `crates/trust/chio-attest-verify/Cargo.toml:46-48`).
- The CLI command `chio attest runtime-quote verify` calls the backends. The kernel boot port `KernelSelfQuoteVerifier` (`crates/kernel/chio-kernel/src/boot.rs:114`) is **test-only**: its only implementations are three test doubles (`crates/kernel/chio-kernel/tests/pq_key_load_after_self_quote.rs:60,90,105`). No schema, family, or normalizer connects quotes to runtime-assurance tiers.

### Limits

- Absent on main: a verifier family for NVIDIA GPU, BlueField, or DOCA evidence; a parser for Entity Attestation Tokens (EAT, RFC 9711); a nonce challenge or replay registry at admission. NVIDIA's attestation services are covered in [01-nvidia-stack.md](01-nvidia-stack.md). One-time consumption of imported results is an explicit non-claim (`spec/PROTOCOL.md:2992-2994`).
- The threat rows `tee_quote_forgery` and `mobile_attestation_replay` are pending with no corpus cases (`docs/security/threat-coverage.md:168-206`).
- Each `RuntimeAttestationEvidence` value is one time-windowed, digest-bound assertion (**shipped**). Continuous or per-event telemetry would need a new evidence type. The sensor-grounded-admission research note surveys H100 attestation and concludes that TEE formats attest launch measurements, not sensor coverage (**design doc**; `docs/papers/sensor-grounded-admission/research/tee-attestation-delta.md:43-57`).
- The bounded release does not qualify "verifier-backed runtime assurance as the sole admission boundary" (QUALIFICATION.md:80). The spec claims one appraisal contract plus concrete bridges, not an EAT federation protocol (`spec/PROTOCOL.md:3077-3080`). It also states, as a normative rule, that new verifier families must project into the same appraisal shape (`spec/PROTOCOL.md:2940-2942`).

### Relevance to the NVIDIA stack

- NVIDIA presents Sentry as a reference system design with no availability date (VERIFIED, [NVIDIA newsroom, 2026-09-28](https://nvidianews.nvidia.com/news/open-agent-safety-platform)). No file in the OpenShell tree at the pinned commit contains "BlueField" or "DOCA" in any letter case (VERIFIED).
- A Sentry or DOCA statement could reach Chio on main only as enterprise-verifier evidence admitted by an operator trust rule. Trust would rest on that configuration, not on verified hardware attestation (INFERRED).
- Where an operator has configured trust rules, a Sentry or DOCA statement that matches no rule would deny the governed call. It would not fall back to tier `none` (INFERRED from the rule-matching code above).

## 2. Capability contract, delegation, caveats, budgets, approvals, revocation

This is the authority object an integration would carry across runtimes. The ship-facing claim covers "recursive delegated-authority admission backed by ancestor capability snapshots" (QUALIFICATION.md:69-71). The machine-readable matrix is narrower: it excludes "authenticated recursive delegation ancestry beyond the preserved presented chain" (`docs/standards/CHIO_BOUNDED_QUALIFICATION_MATRIX.json:16`).

### Token and scope

- `CapabilityToken` (schema `chio.capability.v1`) carries `id`, `issuer`, `subject`, `scope`, `issued_at`, `expires_at`, an optional `delegation_chain`, an optional aggregate invocation budget, and attenuation fields, signed over canonical JSON (**qualified**; `crates/core/chio-core-types/src/capability/token.rs:120-161`; `spec/schemas/chio-wire/v1/capability/token.schema.json`).
- Keys and signatures are Ed25519 by default. P-256 and P-384 signatures verify only in builds with the non-default `fips` feature, and hybrid ML-DSA-65 signatures only with `pq`. Default builds reject them fail-closed, and no release workflow enables either feature (**shipped** as opt-in features; `crates/core/chio-core-types/src/crypto.rs:90-99, 1166-1194`; `crates/core/chio-core-types/Cargo.toml:54-74`).
- Scope is three grant vectors: tools, resources, and prompts. A tool grant names `server_id`, `tool_name`, operations, typed constraints, `max_invocations`, per-invocation and total monetary caps, and `dpop_required` (**shipped**; `crates/core/chio-core-types/src/capability/scope.rs:80-129`).
- The `Constraint` enum has 27 variants (`crates/core/chio-core-types/src/capability/scope.rs:331`). The portable matcher in `chio-kernel-core` evaluates eight of them and fails closed on the rest (`crates/kernel/chio-kernel-core/src/scope.rs:193-273`). The hosted matcher returns `Ok(false)` for `ContentReviewTier`, `MaxTransactionAmountUsd`, and `RequireDualApproval`, so a grant that carries one of them can never authorize a call (**shipped**; `crates/kernel/chio-kernel/src/request_matching.rs:469-470`).
- Typed caveats (`RestrictTool`, `BindSession`, `RestrictAudience`, `RestrictGeo`, `RestrictTimeWindow`) are defined on the wire, but any token that carries a caveat is rejected fail-closed at signing and at validation (**shipped**; `crates/core/chio-core-types/src/capability/token.rs:327-333,570-576`). Third-party discharge is deferred (`crates/core/chio-core-types/src/capability/caveat.rs:17`).

### Delegation

- Delegation only narrows. Each `DelegationLink` is signed by the delegator and records the ancestor capability id, delegator, delegatee, declared attenuation steps, timestamp, and the parent's scope hash. Seven step types exist, from `RemoveTool` to `ReduceTotalCost` (**qualified**, P1; `crates/core/chio-core-types/src/capability/attenuation.rs:64-82,172`).
- A child token's `AttenuationProof` carries parent and child scope hashes plus a normalized subset witness. Verifiers recompute the hashes, re-parse both scopes, and re-run the subset check (**shipped**; `crates/core/chio-core-types/src/capability/attenuation.rs:44,872`).
- P1 gives bounded Lean and executable-test evidence for attenuation (**qualified**; CLAIM_REGISTRY.md:70). The Lean model covers invocation budgets through `reduceBudget` (`formal/lean4/Chio/Chio/Core/Capability.lean:60`). Monetary attenuation evidence is differential-test only (`formal/diff-tests/src/generators.rs:371-481`).
- Chain binding ties the proof's parent hash to the issuer's registered trust-root scope hash or to the previous link. Sibling-sum admission stops children from jointly claiming more of a parent's budget share than it holds (**shipped**; `crates/core/chio-core-types/src/capability/token.rs:383-458`; `crates/kernel/chio-kernel-core/src/capability_verify.rs:219`). The pre-admission pass uses a no-op budget registry, so sibling-sum admission is authoritative only on hosted dispatch (`crates/kernel/chio-kernel/src/kernel/validation.rs:293`).
- Proof-carrying chains are limited to one hop: longer attenuated chains are rejected until per-hop child-scope witnesses exist (**shipped**; `crates/core/chio-core-types/src/capability/attenuation.rs:301-306`). Deeper chains are validated only by the hosted kernel against persisted ancestor snapshots (`crates/kernel/chio-kernel/src/kernel/validation.rs:732-899`), which a portable verifier does not have. The default depth limit is 5 (`crates/platform/chio-control-plane/src/policy/types.rs:247-249`).
- The pure verifier in `chio-kernel-core` is inside the verified core for issuer trust, signature, and time-window checks only (**qualified**; CLAIM_REGISTRY.md:66; `crates/kernel/chio-kernel-core/src/capability_verify.rs:1-21`). It does not check revocation, lineage against the receipt store, scope, or DPoP.

### Approvals

- `GovernedApprovalToken` binds an approver key, the subject, the governed-intent hash, the request id, and a decision (`crates/core/chio-core-types/src/capability/governance.rs:1005`). The kernel rejects a token whose lifetime exceeds 3600 seconds (`crates/kernel/chio-kernel/src/kernel/governed_validation.rs:391-400`), and a replay store makes each approval single-use (**shipped**; `crates/kernel/chio-kernel/src/governed_approval_replay.rs:27`). `docs/release/RELEASE_CANDIDATE.md:144` lists governed transaction approvals among supported guarantees.
- Threshold approvals accept up to 32 approvers and a window of 1 to 3600 seconds, bound to a policy hash and an approver-set digest (**shipped**; `crates/core/chio-core-types/src/capability/threshold_approval.rs:12-13`).
- The human-in-the-loop protocol document is marked as a P0 proposal from April 2026 (**design doc**; `docs/protocols/HUMAN-IN-THE-LOOP-PROTOCOL.md:3`). The kernel ships the approval guard, signed approval tokens, and a webhook channel (**shipped**). Slack, email, dashboard channels, and escalation chains exist only in that document.

### Revocation

- The kernel checks the leaf capability id and every ancestor id in the presented chain against a revocation store (in-memory, SQLite, or remote), so revoking a root cascades on presentation (**qualified**; `crates/kernel/chio-kernel/src/kernel/validation.rs:718`; `crates/kernel/chio-kernel/src/kernel/validation/revocation_trace.rs:4-9`).
- `chio-revocation-oracle` adds signed append-only epoch roots, inclusion proofs, federation gossip, and a passport-revocation bridge (**shipped**). Its trait has five methods (`insert`, `contains`, `epoch_root`, `inclusion_proof`, `non_inclusion_proof`) and no removal (`crates/trust/chio-revocation-oracle/src/api.rs:116-126`). Only in-memory oracle and broadcaster implementations ship (`crates/trust/chio-revocation-oracle/ARCHITECTURE.md:94-101`).
- When a revocation view is installed (the kernel's `delegation` feature), it must be no older than 500 ms by default. With no view installed the check is a no-op (**shipped**; `crates/kernel/chio-kernel/src/kernel/delegation.rs:34-39`; `crates/kernel/chio-kernel/src/kernel/validation.rs:736-742`).
- Non-inclusion is a live re-query, not a standalone proof, and `chio-kernel-core` does not re-verify the root signature (`crates/kernel/chio-kernel-core/src/revocation_view.rs:87-89`). Reversible containment through a separate deny-overlay store exists only in a design document (**design doc**; `docs/superpowers/specs/2026-07-09-security-folder-design.md:35`).
- P2 gives bounded Lean proofs that revoked tokens and revoked presented ancestors cannot pass the pure revocation and evaluation model (**qualified**; CLAIM_REGISTRY.md:71). "Runtime revocation is formally verified end to end" is disallowed wording (CLAIM_REGISTRY.md:92).

### Sender binding

- When a grant sets `dpop_required`, each call needs a DPoP proof that binds the capability id, tool server, tool name, argument hash, nonce, and issue time to the subject key (**shipped**; `crates/kernel/chio-kernel/src/dpop.rs:606`). Grants without the flag are not sender-constrained.
- The DPoP nonce store is process-scoped, with a default capacity of 65,536 entries (**shipped**; `crates/kernel/chio-kernel/src/dpop.rs:56`).

### What the token does not carry

The SAW design describes a per-engagement signed delegation record that binds bounded agent authority: "task, scoped resources, tools, duration, approval mode, revocation, and audit references". A child record "can only narrow the parent's scope, tools, resources, and duration", and the record is "revocable by the sponsor" (PROPOSED, [SAW, What is Secure Agent Workspace, last updated 2026-06-28](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/what-is-secure-agent-workspace.html)). Chio's counterparts:

| SAW record field | Chio counterpart | Status |
| --- | --- | --- |
| Task | No token field. Purpose is a per-request field on the governed intent (`crates/core/chio-core-types/src/capability/governance.rs:870`); task ids live in swarm task graphs (section 5). | shipped |
| Scoped resources | Resource grants and argument constraints (`crates/core/chio-core-types/src/capability/scope.rs:80-129`). | shipped |
| Tools | Tool grants with invocation and monetary caps. | shipped |
| Duration | `issued_at` and `expires_at`; a child may not outlive its parent. | qualified |
| Approval mode | No field. Approval is expressed as threshold constraints and approval tokens. `RequireDualApproval` never matches. | shipped |
| Revocation | Capability-id cascade. No sponsor-authorized revocation path. | qualified |
| Audit references | Not in the token or link. The hosted kernel links a call to its parent through `CapabilitySnapshot` rows and, when a governed intent presents one, a verified `CallChainContinuationToken` with parent request, parent receipt, and parent capability ids (`crates/kernel/chio-kernel/src/kernel/governed_validation.rs:827-990`). | shipped |
| Sponsor | No sponsor field. An `EnterpriseIdentityContext` (provider, tenant, groups, roles) exists per session but is not bound into the token (`crates/core/chio-core-types/src/session/auth.rs:109`). | shipped |

ODIS requires `sponsor_ref` and `lifecycle_state` on an Agent Registration Record ([`RFCs/ODIS.md:679-680`](https://github.com/cosai-oasis/ws4-odis/blob/148dc4187139a41325e3c6d6e7533d956bd33144/RFCs/ODIS.md?plain=1#L679-L680)) and `task_id` on a Delegation Record ([`RFCs/ODIS.md:728`](https://github.com/cosai-oasis/ws4-odis/blob/148dc4187139a41325e3c6d6e7533d956bd33144/RFCs/ODIS.md?plain=1#L728)) (PROPOSED). It requires `parent_delegation_ref` (issuer, `delegation_id`, `record_digest`) on every non-root record and forbids it on a root record ([`RFCs/ODIS.md:723`](https://github.com/cosai-oasis/ws4-odis/blob/148dc4187139a41325e3c6d6e7533d956bd33144/RFCs/ODIS.md?plain=1#L723)) (PROPOSED). It also states that lexical scope-string subset checks are not sufficient unless semantic equivalence is proven ([`RFCs/ODIS.md:415`](https://github.com/cosai-oasis/ws4-odis/blob/148dc4187139a41325e3c6d6e7533d956bd33144/RFCs/ODIS.md?plain=1#L415)) (PROPOSED).

Chio has partial counterparts (**shipped**):

- `DelegationLink` carries the ancestor `capability_id` and a `scope_hash` (`crates/core/chio-core-types/src/capability/attenuation.rs:64-82`).
- The continuation token carries `parent_capability_id` and `delegation_link_hash`, which the hosted kernel checks against the capability lineage (`crates/kernel/chio-kernel/src/kernel/governed_validation.rs:926-958`).
- Passports carry an operator-managed lifecycle state (section 8).

Chio has no `sponsor_ref`, no `task_id` on the token or link, and no digest over a whole parent record (INFERRED).

### Task-bound artifacts beyond the token

- `chio-workflow` defines `SkillGrant`, `WorkflowAuthority`, and a signed `WorkflowReceipt` (**shipped**; `crates/platform/chio-workflow/src/grant.rs:11-49`). `SkillGrant` is an unsigned struct with no id, issuer, subject, absolute expiry, or parent reference. `WorkflowAuthority` is **test-only**: its only callers are the crate's unit tests (`crates/platform/chio-workflow/src/authority.rs:591` onward).
- `chio-workflow-preflight` checks that child tasks stay inside the parent's actions, resources, and budget. Its report is always planning evidence with no live-authority claims, and it has no duration dimension (**shipped**; `crates/platform/chio-workflow-preflight/src/lib.rs:19-56`).
- `chio-governance` signs capability leases and governance receipts for destructive steps (**shipped**; `crates/trust/chio-governance/src/lease.rs:7-28`). The runtime admission path consumes a lease id once as a replay guard but does not check its signature, expiry, or revocation there (`crates/kernel/chio-runtime-core/src/admission.rs:218-277`).

## 3. Receipts, metadata families, checkpoints, anchoring, bilateral DSSE, lineage

This is the evidence layer an integration would offer. The ship-facing claim covers "signed local receipts and checkpoints" (QUALIFICATION.md:72). The bounded release excludes "public transparency-log or strong non-repudiation semantics" (QUALIFICATION.md:82).

### Receipt contract

- A `ChioReceipt` (`chio.receipt.v1`) records one evaluated tool call. Its id is SHA-256 over the RFC 8785 canonical JSON of every body field except the id, and the kernel signature covers the id and body (**shipped**; `crates/core/chio-core-types/src/receipt/body.rs:42`). The body includes capability id, tool server and name, parameter hash, decision, receipt kind, boundary class, content hash, policy hash, per-guard evidence, metadata, trust level, tenant id, and kernel key.
- The signer recomputes the content hash from the output preimage and refuses to sign on mismatch, and a coupling gate checks the body against the decision inputs (**qualified**; `spec/PROTOCOL.md:879-893`; CLAIM_REGISTRY.md:67). The one exception is the relay seam for thin FFI and WASM adapters (mobile FFI, browser WASM, C++ FFI), which trusts the caller-asserted `content_hash` (`spec/PROTOCOL.md:895-906`).
- Only `mediated_decision` + `prevent` + `Allow` counts as authorization. Trace and advisory receipts are evidence and are never authorization (**shipped**; `spec/PROTOCOL.md:1012-1025`).
- `policy_hash` in production receipts is the control plane's runtime fingerprint: SHA-256 over `serde_json` output of selected HushSpec rule blocks plus the reputation extension, not RFC 8785 over the whole policy (**shipped**; `crates/platform/chio-control-plane/src/policy/util.rs:38-67`; `crates/platform/chio-control-plane/src/lib.rs:384`). A third party cannot recompute it from an independently serialized policy, and receipts do not carry the policy source.

### Metadata families

- Reserved top-level metadata keys have typed structs and registered schemas: `financial`, `governed_transaction`, `channel`, `budget_authority`, `delivery_contract`, `finding_delivery`, `finding_recovery`, and the kernel's `admission_operation` (**shipped**; `crates/core/chio-core-types/src/receipt/metadata.rs:206-218,289,480`). `delivery_contract` shows the full pattern: spec paragraph, JSON schema, `deny_unknown_fields` struct, generated wire type, kernel attach with a collision check, and contract tests.
- Collision rejection exists only for `delivery_contract`, `finding_delivery`, and `finding_recovery` (**shipped**; `crates/kernel/chio-kernel/src/kernel/admission_coordinator/terminal.rs:2044-2123`).
- `governed_transaction` carries the intent hash, approval token id, approver key and approval artifact digest, the runtime-assurance block from section 1, and call-chain provenance whose evidence class is `asserted`, `observed`, or `verified` (**shipped**; `crates/core/chio-core-types/src/receipt/governance.rs:18-143`; `crates/kernel/chio-kernel/src/receipt_support/receipt_metadata.rs:14-85`).
- Attribution metadata binds the subject key, issuer key, delegation depth, and matched grant index (**shipped**; `crates/core/chio-core-types/src/receipt/metadata.rs:538-554`).
- A caller-supplied `provenance` block (W3C trace and span ids, an optional supply-chain object) is validated for shape and signed into the receipt, but the referenced material is not verified (**shipped**; `crates/kernel/chio-kernel/src/receipt_support/receipt_metadata.rs:114-201`).
- No metadata family binds an external runtime policy decision or an out-of-band observer statement.

### Checkpoints and anchoring

- Kernel checkpoints (`chio.checkpoint_statement.v2`) commit tool-receipt batches to a Merkle root with an RFC 6962 chain root, predecessor digests, inclusion and consistency proofs, and equivocation detection (**shipped**; `crates/kernel/chio-kernel/src/checkpoint.rs:41,101`). They are qualified as local audit evidence only: the spec limits them to audit and `transparency_preview` claims because leaves cover tool-receipt batches only (**qualified**; `spec/PROTOCOL.md:2168-2176`).
- Anchor batches publish checkpoint roots to Base or Arbitrum, link them into OpenTimestamps super-roots, and normalize Solana memos (**qualified**, row 374). Web3 lanes are rehearsal evidence only and do not authorize mainnet custody (QUALIFICATION.md:219-223).
- `chio-anchor` also ships a Rekor witness client (**shipped**; `crates/economy/chio-anchor/src/witness/rekor.rs:1-27`). Row 374's `cargo test -p chio-anchor` command runs its tests, but no qualified claim names Rekor.
- The Rekor client verifies the signed entry timestamp against a pinned key. When Rekor returns an RFC 6962 inclusion proof, the client checks it against the `rootHash` in the same response, not against a signed Rekor checkpoint. It skips that check when no proof is returned (**shipped**; `crates/economy/chio-anchor/src/witness/rekor.rs:19-27,537-553`).
- The spec correctly says the client does not verify the inclusion path to a checkpoint (`spec/PROTOCOL.md:2233-2241`). It does not mention the response-root check.

### Bilateral DSSE

- Two organizational kernels sign the same DSSE v1 envelope over an in-toto Statement v1 whose subject is the SHA-256 of the canonical receipt body. The strict predicate `chio.bilateral-cosign-invocation.v1` binds the tool-argument hash, a capability lease reference, both kernels' policy verdicts (which must agree), and optional treaty references. The verifier requires exactly two signatures from distinct pinned keys (**shipped**; `crates/trust/chio-federation/src/bilateral_dsse/types.rs:16-22`).
- This lane sits outside the bounded gate. Crate and conformance tests exercise it (for example `crates/tooling/chio-conformance/tests/b4_bilateral_dsse_pae_conformance.rs`), and a path-filtered CI script compares its predicate semantics (`scripts/check-chio-treaty-buyer-hero-loop.sh:238`). No qualification gate or addendum runs it, no evidence-matrix row names it, and no `CLAIM_REGISTRY.md` id covers it.
- The in-toto predicate URI is a proposal to the in-toto Attestation WG, the OpenSSF AI/ML Security WG, and CoSAI Workstream 4, dated 2026-05-04 (**design doc**; `spec/CHIO_BILATERAL_COSIGN_INVOCATION.md:3-5`). The same file describes Workstream 4 as "the Secure AI Software Supply Chain workstream" (`spec/CHIO_BILATERAL_COSIGN_INVOCATION.md:591-593`).
- That description is wrong. CoSAI Workstream 4 is Secure Design Patterns for Agentic Systems (VERIFIED, [CoSAI WS4 repository README, read 2026-09-29](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems)), and ODIS is developed in its `cosai-oasis/ws4-odis` repository (VERIFIED). As written, the outreach step addresses a supply-chain audience and never mentions ODIS (INFERRED). Section 15 records the fix.
- The paper on this construction records that its evaluation ran two kernels in one process with a shared clock, and that party independence collapses when one operator holds both keys (**design doc**; `docs/papers/bilateral-receipt-admission/sections/09-limitations.tex:6-8`).

### Lineage and third-party verification

- Child receipts, signed receipt-lineage statements, and the `chio-lineage` provenance graph link receipts across requests and sessions (**shipped**; `crates/core/chio-core-types/src/receipt/lineage.rs:210-405`). Their evidence classes cannot be upgraded by report labels, which P10 proves in a bounded Lean model (**qualified**; CLAIM_REGISTRY.md:79).
- `chio-lineage` frontiers verify only through `is_signed_by` with a caller-supplied trusted key. The keyless `is_signed()` always returns false by design (**shipped**; `crates/observability/chio-lineage/src/anchor.rs:426-440`).
- `ChioReceipt` has no DAG fields, and the multi-parent receipt DAG helpers in `crates/core/chio-core-types/src/receipt/lineage.rs:62-118` have no caller. The spec's DAG ordinal rule (`spec/PROTOCOL.md:999-1010`) is therefore not implemented for tool receipts. Swarm join receipts carry their own `parent_set_hash` and a positive `dag_ordinal` (**shipped**; `crates/kernel/chio-swarm-authority/src/types.rs:184-200`; `crates/kernel/chio-swarm-authority/src/verifier.rs:344-358`).
- TypeScript, Python, and Go helpers verify receipt signature, id, parameter hash, and signer trust against shared vectors in `tests/bindings/vectors` (**shipped**; `sdks/typescript/chio-ts/src/invariants/receipt.ts`). `chio evidence verify` checks an exported bundle of receipts, child receipts, checkpoints, capability lineage, and inclusion proofs (**shipped**; `crates/kernel/chio-kernel/src/evidence_export.rs:212-225`).
- Receipts prove kernel-observed evaluation events, not external side effects beyond Chio's observation boundary (`spec/PROTOCOL.md:1215-1218`).

## 4. Runtime-security evidence slots on the verifier side

These artifacts are the designed place for runtime-layer evidence such as a sandbox profile or a tool-server acknowledgement. On main they exist only as offline verifier checks.

- `chio-transaction-passport` verifies a bundle that holds execution leases, sandbox attestations, tool-server acknowledgements, trusted-time proofs, revocation-freshness proofs, terminal receipts, and policy-activation receipts. Each is signed over a Chio canonical body by a key listed in a pinned trust root (**shipped** verifier; `crates/platform/chio-transaction-passport/src/runtime_security/artifacts.rs:41,298,1803`; schemas in `spec/schemas/chio-runtime/v1/`).
- Per execution lease, the verifier requires exactly one request digest, route plan, task graph, budget pool, join receipt, and trusted-time proof. It selects the revocation proof, sandbox attestation, acknowledgement, and terminal receipt by first match and does not reject duplicates (**shipped**; `crates/platform/chio-transaction-passport/src/runtime_security.rs:332,431,446,461,505`).
- The signers that produce these artifacts are **test-only**: they appear only in fixed-seed tests and proof-room fixtures. The verifier's callers are the CLI proof verifier and `chio-proof-room`.
- An execution lease verifies only for a swarm child task with a task graph, join receipt, budget allocation, and route plan. A single tool call cannot yield a valid lease (**shipped**).
- A sandbox attestation signs `sandbox_profile_digest` and `egress_policy_digest`, but the verifier only checks their shape (**shipped**). No document defines their preimage, and nothing compares them with an expected value.
- A policy-activation receipt records `initial_load` or `hot_reload` and rejects `widening` ("policy activation cannot widen in-flight authority"). The direction is a label the issuer asserts, and the digest must equal the Chio verifier policy digest (**shipped**; `crates/platform/chio-transaction-passport/src/runtime_security/artifacts.rs:824-834`).
- The seven `claim.runtime.*` rows are marked `enforced` in `spec/registries/claim-registry.v1.json:177-231` and are absent from `CLAIM_REGISTRY.md`.
- `chio-agent-web-interop` verifies projections of 30 external protocols as evidence that never confers Chio authority. OCSF, OpenShell, and DOCA are not among them (**shipped**; `crates/platform/chio-agent-web-interop/README.md:26`).
- The cognition-market Firecracker worker signs a result that binds pinned environment digests to host-measured CPU time, memory, and output size (**shipped**; `crates/platform/chio-finding-worker/src/protocol.rs:621`). It serves the cognition market only, and kernel budgets do not consume it.

Relevance: OpenShell's `filesystem_policy`, `landlock`, and `process` sections take effect at sandbox start, while `network_policies` and `network_middlewares` are live (VERIFIED, OpenShell `docs/how-it-works/policies/schema.mdx:29-33`). Its policy advisor "can add a network rule, but it cannot remove rules or change filesystem, Landlock, or process settings" (VERIFIED, OpenShell `docs/how-it-works/policies/advisor.mdx:13-14`). An approved advisor proposal therefore widens network reach, which Chio's activation receipt rejects, and each live network revision would need its own sandbox attestation (INFERRED).

## 5. Swarm authority

Task binding and pooled budgets for sub-agents live here, not in the capability token.

- `verify_swarm_authority_bundle` is a pure, I/O-free verifier (**shipped**; `crates/kernel/chio-swarm-authority/src/verifier.rs:37`; `crates/kernel/chio-swarm-authority/ARCHITECTURE.md:8-10`). A bundle carries one signed task graph with depth and fan-out ceilings, continuation tokens, per-hop witness chains with attenuation proofs, route-plan receipts, one budget pool, a revocation epoch, and join and terminal receipts (`crates/kernel/chio-swarm-authority/src/types.rs:44,99,247`).
- Route plans must carry the single egress constraint `deny-private-network` (**shipped**; `crates/kernel/chio-swarm-authority/src/verifier.rs:979`). Budget allocations must sum within the pool and reconcile exactly in the terminal receipt.
- The runtime admission hook re-hashes the referenced artifacts, runs the verifier, and consumes single-use continuations durably before dispatch (**shipped**; `crates/kernel/chio-runtime-core/src/admission_hook/swarm_authority.rs:31`).
- Trusted witness keys reach the runtime path only through a builder method, `with_swarm_witness_keys`, that no product binary calls. Swarm-bound runtime admission therefore runs only in tests (**test-only**; `crates/kernel/chio-runtime/src/lib.rs:188,226`). `chio-swarm-authority` also exports mint and sign helpers whose only callers are fixtures (**test-only**).
- Every artifact role (graph issuer, planner, join issuer, epoch authority, hop issuer) is checked against one flat trusted key slice (**shipped**). A raw-hex issuer string may name an Ed25519, P-256, P-384, or hybrid key (`crates/core/chio-core-types/src/crypto.rs:405-421`), although default builds verify only Ed25519 signatures (section 2). A signed terminal graph receipt must exist before any child is admitted. Session anchors and parent receipt ids are checked for presence and uniqueness, not resolved.
- The swarm verifier does not consume `chio.call_chain_continuation.v1` (`crates/core/chio-core-types/src/capability/governance.rs:332`). The hosted kernel verifies that token when a governed intent presents it (**shipped**; `crates/kernel/chio-kernel/src/kernel/governed_validation.rs:827-990`). It checks the signature, time window, subject, trusted or lineage signer, chain id, parent request and receipt ids, origin and delegator subjects, audience, intent hash, parent capability id, delegation-link hash, and the local parent receipt. No portable or swarm path verifies it.
- The spec calls this "a bounded runtime-admission contract" (`spec/PROTOCOL.md:1289-1290`). The eight `claim.swarm.*` rows exist only in the spec registry. No Kani or Lean proof covers the swarm verifier itself; only the per-hop attenuation witness has a Lean theorem.
- There is no approval mode, human-review marker, or reasoning-evidence field in any swarm artifact.

## 6. Dispatch, isolation boundary, egress contract

Chio's kernel is an in-band, in-process mediator. It validates the capability, runs guards, reserves budget and an execution nonce, calls the tool server, and signs the receipt (**shipped**; `crates/kernel/chio-kernel/ARCHITECTURE.md:14-63`).

### Seams an external runtime can use

| Seam | Purpose | Status | Path |
| --- | --- | --- | --- |
| `ToolServerConnection` | Dispatch an authorized call to any executor, keyed by `server_id` | shipped | `crates/kernel/chio-kernel/src/runtime.rs:402`; registered at `crates/kernel/chio-kernel/src/kernel/construction.rs:2017` |
| `RuntimeAdmissionHook` | Pre-dispatch admission check with deny authority; one slot per kernel | shipped | `crates/kernel/chio-kernel/src/kernel/mod.rs:151` |
| `PostInvocationHook` | Inspect, redact, or block tool output | shipped | `crates/kernel/chio-kernel/src/post_invocation.rs:58` |
| `EnvoyKernel` | External-authorizer trait behind the Envoy ext_authz shim; no implementation in the workspace | shipped | `crates/protocol/chio-envoy-ext-authz/src/service.rs:23` |

`ToolServerConnection` has eleven product implementations: stdio MCP, native Chio services, A2A, ACP, two OpenAPI bridge servers, the HTTP authority, the hosted shared upstream, finding reveal, and two CLI cost-gate servers (**shipped**). The other implementations are test servers, examples, conformance fixtures, a load-generator fixture, and snippets in planning documents.

### Isolation

- Agents and tool servers are spawned as ordinary child processes with piped stdio. No seccomp, Landlock, namespace, cgroup, rlimit, or uid change is applied. The only environment hygiene is removal of six `CHIO_*` token variables (**shipped**; `crates/protocol/chio-mcp-adapter/src/transport/stdio.rs:57`; `crates/protocol/chio-mcp-adapter/src/transport/utils.rs:20-32`).
- The host boundary is stated in four places: operators "SHOULD pair Chio mediation with OS or container confinement" and "Chio mediation cannot by itself sandbox arbitrary tool-server code" (`spec/SECURITY.md:156-164`); `ASSUME-SUBPROCESS-ISOLATION` (`formal/assumptions.toml:33`; CLAIM_REGISTRY.md:50); and "Chio does not sandbox code. The sandbox provider does." (`docs/guards/13-CODE-EXECUTION-GUARDS.md:49-56`). The assumption is **qualified** as an audited assumption, not as a Chio control.
- `README.md:135`, `README.md:661`, and `AGENTS.md:11` describe tool servers as "sandboxed processes". The code and the security spec do not support that wording (section 15).
- Two OS sandboxes do exist, both scoped to cognition-market work (**shipped**). One is a Firecracker jailer for hosted finding jobs with no guest network (`crates/platform/chio-finding-worker/src/lib.rs:1-7`; `crates/platform/chio-finding-worker/src/executor.rs:755`). The other is a bubblewrap harness for verified-fix runs (`crates/products/chio-cli/src/cli/dispatch/finding/verified_fix_repository_sandbox.rs:272-277`). Neither confines general agents or tool servers.

### Egress contract and credentials

- `HttpEgressContract` is a typed allowlist (schemes, exact authorities, loopback, link-local and ULA denials, redirect and response-size ceilings) for HTTP that Chio itself sends: oracles, SIEM exporters, A2A and OpenAPI dispatch, and the `chio api protect` upstream call (**shipped**; `crates/protocol/chio-egress-contract/src/lib.rs:15-41`; `spec/PROTOCOL.md:2458`). It does not see sockets that a tool server opens. Agent-facing network rules are guards over tool-call arguments.
- Chio holds its own signing seed and service keys. On the general mediation path it does not broker upstream credentials: wrapped MCP children inherit the kernel's environment, and `chio api protect` forwards the caller's `authorization` header upstream (**shipped**; `crates/products/chio-api-protect/src/proxy/http.rs:126-145`).
- The provider adapters are the exception (section 7). They attach a provider key to each upstream model call, for example `OPENAI_API_KEY` sent as a bearer token (**shipped**; `crates/protocol/chio-openai-adapter/src/transport.rs:54-56,96-122`).

### Bypass

- The risk register lists "Sidecar bypass: agents can call tools without mediation" as HIGH and open (`docs/release/RISK_REGISTER.md:11`). The structural-fixes design calls network enforcement the "strongest fix" and tool-server authentication the "most practical fix" (**design doc**; `docs/protocols/STRUCTURAL-SECURITY-FIXES.md:484-486`).
- Shipped mitigations are opt-in execution nonces, the receipt `trust_level` field, and a static no-bypass gate over MCP, API protect, and OpenAPI adapters. By default `chio mcp wrap` is manifest-gated pass-through; kernel preflight runs only with `--strict-execution-nonce` (**shipped**; `crates/products/chio-cli/src/cli/mcp/wrap.rs:17-19`).

### Off main

- `chio-cage` installs Landlock and a separate seccomp-BPF allowlist on native tool servers the kernel launches. It reports `FullyEnforced` only after the parent observes `PTRACE_EVENT_EXEC` (**unmerged**; `crates/security/chio-cage/README.md:11-15` on PR #1160). It requires Linux 6.7 or later, x86_64, and Landlock ABI 4 (`crates/security/chio-cage/README.md:60-66` on PR #1160).
- `chio-secret-broker` keeps agent, kernel, and tool server on credential references. Its daemon resolves the real secret in its own process and injects it into the outbound HTTPS request (**unmerged**; `crates/security/chio-secret-broker/README.md:3` on PR #1160).
- The branch's status ledger lists M9 entry packages as unpublished, M10 as not release qualified, and M11 (authorized observed pilot and signed promotion stages) as not started (`docs/security/launch-status.md:46-48` on PR #1160).
- Relevance: OpenShell gives the workload credential placeholders of the form `openshell:resolve:env:KEY` and substitutes real values only at bound endpoints (VERIFIED, OpenShell `docs/how-it-works/policies/schema.mdx:175`). The cage and the broker duplicate that layer (INFERRED).
- The cage relies on the parent-child ptrace contract and installs its own seccomp filter. Containerized runs also need "an unconfined outer seccomp profile" (`crates/security/chio-cage/README.md:11-15,163-165` on PR #1160).
- OpenShell's workload filter blocks `memfd_create` and `ptrace` (OpenShell `crates/openshell-sandbox/src/sandbox/linux/seccomp.rs:221-223`). The same file makes `pidfd_open` unavailable (line 164), blocks `pidfd_getfd` and `pidfd_send_signal` (lines 233-234), blocks `execveat` with `AT_EMPTY_PATH` (lines 260-263), and blocks `seccomp(SECCOMP_SET_MODE_FILTER)` (lines 285-294) (VERIFIED).
- The cage therefore cannot run nested inside an OpenShell sandbox (INFERRED from the source of both projects; not tested in a nested run).

## 7. Protocol edges and the inference path

- `crates/protocol/` holds 28 crates. Within it, the four MCP crates (`chio-mcp-adapter`, `chio-mcp-edge`, `chio-mcp-remote`, `chio-hosted-mcp`) are the only ones marked `public_entrypoint = true` (**shipped**; for example `crates/protocol/chio-mcp-adapter/Cargo.toml:13`).
- The MCP surface is the qualified path: stdio `chio mcp serve` and Streamable HTTP `chio mcp serve-http` with OAuth bearer, JWT, introspection, DPoP, mTLS thumbprint, and attestation-bound confirmation (**qualified**; QUALIFICATION.md:333; `docs/release/RELEASE_CANDIDATE.md:487-491`). Each remote session gets its own wrapped MCP child by default, and `--shared-hosted-owner` opts into one shared child (**shipped**; `crates/protocol/chio-mcp-remote/src/remote_mcp/session_core/factory.rs:145-151`).
- The MCP edge accepts only protocol version `2025-11-25` and answers any other `protocolVersion` with `protocol_version_unsupported` (**shipped**; `crates/protocol/chio-mcp-edge/src/runtime.rs:81-82`; `crates/protocol/chio-mcp-edge/src/runtime/jsonrpc.rs:74-76`).
- The Envoy ext_authz crate translates a proxy check into a Chio verdict (**shipped**; `crates/protocol/chio-envoy-ext-authz/README.md:30-35`). It ships no `EnvoyKernel` implementation, its verdict carries no receipt id, and nothing in the workspace depends on it. Its design document, including "Rego guards", is a Tier 0 proposal (**design doc**; `docs/protocols/ENVOY-EXT-AUTHZ-INTEGRATION.md:3,628`). No Rego or OPA code exists in `crates/` or `sdks/`.
- Receipt-bearing HTTP mediation does exist. `chio-tower` injects `x-chio-receipt-id` (**shipped**; `crates/protocol/chio-tower/src/service.rs:169-205`). `chio api protect` evaluates HTTP-shaped requests at `/chio/evaluate`, routes `/v1/evaluate` to a kernel-mediated tool-call handler, and keeps `/v1/evaluate/advisory` advisory-only (**shipped**; `crates/products/chio-api-protect/src/proxy/router.rs:50,87-94`). Four documents describe `/v1/evaluate` differently (section 15).
- A2A consumption is in the shipped v1 contract only where a live kernel receipt backs it (**shipped**; `spec/PROTOCOL.md:59-71`). The A2A and ACP edges and the AG-UI proxy are shipped code that the spec does not describe as natively enforcing Chio policy (`spec/PROTOCOL.md:1431-1437`).
- Provider adapters for eight model APIs sit on the inference path as pass-through clients. They forward the inference request as opaque bytes and evaluate only the tool-use blocks in responses (**shipped**; `crates/protocol/chio-tool-call-fabric/src/adapter.rs:5-10`).
- The adapters hold the provider key in process. The OpenAI transport reads `OPENAI_API_KEY` and sends it as `Authorization: Bearer`, and the Anthropic transport sends `x-api-key` (**shipped**; `crates/protocol/chio-openai-adapter/src/transport.rs:54-56,82-122`; `crates/protocol/chio-anthropic-tools-adapter/src/transport.rs:49-53`).
- `QUALIFICATION.md` has no provider-adapter row, although `README.md:525-526` labels the Anthropic and Bedrock adapters "Shipping, release-qualified" (section 15).
- The adapter READMEs describe a 250 ms streaming verdict gate (for example `crates/protocol/chio-anthropic-tools-adapter/README.md:123`). No production code enforces it: only tests construct `VerdictBudgetExceeded` (`crates/protocol/chio-tool-call-fabric/src/error.rs:16`). Model identity in receipts defaults to `asserted` (**shipped**).
- Relevance: OpenShell 0.1.x removed its managed inference routes and the `inference.local` endpoint; a sandbox now calls each provider's native endpoint through an attached provider (VERIFIED, OpenShell `docs/upgrade/0-1-0.mdx:95`). OpenShell's MCP rules match method and tool name, and "Tool arguments are not matched" (VERIFIED, OpenShell `docs/how-it-works/policies/schema.mdx:347`). Chio's control point is the tool call and its arguments, not the model path (INFERRED).

## 8. Federation, passports, DIDs, identity federation

- `did:chio` is a self-certifying DID over an Ed25519 key, resolved locally (**shipped**; `spec/PROTOCOL.md:261-275`; `crates/trust/chio-did/`). It has no key rotation or update receipts (`docs/reference/DID_CHIO_METHOD.md:103-107`).
- `DidService::new` accepts any service type string and requires an https endpoint, but a deserialized `DidService` skips that check (**shipped**; `crates/trust/chio-did/src/lib.rs:190-219`).
- Enterprise identity federation for `chio mcp serve-http` verifies JWTs through OIDC discovery and JWKS, or introspects opaque tokens, and derives a canonical principal. It can also derive a stable Ed25519 subject key per principal from a seed under the label `chio.identity_federation.v1` (**shipped**, documented as an alpha; `docs/reference/IDENTITY_FEDERATION_GUIDE.md:1-5`; `crates/protocol/chio-mcp-remote/src/remote_mcp/session_core.rs:121`).
- When an issuer is configured, a JWT without `iss` is rejected (`crates/protocol/chio-mcp-remote/src/remote_mcp/oauth/bearer_auth.rs:398-405`). For opaque tokens admitted by introspection, a response without `iss` passes the issuer check, and the principal falls back to the configured issuer (**shipped**; `crates/protocol/chio-mcp-remote/src/remote_mcp/oauth/bearer_auth.rs:644-653`; `crates/protocol/chio-mcp-remote/src/remote_mcp/session_identity.rs:384-388`).
- A provider-admin registry covers OIDC JWKS, OAuth introspection, SCIM, and SAML records, and SCIM deprovisioning revokes tracked capabilities with a signed receipt (**shipped**). Okta, Auth0, and Azure AD are generic JWT provider profiles (`crates/protocol/chio-mcp-remote/src/remote_mcp/session_identity.rs:398-418`).
- In federated issuance, any `provider_record_id` activates the enterprise-provider lane, and one that does not resolve to a validated record returns 403 (**shipped**; `crates/platform/chio-control-plane/src/trust_control/passport_handlers.rs:1147-1151,1178-1188`). The SCIM lifecycle check applies only when a SCIM lifecycle file is configured (`crates/platform/chio-control-plane/src/trust_control/config_and_public.rs:1431-1436`).
- Agent passports (`chio.agent-passport.v1`) bundle independently signed reputation credentials with an operator-managed lifecycle (active, stale, superseded, revoked, not found), an OID4VCI issuance lane, and an OID4VP verifier bridge (**qualified**; QUALIFICATION.md:331-335,362,370-372).
- Treaties (`chio.federation.treaty-scope.v1`), ladder intersections that take the most restrictive mode, cross-boundary admission reports, bilateral DSSE, FROST signing, revocation gossip, and the iroh transport crate are **shipped** (`crates/trust/chio-federation/src/treaty.rs:9`; `crates/trust/chio-federation-transport-iroh/`; `docs/adr/ADR-0014-iroh-federation-transport.md`).
- Their evidence is crate and conformance tests (for example `crates/tooling/chio-conformance/tests/frost_quorum.rs`), plus path-filtered CI checks for treaties (`scripts/check-chio-treaty-bound-provenance.sh`). No qualification gate or addendum runs them, no evidence-matrix row names them, and no `CLAIM_REGISTRY.md` id covers them.
- SPIFFE appears only as a workload identity projected from runtime attestation, not as a federation peer or passport subject (**qualified** mapping, row 364).
- Vendor agent-identity products have no integration on main. AWS AgentCore Gateway appears only as an MCP consumer in one test (`integrations/mcp-adapter/tests/agentcore_gateway_consumer.rs`).
- Relevance: OpenShell's multi-player RFC "scopes multi-player to a single gateway" and calls multi-gateway federation "a separate concern" (VERIFIED, OpenShell `rfc/0011-multi-player-design/README.md:57-59`). Cross-organization admission is a Chio capability with no OpenShell counterpart (INFERRED), but its Chio lane is shipped, not qualified.

## 9. Observability, SIEM, OTel, compliance mappings

None of the observability crates or compliance mappings appears in `QUALIFICATION.md` or `CLAIM_REGISTRY.md`. They are shipped code outside the qualified boundary. The spec states that exporter, report, and OpenTelemetry projections are not authoritative unless they embed and verify the signed receipt (`spec/PROTOCOL.md:1194-1202`).

- `chio-siem` maps each receipt to an OCSF 1.3.0 event with `class_uid` 3002 (**shipped**; `crates/observability/chio-siem/src/ocsf.rs:46-49`). OCSF 1.3.0 defines class 3002 as Authentication, in the Identity & Access Management category (VERIFIED, [OCSF 1.3.0 schema, Authentication class, read 2026-09-29](https://schema.ocsf.io/1.3.0/classes/authentication)).
- The module calls the class "Authorization" and links `https://schema.ocsf.io/1.3.0/classes/authorization`, a page that returns HTTP 404 (`crates/observability/chio-siem/src/ocsf.rs:3-6,51-52`). OCSF 1.3.0 has no Authorization class; its session-authorization class is Authorize Session (3003) (VERIFIED, [OCSF 1.3.0 `events/iam/authorize_session.json`](https://github.com/ocsf/ocsf-schema/blob/v1.3.0/events/iam/authorize_session.json)).
- In the mapping, `metadata.uid` is the receipt id, `policy.uid` is the policy hash, guard evidence becomes enrichments, and the receipt JSON goes into `raw_data` (**shipped**). `raw_data` is plain `serde_json` output, not the canonical JSON the module comment describes (`crates/observability/chio-siem/src/ocsf.rs:27,189-191`).
- Before export, the SIEM path re-verifies each receipt's id, signature, parameter hash, and signer trust, and labels untrusted allows as unverified rather than as OCSF successes (**shipped**).
- Exporters for OCSF over HTTPS, CEF, Splunk HEC, Elasticsearch, Datadog, Sumo Logic, a generic webhook, and PagerDuty or OpsGenie alerting exist as library types (**shipped**). The only operator binary that wires any of them, `chio-wall siem-export`, registers only the webhook exporter and alerting; nothing wires the OCSF exporter (`crates/products/chio-wall/src/commands.rs:1195-1214`).
- Five exporters expose a public, non-test `new_plaintext_for_tests` constructor that skips the https check (for example `crates/observability/chio-siem/src/exporters/ocsf_exporter.rs:128`).
- Tool receipts carry no session id, and the OCSF mapping does not lift trace ids, request ids, or attribution out of `raw_data`. Session identity lives in child receipts, session anchors, and lineage statements, which the SIEM path does not export.
- `chio-otel-receipt-exporter` is a receiver: it accepts OTLP spans with W3C ids and a `chio.verdict` attribute and signs each into a detect-only observation receipt (**shipped**). The kernel's locked span shape has 12 attributes, and `chio.verdict` is not among them (**shipped**; `crates/kernel/chio-kernel/src/otel.rs:66-79`).
- The audit-log export schema `chio.audit-log.export.v1` defines a record with OCSF and CEF blocks and an optional Splunk block (**design doc**; `spec/audit-log/export-schema.v1.json`). Nothing in the tree emits conforming records. Its CI lint checks only the schema's shape and a CEF golden file (`.github/workflows/audit-log-schema-lint.yml:32-57`). The schema pins the same `class_uid` 3002 under the name "Authorization" (`spec/audit-log/export-schema.v1.json:87-92`).
- Six compliance mappings cover NIST AI RMF, ISO 42001, EU AI Act Article 19, OWASP LLM Top 10, PCI DSS v4, and Colorado SB 24-205 (**design doc**, self-described pre-release profile). They mark isolation, segmentation, and supply-chain integrity as deployer responsibility. The PCI DSS v4 mapping, for example, puts Requirement 1 out of scope (`docs/compliance/pci-dss-v4.md:46,97`; `docs/compliance/owasp-llm-top-10.md:75`).
- Relevance: OpenShell's audit trail is OCSF 1.8.0 across nine event classes: network, HTTP, and SSH activity, process activity, detection finding, application lifecycle, device config state change, API activity, and base event (VERIFIED, OpenShell `crates/openshell-ocsf/src/lib.rs:25` and `crates/openshell-ocsf/src/events/mod.rs:35-54`). Its OCSF crate contains no signing code (VERIFIED).
- Chio's mapping targets OCSF 1.3.0 Authentication (3002), a version and class OpenShell does not emit, and no shared correlation key exists at the pinned commits (INFERRED).

## 10. Deployment shapes and harness integrations

### Binaries and releases

- Chio ships as one binary, `chio` (crate `chio-cli`) (**shipped**). These public GitHub releases exist:
  - [`v0.1.0` on backbay-labs/chio, 2026-09-09](https://github.com/backbay-labs/chio/releases/tag/v0.1.0), with binaries for five targets.
  - [`v0.1.0` on bb-connor/arc, 2026-04-22](https://github.com/bb-connor/arc/releases/tag/v0.1.0), with binaries for five targets and a Homebrew formula, `chio.rb`.
  - [Agentic OS application runtime preview, 2026-09-10](https://github.com/backbay-labs/chio/releases/tag/agentic-os-2026-09-10-9ffca8d6), a prerelease on backbay-labs/chio.
  - [Chio enterprise evidence verifier c5a9a75e1, 2026-07-26](https://github.com/bb-connor/arc/releases/tag/security-evidence-verifier-c5a9a75e1), a prerelease on bb-connor/arc with one Linux x86_64 binary.
- `docs/install/README.md:3-5` says Chio is not yet published to a package registry, GitHub Release asset set, Homebrew formula, or container registry. The releases above contradict the release-asset and Homebrew parts (section 15).

### Shapes

| Shape | Surface | Status | Where keys and receipts live | Main limit |
| --- | --- | --- | --- | --- |
| Stdio MCP wrapper inside the workload | `chio mcp serve` | qualified | Inside the workload | A client can talk to the upstream server directly (`docs/guides/MIGRATING-FROM-MCP.md:186-188`) |
| Hosted MCP edge outside the workload | `chio mcp serve-http` | qualified | Outside | Covers MCP traffic only; bypass prevention needs network policy |
| HTTP sidecar or reverse proxy | `chio api protect`, `chio start` | shipped | Beside the workload | Forwards the caller's `authorization` header; `chio start` refuses to run without `--receipt-store` or `--allow-ephemeral-receipts` (`crates/products/chio-cli/src/cli/runtime.rs:250-262`) |
| Kubernetes admission | `sdks/k8s/webhooks` | shipped | Trusted issuer keys in `CHIO_WEBHOOK_TRUSTED_KERNEL_KEYS`; no receipts | See below |
| Cloud reference manifests | `deploy/` (Cloud Run, ECS, Azure Container Apps), Lambda extension | shipped | Per-instance SQLite or in-memory | Reference infrastructure, "not deploy-ready" (`deploy/README.md:23`) |
| Embedded core | `chio-kernel-core` via C ABI, wasm, UniFFI | qualified | Caller-supplied | Capability checks only; qualified through the portable-kernel lanes (QUALIFICATION.md:191-197) |

- The Kubernetes validating webhook verifies Ed25519 capability tokens on pod annotations (**shipped**). It fails closed when either `CHIO_WEBHOOK_TRUSTED_KERNEL_KEYS` or `CHIO_WEBHOOK_REQUIRED_SCOPES` is empty (`sdks/k8s/webhooks/config.go:14-24`).
- The webhook serves plain HTTP with a warning when TLS files are not set (`sdks/k8s/webhooks/server.go:200`). It never reads `delegation_chain` (`sdks/k8s/webhooks/capability.go:25`), and its mutating webhook emits no patch (`sdks/k8s/webhooks/server.go:142-153`). No Deployment or Service manifest exists for the service both webhook configurations name, and the ChioPolicy CRD has no consumer. `README.md:591` labels Kubernetes support "Shipping".
- The Kubernetes Job controller's Go step receipt has no `payload` field, which the Rust sidecar requires (**shipped**; `sdks/k8s/controller/internal/chio/types.go:220-235`; `crates/products/chio-api-protect/src/proxy/sidecar.rs:210-216`). The sidecar therefore rejects any Job receipt that has steps.
- The embedded core (`chio-kernel-core`, `no_std` plus `alloc`) builds for wasm, Workers, and mobile, and a C ABI exists (**qualified**, portable-kernel lanes; `crates/kernel/chio-kernel-core/README.md:1-15`; `crates/sdk/chio-cpp-kernel-ffi`). The embedded path checks capabilities only: no guards, revocation lookup, DPoP replay store, durable budgets, approvals, or receipt persistence.

### Key custody and placement

- Every product-path signer holds its Ed25519 seed in process memory. The C ABI, UniFFI, and wasm adapters take the raw seed on each call (**shipped**).
- Remote signing backends exist for an HTTP signer and Vault Transit (**shipped**; `crates/trust/chio-signing-remote/src/lib.rs:102,263`). They sign any non-empty message up to 1 MiB with no policy check, and only the hosted cognition-market profile wires them. No HSM, KMS, TPM, or PKCS#11 backend exists.
- `chio-tee` is a shadow-runner capture sidecar, not a TEE component. Its Enforce mode takes the verdict from the kernel's own receipt and does not re-evaluate (**shipped**; `crates/trust/chio-tee/src/runner.rs:337-342`). Its module comment describes TEE-side replay (section 15).
- `chio-custody-hw` verifies WebAuthn passkey assertions, mints five-minute `PasskeyCapability` envelopes, and ships App Attest and Play Integrity verifiers (**shipped**; `crates/trust/chio-custody-hw/src/capability.rs:100`). The mobile kernel exposes the device-attestation verifiers through its FFI entry points (`crates/kernel/chio-kernel-mobile/src/lib.rs:27-30,76-79`).
- The kernel's `PasskeyCapabilityVerifier` is **test-only**: its only caller is `crates/kernel/chio-kernel/tests/passkey_capability_dispatch.rs` (`crates/kernel/chio-kernel/src/custody.rs:83`). Device attestation is not bound into capability issuance.

### Harness integrations

- Claude Code registers a wrapped MCP server in one line: `claude mcp add fs -- chio --receipt-db ./chio.db mcp serve --preset code-agent ...` (`README.md:256-270`). The command runs the **qualified** stdio MCP surface. `chio mcp wrap --emit-config` emits config for Cursor, Claude Desktop, Continue, and Zed (**shipped**; `crates/products/chio-cli/src/cli/mcp/ide.rs:14-22`).
- Hermes has two paths (`docs/integrations/HERMES.md:1-11`). Path A adds `chio mcp serve --preset code-agent` as an MCP server in the Hermes config. Path B is the in-repo `chio-hermes` plugin: 12 `chio_*` tools, a `pre_tool_call` policy hook, and per-session JSONL receipts, calling a local sidecar at `CHIO_SIDECAR_URL` (**shipped**; `sdks/python/chio-hermes/src/chio_hermes/hooks.py:46`).
- The plugin README says that with chio releases before 0.2 the sidecar calls report `chio_sidecar_unreachable` and only client-side guards apply (`sdks/python/chio-hermes/README.md:105-117`). Its PyPI status differs between two documents (section 15).
- A LangChain adapter also lives in tree (`sdks/python/chio-langchain`) (**shipped**). Plugins for Claude Code, Cursor, Codex, OpenCode, and OpenClaw live in separate backbay-labs repositories (`README.md:608-621`). Nothing in this repository tests them.
- The six-host program on PR #1156 (Claude Code, Codex, Cursor, Hermes, Pi, OpenClaw) records "zero of six integrations accepted" (**unmerged**; `docs/integrations/acceptance/20260909/PROGRAM.md:3` on that branch). Its supported work is remote read, write, edit, and list through a kernel-owned filesystem. Shell, network, delegation, and background routes stay disabled or confined (`docs/integrations/acceptance/20260909/PROGRAM.md:47-49`).
- On PR #1156, the Hermes README calls the `pre_tool_call` plugin "a diagnostic compatibility surface" and adds `chio-hermes-restricted` (**unmerged**; `sdks/python/chio-hermes/README.md:61-74` on that branch). A parent launcher owns the gateway and model relay, Hermes receives temporary loopback tokens, and a macOS Seatbelt profile confines the agent.
- The protected launchers for the other hosts live in the external plugin repositories. The program record also covers OpenClaw Docker images and a Docker watchdog for OpenClaw (`docs/integrations/acceptance/20260909/PROGRAM.md:451,488` on PR #1156). The owner requirement lets required isolation "live in an existing host sandbox or resource boundary", provided its enforcement is tested (`docs/strategy/chio-direction/19-priority-agent-integrations.md:90-91` on that branch).
- Relevance: OpenShell's overview names Claude Code, OpenCode, Codex, and GitHub Copilot CLI as coding agents it can run "with constrained file and network access" (VERIFIED, OpenShell `docs/about/overview.mdx:53`). No Chio document or test runs any Chio surface inside OpenShell.

## 11. Economy

- Tool grants carry per-call and total monetary caps in integer minor units with an ISO 4217 currency (**shipped**; `crates/core/chio-core-types/src/capability/scope.rs:80-118`). Delegation can only lower them in the same currency (**qualified** as part of P1, attenuation step `ReduceTotalCost`; `crates/core/chio-core-types/src/capability/attenuation.rs:172`). Monetary attenuation evidence is differential-test only; the Lean model covers invocation budgets (section 2).
- Every cost-bearing call opens a budget hold at the worst-case per-call cap, keyed to the presented capability, and reconciles to the cost the tool server reports. The kernel bounds realized cost but does not measure it (**shipped**; `crates/kernel/chio-kernel/src/kernel/validation.rs:2116-2187`). Hold expiry is a SQLite reaper that books the worst case. No expire request exists, and the declared `Expired` disposition is never produced.
- Budget stores report only two guarantee levels, `single_node_atomic` and `advisory_posthoc`; `HaLinearizable` and `PartitionEscrowed` are declared but never returned (**shipped**; `crates/kernel/chio-kernel/src/budget_store/model.rs:387-392,421-424`). Sibling budget shares live in an in-memory registry, and no code debits an ancestor capability's monetary counter. The bounded release excludes "distributed-linearizable budget truth" (QUALIFICATION.md:81).
- Receipts carry `financial` and `budget_authority` blocks (hold id, guarantee level, exposure, realized spend, settlement status) (**shipped**). The authoritative-spend check binds the execution nonce to capability id, tool server, tool name, parameter hash, and reserved hold, but not to the request id that the spec requires (`crates/core/chio-core-types/src/receipt/authoritative_spend.rs:156,284`; `spec/PROTOCOL.md:1047-1054`).
- `chio-metering` has one outside consumer, which imports only `CostDimension` (**shipped**; `crates/guards/chio-data-guards/src/warehouse_cost_guard.rs:55`). The `chio.cost-metadata.v1` block it describes is never emitted.
- The x402 adapter is a prepaid HTTP bridge. A response without `settled` counts as settled, and capture, release, and refund are local bookkeeping (**shipped**; `crates/kernel/chio-kernel/src/payment.rs:333-352,512-513`). No code handles HTTP 402 challenges or payment headers. The CLI default payment adapter moves no funds.
- `chio-settle` rails (EVM, Solana, CCIP, EIP-3009 digest preparation, Circle policy evaluation, ERC-4337 compatibility records) are rehearsal evidence; mainnet custody waits on external assurance (**qualified** as rehearsal evidence only; QUALIFICATION.md:219-223).
- The cognition market's single-operator SQLite profile is the qualified boundary (**qualified**; `docs/market/README.md:10-12`). The hosted PostgreSQL profile is qualified at code level only: its qualification record sets `codeQualified` to true and `productionReady` to false (`.github/workflows/cognition-market-hosted.yml:175-179`). Cross-organization escrow is designed but unbuilt (**design doc**; `docs/market/README.md:85-89`). The comptroller market position is an explicit non-claim (QUALIFICATION.md:83).
- Relevance: ODIS lists an "Economic Layer" as future work: "Identity-bound metering, billing propagation, and financial transaction authorization for agent-mediated commerce" (PROPOSED, [`RFCs/ODIS.md:1156`](https://github.com/cosai-oasis/ws4-odis/blob/148dc4187139a41325e3c6d6e7533d956bd33144/RFCs/ODIS.md?plain=1#L1156)).
- SAW describes "cost telemetry and budget controls", with a per-workspace meter that feeds centralized FinOps integration with budget gates (PROPOSED, [SAW, Deployment tiers, last updated 2026-06-28](https://docs.nvidia.com/enterprise-reference-architectures/secure-agent-workspace-reference-design/latest/deployment-tiers.html)). The SAW delegation record's field list names no budget or spend dimension (VERIFIED, SAW page cited in section 2).
- Monetary attenuation along a delegation chain is the dimension NVIDIA's artifacts do not carry (INFERRED). Inference spend flows through OpenShell's egress to provider endpoints, outside any Chio hold (INFERRED).

## 12. Formal verification, containment, and the papers on out-of-band observation

### Proof estate

- `formal/proof-manifest.toml` (boundary `implementation_linked_protocol_core`) binds ten properties, P1 to P10, to Lean 4, Aeneas, Creusot, Kani, TLA+ with Apalache, and differential tests (`formal/proof-manifest.toml:158-171`). Each is approved only "with scope" as a bounded proof over a model; only P4 includes a bounded Rust refinement, for the inclusion-proof walk up to eight leaves (**qualified** wording; CLAIM_REGISTRY.md:70-79).
- The manifest excludes "subprocess effects, and tool-server behavior after the verified decision core allows a call" (`formal/proof-manifest.toml:221`). Every property concerns authority semantics; none concerns isolation.
- `capability_monotonicity` and the `delegation_step_*` facts appear in the P1 and P5 `property_matrix` entries and in `formal/theorem-inventory.json`, so they are release evidence (**qualified**; `formal/proof-manifest.toml:161,165`).
- `delegate_no_widen` and `revocation_is_cut` are root-imported (`formal/lean4/Chio/Chio.lean:32`; `formal/lean4/Chio/Chio/Capability/Delegation.lean:200,230`). They are absent from `formal/theorem-inventory.json` and from every `property_matrix` entry, so they are not release evidence under `formal/proof-manifest.toml:238`.
- All 15 lane gates in `releases.toml`, including the Lean, Kani, and Apalache lanes, have posture `advisory`, so none of them blocks release. The theorem inventory lists 165 theorems; `docs/formal/CURRENT_STATE.md:80` says 149 (section 15).
- Downgraded or disallowed wording includes "Chio is a formally verified protocol" without assumption and implementation-linkage text (downgraded), "Lean 4 verified" without boundary text, and any P2, P3, or P4 "end to end" claim (CLAIM_REGISTRY.md:90-96).
- `chio policy analyze --against` is "executable static analysis, not a formal verification claim" (`docs/reference/POLICY_ANALYSIS.md:94-95`).

### Containment

- `ChioKernel::emergency_stop` denies every call routed through that kernel and signs a deny receipt for each (**shipped**; `crates/kernel/chio-kernel/src/kernel/construction.rs:1570`). The stop is an in-memory flag behind a static `X-Admin-Token` header (`crates/platform/chio-http-core/src/routes.rs:93`). It is not persisted across restart, has no scope or TTL, and signs no record of engage or resume.
- `admit_governed_active_response` admits a response plan over five closed effects (`ThrottleSession`, `RestrictEgress`, `SuspendSession`, `SuspendCapabilitySet`, `FreezeIssuance`) bound to an operator capability and an m-of-n approval set (**test-only**; `crates/kernel/chio-kernel/src/governed_active_response.rs:110,222`; `crates/core/chio-core-types/src/capability/governance.rs:759-765`). Only unit tests call it, and no executor exists on main. Its wire schema and its Rust constant disagree on the plan schema name (section 15).
- The executor, containment overlays, correlator, and active-response authority exist only on PR #1160, where the rollout contract calls the boundary "dark and component-scoped" (**unmerged**; `docs/security/active-defense-rollout.md:5` on PR #1160).
- The security design admits automatic responses only from "configured internal detector keys or verified Chio receipts"; unsigned and external events stay advisory (**design doc**; `docs/superpowers/specs/2026-07-09-security-folder-design.md:52`). A signal from Sentry would therefore stay advisory unless an operator pins its key (INFERRED).

### Papers

Six paper directories are tracked, each with a README. `docs/papers/evidence-crosses/` and `docs/papers/review-2026-09/` are not tracked on main. All paper Lean is paper-local and is not release evidence (`formal/proof-manifest.toml:238`).

| Paper | What it contributes | Status |
| --- | --- | --- |
| Sensor-grounded admission | Receipts conditioned on a signed attestation of sensor state: a closed eight-kind `ProviderKind` enum, installed, active, healthy, and degraded flags, drop and miss counters. The attestation is signed with the receipt key, and an "out-of-band sensor-coverage auditor" is named but left unspecified (`docs/papers/sensor-grounded-admission/sections/03-substrate.tex:53`; `docs/papers/sensor-grounded-admission/sections/10-conclusion.tex:8`; `docs/papers/sensor-grounded-admission/lean/SensorGroundedAdmission.lean:63-72`). | design doc |
| Reversible action | Typed containment: reversible actions auto-revert at a TTL, and destructive actions (terminate, network isolate, grant revoke) need a bilateral cosignature. The headline TTL theorem is `sorry` in a planning file (`docs/papers/reversible-action/theorems.lean:4,210-220`). | design doc |
| Delegated emergency authority | Emergency action as a bounded executive act: a tuple of action, TTL, rollback witness, and quorum predicate (`docs/papers/delegated-emergency-authority/sections/04-grammar.tex:33-35`). | design doc |
| Agentic tool safety | Lists four boundaries where its guarantee does not hold, including bypassed dispatch (`docs/papers/agentic-tool-safety/sections/06-threat-model.tex:25`). | design doc |
| Bilateral receipt admission | The bilateral DSSE construction from section 3. Its Lean accept-set model is listed in the proof manifest (`formal/proof-manifest.toml:50`). | design doc |
| Programmable sovereignty | Its claim ledger lists five items as not established, including "Two configured keys do not prove two independent organizations" and "The buyer package does not prove remote process integrity or legal effect" (`docs/papers/programmable-sovereignty/CLAIM_LEDGER.md:34-41`). | design doc |

Relevance: Sentry could fill the sensor paper's unspecified auditor role for sensor coverage (INFERRED). A Sentry record of a call with no Chio receipt would be a related bypass signal, if Sentry records are signed. NVIDIA describes Sentry as using DOCA to "provide attested telemetry" (PROPOSED, [NVIDIA newsroom, 2026-09-28](https://nvidianews.nvidia.com/news/open-agent-safety-platform)); whether its records are signed is not documented. Chio's own kill switch has no TTL and would not satisfy its papers' definition of a bounded executive act (INFERRED).

## 13. Policy engine, guards, approvals, negotiation

- Chio's policy language is a dialect of HushSpec that accepts only `hushspec: 0.1.0` (**shipped**; `crates/guards/chio-policy/src/version.rs:3-5`). It has 14 rule blocks, from `forbidden_paths` and `egress` to `velocity` and `human_in_loop`, plus extensions for posture, origins, detection, reputation, and runtime assurance (`crates/guards/chio-policy/src/models/rules.rs:39-65`). Every struct rejects unknown fields, and invalid policies fail at load.
- HushSpec compiles to a native Rust guard pipeline plus a default capability scope (**shipped**). The compiled tool guard matches tool names exactly (`crates/guards/chio-guards/src/mcp_tool.rs:123,129`). The compiler never reads the egress block's `default` field (`crates/guards/chio-policy/src/compiler/rules.rs:93-104`). No Rego, OPA, or Cedar code exists in `crates/` or `sdks/`.
- HushSpec is published separately as an Apache-2.0 specification, and its versioning policy declares version 1.0.0 stable, dated 2026-09-15 (VERIFIED, HushSpec `LICENSE` and `spec/versioning.md:4-6`). Release v1.0.0 was published on 2026-09-23 (VERIFIED, [HushSpec v1.0.0 release, 2026-09-23](https://github.com/backbay-labs/hush/releases/tag/v1.0.0)).
- The HushSpec 1.0 rule-block registry is closed, lists 12 blocks, and has no `velocity` or `human_in_loop` block (VERIFIED, HushSpec `spec/registries/rule-blocks.yaml:6-14,17-64`). Chio's dialect adds those blocks plus reputation and runtime-assurance fields, so Chio is not a conforming HushSpec 1.0 engine (INFERRED).
- `chio policy analyze` finds shadowed, unreachable, contradictory, and overlapping rules. With `--against` it returns `refines`, `does_not_refine` with a confirmed widening witness, or `inconclusive` (**qualified** as POLICY-ANALYZE; CLAIM_REGISTRY.md:80; `crates/guards/chio-policy/src/analyze/mod.rs:743`). Witnesses are confirmed against the reference evaluator, not against the compiled guards the kernel runs.
- Conditional rule activation is reachable only through `chio_policy::evaluate_with_context`, which has no non-test caller (**test-only**; `crates/guards/chio-policy/src/evaluate/engine.rs:57`).
- Guards implement a synchronous trait and the pipeline fails closed. A generic guard that returns `PendingApproval` is denied, because approvals run through separate approval machinery (**shipped**; `crates/kernel/chio-kernel/src/kernel/dispatch.rs:409-419`).
- Guards are fixed when the kernel is constructed; there is no hot reload of policy (**shipped**; `crates/kernel/chio-kernel/src/kernel/construction.rs:1922`).
- External HTTP guards deny on error and reject private-network, CGNAT, and link-local endpoints (**shipped**; `crates/guards/chio-external-guards/src/external/endpoint_security.rs:124`). A co-located OpenShell gateway or Sentry endpoint would need localhost access or a new validator (INFERRED).
- WASM guards run in Wasmtime with no network imports and are signed and distributed over OCI with Sigstore (**shipped**). The CLI uses the crate to build, sign, publish, and verify guards (`crates/products/chio-cli/src/guard/`), but no kernel or serve path loads them. Nothing outside the crate uses its hot-reload machinery (**shipped**, no production caller; `crates/guards/chio-wasm-guards/`).
- Capability negotiation in the spec is a feature bitset intersected between federation peers, not agent-facing negotiation of authority (**shipped**; `crates/core/chio-core-types/src/capability/features.rs:72-93`). An agent can narrow its own authority by delegation. Wider authority requires new issuance, which can deny or clamp by reputation and runtime-assurance tier.
- There is no policy-advisor workflow in which an agent proposes a narrower policy for human review.
- Relevance: OpenShell evaluates policy with the regorus Rego interpreter (OpenShell `crates/openshell-supervisor-network/Cargo.toml:39`) and checks proposals with a Z3-based prover (OpenShell `crates/openshell-prover/Cargo.toml:14-15`) (VERIFIED). Its advisor handles network access only and by default waits for human review (VERIFIED, OpenShell `docs/how-it-works/policies/advisor.mdx:13-14,22-25`; details in [01-nvidia-stack.md](01-nvidia-stack.md)). HushSpec and OpenShell policy overlap only on host egress allowlists and MCP tool allow and deny lists (INFERRED).

## 14. Positioning and claim boundary

### Current category language

| Text | Where it lives |
| --- | --- |
| "Chio: a Rust kernel for agentic operating systems. Signed tokens in, signed receipts out." | Hero image alt text, `README.md:4`; `docs/assets/hero.svg`, `docs/assets/hero-mobile.svg` |
| "The kernel your agents answer to." | `README.md:16` (HTML only, in no SVG) |
| "A signed receipt for every call · Authority that can only narrow · Agents that pay each other" | Subhead alt text, `README.md:22`; `docs/assets/subhead.svg`, `docs/assets/subhead-mobile.svg` |
| "PROOF-CARRYING AUTONOMY" | `docs/assets/pillars.svg`, `docs/assets/pillars-mobile.svg` |
| "Chio proves what an agent was allowed to do, what it cost, and what happened." | `README.md:49-51`; a variant at `docs/start-here/VISION.md:45` |
| "Chio occupies the authorization and attestation layer." | `docs/start-here/VISION.md:68` |
| "a protocol for secure, attested tool access in AI agent systems" | `AGENTS.md:5` |
| "Trusted enforcement layer that validates capabilities, runs guards, dispatches calls, and signs receipts" | `spec/PROTOCOL.md:174` (the kernel row) |
| "a cryptographically signed, fail-closed governance and evidence control plane ..." | QUALIFICATION.md:69-74, the only ship-facing claim |

The phrase "authority kernel" is not used as category language anywhere in the repository.

### Boundary

- The bounded gate `cargo xtask qualify bounded-chio` (QUALIFICATION.md:52-54) backs the only ship-facing claim (QUALIFICATION.md:67-74). "Universal control plane" and "comptroller-capable" are optional repo-local addenda (QUALIFICATION.md:89-116).
- The non-claims are explicit: verifier-backed runtime assurance as the sole admission boundary, consensus-grade HA or distributed-linearizable budget truth, public transparency-log or strong non-repudiation semantics, and a proved comptroller market position (QUALIFICATION.md:76-83).
- The machine-readable matrix summary is weaker than the document's sentence. It says "bounded delegated-authority semantics" and lists "authenticated recursive delegation ancestry beyond the preserved presented chain" as a non-claim (`docs/standards/CHIO_BOUNDED_QUALIFICATION_MATRIX.json:7,16`). The gate checks the matrix's structure and that witness files exist; it never reads `qualifiedClaim` or `nonQualifiedClaims` (`xtask/src/qualify.rs:99-120,137`).
- ADR-0011 defines boundary classes. Its `cannot_see` class covers activity that "is below or outside Chio's mediation layer", with the allowed wording "out of layer, not covered, external to Chio" (`docs/adr/ADR-0011-boundary-taxonomy-product-wording.md:27,43`). Host-level enforcement such as OpenShell sandboxing, and hardware enforcement such as Sentry, would fall in `cannot_see` (INFERRED; the ADR names neither).
- The Agent Web taxonomy allows "verified by Chio" only where a Chio verifier recomputes digests and verifies signatures against pinned keys. It states that SPIFFE "does not delegate agent authority" and that OAuth tokens "are not Chio capabilities" (`docs/standards/CHIO_AGENT_WEB_PROTOCOL_TAXONOMY.md:13-18,37-42`).
- `docs/reference/COMPETITIVE_LANDSCAPE.md` was last updated 2026-03-21 (line 5). It has no runtime, sandbox, or hardware category. Its agent-identity section (line 265) covers IETF AIMS, UCAN, and SPIFFE/SPIRE and mentions neither ODIS nor SAW.
- `docs/start-here/VISION.md:93-95` describes seven shipped guards (section 15). At `f5566d9a76` no document mentions NVIDIA's agent stack.

## 15. Documentation that disagrees with the code or its sources

Each row gives the document and line, what it says, and what the code or an upstream source shows.

| Document | What it says | What the code or source shows |
| --- | --- | --- |
| `docs/reference/WORKLOAD_IDENTITY_RUNBOOK.md:85` | Chio ships three verifier families | Four: `AzureMaa`, `AwsNitro`, `GoogleAttestation`, `EnterpriseVerifier` (`crates/core/chio-core-types/src/runtime_attestation.rs:12-30`) |
| `spec/PROTOCOL.md:2988-2990` | The appraisal-result boundary is locally qualified across the Azure, Nitro, Google, and `enterprise_verifier` bridges | QUALIFICATION.md:365-368 name only Azure, Nitro, and Google |
| `spec/PROTOCOL.md:476-483` | Lists typed caveats as part of the attenuation model | Any token that carries a caveat is rejected at signing and validation (`crates/core/chio-core-types/src/capability/token.rs:327-333,570-576`) |
| `docs/reference/DPOP_INTEGRATION_GUIDE.md:76` | Nonce store default capacity is 8192 | `DEFAULT_DPOP_NONCE_STORE_CAPACITY` is 65,536 (`crates/kernel/chio-kernel/src/dpop.rs:56`) |
| `spec/PROTOCOL.md:999-1010` | Receipts carry `parentSetHash`, `dagOrdinal`, and an HLC triple for multi-parent lineage | `ChioReceipt` has no DAG fields; only swarm join receipts carry `parent_set_hash` and `dag_ordinal` (`crates/kernel/chio-swarm-authority/src/types.rs:184-200`) |
| `spec/PROTOCOL.md:1047-1054` | The execution-nonce binding must include `request_id` | The authoritative-spend check does not bind `request_id` (`crates/core/chio-core-types/src/receipt/authoritative_spend.rs:156,284`) |
| `spec/PROTOCOL.md:2233-2241` | The Rekor client does not verify the inclusion path to a checkpoint (accurate) | The text omits that the client checks a returned proof against the response's `rootHash` (`crates/economy/chio-anchor/src/witness/rekor.rs:19-27,537-553`) |
| `spec/CHIO_BILATERAL_COSIGN_INVOCATION.md:591-593` (audience at line 5) | CoSAI Workstream 4 is "the Secure AI Software Supply Chain workstream" | Workstream 4 is Secure Design Patterns for Agentic Systems, and ODIS is developed in its repository (section 3). The outreach step should use that name and address ODIS. |
| `README.md:135`, `README.md:661`, `AGENTS.md:11` | Tool servers run as "sandboxed processes" | Tool servers are plain child processes with no confinement (`crates/protocol/chio-mcp-adapter/src/transport/stdio.rs:57`); `spec/SECURITY.md:156-164` says mediation cannot sandbox tool-server code |
| `crates/observability/chio-siem/src/ocsf.rs:3-6,51-52`; `spec/audit-log/export-schema.v1.json:87-92` | OCSF class 3002 is "Authorization", with a link to `schema.ocsf.io/1.3.0/classes/authorization` | OCSF 1.3.0 defines 3002 as Authentication and has no Authorization class; the linked page returns HTTP 404 (section 9) |
| `crates/observability/chio-siem/src/ocsf.rs:27` | `raw_data` holds full canonical JSON | `raw_data` is `serde_json::to_string` output (`crates/observability/chio-siem/src/ocsf.rs:189-191`) |
| `docs/integrations/otel.md:33-37` | Required span attributes include `chio.tenant.id`, `chio.policy.ref`, `chio.verdict`, and `chio.tee.mode` | The kernel's locked span shape has 12 attributes and none of those four (`crates/kernel/chio-kernel/src/otel.rs:66-79`) |
| `README.md:525-526` | The Anthropic and Bedrock adapters are "Shipping, release-qualified" | `docs/release/QUALIFICATION.md` has no provider-adapter row |
| `docs/integrations/providers.md:14` | The OpenAI adapter crate is "Deferred, crate name TBD" | `crates/protocol/chio-openai-adapter` exists and its transport makes upstream calls (`crates/protocol/chio-openai-adapter/src/transport.rs:82-122`) |
| `crates/products/chio-api-protect/README.md:88`; `docs/guides/MIGRATING-FROM-MCP.md:122-123`; `docs/sdk/PYTHON.md:113`; `docs/sdk/TYPESCRIPT.md:54` | `POST /v1/evaluate` is retired with 410, or is a deprecated advisory alias | The router sends `/v1/evaluate` to the kernel-mediated handler (`crates/products/chio-api-protect/src/proxy/router.rs:91-94`) |
| `docs/reference/AGENT_PASSPORT_GUIDE.md:735` | `did:chio` issuance and resolution are not shipped | `crates/trust/chio-did/` resolves `did:chio` locally; `docs/reference/DID_CHIO_METHOD.md:103-107` lists only update and rotation work as unshipped |
| `docs/install/README.md:3-5` | Chio is not published to a GitHub Release asset set or a Homebrew formula | Releases with binaries exist on both repositories, and the bb-connor/arc `v0.1.0` release includes `chio.rb` (section 10) |
| `README.md:310-311` | The Hermes plugin is not yet on PyPI | `docs/integrations/HERMES.md:70` gives `pip install chio-hermes` |
| `crates/trust/chio-tee/src/mode.rs:6-9` | Shadow and Enforce modes replay decisions in a TEE | Enforce takes the verdict from the kernel's own receipt and does not re-evaluate (`crates/trust/chio-tee/src/runner.rs:337-342`) |
| `docs/formal/CURRENT_STATE.md:80` | 149 catalogued theorems | `formal/theorem-inventory.json` lists 165 |
| `spec/schemas/chio-wire/v1/agent/active-response-governed-intent.schema.json:22` | `plan_schema` is `chio.governed-response-plan.v1` | The Rust constant is `chio.response-plan.v1` (`crates/core/chio-core-types/src/capability/governance.rs:29`) |
| `docs/start-here/VISION.md:93-95` | Seven shipped guards | `README.md:674` describes a pipeline of 26 named guards |
