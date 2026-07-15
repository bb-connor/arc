# Chio Policy Expansion: Spec Re-Convergence, Integrity, Consolidation, Expressiveness

- Status: Draft for review (2026-07-15)
- Scope: two repositories - `arc` (Chio engine, `crates/guards/chio-policy` and its consumers) and `hush` (the open HushSpec specification at `standalone/hush`, published as `hushspec` on crates.io, `@hushspec/core` on npm, `hushspec` on PyPI)
- Related: `docs/superpowers/specs/2026-07-09-protocol-primitives-design.md`, `docs/superpowers/specs/2026-07-09-security-folder-design.md`, `docs/formal/plan/FV-C4-policy-smt-analyzer.md`, `docs/architecture/reliability/RFC-0013-money-path-durability.md`, `docs/release/RISK_REGISTER.md`

## 1. Problem statement

A July 2026 research sweep (four-agent: crate internals, enforcement surfaces, docs/roadmap, external landscape) assessed whether Chio policies cover the full use-case scope. Findings, condensed:

**Coverage inside the lane is strong.** HushSpec-driven enforcement covers tool access, egress with SSRF companions, filesystem, shell, computer-use, secrets, patch integrity, velocity, single-gate human-in-loop, prompt-injection/jailbreak detection, posture state machines, origin profiles, reputation-gated issuance, and runtime-assurance gating. Against the strongest external anchor (the seven governance properties agent protocols cannot express, per the 2026 protocol-governance-gaps analysis, arXiv 2606.31498), Chio has audit fully covered and temporal, spend, revocation, and delegation partially covered. Obligations and provenance are missing. Cedar, the rigor benchmark, deliberately covers none of obligations, velocity, sessions, or HITL: that is the whitespace this program targets.

**Three gap clusters block expansion from being honest:**

1. **Wired-vs-staged holes inside existing features.** The `ChioApproverSet {n, of}` multi-party approval shape parses but is an inert passthrough. `Warn` decisions exist in the reference evaluator but do not survive compilation; `jailbreak.warn_threshold` is parsed then dropped (`crates/guards/chio-policy/src/compiler/detection.rs`). Governance metadata (`expiry_date`, `lifecycle_state`) is descriptive only. `CryptoFloor` is mirrored at the kernel boundary by hand instead of wired from the policy loader. `merge` is not deny-absorptive, so a child policy can silently relax a parent.
2. **Fragmentation across roughly six policy planes.** The control-plane loader forks between HushSpec and a legacy Chio-YAML format that reaches guard knobs HushSpec cannot (`chio-control-plane/src/policy/loader.rs`). Kernel budget and monetary caps ride capability-token fields. Federation admission uses separate signed policy records. The Claude Code host path is gated by a Python `CodeAgentPolicy` with hardcoded constants while the kernel tool-call route is advisory-only. Many guard defaults are hardcoded or Chio-YAML-only.
3. **Spec schism between arc and hush.** The open HushSpec repo is the normative home (spec prose, JSON Schemas, conformance levels L0-L3, testkit, four SDKs, Ed25519 policy signing, a receipt schema with an `enforcement` disposition). But the two implementations have diverged three ways at the same version number `0.1.0`:
   - hush spec prose defines 10 rule blocks; hush schema and SDKs implement 12 (`browser_automation`, `code_execution` are undocumented in prose).
   - arc implements 14 (`velocity`, `human_in_loop` exist nowhere in hush).
   - arc adds three extension keys (`reputation`, `runtime_assurance`, `chio`) that hush section 9.5 requires conformant parsers to reject, and arc's builtin-extends prefixes (`chio:`, `hushspec:`) differ from hush's (`builtin:`). arc does not depend on the `hushspec` crate; there is no conformance coupling in either direction. A policy written for one engine is not portable to the other, which defeats the format's stated thesis.

## 2. Goals

- One normative spec, one conformance story: hush is the standard; arc is the flagship Level 3 engine with a published profile of its extensions.
- Every schema field that parses either enforces or is rejected. No inert shapes.
- HushSpec becomes the single authoring plane for guard config, issuance ceilings, and host-side gating in the Chio ecosystem.
- New expressiveness lands spec-first in hush where portable (obligations, memory governance, delegation), vendor-scoped where Chio-specific.

## 3. Non-goals

- Topical confinement rails, learned/behavioral policy mining, a general content-moderation taxonomy (classifier and host territory; external guards already bridge to SaaS moderation).
- An SMT backend for policy analysis (FV-C4 phase 3 already defers it; the decidable fragment suffices).
- Merging federation admission policy (signed `FederatedOpenAdmissionPolicy` records) into HushSpec. Different trust domain and lifecycle; document the boundary instead.
- Payment-mandate policy. Deferred until RFC-0013 money-path durability lands (settlement hook results are currently discarded; policy must not govern a rail that drops outcomes).
- Freezing HushSpec at v1.0. This program targets 0.2.0; the v0.x series explicitly permits iteration.

## 4. Program shape: four phases

Phases are ordered by dependency, not priority. Phase 0 unblocks honest versions of everything after it. Phases 1 and 2 are arc-side and can proceed in parallel once Phase 0's version/namespace decisions are fixed. Phase 3 items are independently shippable.

### Phase 0: Spec re-convergence (hush + arc)

**0.1 HushSpec 0.2.0 in hush.** Add prose sections for `browser_automation` and `code_execution` (closing hush's own prose-vs-schema gap). Upstream `velocity` and `human_in_loop` from arc as core rule blocks 3.13 and 3.14: both are portable, runtime-agnostic semantics (token-bucket rate and spend caps in minor units plus currency; confirmation globs, monetary approval thresholds, timeout with deny/defer). The `human_in_loop` core block gains an optional `approvers { n, of, timeout_seconds }` sub-block, lifting the n-of-m shape out of the vendor slot and into the standard, with single-gate confirmation as the base level. Update the core JSON Schema, all four SDKs, fixtures, and conformance vectors in the same release.

**0.2 Companion specs for reputation and runtime assurance.** Both schemas are engine-agnostic (scoring weights, tier ceilings, attestation tiers, verifier bindings) even though Chio is today's only implementation. Add `spec/hushspec-reputation.md` and `spec/hushspec-runtime-assurance.md` in hush, mirroring the posture/origins/detection companion pattern: core parsers MUST accept the keys, MAY ignore contents. This legalizes arc's two extension keys.

**0.3 Vendor extension namespace.** Amend hush section 9.5: `extensions.vendor.<name>` is a registered namespace whose contents are an opaque mapping. Parsers MUST accept declared vendor keys structurally and MUST reject undeclared top-level extension keys as before. Engines interpret only their own vendor namespace. arc migrates `extensions.chio` (market_hours, signing, k8s_namespaces, rollback) to `extensions.vendor.chio`, with a deprecation alias for one minor version and a `chio policy migrate` rewrite. The advanced HITL sub-block leaves the vendor slot entirely (absorbed by 0.1).

**0.4 Extends-prefix unification.** Spec 0.2.0 names `builtin:<name>` the canonical builtin prefix. arc accepts `builtin:` and keeps `chio:`/`hushspec:` as parse-time aliases flagged by the analyzer (Phase 3.4). hush SDKs keep accepting bare names.

**0.5 Conformance coupling.** arc CI gains a job that runs the hush conformance vectors (the `hushspec-evaluator-test.v0.schema.json` format) against `chio-policy`'s reference evaluator, and arc publishes `spec/HUSHSPEC_PROFILE.md`: conformance level (3), supported spec versions, implemented companion extensions, vendor blocks, and every intentional delta. Vectors are vendored with a sync-check script (same pattern as the supply-chain baselines) rather than a live git dependency.

**0.6 Adopt signing and enforcement disposition in arc.** The arc policy loader verifies hush `PolicySignature` (Ed25519) sidecar files when present, and the control plane gains a `require_signed_policies` toggle (fail-closed when set). arc's `DecisionReceipt` adds the receipt schema's `enforcement` field (`evaluated` vs `enforce` vs `monitor`), which Phase 3.4's dry-run mode requires. Monitor mode follows hush section 6.2 exactly: operator config, never a document property, panic always enforces.

**Versioning consequence:** both repos move `HUSHSPEC_SUPPORTED_VERSIONS` to `["0.1.0", "0.2.0"]`. 0.1.0 documents remain valid 0.2.0 documents (additions are optional fields and new blocks; v0 minor rules permit this).

### Phase 1: Integrity (arc)

Make the schema honest. Every item is small; together they close the wired-vs-staged gap.

- **1.1 Enforce n-of-m approval.** Implement threshold governed approval per the protocol-primitives design (the threshold verifier also unblocks `chio-quarantine`'s approval-requiring response plans). Policy surface: the new core `human_in_loop.approvers` block from 0.1. Compilation target: approval-token collection with n distinct approver identities before the constraint clears; timeout follows the existing `on_timeout` deny/defer semantics.
- **1.2 Warn survives compilation.** Per hush section 6, `warn` means permitted pending confirmation, and engines that cannot confirm SHOULD deny. The compiled plane maps warn-producing constructs to the existing confirmation machinery (`RequireApprovalAbove`, approval queue) where a confirmation channel exists, and to deny where none does. `jailbreak.warn_threshold` either wires to an advisory signal with receipt evidence or becomes a validation error; silently dropping it is removed as an option.
- **1.3 Governance metadata enforcement.** `expiry_date` in the past or `lifecycle_state` not in {approved, deployed} rejects at load behind a control-plane setting (`enforce_governance_metadata`, default on for HushSpec-format loads, with a documented override for development). Clock injected, not sampled ambiently.
- **1.4 CryptoFloor wiring.** The HushSpec/control-plane load path translates the parsed floor into `set_capability_crypto_floor` at kernel construction instead of relying on operators to mirror it by hand.
- **1.5 Relaxation visibility.** Document the non-deny-absorptive merge property in hush section 4 prose, and emit a validation warning when a child clears or narrows a parent block that carried deny semantics. Full refinement checking stays in FV-C4 (Phase 3.4); this is the cheap tripwire.
- **1.6 Money-path fail-closed minimums.** F72 (currency-mismatch cap bypass in `BudgetTree`) is an unconditional fail-closed fix: mismatch denies. F68's minimum (settlement observer outcome logged and dead-lettered instead of discarded) proceeds under RFC-0013 coordination; full retry machinery stays in that RFC.
- **1.7 Doc drift.** Fix the stale "12 guard types" compiler header and test name (17 real). Remove the false retry/dead-letter claim in `chio-settle/src/hook.rs`. Add the risk-register TOCTOU caveats to `PARTNER_PROOF.md`. Resolve the stale-leader-fencing contradiction between `QUALIFICATION.md` and `CHIO_BOUNDED_OPERATIONAL_PROFILE.md` in whichever direction the evidence supports.

### Phase 2: Consolidation (arc)

One authoring plane.

- **2.1 Retire the Chio-YAML policy fork.** Expose the Chio-YAML-only guard knobs through HushSpec: portable ones (sql_query, vector_db result caps, warehouse cost ceilings, query-result limits) proposed upstream as a `data_access` core block or data companion spec in hush 0.3; Chio-specific ones (cloud_guardrails providers, external threat-intel providers, wasm_guard entries) under `extensions.vendor.chio.guards`. Ship `chio policy migrate` (Chio-YAML in, HushSpec out), loader deprecation warnings for the legacy format, and a removal target two arc minor releases out.
- **2.2 Policy-authored issuance ceilings.** HushSpec becomes the source for default token constraints at issuance: monetary caps (`max_total_cost`, `max_cost_per_invocation`), invocation ceilings, and delegation depth flow from policy blocks to the Capability Authority the same way reputation tiers already do (`chio-control-plane/src/issuance/scope.rs`). Kernel-side enforcement is unchanged; what changes is where operators author the numbers.
- **2.3 Host-side unification on the hush SDKs.** The Python `CodeAgentPolicy` replaces its bespoke parser and hardcoded constants with the published `hushspec` PyPI package evaluating the same `code_agent.yaml` (which already ships byte-identical in arc and the plugin). Hardcoded writable-roots/git-deny/approval constants move into that document. `@chio/bridge` hosts gate client-side with `@hushspec/core`. Kernel remains authoritative where connected; the host gate becomes a conformant HushSpec evaluator instead of a lookalike.
- **2.4 Federation boundary documented.** A short doc states why federation admission stays a separate signed record system (different trust domain, different lifecycle, different signers) so the fragmentation reads as a decision instead of an accident.

### Phase 3: New expressiveness (spec-first in hush, enforcement in arc)

- **3.1 Obligations.** New companion spec `hushspec-obligations.md`: an `on_allow` duties model (redact, notify, log-extra, watermark, annotate-receipt) attached to rule blocks, with the invariant that an undischargeable obligation converts allow to deny (fail-closed). The receipt schema gains an `obligations[]` array with per-obligation discharge status, making Chio the engine where obligations are provable after the fact, which no incumbent engine offers. arc implementation generalizes the existing `PostInvocationPipeline`/SanitizerHook into an obligation executor.
- **3.2 Delegation constraints.** Policy surface for what the kernel already enforces from tokens plus the protocol-primitives aggregate budgets: `delegation { max_depth, require_attenuation, allowed_delegates (workload-identity matches), family_budgets }`. Placement: core rule block in hush 0.3 (the concepts are portable; SPIFFE-shaped identity matching already exists in both schemas).
- **3.3 Memory governance.** New core rule block `memory_access` (hush 0.3): store allowlists, write constraints, provenance labels on entries, retention TTL, and read receipts. Closes the risk register's HIGH "agent memory stores ungoverned" item (`docs/release/RISK_REGISTER.md`). arc already carries a `MemoryStoreAllowlist` token constraint to build on; add a MemoryGuard for the rest.
- **3.4 Policy tooling as product surface.** `chio policy analyze` per FV-C4 (shadowing, unreachable rules, contradictions, policy-diff refinement with witnesses; bounded analyzer, no SMT), now with two additions from this program: extends-alias and relaxation warnings (1.5, 0.4). Dry-run/shadow mode uses the 0.6 enforcement disposition so operators can stage a policy in monitor and diff receipts before enforcing. Decision replay reuses the hush evaluator-test vector format so a receipt log replays as a conformance run. A thin `h2h lint` in hush mirrors the analyzer's document-level checks later; the full analyzer stays arc-side.
- **3.5 Payment mandates (deferred, named).** When RFC-0013 lands, a `hushspec-mandates.md` companion (which mandates an agent may sign, per-transaction and cumulative caps, allowed rails/counterparties) pairs with AP2/x402-era agent commerce. Listed so the roadmap shows the intent without widening claims now.

## 5. Placement litmus

A capability lands in hush core when it is runtime-agnostic and most agents need it (velocity, human_in_loop, memory_access, delegation). It lands as a hush companion spec when portable but optional (obligations, reputation, runtime assurance, future mandates). It lands under `extensions.vendor.chio` when it encodes Chio deployment specifics (market hours, k8s namespaces, rollback, provider-specific guard config). When in doubt, vendor first; promotion to companion or core is a compatible move, demotion is not.

## 6. Testing

- hush: every 0.2.0 addition ships with schema updates, four-SDK parity tests (the repo's existing cross-SDK parity audit discipline), fixtures, and new conformance vectors covering velocity, human_in_loop (including n-of-m), and vendor-namespace acceptance/rejection.
- arc: the CI conformance job (0.5) is the drift tripwire from day one. Phase 1 items each carry the test shape of the feature they complete (n-of-m approval-token collection, warn-to-confirmation mapping, expired-metadata rejection, crypto-floor construction wiring, currency-mismatch deny). Phase 2.3 is verified by running the hush Python SDK's own test suite against `code_agent.yaml` plus golden-decision parity tests between the old Python gate and the new evaluator on a recorded corpus of tool calls.
- Property tests: extend `property_evaluate.rs` invariants to the new blocks (deny precedence, determinism, merge identity).

## 7. Risks

- **Two-repo coordination.** Spec 0.2.0 (hush) must merge before arc's 0.2.0 support; the conformance job pins vendored vectors so arc never floats against an unreleased spec. Mitigation: land 0.1-compatible arc work (1.3-1.7, 2.1 vendor-side, 2.4) independent of the spec release.
- **Migration churn.** `extensions.chio` to `extensions.vendor.chio` and `chio:` to `builtin:` break existing documents. Mitigation: parse-time aliases for one minor version, `chio policy migrate`, analyzer warnings, changelog callouts.
- **Host swap regression risk (2.3).** The Python gate is the authoritative gate today. Mitigation: golden-decision parity corpus before cutover, monitor-mode soak using 0.6, keep the old path behind a flag for one release.
- **Scope creep in 0.2.0.** The spec release is intentionally limited to prose-gap closure, two upstreamed blocks, two companion specs, vendor namespace, and prefix canonicalization. `data_access`, `delegation`, `memory_access` wait for 0.3.
- **Claim discipline.** Nothing in this program is announced as covered until the conformance vectors pass and the profile doc lists it as wired. The profile doc is the single place that says what is real.

## 8. Deliverables checklist

Phase 0: hush spec 0.2.0 (prose, schemas, SDKs, vectors); arc `HUSHSPEC_PROFILE.md`; arc conformance CI job; signing verification + `enforcement` receipt field in arc; vendor-namespace migration with aliases.
Phase 1: n-of-m enforcement; warn compilation semantics; metadata enforcement; crypto-floor wiring; relaxation warning; F72 fix and F68 minimum; drift fixes.
Phase 2: Chio-YAML migration tool + deprecation; policy-authored issuance ceilings; host SDK unification; federation boundary doc.
Phase 3: obligations companion + executor; delegation block; memory_access block + guard; `chio policy analyze` + dry-run + replay.
