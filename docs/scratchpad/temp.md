• Findings

1. P0: ARC still does not have authenticated end-to-end provenance, which is the biggest gap against the full vision. The maximal doc says the core primitive is non-repudiation and
   reconstructable authorization lineage in docs/VISION.md:51, but the shipped bounded profile explicitly says governed call_chain is only preserved caller context, not authenticated
   upstream provenance in docs/standards/ARC_BOUNDED_OPERATIONAL_PROFILE.md:14. In code, the kernel only syntax-checks that structure in crates/arc-kernel/src/kernel/mod.rs:2730 and then
   signs it into receipts in crates/arc-kernel/src/receipt_support.rs:134; the repo’s own review memo says ARC is currently signing caller assertions and local observations as if they
   had the same evidentiary strength in docs/review/04-provenance-call-chain-remediation.md:5.
2. P0: runtime attestation is not verifier-backed end to end yet, so the “attested” part of ARC is still weaker than the vision implies. Issuance still accepts caller-supplied
   RuntimeAttestationEvidence in crates/arc-cli/src/issuance.rs:122, and policy is computed directly over that object in crates/arc-cli/src/issuance.rs:393. The remediation memo is
   explicit that verifier adapters exist, but they are not yet the sole authority on the hot path in docs/review/03-runtime-attestation-remediation.md:5.
3. P0: the comptroller thesis is not achieved because budget truth and cluster authority are still bounded/local rather than distributed-linearizable. The core budget interface openly
   documents an HA overrun bound in crates/arc-kernel/src/budget_store.rs:37, SQLite replication merges spend rows with seq/LWW plus MAX(...) in crates/arc-store-sqlite/src/
   budget_store.rs:61, and trust-control leader selection is still deterministic “sort candidates, pick first reachable” in crates/arc-cli/src/trust_control/cluster_and_reports.rs:1073.
   The bounded profile already marks these surfaces as leader-local or local-only in docs/standards/ARC_BOUNDED_OPERATIONAL_PROFILE.md:16, and the review memo correctly says ARC still
   has a replicated counter, not a real distributed spend-authorization protocol in docs/review/08-distributed-budget-remediation.md:5.
4. P1: hosted identity continuity and multi-tenant isolation are still weaker than the larger ARC security story. Session reuse only compares transport plus a narrow auth tuple in
   crates/arc-cli/src/remote_mcp/oauth.rs:829, and shared_hosted_owner literally reuses one upstream subprocess across sessions in crates/arc-cli/src/remote_mcp/session_core.rs:1983. The
   repo’s own memos say DPoP is optional, privilege-shrink continuity is under-checked, and shared-hosted-owner is not a complete non-interference model in docs/review/06-authentication-
   dpop-remediation.md:5 and docs/review/09-session-isolation-remediation.md:8.
5. P1: reputation, passport, and federation are still portability scaffolding, not a true cross-operator trust network. Local reputation is genuinely local in crates/arc-reputation/src/
   score.rs:3, imported trust is basically local score plus attenuation and allowlists in crates/arc-reputation/src/compare.rs:242, and federation import controls explicitly require
   local activation, manual review, stale rejection, and no ambient runtime trust in crates/arc-federation/src/lib.rs:124 and crates/arc-federation/src/lib.rs:974. The remediation memo
   is blunt that ARC has local truth plus bounded portability, not yet issuer-independent portable trust or real Sybil resistance in docs/review/11-reputation-federation-
   remediation.md:5.
6. P1: the proof and transparency moat is not yet at the level the strongest docs imply. The formal review memo says there is no mechanized refinement from Lean to Rust, the proof gate
   is narrower than the public claims, and the symbolic crypto model is being over-read in docs/review/01-formal-verification-remediation.md:8. Separately, the non-repudiation memo says
   the receipt plane is still operator-local signed audit evidence, not a true append-only public transparency substrate in docs/review/05-non-repudiation-remediation.md:5, which matters
   because docs/VISION.md:176 still uses much stronger ledger language.
7. P2: there is still at least one concrete runtime integrity hole even inside the bounded story: configured delegation depth is not enforced at admission. KernelConfig exposes
   max_delegation_depth in crates/arc-kernel/src/kernel/mod.rs:606, but admission currently validates with None in crates/arc-kernel/src/kernel/mod.rs:2090, so the configured ceiling is
   ignored.

The bottom line is that ARC is good enough to justify the narrower claim already written in docs/protocols/STRATEGIC-VISION.md:36: a cryptographically signed, fail-closed, intent-aware
governance control plane. The control-plane substrate built in .planning/phases/407-universal-binding-resolution-and-executor-registry/407-01-SUMMARY.md:3, .planning/phases/409-dynamic-
intent-aware-governance-control-plane/409-01-SUMMARY.md:3, and .planning/phases/410-shared-lifecycle-contract-and-runtime-fidelity-closure/410-01-SUMMARY.md:3 is real, and the repo’s own
qualification gate says that claim now holds in target/release-qualification/universal-control-plane/qualification-report.md:8.

But ARC is not yet good enough to claim the full maximal vision from docs/VISION.md. The repo itself already says it is not yet qualified for a proved comptroller-of-the-agent-economy
position in target/release-qualification/comptroller-market-position/qualification-report.md:7. The missing pieces are mostly the hard ones: verified provenance, verifier-owned runtime
assurance, real distributed economic truth, strong hosted identity/isolation semantics, and network-grade trust/reputation clearing.
