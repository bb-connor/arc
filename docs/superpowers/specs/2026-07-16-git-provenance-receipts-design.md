# Chio Git Provenance: Commits and Pushes as Governed, Receipted Operations

- Status: Draft for review (2026-07-16). Proposal only. Part of the substrate-receipts program; this is the plane where the runtime receipts become evidence about code artifacts.
- Scope: `arc` (a `chio git` surface in `chio-cli`, receipt schema additions, `chio-disclosure-lineage` composition), git client hooks, and a server-side gate (pre-receive script now, forge app later).
- Related: `docs/superpowers/specs/2026-07-15-bun-runtime-enforcement-design.md` (session receipt chains this design binds to), `docs/superpowers/specs/2026-07-16-python-audit-receipts-design.md`, `crates/trust/chio-disclosure-lineage`.

## 1. Context and problem statement

A growing share of commits are agent-authored, and the ecosystem's answer so far is honor-system metadata: `Co-authored-by` trailers, an emerging `Assisted-by` trailer convention, and git-ai's line-level provenance in Git Notes implementing the multi-vendor Agent Trace draft. All of it is self-reported, unverifiable, and strippable. Meanwhile the EU AI Act's machine-readable disclosure obligations (August 2026) are turning structured AI attribution from a preference into a requirement, and every enterprise buyer of agent tooling is starting to ask the same question: which of our code did agents write, and under what controls?

Chio can answer that question in a way trailer conventions cannot, because the substrate-receipts program produces something to bind to: an attested session chain. The delta over the entire existing landscape is one move: bind the commit hash into the receipt chain, so "this diff came from session S under policy P" is a verifiable statement rather than a claim in the commit message.

## 2. Goals

- **Commit binding.** A governed session that creates a commit emits a commit receipt into its chain: commit hash, tree hash, diff digest, session id, policy hash, and pointers to the session's runtime receipts. The commit itself carries only a pointer (trailer and/or note); the binding lives in the receipt store, so stripping the pointer breaks nothing.
- **Push gating.** A server-side choke point (pre-receive hook; forge app later) that evaluates repo policy over incoming commits: for example, agent-authored commits must carry valid receipt bindings, human commits are exempt via commit signature, unattested commits are rejected or quarantined per policy.
- **Offline verification.** `chio git verify <rev-range>` answers, against an export bundle, which commits in a range are receipt-bound, by which sessions, under which policies.
- **Interop, not competition.** Emit Agent Trace-compatible notes alongside the binding so git-ai-aware tooling reads Chio-attested commits natively.

## 3. Non-goals

- Line-level provenance. git-ai already does line attribution well; Chio binds at commit granularity and points at richer metadata rather than reproducing it.
- DCO semantics. An agent never adds `Signed-off-by`; that trailer certifies a human right the agent cannot hold. The binding is a separate mechanism with separate meaning.
- Code review enforcement or branch protection. Forges do this; the gate composes with it (a receipt binding can carry approval receipts, but requiring review is the forge's job).
- Guaranteeing code quality. The claim is provenance and governance, never correctness.

## 4. Architecture

**4.1 Client side.** A `post-commit` hook (installed by `chio init`, or invoked by the host plugin after agent-driven commits) computes the binding and submits it to the session signer, which appends a commit receipt to the active chain. The commit gains a trailer (`Chio-Receipt: <receipt-id>`) and a Git Note in a dedicated ref (`refs/notes/chio`) carrying the receipt id plus an Agent Trace-compatible payload. Both are conveniences; the store is authoritative.

**4.2 History rewrites.** Rebase, squash, and amend change commit hashes, invalidating bindings by design. The hook re-attests rewritten commits with a receipt that references the predecessor receipt(s), so lineage survives rewrites as an explicit chain (three commits squashed into one produce one receipt referencing three). An unexplained hash with no binding and no lineage is exactly what the gate is supposed to notice.

**4.3 Server side.** Phase one is a pre-receive script for self-hosted git: for each pushed commit, look up the binding (via the receipt store or a pushed export bundle), evaluate repo policy, accept or reject with a structured message. Phase two is a forge app (GitHub first) doing the same as a required check, which also covers hosted repos where pre-receive is unavailable. The gate is the enforcement choke point of this design: everything client-side is evidence generation.

**4.4 Policy surface.** A repo-level Hush document (or block in the workspace document) under `extensions.vendor.chio.scm`: which refs require bindings, what counts as exempt (human signature allowlists), whether unattested commits are rejected or quarantined-and-receipted, whether approval receipts are required for protected paths. Placement litmus: vendor first; commit governance is portable in principle and a promotion candidate once a second consumer exists.

## 5. Trust model

What a verified binding proves: this commit hash was presented to the signer by session S at time T, under policy hash P, and S's runtime receipts (install, fs, net, spawn) are retrievable behind it. What it does not prove: that the diff's content was produced exclusively inside S (an agent can commit text from anywhere; the runtime receipts constrain but do not determine content provenance), that the code is reviewed or correct, or anything about commits policy chooses to exempt. Humans committing without attestation are a policy decision at the gate, not a hole: the gate makes unattested commits visible and governable, which is the entire point.

The signer-side binding matters for a subtle reason: a commit trailer is written by whoever writes the commit, but the receipt is signed by the out-of-process signer with the session's sequence numbers around it, so an agent cannot retroactively manufacture bindings for commits its session did not present, and gaps are detectable as always.

## 6. Operator experience

Developer: invisible until the gate speaks; `git log` shows the trailer; `chio git verify HEAD~20..` answers what is bound. Platform team: repo policy in the same review flow as everything else; the fleet question becomes "what fraction of merged code is receipt-bound," which is a query over notes plus store; incident response gets "which sessions touched this file's history, under which policies." Auditor: the EU AI Act disclosure artifact is generatable from the notes ref plus export bundle, machine-readable, with cryptographic backing the trailer conventions lack.

## 7. Rollout and claim discipline

1. Client-side binding plus `chio git verify` ship first: pure evidence generation, no gate, no behavior change, immediately useful for the disclosure-report story.
2. Pre-receive gate in report-only mode (receipted, not rejecting) to measure unattested-commit rates before anyone turns on rejection.
3. Enforcing gate and forge app after report-only soak. No claim uses the word enforcement until the gate is the thing making it true, and every claim carries section 5's scoping.

## 8. Risks and open questions

- **Volume and note management.** Monorepos generate commit receipts at scale; notes refs need the same aggregation thinking as fs receipts (per-push digests are the likely answer; decide during implementation).
- **Agent Trace is a moving draft.** Interop payloads may churn; the binding format is ours and stable, the interop layer is versioned separately.
- **Forge app surface.** A GitHub App holds credentials and webhook infrastructure; that is a real operational commitment and phase two for a reason.
- **Store availability at the gate.** Pre-receive needs binding lookups; offline forges need bundles pushed alongside (a `chio git push-evidence` companion), and the failure mode (store unreachable) must be policy-chosen: fail-closed rejects, report-only logs.
- **Cross-program dependency.** The binding is only as interesting as the session chain behind it; this design's value scales with the runtime receipt sources shipping.

## 9. Deliverables

`chio git` subcommands (init-hooks, bind, verify, push-evidence) in `chio-cli`; commit receipt schema + lineage-on-rewrite semantics; notes-ref writer with Agent Trace payload; pre-receive gate (report-only, then enforcing) with `scm` policy block validation; disclosure-report generator (machine-readable attribution summary over a rev-range); forge app as a named phase-two deliverable.

## 10. References

- git-ai / Agent Trace: https://rywalker.com/research/git-ai
- Attributing AI commits (landscape): https://crashoverride.com/resources/knowledge-base/code-ownership/attributing-ai-commits-git
- Assisted-by trailer proposal: https://www.baristalabs.io/blog/ai-assisted-commits-need-provenance-trailer
