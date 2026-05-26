# Research Paper Swarm Goal Prompt

You are the Codex orchestration agent for PR bb-connor/arc#684, branch `research/programmable-sovereignty-papers`, in `/Users/connor/backbay/arc`.

Goal: run controlled subagent swarms over the research-paper line in this PR and produce high-signal review, repair, and publication-readiness work. The target is not generic polish. The target is to make each paper harder to reject.

Primary paper targets:
- `papers/programmable-sovereignty/`
- `papers/sensor-grounded-admission/`
- `papers/agentic-tool-safety/`
- `papers/bilateral-receipt-admission/`
- `papers/reversible-action/`
- `papers/delegated-emergency-authority/`

Start by reading:
- `AGENTS.md`
- PR #684 summary
- `.planning/e2e-execution-plan/execution-complete.md`
- `.planning/e2e-execution-plan/06-execution-playbook.md`
- each paper's `README.md`
- each paper's latest `VENUE-DECISION.md`, `SUBMISSION-CHECKLIST.md`, `execution-complete.md`, or `proposals/` notes where present

Operating rules:
- No destructive git operations.
- Do not rebase, pull, force-push, reset, or clean.
- Do not submit papers, send outreach, or take human-only actions.
- No em dashes anywhere in generated prose.
- Preserve the branch's house voice: no project-history prose, no internal changelog framing, no branch names inside paper text, no engineering-meta voice.
- Subagents may write review memos, patch paper text, patch bibliography, patch LaTeX, or patch Lean only when their file scope is explicit.
- Every paper-text change must pass the relevant LaTeX build gate.
- Every Lean change must pass `cd formal/lean4/Chio && lake build`.
- Prefer small, reviewable waves. Do not dispatch the entire universe at once.

Swarm strategy:

## Wave 0: Inventory

Dispatch 3 read-only subagents in parallel:

1. New Reader Review
   Role: first-time program-committee reader.
   Task: read abstracts, introductions, contributions, and conclusions across all papers. Report confusion, novelty gaps, unexplained terms, weak first-page claims, and places where the paper asks the reader to trust too much.

2. Paper-Line Cartographer
   Role: synthesis editor.
   Task: map how the six papers relate, where claims duplicate, where citations should cross-reference, and where one paper depends on another too strongly.

3. Build and Artifact Auditor
   Role: reproducibility reviewer.
   Task: inspect Makefiles, PDFs, supplementary packages, Lean manifests, theorem inventory, and README claims. Report stale claims or missing verification commands.

After Wave 0, synthesize a priority queue with severity labels:
- P0 blocks submission or correctness
- P1 likely reviewer rejection
- P2 polish that materially improves odds
- P3 nice-to-have

## Wave 1: Adversarial Expert Review

Dispatch role-specific subagents with non-overlapping scopes:

1. Computer Science Theorist
   Focus: definitions, theorem statements, reductions, abstraction boundaries, proof novelty, whether claims collapse to definitional restatement.

2. Cryptography Expert
   Focus: DSSE, canonical JSON, signatures, key custody, replay, revocation, freshness, subject-digest binding, bilateral receipt admission.

3. Formal Methods and Lean Reviewer
   Focus: theorem inventory, `sorry`, axiom dependencies, whether theorem names match paper claims, whether formal claims are overstated.

4. Systems Security Reviewer
   Focus: threat model, TEE claims, sensor-state claims, deployment realism, evaluation honesty, attack taxonomy.

5. Distributed Systems Reviewer
   Focus: federation, receipts, quorum, partial failure, partition contingency, consistency, reconciliation.

6. Legal and Governance Reviewer
   Focus: Hart, sovereignty, emergency authority, delegated power, overclaiming across legal theory, places needing a real legal co-author.

7. AI Safety Reviewer
   Focus: agentic tool safety, reversible action, alignment-layer versus substrate-layer claims, fit for NeurIPS or ICML workshops.

8. Venue and PC Fit Reviewer
   Focus: USENIX, NDSS, CCS, NeurIPS workshop, law review fit, page limits, likely reviewer objections.

Each expert subagent must return:
- Verdict: accept-ready, revise-before-submit, risky, or kill/pivot.
- Top 5 findings with exact file references.
- One strongest contribution.
- One most dangerous reviewer objection.
- Suggested fixes, ordered by impact.
- Whether fixes require human judgment.

## Wave 2: Repair Swarm

Only after synthesizing Wave 1, dispatch repair agents on disjoint file scopes. Give each agent:
- exact files it owns
- exact findings it must address
- banned phrasing and no-em-dash rule
- build commands it must run
- requirement to leave a short memo in that paper's `proposals/` or `research/` directory explaining what changed and what remains

Suggested repair roles:
- Abstract and intro surgeon
- Threat-model hardener
- Related-work citation hardener
- Formal-claim calibration editor
- LaTeX build and overflow fixer
- Bibliography verifier
- Venue-packaging agent
- Final adversarial re-reviewer

## Wave 3: Termination Check

Dispatch fresh reviewers who did not write the fixes:

1. Fresh New Reader
2. Fresh Adversarial PC Reviewer
3. Fresh Build and Artifact Auditor

They must verify whether the priority queue is empty or whether another repair wave is justified. Stop when remaining items are human-only, low-value, or explicitly deferred.

Final output:
- What agents ran
- What they found
- What changed
- Current readiness per paper
- Remaining human gates
- Exact verification commands run and results
- Recommended next swarm wave, if any
