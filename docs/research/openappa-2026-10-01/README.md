# OpenAPPA research and a concrete proposal for Chio

Research date: October 1, 2026. Scope: source, architecture, docs, product direction, published evaluations, and model-free local experiments.

**Recommendation: learn aggressively from OpenAPPA; implement its useful recovery and integration ideas on Chio's authority and execution machinery. Do not make it a mandatory runtime dependency on the evidence currently available.** Confidence: high that the ideas matter; moderate that adapting them is cheaper than embedding its runtime; unknown whether Chio can outperform it until comparable workloads run.

The strongest counterargument to dismissing this project is that OpenAPPA has a coherent, usable answer to a problem Chio can describe architecturally: after a legitimate action is blocked, what exactly can the agent do next? It combines information-flow policy, stateful enforcement, recoverable decisions, adapters, connector policy packages, setup guidance, trajectory tests, and benchmarks that count completed work. That is a substantial product, even while explicitly in preview.

The strongest counterargument to adopting it wholesale is that Chio already owns capability authority, admission capture, execution ownership, outcome-unknown recovery, and receipts. Introducing another runtime that owns trajectory state, offers, approvals, and dispatch reservations creates a second authority lifecycle. Neither system's decision alone would prove that the combined operation is safe. The integration would have to preserve both systems' state and semantics atomically.

OpenAPPA should make us excited about the problem and impatient about our product gap. It does not establish that Chio should become its wrapper.

## Read the findings

- [Second pass on current security and agent processes](security-branch-second-pass.md): the real flow prototype, native custody evidence, immutable-call correction and next integration design.
- [Technical review](technical-review.md): architecture, algebra, runtime, adapters, filesystem boundaries, benchmarks, vision, and the comparison with Chio.
- [Chio proposal](chio-proposal.md): what to replicate, what to improve, implementation boundaries, and acceptance criteria.
- [Reproducible experiments](experiments/README.md): the authored policy scenarios and file-ledger probe.
- [Source manifest](evidence/source-manifest.json) and [reviewed-file inventory](evidence/source-inventory.json): revision and file-hash evidence.
- [Test results](evidence/test-results.json), [experiment results](evidence/experiments.json), and [benchmark cross-check](evidence/published-benchmark-crosscheck.json).

## What was actually done

Cloned the full [OpenAPPA repository](https://github.com/archestra-ai/OpenAPPA) into a separate research checkout and pinned it to `a96f87d1fec900caf890f14342a089a32b3bfaff`, the October 1 ingress/frontmatter/delegation hardening commit. Mapped the workspace and reviewed the core engine, policy compiler, event store, runtime boundary, adapters, package/module mechanisms, connector policy, coding-agent mediation, telemetry, evaluation harnesses, and product documentation. This is focused source research, not a line-by-line audit of all 1,114 tracked files.

Also cloned the public [Chio repository](https://github.com/backbay-labs/chio) at its captured default-branch head, `5b8bec41d32f3838b880576fe6123c983ecebf8d`. Compared it with current documentation and inspected newer local development source. These are separate evidence classes. The public default branch captured here is dated September 2; newer flow/security implementation evidence is not proof of public availability or completed combined qualification. Local development files are inventoried by relative path and hash without public checkout instructions for unpublished revisions.

Selected OpenAPPA tests passed locally on macOS:

| Run | Passed | Failed | Ignored |
|---|---:|---:|---:|
| Engine, policy, event store, Claude Code and kagent adapters | 683 | 0 | 0 |
| Runtime library and 12 selected integration suites | 819 | 0 | 2 |
| **Total** | **1,502** | **0** | **2** |

The two ignored tests require a live TypeSafe API. Runtime suites included crash recovery, policy reload, child returns, input substitution, caller/principal handling, hook failure behavior, replay, and embedded hosting. This does not qualify a live model provider, a real installed coding-agent session, a PostgreSQL deployment, or Linux confinement. No Chio runtime test suite or paid model evaluation was run in this first research pass. The [second pass](security-branch-second-pass.md) records separate, later Chio flow, native custody and process tests.

Two authored replay files passed all **14 action expectations**. A separate Rust probe reproduced the documented process-local file-ledger limitation: identical file bytes had a restricted label before ledger recreation and the configured public starting label afterward. The probe directly exercises `FileStore`; it is not an end-to-end coding-agent attack or an undisclosed vulnerability.

## The findings that change the strategy

1. **OpenAPPA is more than a policy checker.** The current implementation has immutable policy openings, durable operations, idempotent result processing, effect reservations, replay validation, stale-offer checks, and indeterminate-outcome handling. Claiming that Chio alone supplies durability would be wrong. [Engine semantics](https://github.com/archestra-ai/OpenAPPA/blob/a96f87d1fec900caf890f14342a089a32b3bfaff/appa-engine/src/lib.rs), [storage semantics](https://github.com/archestra-ai/OpenAPPA/blob/a96f87d1fec900caf890f14342a089a32b3bfaff/appa-eventlog/src/lib.rs).
2. **The best feature is recoverable enforcement.** A denial carries policy-derived alternatives, with approvals and transformations bounded to a specific operation. A planner that produces a legal next step is much more useful than a string explaining a prohibition. [Planner](https://github.com/archestra-ai/OpenAPPA/blob/a96f87d1fec900caf890f14342a089a32b3bfaff/appa-engine/src/plan.rs#L1).
3. **Connector semantics are part of the product.** Its batteries describe data provenance, recipients, membership lookups, required trust, and approved transformations. A list of allowed tool names is not equivalent. [Batteries](https://github.com/archestra-ai/OpenAPPA/blob/a96f87d1fec900caf890f14342a089a32b3bfaff/website/content/docs/batteries.md).
4. **Deterministic enforcement still depends on truthful inputs.** Classification, membership sources, sanitizers, adapters, and physical dispatch remain trust boundaries. A deterministic decision over an incorrect annotation remains an incorrect decision. The code makes many of these boundaries explicit; the broad homepage language is less precise.
5. **The filesystem work is promising and explicitly experimental.** File-content labels, model-output labels, and copy/move semantics are thoughtfully separated. The ledger is process-local, the workspace assumes one writer, and native harness reads, inference traffic, and final responses are outside that feature's checks. Chio can target durable artifact provenance and stronger execution mediation, but must demonstrate them rather than announce superiority. [Coding-agent limits](https://github.com/archestra-ai/OpenAPPA/blob/a96f87d1fec900caf890f14342a089a32b3bfaff/website/content/docs/coding-agents.md#L173).
6. **The marketing headline is not the cleanest comparison.** The published same-actor Claude comparison gives OpenAPPA 75% completion in both suites. IFC-tuned Auto completes 85% and 95.8%, respectively, with zero and six scored attacks. OpenAPPA records zero in both. The security/utility tradeoff is real; zero observed attacks is not a universal guarantee. [Detailed evaluation](https://github.com/archestra-ai/OpenAPPA/blob/a96f87d1fec900caf890f14342a089a32b3bfaff/website/content/docs/evaluation.md#L112).

## What to build first

| Priority | Replicate | Improve in Chio | First evidence required |
|---|---|---|---|
| P0 | Typed remedies after denials | Bind offers to existing capability, flow, policy, operation, revocation, budget, and execution state | A denied disclosure becomes one exactly authorized send; the next send remains denied |
| P0 | Friendly policy trajectory tests | Extend existing receipt replay with authority and effect assertions | Allowed work, denied work, expired offers, and unknown outcomes exercise the real admission path |
| P1 | Semantic connector packs | Operator-bound ACL sources, authenticated versions, coverage checks, deterministic common contracts | Two real tool sets have explicit source/sink semantics and refuse uncovered operations |
| P1 | Isolated reads with constrained returns | Bind the return to isolation evidence and provenance; preserve lineage restrictions | Raw sensitive context stays outside the parent; all return/error channels are mediated |
| P1 | File-version provenance | Durable labels through restart, copy, restore, and concurrent mutation | A restricted artifact cannot reopen as public or publish bytes without committed label evidence |
| P1 | Security and useful-work evaluations | Compare actual effects, recovery, application glue, and runtime failure under matched conditions | A workflow keeps working without unauthorized effects and removes meaningful host-side supervision |
| P2 | Feedback-driven policy maintenance | Reports propose reviewed changes with replay and rollback evidence | A benign complaint cannot automatically weaken policy |

The first vertical slice should be **private support ticket → approved public issue**, including a failed unauthorized attempt, one exact approval, a restarted process, and a refused reuse. It exercises the recovery experience and Chio's kernel contract in one understandable workflow. A second unrelated workflow and host should follow before claiming a general integration advantage.

Everything added in this directory is research, evidence, and proposed design. No Chio product behavior was changed, and nothing was pushed, deployed, or published by this work.
