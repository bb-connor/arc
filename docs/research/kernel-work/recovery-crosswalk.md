# Recovery baseline and the cross-owner research boundary

Task 1, 2026-10-02. All PR #1172 revision-3 P0-P6 semantics are assumed shipped,
as instructed. This crosswalk neither reopens their implementation tasks nor
claims new test results. The [baseline manifest](recovery-baseline.json) pins
`de84fc306efbb4c8dd6de748d0ad2a8d695fd30e`, 16 documents and 111 requirements.

The normative wording, phase, owning crates and inherited acceptance-test name
remain in the pinned [requirements.json](https://github.com/bb-connor/arc/blob/de84fc306efbb4c8dd6de748d0ad2a8d695fd30e/docs/architecture/recoverable-agent-runtime/requirements.json).
The groups below assign each requirement once for auditability. They are research
indexes, not replacement modules or a second runtime API. Machine-readable
membership is in [claim-register.json](claim-register.json).

F01-F16 are **planned** Task 2 fixtures. X1-X5 are the experiments in the approved
design. No fixture is represented here as executed.

## Supplied behavior and future experiment seams

| Group | Supplied recovery capability and exact requirements | Future composition seam; implementation ownership |
| --- | --- | --- |
| C01 | One native authority; serialized evidence is not live ownership; domain/action binding and capability ceiling: SEC-01, SEC-02, SEC-06, SEC-11, RUST-02, RUST-11 | F02/F11/F16: adversarial remote edge, receipt or planner output cannot mint local dispatch. Existing kernel/flow/types/process projection owners |
| C02 | Stable commands, reservation before approval, one unresolved continuation, immutable process envelope, native capture and exactly one logical-call charge: SEC-03, REC-01, REC-02, REC-03, REC-04, REC-05, REC-08, REC-15, REC-21 | F01/F04/F09: cross-owner references identify the existing local operation; no alternative execution path. Existing kernel/process/store/control-plane owners |
| C03 | Exact issuance/request custody, native intent before entry, original nonce recovery, cross-store attachment, cancellation-safe ownership and no transaction held over provider await: REC-09, REC-18, REC-19, REC-23, REC-24, RUST-04, RUST-05, RUST-09 | F04/F15, X2: one edge survives ACK loss at each local bridge cut without recapture or regenerated authority. Existing issuer/kernel/process/store owners |
| C04 | Unknown/partial/withheld effects remain spent; authoritative closure; no cancellation rollback; qualified effect cardinality and retention: SEC-04, SEC-10, REC-10, REC-11, REC-13, REC-20, CON-12, OPS-10 | F05/F06/F14, X2: parent cancellation/payment cannot manufacture no-effect evidence at a child or publisher. Existing native effect/recovery/provider-adapter owners |
| C05 | Exact all-owner approvals, materialized inputs, separate confidentiality/integrity powers, retained knowledge and one-crossing transformations: SEC-05, REC-06, REC-07, REC-16, REC-17, REC-22, CON-07, CON-08, CON-09 | F01/F02/F03/F12: preserve owner and authority-class identity when the approval issuer is remote; no approval of unknown future bytes. Existing approval/semantic/flow owners |
| C06 | Current scoped observations, epochs, actual recipient/ACL, historical/current/held prerequisites and non-atomic snapshots: SEC-07, REC-12, REC-14, CON-04, CON-05, CON-13, SIM-02, SIM-07 | F03/F06/F09/F13/F15: define which remote facts are sufficient and when they expire, without a global snapshot or fresh-check-to-effect fiction. Existing native/control-plane/connector owners |
| C07 | Pure bounded deterministic advice, explicit incompleteness, audience-safe reports and bound signatures, no executable advice: SIM-01, SIM-03, SIM-04, SIM-05, SIM-06, SIM-08 | F16 and positive F01/F06/F09, X2/X4: compare permitted actions and decision cost, not number of denials. Existing planner/preview owners |
| C08 | Qualified semantic package, coverage, operator ceilings, bounded annotator powers, all output dispositions and historical generation preservation: CON-01, CON-02, CON-03, CON-06, CON-10, CON-11 | F08/F11/F12/F14: a remote package or annotation supplies evidence under scope, not tenant authority; count translation and adapter work. Existing semantic/registry/kernel owners |
| C09 | Immutable provenance, durable publication/read joins, derivation, restore, quarantine, GC and filesystem/release mediation: ART-01, ART-02, ART-03, ART-04, ART-05, ART-06, ART-07, ART-08, ART-09, ART-10, ART-11, ART-12 | F08/F11/F12/F15, X5: cross-owner copies and paid artifacts retain every restriction; financial commitments must not leak private evidence. Existing artifact/process/kernel/store/backend owners |
| C10 | Ordinary inheritance, verified confined lineage, provider context, exact return, pre-release parent join, all channels, resource ancestry and governed seeds: ISO-01, ISO-02, ISO-03, ISO-04, ISO-05, ISO-06, ISO-07, ISO-08, ISO-09, ISO-10 | F08/F09/F10, X1/X5: independently paid specialist remains in the economic/resource ancestry even with a separate observation lineage. Existing cage/process/kernel/control-plane owners |
| C11 | Complete declared release channels and safe diagnostics/telemetry: SEC-09, RUST-07, OPS-08 | F08/F11/F16: approval, payment, receipt and error metadata cannot become a new disclosure route. Existing kernel/flow/observability owners |
| C12 | Time/key/migration discipline, replay authorization and scoped historical settlement: OPS-05, OPS-06, OPS-11, OPS-13 | F04/F07/F14/F15: expired initiating authority does not stop authorized internal settlement, or grant current lookup/result access. Existing native/store/control-plane owners |
| C13 | Fail-closed aggregate bounds, bounded wire variants, durable intake quotas and reserved recovery capacity: SEC-08, RUST-03, RUST-10, OPS-09, OPS-12 | F09/F15/F16: prove progress only within stated bounds and availability; a flooded remote owner cannot consume recovery headroom without accounting. Existing substrate/store/control-plane owners |
| C14 | Pure dependency direction, quality/portable features, common SDK semantics, deployment profiles, negative wire vectors, setup coverage and non-authorizing policy feedback: SEC-12, RUST-01, RUST-06, RUST-08, OPS-01, OPS-02, OPS-03, OPS-04, OPS-07 | Qualification dependency for F01-F16, rather than a new model theorem. Keep source/profile identity and capability assumptions in all reports. Existing P0-P6 owners retain builds, deployment and qualification |
| C15 | Paired positive/negative trajectories, native crash/mutation tests, source correspondence, matched comparison and performance/provenance accounting: TEST-01, TEST-02, TEST-03, TEST-04, TEST-05, TEST-06, TEST-07, TEST-08 | Tasks 2/4/5/6 reuse these methods; the research adds cross-owner assertions and matched observations. Existing conformance owners retain local qualification; this effort owns only its new comparison |

## Contracts to formulate, rather than assume supplied

The following J1-J5 names identify research obligations. They are not proposed
production crates, granted authority types, or additions to the PR's shipped
assumption. The complete existing architecture may supply their eventual
realization. Task 2 determines that correspondence before any implementation.

| ID | Remaining composition contract | Existing input | What would establish it |
| --- | --- | --- | --- |
| J1 | Each edge preserves domain-qualified owner/compartment/authority identity, with an explicit receiver-host trust policy and restriction-preserving translation | C01/C05/C08/C09/C10/C11; DLM/DStar prior art | An assume/guarantee relation and adversarial F02/F08/F11/F12 showing every honest owner's modeled release rule survives the edge |
| J2 | A work obligation references exclusive, non-equivocating backing and the original local operation; financial resolution cannot release uncertain execution exposure | C02/C03/C04/C10/C12 plus the existing funded-work settlement contract | Atomic or recoverably ordered attachment with all crash cuts stated; F04/F05/F10/F14. Child independence itself is a regression, not novelty |
| J3 | Remote prerequisites say whether they are historical facts, current predicates or held reservations; an assertion is useful only under its issuer's evidence authority | C01/C06/C12 | Exact validity/retention rules and F03/F06/F07/F13/F15; no inferred global atomicity or timeless approval |
| J4 | Local contracts compose into useful allowed continuations with bounded computation and stated coordination/state costs | C02/C04/C06/C07/C13 and J1-J3 | A defined finite profile and positive F01/F06/F09/F16, compared with B1/B3 and established knowledge-based control. A universal safety condition alone is not an algorithm |
| J5 | A reusable interface supports a second task family without moving bespoke correctness logic into uncounted adapters | C08/C09/C10/C14/C15 and J1-J4 | Matched integration/recovery work and source correspondence, including improvements to baseline libraries. No code-count-only or self-reported productivity conclusion |

K5's quantifier is **for each honest resource owner** under explicit local and
remote trust premises. It must not assume all counterparty kernels honest and
then claim resistance to malicious counterparties. A recipient approved to
learn a secret can leak it outside the modeled protection; continued enforcement
requires that owner's qualified host assumption on the receiving side.

J1-J5 overlap established techniques. The research must identify a nontrivial
sufficiency result, cost tradeoff or reusable systems result. None is promoted to
a novelty claim merely by being listed in this table.

## Boundaries that the next task must preserve

- One unresolved effectful continuation per local workflow. Independent sibling
  progress requires a separately authorized workflow and accounted allocation.
- Separate intent, process-request and native-material digests. Grants do not
  rewrite a frozen caller envelope; original nonce issuance is retained by its
  owning operation.
- Initial provider profile: one outbound effect submission. E1 resolves by
  authoritative lookup; E2 can remain unknown. No fresh key or blind retry.
- Local factual capture cannot freeze remote state by itself. Use a provider
  precondition or held reservation where atomic remote validity is required;
  otherwise state the allowed staleness and refuse unsupported guarantees.
- Planner limits remain the PR's 16 offers, 8 top-level steps, 32 expanded nodes,
  depth 8, 64 evidence references, 16 approvals, 64 KiB envelopes, wire depth 32
  and 4,096 aggregate entries. Any smaller exploration bounds are model bounds.
- Monetary settlement, effect truth and current result-read authority remain
  separate. An immutable unknown terminal record cannot be rewritten as success
  by repairing a projection.

No recovery feature is assigned to this research as an implementation backlog.
Task 5 will resolve actual source anchors from the recovery owners when native
measurements are needed. Task 1 consumes the instructed shipped contracts now.
