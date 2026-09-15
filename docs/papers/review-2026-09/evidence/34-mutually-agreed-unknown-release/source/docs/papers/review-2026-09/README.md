# Whitepaper Review, September 2026

A comprehensive review of the two Chio whitepapers against the repository at `main` `fe5657020c`, conducted 2026-09-10 to 2026-09-11 with three waves of orchestrated, adversarially verified analysis and a full benchmark reproduction on the Linux Neoverse-N1 host the first paper describes.

Start with `01-executive-summary.md`. The method and every pinned fact are in `00-method-and-scope.md`. The roadmap is `10-roadmap.md`.

| File | What it is |
| --- | --- |
| `00-method-and-scope.md` | Method, waves, pinned facts, reproduction commands |
| `01-executive-summary.md` | The verdict, the ten most consequential findings, the recommended direction |
| `02-p1-claim-audit.md` | Paper 1 claim-by-claim audit, gate runs, benchmark reproduction, appendix of findings |
| `03-p2-claim-audit.md` | Paper 2 claim-by-claim audit, appendix of findings |
| `04-formal-evidence-audit.md` | What the cited theorems prove, the wider harness estate, assumption discipline |
| `05-cross-paper-consistency.md` | Contradiction matrix, the six-paper family, spec staleness |
| `06-foundational-paper-benchmark.md` | Rubric derived from foundational documents; both papers scored |
| `07-simulated-pc-reviews.md` | Six program-committee reviews of the papers as submitted |
| `08-the-thesis.md` | Five candidate theses, two judges, the recommended unified thesis |
| `09-claim-surface-and-landscape.md` | What Chio truthfully supports today; competitive and prior-art landscape |
| `10-roadmap.md` | Prioritized actions in four phases |
| `11-prose-and-structure-audit.md` | Reader-experience audit, missing related work, structural recommendations |
| `12-execution-record.md` | What phases 0 through 3 delivered, the status of every finding, and the measurements before and after |
| `13-code-the-paper-owes.md` | Implementation gaps identified before the breakthrough review |
| `14-handoff-is-this-a-breakthrough.md` | The skeptical review assignment |
| `15-breakthrough-judgment.md` | Negative judgment, counterexamples and what would change it |
| `16-outcome-continuation-research.md` | Prior art and receiver-owned lease/governance implementation |
| `17-outcome-continuation-experiment.md` | Durable outcome slots and a verified artifact workflow |
| `18-matched-outcome-ledger.md` | Independent ledger matches the tested local outcome guarantees |
| `19-receiver-outcome-graph.md` | Process recovery, replaceable couriers and the matched ledger across three receivers |
| `20-isolated-outcome-graph.md` | Linux credential isolation and process-death checks with the same matched graph |
| `21-verified-source-repair.md` | A real Git-hook repair, isolated behavioral checking and exact-source publication |
| `22-receiver-owned-outcome-checking.md` | Executed upstream-honesty counterexample and receiver-side checking without an upstream signature |
| `23-recoverable-git-publication.md` | Checked source publication recovered through Git state, with generic claims preserved and an equivalent ledger comparison |
| `24-portable-artifact-checking.md` | Consumer verification without receiver keys or stores, and an executed false-publication counterexample |
| `25-artifact-validity-is-not-scarce-work.md` | Fresh claims and varied artifacts can reuse one repair; both protected logical-job budgets still admit once |
| `26-checked-repair-exchange.md` | Encrypted repair delivery and atomic local credit settlement, with buyer/seller counterexamples and explicit operator trust |
| `27-interorganization-work-protocol.md` | Direction toward independent organizations, existing infrastructure map, and a tested A2A client-to-kernel edge connection |
| `28-recoverable-market-agreements.md` | Existing signed market artifacts over A2A, separate journals, process-kill acceptance recovery and public agreement verification |
| `29-checked-work-and-local-settlement.md` | Executed review, checked finding and receipt inclusion, native local-credit settlement, payment recovery and a remaining output-rejection terminal gap |
| `30-recoverable-checked-output-rejections.md` | Explicit zero-charge checker contract, signed rejection, native hold-release recovery and one-time buyer reservation restoration |
| `31-python-rust-work-interoperability.md` | Separate Python buyer and verifier, native market and receipt interoperability, own durable journal and 16 process scenarios against the Rust provider |
| `32-public-enrollment-and-https.md` | Native TLS 1.3 endpoint, signed public enrollment, receiver-owned trust activation and sender-constrained negotiation, with 17 HTTPS process scenarios |
| `33-verifiable-uncertain-work.md` | Qualified native incident export, exact remote incident bindings, Python retention without monetary mutation, and crash recovery across both public verifiers |
| `34-mutually-agreed-unknown-release.md` | Co-signed incident-bound payment release, append-only native authority, independent Python accounting and HTTPS crash recovery |
| `findings.json` | Machine-readable findings with verifier verdicts and execution status |

Phases 0 through 3 of the roadmap were executed on the branch
`paper/roadmap-phase-0-1` in fourteen commits from `84f2d3eaff` to
`c76f19a062`. Read `12-execution-record.md` before acting on any document in
this set: 151 of the 172 findings are closed, and the measurements in the
tables below were superseded by a single clean-tree re-measurement.

The analysis in files `00` through `11` is advisory and changed no paper, spec,
or source file. House rule: no em dashes anywhere in this set.

Reports `15` through `34` record later local work on an uncommitted tree based
on `2b3b5af8cbfbc6f16ce6005de3f97cd149803b81`. Their evidence is versioned by
source hashes in the adjacent manifests. These reports do not assert merged
changes, exact-commit remote CI qualification or an achieved breakthrough.
