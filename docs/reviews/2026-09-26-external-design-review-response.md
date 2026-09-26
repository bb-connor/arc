# Response to the external design review of September 26, 2026

An independent reviewer examined the September 25 and 26 specifications and plans
against integration `33ba7eebc4` and the Packet 1 checkpoint `cf6acf4ed7`, ran
focused probes, and returned ten findings with evidence. The review is retained
at `/tmp/chio-spec-review-20260926/review.md` with its probes alongside it. This
document records the disposition of each finding, where the correction landed,
and what changed for the lanes that were already executing.

**Every finding is accepted.** Four are P1 defects in designs this lineage
produced, and two of those (R1 and R3) had already been issued to running lanes.
The redirects went out before this document was written.

This is the independent review the standard's rule 12.1 requires, and it did what
that rule exists for: it found the places where a reviewer who had written the
design could not see past it.

## Dispositions

| Finding | Severity | Accepted | What was wrong | Correction landed in |
| --- | --- | --- | --- | --- |
| R1 `LiveAuthorizedPlan` lets the caller choose the recovery exception | P1 | yes | one token, constructed from a caller-supplied `commit_mode`, served both fresh admission and resume; a legacy plan plus a caller-selected resume mode obtained authority with no durable proof | design mechanism A now specifies three types (fresh admission; committed dispatch with automatic or governed approval; committed admission before a dispatch row, the last two added by the follow-up review's F2); addendum 1B rewritten; Lane D redirected before reaching 1B |
| R2 legacy retirement can strand irreversible commitments | P1 | yes | "zero dispatch rows or lease horizon" ignores the crash after admission commitment and before a dispatch row exists, which the kernel explicitly recovers (`active_response_committed_recovery.rs:365`, `:509`) | addendum 1C rewritten: stop new legacy admissions separately; retire reconciliation only after an obligations inventory is terminal; Lane D redirected |
| R3 blanket SQLite poison recovery premise is false | P1 | yes | `Transaction::drop` discards the rollback result; the probe shows `into_inner()` returning a connection still inside a transaction with the uncommitted row readable; every one of the 18 stores pairs commits with external anchors or filesystem state (`fiscal_store.rs:338` commits before its anchor sync) | standard 14.1 rewritten; addendum 10.1 rewritten as phase-aware recovery with fencing; Lane B held and redirected mid-conversion |
| R4 tenant isolation confuses content addressing with authorization | P1 | yes | a domain hash is computable from its inputs and identifiers appear in receipts and logs; "unguessable derivation" is not an authorization boundary | standard 14.6 and 14.7 rewritten; addendum 10.3 rewritten; every isolation test gives tenant B tenant A's exact valid identifier and requires denial |
| R5 parent Packet 4 has no owner | P2 | yes | the addendum assigned corrections 4A and 4B and orphaned the requirement they amend | dispatch: Lane M owns parent Packet 4 in full; a requirement-to-lane ledger is added |
| R6 Wave 2 ownership overlaps | P2 | yes | F, H, I and J touched the same stores; K's deny set touched every crate; 10.4 and retention had no ordering edge | dispatch Wave 2 rewritten as sequenced store waves with published file ownership; lint remediation moves to the owners; freeze depends on the last source change; Packet 7 becomes a separately qualified candidate |
| R7 nextest changes test contracts and overstates leak detection | P2 | yes | a 180 s cutoff would kill a native harness that allows 300 s; `leak-timeout` only sees children holding inherited stdio and passes leaks by default | hardening H5 rewritten |
| R8 lint propagation misses Rust lints and specifies an invalid Cargo combination | P2 | yes | H0 compared only `[lints.clippy]`; H4 asked for `workspace = true` plus local additions, which Cargo rejects (`cannot override workspace.lints in lints`) | hardening H0, H1 and H4 rewritten |
| R9 analytics rewrite lacks an exact unsigned aggregation contract | P2 | yes | `cost_charged_be` is `to_be_bytes()` of a u64; SQL `SUM` or `CAST` on the BLOB is not decoding; the current JSON path saturates 2^63 to 2^63 minus 1, a latent defect "byte-identical" would have preserved | addendum 9.2 rewritten; Lane C redirected before reaching 9.2 |
| R10 wire and domain test plan can hide compatibility breaks | P2 | yes | 1E told tests to reference the production constant, removing independence; H10 pins identifiers, not serialized shapes | addendum 1E rewritten; hardening H10 narrowed to identifier-change acknowledgement, with shape fixtures and old/new reader tests as the compatibility mechanism; standard 2.7 adjusted |

The four additional corrections are also accepted: H11's measurement is a package
graph, not binary linkage, and the "HTTP client in the binary" wording is
withdrawn until the artifact is measured; H7's "seal to the transport key" is not
an envelope design, and the immediate boundary is removing `Serialize` from the
plaintext round-2 form; H2's exclusion contract is reconciled and a listed crate
must show its unsafe code executed; U6's cancellation reasoning was too strong,
because cancelling a future that awaits `spawn_blocking` does not stop the
blocking work and the caller can lose the acknowledgement while the operation
commits.

## What the review kept, and why that matters

The reviewer named the September 25 closeout plan the strongest artifact: concrete
product behavior, real crash boundaries, explicit acceptance, qualification tied to
a frozen candidate. The additions from the 26th are judged worthwhile as hardening
but faulted for spreading focused work across broad migrations and for design
errors in three of the new types. That judgment is accepted as the sequencing rule
going forward: finish the bounded production dry-run and its recovery and fuzz
evidence; let independent gate work and CI repair continue; defer broad connection,
module and toolchain migrations to separately reviewable changes with their own
qualification.

## Requirement-to-lane ledger

Every requirement in the parent plan and the addendum has exactly one owning lane.
A correction never substitutes for the requirement it amends.

| Requirement | Owner | Status |
| --- | --- | --- |
| Parent Packet 1, production signed response dry-run, all seven items | Lane D | in progress from checkpoint `b0f66c2a01` |
| Corrections 1D, 1A, 1B (revised), 1C (revised), 1E (revised), 1F | Lane D | in progress |
| Parent Packet 2, repaired boundaries in real composition; corrections 2A, 2B | Lane J | Wave 2, needs the x86_64 CI runner for native cases |
| Parent Packet 3, retention liveness; correction 3A; 10.4 chain-link bind | Lane J (receipt-store owner) | Wave 2, sequential inside the lane |
| **Parent Packet 4, fuzz harnesses, campaigns, Kani, lifecycle model, temporal timeout** | **Lane M** | Wave 2 after D merges; previously unowned |
| Corrections 4A (clock port) and 4B (assertion conversion) | 4A: Lane G after D; 4B: each boundary's owner, as an exit criterion | Wave 2 |
| Parent Packet 5, delivery blockers | operator authority, tracked separately | ongoing |
| Parent Packet 6, freeze, qualify, independent review | orchestrator plus independent reviewer | after the last source-changing lane |
| Packet 0 gates | Lane A | merged (0.1, 0.3, 0.4, 0.5); 0.2 held for B |
| Packet 8 `ExposureUnits`; 9.3 `prepare_cached` | Lane S (single store owner) | Wave 2, in that order |
| 9.4 connection strategy | successor candidate (Wave 3, with Packet 7); a store whose 10.1 fence cannot be made safe is the one in-candidate exception | deferred per the follow-up review's F5 |
| Packet 9.1, 9.2 (revised) | Lane C | in progress |
| Packet 10.1 (revised, phase-aware) | Lane B | in progress, redirected |
| Packet 10.2 `UntrustedJsonText` | Lane G | Wave 2 after 1F |
| Packet 10.3 (revised, authorization classification) | Lane S | Wave 2, classification before any remediation |
| Hardening gates and configuration (H0, H2 lane, H5 config, H6 runbook, H9, H10 snapshot, H11 gate) | Lane K | Wave 2; K owns no production source |
| Hardening remediation in source (H1 comments, H3 forbids, H4 attributes) | each crate's owning lane, as an exit criterion; measured list from K | Wave 2 |
| H7 FROST round-2 envelope | a dedicated lane after a design note, not Lane K | Wave 3 |
| Packet 7 structural remediation | post-freeze, separately qualified candidate | Wave 3 |
| CI regressions at `3cd73631a1` | Lane R | merged |

## What this cost

Two lanes had begun work on designs the review overturned. Lane B had started
converting connection guards to blanket recovery; Lane D had not yet reached 1B.
Both were redirected within the same hour the review arrived, with the review's
own probe cited as the reason. The gate that should have caught R1 and R3 before a
brief was issued is the one rule 12.1 already names and this lineage had been
saying it lacked: an independent reader.
