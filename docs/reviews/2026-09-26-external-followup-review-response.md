# Response to the follow-up external review of September 26, 2026

The reviewer who examined the September 26 designs returned the same day to
check the corrections, the running lanes and the working process, against
integration `a27f5e9171`, nine child transcripts and the recorded test
evidence. Their review is retained at
`/tmp/chio-followup-review-20260926/review.md` with its probes, and the history
report at
`/home/connor/.superpowers/diagnosing-superpowers/a17733e5-ffc4-4e77-8f7c-b9a65f418804/report.md`.
Five findings, one gate limitation and three execution habits. All accepted.

The review's headline is also accepted: the corrections are stronger than the
originals, and none of the production security implementations had integrated
at the review cut. The acceptance boundary it names is adopted verbatim:
finish D's production behavior, B's verified recovery and C's exact analytics
semantics; run M's fuzz and model work against the merged behavior; keep gate
work moving; freeze and qualify a concrete candidate before treating any broad
migration as delivered.

## Dispositions

| Finding | Severity | What was wrong | Correction |
| --- | --- | --- | --- |
| F1 FROST opening not bound to the expected ceremony | P1, design | the opening procedure authenticated the envelope's own metadata and never compared `ceremony_id`, `key_epoch`, `participant_set_digest` and round with the ceremony the recipient is running; an unmodified old envelope authenticates because nothing in it changed | the [sealing design](../superpowers/specs/2026-09-26-frost-round2-envelope-design.md) now takes the validated ceremony context at the opening boundary and compares every identity before any cryptography, as `validate_package` (`frost_ceremony.rs:784`) does today; tests present an unmodified valid envelope to a different ceremony, epoch and roster, distinct from the mutation tests |
| F2 recovery authority strands automatic dispatches | P1, design | `CommittedResumeAuthority` required `operation_id: AdmissionOperationId`, but committed recovery also resumes automatic dispatches (`validate_committed_governed_operation` returns `None` for them, `active_response_committed_recovery.rs:828`); a universal resume token with a mandatory governed operation either strands automatic recovery or invites an untyped exception | mechanism A now has three types: `FreshLiveAdmission`; `CommittedDispatchAuthority` for an exact executor-committed dispatch, carrying the recovered approval as `Automatic` or `Governed(permit)`; and `CommittedAdmissionAuthority` for a governed commitment with no dispatch row, which re-enters live admission rather than authorizing execution. Both recovery types are module-private constructions from verified records. Addendum 1B, standard 2.3, the dispatch and the M and G briefs follow; Lane D was told to hold the single-token form before this landed |
| F3 production arithmetic behind a negative `cfg` was invisible | P2, merged gate | `check-accounting-arithmetic.py` treated any `cfg` containing the word `test` or `kani` as test-only and blanked the item, so `#[cfg(not(test))]` and `#[cfg(not(kani))]` hid production subtractions; reproduced by the reviewer's probe | the gate now evaluates the predicate under production assumptions (`test` and `kani` false, every other atom unknown) with three-valued logic over `all`, `any` and `not`, and excludes an item only when the predicate can never hold in production; the self-test adds a fixture with `cfg(not(test))`, `cfg(any(test, feature = ...))`, a multi-line `cfg(all(not(kani), unix))` and `cfg(not(any(test, kani)))`, all counted, and `cfg(all(test, feature = ...))`, excluded. The workspace count did not change, so no production site was hiding behind a negative predicate today; the gate could not have said so before |
| F4 FROST replay state had no owner or lifetime | P2, design | "first accepted wins" pointed at `validate_round2_transcript`, which allocates a fresh set per call and detects duplicates inside one transcript only; ceremony identifiers are deterministic from the configuration, so retries reuse them | the design specifies stateful acceptance owned by the FROST ceremony store (`chio-store-sqlite/src/frost_store/ceremony.rs`): an acceptance row keyed by ceremony, epoch, round, sender and recipient carrying the envelope digest, written atomically with the encrypted share; equal digest idempotent, different digest a durable ceremony failure; durable abandonment; a retry is a new epoch and a reused failed configuration is refused at `begin_ceremony`; tests across calls and across a store reopen. The leakage test no longer proposes serializing `FrostRound2Transition`; secret-bearing types are asserted at compile time to implement neither `Serialize` nor `Deserialize`, and the public sealed envelope is what gets serialized and inspected |
| F5 contradictory actionable plans | P2, execution contract | the hardening spec's sequencing table still assigned Lane K the kernel `.inc` deletion, unsafe-lint remediation, `forbid`, the TCB deny set and possibly H7, while the dispatch forbade K production source; H2, H5, H7 and H10 carried stale passages; 9.4 was scheduled inside the candidate the response had promised to keep free of broad connection migrations | the hardening table is rewritten with the dispatch's Wave 2 table declared authoritative and every source remediation assigned to the crate's owning lane from K's measured lists; H2's classification and acceptance carry the two exclusion reasons and the unsafe canary; H5 calls an isolation-only failure a lead and its lane additive; H7 points at the design note and names the type split as the first task; H10's acceptance states that it covers identifiers only. 9.4 moves to the separately qualified successor candidate, with one in-candidate exception (a store whose phase-aware fence cannot be made safe), recorded in the addendum, the dispatch, the S brief and the requirement ledger |

**Gate limitation, negative assertions.** Accepted as stated: the gate is a
per-file net-count ratchet, and a change that strengthens one old assertion
while adding a weak one for a new boundary passes at an unchanged count. Its
docstring now says exactly that and names changed-test review as part of the
contract; pinning existing debt by site identity so new sites are rejected is
queued for Lane K after its current items. The Lane A ledger's "refuse new weak
assertions" was an overclaim and is corrected here.

## Execution habits

All three are real and are now rules, recorded in the orchestrator's memory so
they survive the session.

1. **Integration is transactional.** `/home/connor/lanes/tools/integrate.sh`
   requires a clean tree with no unfinished Git operation, applies an exact
   commit list, runs the gates on that tree, pushes only when every step passed,
   verifies the remote head, and on any failure resets to the recorded head and
   names the step. Conflicts are resolved separately and explicitly, then the
   script runs for the remainder. The sequence that pushed one of four intended
   commits could not have happened under it.
2. **Exit status is captured before any pipe.** Commands whose status matters
   redirect to a file and report `$?` on the next line, or use `pipestatus`; a
   status printed after `| tail` or `| head` is not evidence. The transcript
   contained an `apply --check rc=0` beside a failed apply; that line was
   false, and the rule exists because of it.
3. **Heavy Cargo work does not share a target directory.** Cargo serializes on
   the directory lock, so four lanes sharing one directory were one build queue
   in disguise. New lanes each get `/home/connor/chio-lanes-target-<lane>`,
   cold; the running lanes finish on the shared directory rather than being
   restarted.

The review's own gate, `review-gate.py`, had the F3 shape too: a production
file containing an inline `#[cfg(test)]` module was classified as a test file,
which hid every `unwrap` in its production half from the mechanical check. It
now classifies by path and counts inline test changes only when the diff adds
test items.

## What did not change

The lanes' direction. B's phase-aware recovery, C's exact aggregation contract
and D's rejection taxonomy were judged correct in substance; their remaining
work is completion and qualification, not redesign. The review's status table
is adopted as the honest description of where each lane stands, and the
distinctions it insists on (specification corrected, implemented, locally
verified, hosted qualification) are the vocabulary the ledger uses from here.
