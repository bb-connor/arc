# Execution Record

What the roadmap in `10-roadmap.md` actually closed, and what it did not.

Phases 0 through 3 were executed on the branch `paper/roadmap-phase-0-1` in
fourteen commits, `84f2d3eaff` through `c76f19a062`, on top of `main` at
`fe5657020c`, the commit the review was written against. Phase 4 was not
executed. Every status below is judged against the tree at `c76f19a062`.

Of the 172 findings, 151 are closed, 15 are partly closed, and 6 are open.
`findings.json` carries the same verdict per finding in a `status` field, with
`closed_by` naming the commit.

## The commits

| Commit | What it delivered |
| --- | --- |
| `84f2d3eaff` | Phase 0 in full; the bulk of Phase 1: source, spec, registry, benchmark-harness and paper changes |
| `44170f9213` | Corrections to that change set, plus the paper-artifact CI gate |
| `4338338e08` | One measurement run on the Linux Neoverse-N1 host; regenerated ledger block and both PDFs |
| `8bb7b5e102` | Artifact manifest pinned at that measurement |
| `9f118535b6` | Phase 2.3, 2.4 and 2.7: the structural fail-closed theorems, the predicate-shape bridge, the treaty-path harnesses, the sibling Lean repairs |
| `aec4409984` | Corrections to the Phase 2 change set, plus Phase 2.5 |
| `b20144b8bd` | Phase 2.1: the cross-organization federation measurement |
| `a7f4897852` | Phase 3: `docs/papers/evidence-crosses`, the executed substitution corpus, a clean-tree guard on every benchmark driver, and a re-measurement under it |
| `85acf72cde` | The federation benchmark registered as PS-B04 and provenance-digested |
| `6e6e2f88f2` | Every benchmark re-measured on a clean worktree |
| `041aa18374` | The federation driver records its input tree digest |
| `1ce14c26ab` | The federation run re-measured with that digest recorded |
| `b13ceda988` | Both papers rebuilt against the clean-tree measurements |
| `c76f19a062` | Artifact manifest pinned at the clean-tree measurement |

## Phase 0: stop the bleeding

All four items landed in `84f2d3eaff`.

- **0.1 Freeze P2.** `docs/papers/bilateral-receipt-admission/README.md` is
  rewritten as a retirement note naming what the paper gets wrong about the
  shipped construction, pointing at the spec and at the surviving paper, and
  instructing that the sources not be rebuilt for distribution. The family
  index carries the same status.
- **0.2 Decide the measurement machine.** The Linux aarch64 Neoverse-N1
  workstation. Recorded in `CLAIM_LEDGER.md` under "Measurement environment",
  which also states that the MacBook Pro results are superseded and cited
  nowhere.
- **0.3 Venue metadata.** `paper-usenix.tex`, `README.md`,
  `supplementary/README.md` and `artifact-manifest.json` all read "USENIX
  Security 2027 (submission cycle to be confirmed)". The passed Cycle 1
  deadline is gone from P1.
- **0.4 Family index.** `docs/papers/README.md` lists every paper with its
  status, the Lean artifacts it cites, whether each of those is in the proof
  root or paper-local, and the venue metadata its source carries, followed by
  three rules governing theorem citation, the parent's title, and retired
  sources.

## Phase 1: make P1's evidence record true

Nine of the ten items landed. The change set is `84f2d3eaff` with corrections
in `44170f9213`; the run that populates it is `4338338e08`, re-measured on a
clean tree at `6e6e2f88f2` and pinned at `c76f19a062`.

- **1.1 Re-run on the chosen machine.** `run-bilateral-admission.sh` records
  CPU model, online cores, memory, kernel, rustc, the toolchain pin, the
  one-minute load average and a worktree-clean flag, on both Linux and Darwin,
  and refuses to run above a load ceiling. The retained run is the Linux host.
- **1.2 Generate the ledger from the results.** The measurement block in
  `CLAIM_LEDGER.md` sits between generated markers and is written by the same
  script that writes the inline macros. `--check` now asserts that the macro
  values occur in `pdftotext` of the pinned PDF and in the ledger, and that
  the environment record matches the results. `44170f9213` added
  `.github/workflows/paper-artifact-check.yml`, which runs the check on every
  pull request and push touching the covered paths.
- **1.3 Allow path, honest denial, sustained load.** A new allow fixture
  dispatches to the counting tool server with the counter asserted equal to
  the iteration count; the denial is described as a policy-summary early exit
  that never reaches the binding comparisons or the signature checks; a
  60-second sustained-load program reports calls per second with receipt-store
  growth.
- **1.4 Statistics.** Mean, standard deviation and a 95 percent bootstrap
  interval accompany every median. The deny, allow and receipt-append benches
  are timed per invocation; the remaining rows are labelled Criterion batch
  means and report a maximum rather than a p99. Sample counts rose from 20 and
  30 to 100 per path and 100 or more per component.
- **1.5 Rewrite section 5.** The section names `verify_treaty_dsse_evidence`,
  `verify_chio_bilateral_dsse_envelope` and
  `VerifiedFederationTreatyMaterial::verify` as the pre-dispatch verifiers with
  what each checks; peer pins, manifest freshness, the revocation epoch and the
  receipt store move to the offline buyer verifier, with the sentence that the
  hook does not call it; the continuation is consumed at admission and released
  only on pre-dispatch denial or abort; the admission-report digest is bound,
  not compared; budget follows the hook.
- **1.6 Real surfaces and real evidence.** Sections 5 and 6 state the
  five-surface split of the twenty negative cases. The manifest gained PS-T08
  (kernel tests), PS-T09 (durable admission over SQLite) and PS-T10 (the
  conformance byte-mutation suites), and PS-T06 was widened to the whole
  federation crate.
- **1.7 One ladder vocabulary.** The `quorum_required` aliases were removed
  from `chio-runtime-core`, the Lean constructor was renamed to `maintenance`,
  section 3 follows the spec and introduces quorum-required as a consistency
  model, and `formal/diff-tests/tests/ladder_mode_rank_diff.rs` asserts the
  rank functions agree on every input.
- **1.8 Spec to code.** `CHIO_BILATERAL_COSIGN_INVOCATION.md` accepts one
  predicate URI with the second reserved, requires exactly two signatures in
  every mode, carries the code-only codes, marks `consistency.anchor_unverified`
  and `consistency.quorum_underpopulated` reserved and not emitted, states the
  shipped signature-verification order, and renumbers the algorithm.
  `CHIO_LADDER.md` 6.3 rule 4 now states the fail-closed behavior and names the
  schema fields the runtime does not consult.
- **1.9 Proof registries.** `Treaty/ReceiptPredicate.lean` is a proof-manifest
  root file; its two theorems and the three `BilateralAccept` corollaries are
  in `formal/theorem-inventory.json`; `evaluate` and `refinesOn` are in the
  Lean mutation allowlist; `ASSUME-FEDERATED-ORIGIN-CLASSIFICATION` is
  registered in `formal/assumptions.toml`; and the assumptions table cites six
  registry identifiers by name.
- **1.10 JSON store release scoping.** Not done. `release_treaty_continuation`
  in `store/json.rs` and `store/memory.rs` still ignores the admission id and
  removes the continuation for any caller; only the SQLite store scopes the
  delete by both keys.

## Phase 2: build what the thesis needs

Three items landed in full (2.2, 2.3, 2.7), two with one piece outstanding
(2.4, 2.5), one in a reduced form (2.1), and one not at all (2.6). The Phase
2.2 corpus was committed alongside the paper it argues for, at `a7f4897852`.

- **2.1 The cross-organization experiment, on one host.** `b20144b8bd`,
  re-measured at `1ce14c26ab`. Three processes on the Linux workstation,
  origin, receiver and driver, each generating its own keys and owning its own
  stores, issuers, agreements, leases and receipt log, over iroh QUIC with
  relays disabled. The driver measures the admitted round trip, the receiver's
  own evaluation window, and evidence preparation; seven denial scenarios drive
  over the wire with the receiver's dispatch counter asserted zero; revocation
  is measured to the first denial at the connected peer and to a denial after
  one cut link, each over ten repeats with bootstrap intervals; freshness-window
  denials are counted and excluded rather than dropped. The bench driver derives
  its host count from the roles it starts and refuses to start a role whose host
  is not local, and the topology record reports one host. **This is not the
  two-host experiment the roadmap asked for.** It removes the shared address
  space, stores and key material; it does not remove the shared operating
  system or clock source. The request hop uses a transport defined for the
  experiment, because no shipped lane carries a tool call.
- **2.2 Security definitions and reductions.** Delivered in
  `docs/papers/evidence-crosses/sections/06-security.tex` at `a7f4897852`.
  Admission binding, receiver locality, single use and audience binding, each
  reduced to `ASSUME-ED25519`, `ASSUME-SHA256`, `ASSUME-CANONICAL-JSON` or
  `ASSUME-SQLITE-ATOMICITY`. The drop-a-field table is no longer an argument:
  `crates/kernel/chio-runtime-core/tests/runtime_treaty_binding_substitution.rs`
  builds an admissible bundle per case, substitutes one of the fifteen binding
  fields, re-signs with both participant keys, asserts both signatures verify,
  and drives it through the pre-dispatch hook. The corpus corrected two rows the
  argument had asserted: reversing the two signer identifiers is refused by
  envelope verification before the ordered comparison runs, and the
  admission-report digest is never compared, so a substitution of it is admitted
  and the receiver overwrites the field before signing.
- **2.3 Structural fail-closed theorem.** `9f118535b6`. Occurrence predicates
  for unsupported and undefined atoms, their characterization theorems, denial
  corollaries, an atom collector with exactness theorems, and a new
  `PredicateShape` module that lifts the receipt predicate language into the
  admission predicate language, proves denotation agreement on the supported
  and defined image, and records the three impossibilities that block a total
  correspondence.
- **2.4 Treaty-path harnesses.** `9f118535b6` and `aec4409984`. A libFuzzer
  target over `verify_chio_bilateral_dsse_envelope` with three pinned seeds; a
  dudect timing harness over the same verifier, corrected so both classes fail
  at the same gate with byte-identical curve inputs and sit at the host's null
  floor; cargo-mutants shards for the federation and runtime-core treaty paths,
  with the admission-hook shard following the directory so a module split
  cannot silently narrow it; and a crash-reopen test that drives continuation
  consumption across a store reopen, registered as PS-T11. The precedence test
  asserting the gate order under two simultaneous faults was not added.
- **2.5 Rejection code separate from diagnostic.** `aec4409984`. A
  `RejectionCode` set fixed at compile time with `VerifierError::redacted` and
  `BilateralCoSigningError::redacted`, `VerifierFailure::from_error`, and tests
  asserting that a tampered package's exported report carries
  `subject.digest_mismatch` and none of the package's digests, fingerprints or
  verdict strings. The spec's rule against exporting diagnostic detail now
  covers the co-signing protocol's own refusal reply. The claim is scoped in
  the ledger to what the tests establish: the iroh co-sign lane's
  `WireReply::Err` still carries a rendered detail beside its code.
- **2.6 Bounded model of the durable admission operation.** Not done. No
  Apalache or TLA+ model was added for the eighteen-state record.
- **2.7 Sibling Lean artifacts.** `9f118535b6` and `aec4409984`.
  `reversible-action/theorems.lean` elaborates against the current proof root
  with its headline theorem discharged and no `sorry`, and the paper's model
  section records the definitional bridges as such;
  `sensor-grounded-admission/lean/` is recorded as paper-local with an accurate
  axiom record, its supplementary archive regenerated so its byte-identity
  claim is true, and its manifest module path corrected.

## Phase 3: write the paper

`docs/papers/evidence-crosses` exists, at `a7f4897852`, rebuilt at
`b13ceda988`.

It follows the roadmap's plan: the title from the judge panel, the refund
scenario carried end to end from a real package fixture, the receipt as the
named primitive in its two forms, the nine-section plan, real authors and the
repository URL rather than a decorative anonymization, and a build gated on
page count, word budget, an em-dash check and a macro-freshness check. Every
quantity is read from a measurement macro or from `derived-macros.tex`, whose
generator names the artifact each count came from and fails when one drifts.
The related work adds the trust-management line, workload identity, token
exchange, interchain light clients and the agent protocols, and derives from
them rather than positioning against them.

Two of the roadmap's "must not claim" items are satisfied by construction: no
ladder mode is called quorum-required, and the "no shared kernel" claim is not
made, because 2.1 ran on one host. The paper's limitations open by saying so.

## Findings by area

| Area | Closed | Partly closed | Open | Total |
| --- | ---: | ---: | ---: | ---: |
| IMPL1, P1 implementation and evidence pointers | 19 | 0 | 1 | 20 |
| BENCH1, P1 measurement record | 14 | 2 | 1 | 17 |
| IMPL2, P2 implementation audit | 30 | 0 | 0 | 30 |
| FORM, formal evidence | 17 | 1 | 0 | 18 |
| HARN, harness and assumption discipline | 16 | 5 | 1 | 22 |
| XREF, cross-paper and spec consistency | 21 | 2 | 0 | 23 |
| PROSE, reader experience and structure | 27 | 5 | 3 | 35 |
| CRIT, completeness critic | 7 | 0 | 0 | 7 |
| **Total** | **151** | **15** | **6** | **172** |

Two qualifications on "closed".

**Seventy-eight findings are closed by retirement, not by repair.** Of the 82
findings whose target is P2, 78 are closed because the text they target is no
longer circulated or cited. P2's gate order, rejection-code taxonomy, wire
format, subject-digest definition, trust-store model, worked envelope, formal
sketch, benchmark numbers and bibliography were not corrected. The paper was
retired at `84f2d3eaff`, its README says why, and the family index forbids
circulating or citing it. The other four P2 findings were closed or partly
closed on their own terms, because their substance was a registry or harness
gap rather than P2 prose: FORM-18 and HARN-04 (register the three corollaries),
HARN-11 (a verifier-level timing harness), and FORM-08 (the Lean fail-closed
gap).

Where a retired finding also named a repository defect, the repository half is
reported above and is not closed by the retirement: the anchor-quorum policy
(FORM-15, XREF-06, HARN-01, IMPL2-16) was not implemented and is claimed by no
surviving paper; operator-attribution metadata (HARN-02, IMPL2-13, XREF-05) was
not implemented and P1's PS-A-01 wording stands; the code-versus-diagnostic
separation (IMPL2-07, HARN-10, PROSE-11, PROSE-25) landed for the in-process
verifier and the exported buyer report but not for the iroh lane; the precedence
ordering (HARN-22) has no test.

**Five findings are closed with no commit**, because the review confirmed the
text accurate and recommended no correction: IMPL1-14, IMPL1-18, FORM-09,
FORM-12 and FORM-17. Their `closed_by` field is absent.

## What is not closed

Twenty-one findings. None is blocked behind `origin/security/launch-integration`:
that branch touches no file under `docs/papers/`.

### Open (6)

| Finding | Why |
| --- | --- |
| IMPL1-16 | Not yet done: `run-replay-corpus.sh` still derives the generic corpus size from a test name rather than from the fixture count. |
| BENCH1-13 | Not yet done: the same script, the same line; the fallback parse would report the test count, not the fixture count. |
| HARN-16 | Not yet done: neither paper cites `runtime_admission_policy_exact` or the signer theorems with their mirror anchors. |
| PROSE-19 | Not yet done: P1's two disclaimers are still repeated throughout the paper rather than stated once in the threat model and once in the assumptions table. |
| PROSE-30 | Phase 4, not executed: P1's bibliography still carries 70 entries with the uncited legal-political set, the `sagaNDSS2025` key is unrenamed, the disowned sovereignty paragraph stands in section 7, and the directory name still says programmable-sovereignty. |
| PROSE-35 | Judgment left to the author: P1's Lean and differential-testing material is still section 4, before Implementation. The new paper places its formal section after security, which is the arrangement the roadmap prescribed. |

### Partly closed (15)

| Finding | What landed, and what did not |
| --- | --- |
| BENCH1-11 | The paper now says the matrix wall clock is dominated by one cargo invocation per case, and the replay script reports the generic and bilateral corpora separately. Both wall-clock numbers are still printed, and the second run's profile is still not named. |
| BENCH1-14 | The page gate anchors on the References heading registered from inside the bibliography environment, so it no longer misfires on body text. Whether 13 is the venue's body-page limit is a judgment left to the author and remains unconfirmed against the call for papers. |
| FORM-08 | The occurrence theorems force denial by induction over the predicate, so the six PredicateLang mutants can no longer be introduced against the current proof root. The Lean campaign has not been re-run, no Lean mutation report is retained under `formal/mutation/evidence/`, and the six issues are recorded as awaiting the next scheduled lane run. |
| HARN-07 | Sections 3 and 5 put budget admission after the hook. No test pins the ordering, so a reordering would not be caught. |
| HARN-09 | A crash-reopen test drives continuation consumption across a store reopen and is registered as PS-T11. The introduction's "each continuation can be consumed only once" is still unqualified as to store and concurrency. |
| HARN-12 | PS-T10 registers the conformance byte-mutation suites and PS-T06 was widened to the whole federation crate. P1's artifact table still does not cite the conformance suite as independent corroboration of the negative matrix. |
| HARN-14 | The new paper's admission section states durable before dispatch, receipt before response, and the release-or-retain disposition with an unconfirmed release recorded as ambiguous. Neither paper cites the Apalache invariants by name with their bounds. |
| HARN-15 | PS-T10 registers the signature-slice and PAE conformance suites as paper evidence. Neither paper's prose cites them. |
| XREF-18 | P1 now uses "buyer package" throughout and expands the pre-authentication encoding on first use. No glossary table maps each term to its code symbol and schema id. |
| XREF-23 | P1's four venue fields read "submission cycle to be confirmed". The sensor-grounded paper still names the passed Cycle 1 deadline in `paper-usenix.tex`, `supplementary/README.md` and `supplementary/proof-manifest.toml`, which is Phase 4 work; the actual submission status is a judgment left to the author. |
| PROSE-18 | The new paper adds the trust-management, workload-identity, token-exchange, interchain and agent-protocol references. P1's related work is unchanged, and neither paper cites the payment protocols. |
| PROSE-22 | The pre-authentication encoding is expanded on first use. No glossary paragraph was added to P1 section 3. |
| PROSE-29 | The new paper carries real authors and the repository URL, which is the decision the roadmap asked for. P1's anonymous author block and anonymous institution are unchanged, so the family still ships one decorative anonymization. |
| PROSE-31 | RQ4 reports the two corpora separately and RQ1 explains what dominates the matrix wall clock. Both times are still printed. |
| PROSE-32 | P1's abstract was rewritten around the admitted path, the real host and the corrected denial description. No separate insight sentence was added after the problem statement; the P2 half is moot under retirement. |

### Roadmap items with no finding attached

Three roadmap actions were not delivered and are not represented in the counts
above, because the review raised them as verifier notes or judge priorities
rather than as numbered findings.

- **1.10.** `release_treaty_continuation` in the JSON and in-memory admission
  stores still ignores the admission id. Only the SQLite store scopes the
  delete by continuation and admission together. The single-use argument in
  `06-security.tex` states the scoped behavior, so it holds for the SQLite
  store and overstates the other two.
- **2.4, in part.** No precedence test asserts the gate order under two
  simultaneous faults.
- **2.6.** No bounded model of the eighteen-state durable admission operation.

## Measurements

Every number in the review's own tables was superseded. The review found three
disagreeing records of the same benchmark: the committed PDFs, built
2026-07-26, printed a Linux run; the retained result files and the TeX macros,
replaced on 2026-08-01 by commit `0c01448309`, printed a later MacBook Pro run;
and the prose described the Linux server while compiling the laptop's numbers.
The review's own rerun on the Linux host agreed with neither file set.

There is now one record. The retained results, the ledger, the environment
file, the macros, both PDFs and the artifact manifest all come from one run, on
one host, at one commit, on a clean worktree, and the artifact check fails if
any of them disagrees.

### Local admission

The final column is the run recorded at `a7f4897852` and committed at
`85acf72cde`. Two earlier runs on the same host were superseded: the one
committed at `4338338e08` measured 11.173 ms p50 for the denial, 15.933 ms for
the allow and 2.390 s for the workflow, and the one committed at `a7f4897852`
measured 7.423 ms, 14.140 ms and 2.097 s. All three record a clean worktree.
The first of them sits within half a percent of the July Linux run's 11.124 ms
and close to the review's own 10.43 ms rerun, which settles the question the
review raised about which machine produced which number.

| Measured path | Committed PDFs (Linux, 26 Jul) | Retained files (MacBook Pro, 1 Aug) | Review rerun (Linux host) | Retained run |
| --- | ---: | ---: | ---: | ---: |
| Pre-dispatch admission, allow | not measured | not measured | not measured | 13.863 ms p50, 26.176 ms p99, n = 200 |
| Pre-dispatch admission, denial | 11.124 ms p50, 20.530 ms p99 | 4.115 ms p50, 9.790 ms p99 | 10.43 ms p50, 17.05 ms p99 | 7.073 ms p50, 18.646 ms p99, n = 400 |
| Complete buyer workflow | 2.488 s p50, 3.291 s p99 | 2.370 s p50, 3.379 s p99 | 2.51 s p50, 2.56 s p99 | 2.089 s p50, 2.142 s p99, n = 100 |
| Producer workflow | 2125.243 ms p50 | 1858.068 ms p50 | 2.23 s p50 | 1820.939 ms p50, n = 100 |
| Receipt sign | 234.322 us | 134.705 us | 231 us | 229.340 us median, 270.205 us max |
| Receipt verify | 337.792 us | 142.327 us | 338 us | 337.470 us median, 344.582 us max |
| Strict bilateral DSSE verify | 436.660 us | 101.079 us | 339 us | 339.127 us median, 350.904 us max |
| Cross-boundary admission allow | 20.487 us | 14.389 us | 20.6 us | 20.688 us median, 21.207 us max |
| SQLite receipt append | 7841.308 us | 3186.111 us | 7.95 ms | 4681.643 us p50, 13566.644 us p99, n = 500 |
| Offline buyer package verify | 50363.443 us | 15164.363 us | 49.8 ms | 49703.524 us median |
| Negative matrix wall clock | 15.7 s | 10.7 s | not reported | 14.3 s |
| Bilateral replay wall clock | 14 s | 11 s | not reported | 14 s |
| Buyer package | 51,843 bytes | 51,843 bytes | 51,843 bytes | 51,843 bytes |
| Sustained load | not measured | not measured | not measured | 3,543 calls in 60 s, 59.0 calls/s, 41,039.3 KiB store growth |

Method, before and after:

| | Before | After |
| --- | --- | --- |
| Host in the prose | Linux/aarch64, eight Neoverse-N1 cores, 49.2 GB | read from the macro file |
| Host in the environment record | Darwin 25.4.0, T6000, no core count, no memory | Linux 6.17.0-1020-oracle aarch64, Neoverse-N1, 12 cores, 46.9 GiB, load 3.93 |
| Toolchain | rustc 1.93.0 recorded, 1.94.1 pinned by the repository | rustc 1.94.1, matching the pin |
| Samples | 20 per workflow path, 30 Criterion batch means per component | 100 per path, 100 Criterion samples, 200 to 500 timed invocations on the per-invocation paths |
| Dispersion | none; p99 was the largest of 20 or 30 samples | mean, standard deviation and a 95 percent bootstrap interval on every row; p99 only where it is a true percentile over 100 or more samples |
| Worktree state at measurement | unrecorded | recorded, and the drivers refuse to measure a tree with uncommitted changes to their inputs |
| Artifact gate | per-file hashes only; green over a manifest that pinned July PDFs beside August results | also asserts the macro values against the ledger, the pinned PDF text and the environment record, and runs in CI on every commit touching the covered paths |

Two things follow. The substantive addition is the allow path: the cost an
admitted call pays in the hook, with a real dispatch and the counter asserted,
which no earlier run measured. And the review's second reading holds: the
denial is dominated by the durable receipt, not by treaty verification. The
SQLite append at 4.682 ms p50 is 13.8 times the 339 us envelope verification
and 226 times the 20.7 us decision over resolved evidence.

The three Linux runs of the denial path, 11.173 ms, 7.423 ms and 7.073 ms, span
37 percent with no change to that path between the last two. The harness now
reports the interval that shows this rather than a single median, and the
retained run's 95 percent interval on the mean is 8.061 to 9.620 ms.

### Cross-organization admission

New in this execution; there is no before. Four runs were taken. The first
predates the paper. The second is the one the paper first compiled from, and
its environment record marks the worktree modified, because the local benchmark
that ran before it had already written its own result files. `85acf72cde`
scoped the uncommitted-changes guard to each benchmark's own inputs so a
preceding run's results could not block it, `6e6e2f88f2` re-measured on a clean
tree, and `1ce14c26ab` re-measured again once the driver recorded its input
tree digest. Only the last is cited.

| Run committed at | Records commit | Worktree | Admitted p50 | Denied p50 | Revoke to deny p50 | Cut to deny p50 | Absorbed |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |
| `b20144b8bd` | `aec4409984` | clean | 197.683 ms | 58.616 ms | 406.050 ms | 932.471 ms | 67 |
| `a7f4897852` | `b20144b8bd` | modified | 203.809 ms | 58.323 ms | 430.385 ms | 928.304 ms | 84 |
| `6e6e2f88f2` | `85acf72cde` | clean | 201.601 ms | 56.438 ms | 426.963 ms | 726.618 ms | 114 |
| `1ce14c26ab` | `041aa18374` | clean, input digest recorded | 206.803 ms | 58.821 ms | 322.899 ms | 744.681 ms | 88 |

The retained run, in full:

| Quantity | Value |
| --- | --- |
| Admitted round trip at the driver | 206.803 ms p50, 234.520 ms p99, mean 207.920 ms [205.924, 209.998], n = 100 |
| Receiver evaluation window | 203.787 ms p50 |
| Evidence preparation at the driver | 3.297 ms p50 |
| Denied round trip | 58.821 ms p50, 88.462 ms p99, n = 140 over 7 scenarios, dispatch counter zero |
| Revoke to first denial | 322.899 ms p50 over 10 repeats, 67.612 to 437.435 ms, median 2 calls |
| Cut link to denial | 744.681 ms p50 over 10 repeats, 476.237 to 1093.769 ms, median 2 calls |
| Freshness denials absorbed | 88: 0 admitted, 3 denied, 85 revocation |
| Co-signing connections per admitted call | 3, measured rather than asserted |
| Epoch clock | 250 ms nominal tick, 250 ms achieved median over 193 intervals, 500 ms freshness window |
| Topology | 1 host, 3 processes, iroh QUIC with relays disabled |

The seven denial scenarios are `chio_treaty_missing_scope`,
`chio_treaty_scope_hash_mismatch`, `chio_treaty_missing_intersection`,
`chio_treaty_intersection_mismatch`, `chio_treaty_missing_required_evidence`,
`request_smuggled_trust_root` and `request_smuggled_dynamic_trust`. The same
admission with both kernels in one process costs 13.863 ms, so the boundary
cost is the three synchronous co-signing round trips rather than verification.

The commit message on `b20144b8bd` quotes the first run's numbers. They were
superseded three runs later; cite the retained run instead.

## What this execution did not do

It did not run the two-host experiment; the cross-organization measurement is
three processes on one machine, and both the new paper's evaluation and its
limitations say so. It did not model the durable admission operation. It did
not reduce the iroh co-sign lane's refusal reply to a code. It did not scope
the JSON and in-memory continuation release by admission id. It did not touch
P2's sources beyond the retirement note. It did not execute Phase 4: the
sibling venue metadata, P1's bibliography, the P1 directory name and the
sovereignty paragraph are unchanged.
