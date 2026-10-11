# Review validation, pass 6, September 26, 2026

Every quantitative or factual claim from passes 1 to 5 re-derived from source at
`3cd73631a18a6ec169b1e1a5bbd3ebe8bcb00130` plus the uncommitted Packet 1 tree.
Where a script produced a number, the script was re-run. Where a claim rested on a
prior review's description, the code was read directly. Two claims were tested by experiment and two by exhaustive read rather than by sample. Corrections have been applied in place to
the earlier documents; this report is the record of what changed and why.

**Result: of 53 claims tabulated, 36 verified as stated, 12 corrected, 1 refuted, 4
upgraded from inferred to empirically confirmed. (Pass 7 corrected this sentence:
the first version said 61 and 44, written from memory rather than counted, which is
error type 1 in the list below.) No headline finding reversed
except P8, whose core claim was wrong. Three findings became stronger. The most
important correction is to my own pass 4 finding S1, whose "three stores recover"
framing was based on the wrong locks.**

## Empirical tests run this pass

| Test | Result |
| --- | --- |
| `rustfmt --check` directly on 36 `.inc` fragments, versus `cargo fmt --all -- --check` | `cargo fmt` flags 18 files, all in Codex's uncommitted set, **zero `.inc`**; `rustfmt` would reformat **21 of 36** fragments. Q1's rustfmt blind spot is confirmed, not inferred. |
| `EXPLAIN QUERY PLAN` on the analytics predicate shape, against the repository's own `chio_tool_receipts` DDL and all six indexes, SQLite 3.50.4 | Production shape: `SCAN r` with `capability_id` bound, and again with a timestamp range bound. Direct-predicate shape: `SEARCH r USING COVERING INDEX idx_chio_tool_receipts_grant`. P1's index claim is confirmed. Caveat: empty table after `ANALYZE`; the mechanism is structural, not statistical. |
| All 59 `unwrap_used`/`expect_used` allow-escapes, context read | 59 of 59 on `#[cfg(test)]` items (58 by pattern, 1 confirmed by hand at `router.rs:812`, `#[cfg(all(test, unix))]`). Q6 had spot-checked 4. |
| The fourth `pre_exec` closure, `verified_fix_sandbox.rs:179` (`write_current_pid`), not read in pass 2 | Stack buffer, manual decimal formatting, raw `libc::write` loop, `last_os_error()`. Async-signal-safe. All four closures are now confirmed. |

## Claims by pass

Status key: **V** verified as stated, **C** corrected, **R** refuted, **U** upgraded.

### Pass 1 (Q)

| Claim | Original | Verified | Status |
| --- | --- | --- | --- |
| Hygiene gate walks `(".rs", ".md")` at line 53 | as stated | same | V |
| Assembled modules via `include!`; over the 2,000 cap | 57; 46 | 57; 46 | V |
| `tests.rs` 40,754/80; `security_state.rs` 13,473/49; `service.rs` 5,087/3; `ports.rs` 5,033/4; `finding_challenge_store.rs` 6,031/731; `finding_challenge_coordinator.rs` 7,173/1,270 | as stated | identical | V |
| 208 `include!` sites, 79 TCB fragments, 6 nested | as stated | 208; 79 | V |
| `cargo fmt` does not visit `.inc` | inferred from rustfmt behavior | empirically confirmed (above) | U |
| Four other gates match `{".rs", ".inc"}` | as stated | same | V |
| Q2 `ResponseExecutionBinding` pub fields, detached `validate()` | as stated | same | V |
| Q2 `PortError::invalid_data()` "discards the observed version" | as stated | accurate; note it does carry `kind` and an ad-hoc `code` string | V |
| Q3 enforcement surface | "six hand-placed call sites" | **five** call sites plus the definition (`response.rs:268`) | C |
| Q3 duplicated inverse rule at `:684` / `:687` | as stated | same | V |
| Q4 `Option<ResponseExecutionBinding>`; `authorization_body()` covers `execution` | as stated | same | V |
| Q5 three unrelated `Clock` traits | as stated | same | V |
| Q5 direct `SystemTime::now()` in production security files | "roughly twelve files" | **60 files, 80 call sites** (test, kani and process-boundary fixtures excluded) | C |
| Q6 allow-escapes all test-scoped | 4 of 59 sampled | 59 of 59 | U |
| Q6 `deny_unknown_fields` gaps are fieldless enums | claimed for both files | true for `chio-keyring/src/store.rs`; **false** for `chio-decoy/src/materialize.rs`, which derives `Deserialize` on three structs (`MaterializationIdentity`, `FileOwnershipProof`, `MaterializationReceipt`). No parse site found inside the security crates; severity unresolved, low | C |
| Q6 zero em dashes; cage `prlimit64` fix; broker `credential_version` fence | as stated | same | V |

### Pass 2 (R)

| Claim | Original | Verified | Status |
| --- | --- | --- | --- |
| R1 `[profile.release]` lacks `overflow-checks`; lints deny only `unwrap`/`expect`; dev/test keep checks (comment line 333) | as stated | same | V |
| R1 guards at `in_memory/terminal.rs:649,709`; `trait_impl.rs:972`; `composite/.../terminal.rs:57,67` plus SQL `:91` | as stated | same | V |
| R2 `map_err(\|_\| ...)` discards in quarantine plus coordinator | 112 | 112 | V |
| R2 `StateMachineError` variant count | 12 | **17** (`head -30` truncated the enum). The five missed include `Shape(#[from] ResponseShapeError)` and `Store(#[from] PortError)`: source-preserving variants exist in the same enum the new code bypasses | C |
| R2 `InvalidDispatch` production sites in `state_machine.rs` | 6 sites, "six distinct rules" | **6 return sites** (`:685, :687, :696, :707, :715, :878`) covering **at least 11 distinct conditions**; the `\|\|` at `:689-696` alone carries six | C |
| R3 negative assertions weak/mid/strong | 213 / 239 / 91, 39% | 213 / 239 / 91, 39% | V |
| R4 domain declarations; duplicated values | 243; 8 | 243 declarations, 232 distinct values; 8 duplicated | V |
| R4 unterminated domains | 13 | **14** | C |
| R4 specific duplicate locations | as stated | same | V |
| R5 `pre_exec` closures async-signal-safe | 3 read | 4 read, all clean | U |
| R5 `KillProcess` re-asserted at 3 boundaries; arch check `:1043`; SAFETY ratios; schema exact-equality 0 / 13 | as stated | same | V |

### Pass 3 (P)

| Claim | Original | Verified | Status |
| --- | --- | --- | --- |
| P1 `json_extract` per row; `cost_charged_be BLOB` at `open.rs:569`; six indexes `:579-589`; no `LIMIT` | as stated | same | V |
| P1 optional-filter shape defeats the indexes | "generally prevents" | **confirmed by `EXPLAIN QUERY PLAN`** (above) | U |
| P2 one benchmark; `receipt_store.rs` has zero `.prepare()` | as stated | same | V |
| P2 per-path `.prepare()` counts | security state 33; budget 31 | **security state 43; budget store 55** (pass 3 summed only the files that made a `head -18` list). Commit chain 13, revocation 11, admission `part_01` 8 verified | C |
| P3 `.prepare()` / `.prepare_cached()` | 420 / 0 | 420 / 0 | V |
| P4 `Mutex<Connection>` in fiscal, purchase, decoy, challenge stores | as stated | same; `finding_challenge_store.rs:658` confirmed on the connection | V |
| P5 duplicate `ensure_open_hold` read | as stated | same | V |
| P6 hex-encode-to-compare | "80 sites" | **121 sites across 80 files** (pass 3 reported a file count as a site count) | C |
| P7 clone/`to_string` density table | as stated | same | V |
| P8 no check that constraint keys are a subset of allowed syscalls | "I could find no check" | **Refuted.** `sandbox.inc:1086-1094` rejects any plan whose `argument_constraints` key is not in the allowed set (`SeccompInstallFailed`, `"seccomp_constraint"`), and `:1068-1073` rejects an allowed name with no syscall number. A typo fails the launch; it does not weaken the filter. `:1077` (absent constraints compile to an unconditional allow; pass 7 corrected the line from the inherited `:1074`) is accurate, and irrelevant given the subset check. P8 downgraded to Low: residual is compile-time versus launch-time typing and the test helper's string-literal `remove("prlimit64")` | R |
| P8 removal by string literal at `part_02.rs:1398` | as stated | same; it is a test-fragility point, not a security one | V |

### Pass 4 (S)

| Claim | Original | Verified | Status |
| --- | --- | --- | --- |
| S1 four stores map connection-mutex poison to a permanent error, no `catch_unwind` | as stated | same | V |
| S1 "three stores recover" (`authority.rs`, `receipt_store.rs`, `finding_status_store.rs`) | recovery counted per file | **Wrong locks.** `authority.rs:694,718` recover a `cached_public_key` mutex; `receipt_store.rs:1407` recovers `health.last_error`; `finding_status_store.rs:1791,1807` are `into_inner()` on an owned value, not poison recovery. **No SQLite connection guard in any store recovers from poisoning.** The receipt store is pool-based and has no connection mutex (pass 7 corrected this row's "mapped to error: yes"); 18 store structs across 22 files do, all mapping poison to error. Finding simplified and strengthened | C |
| S1 `catch_unwind` production sites | 36 | **61** call expressions (36 undercounted; comment lines excluded now) | C |
| S1 `panic = "unwind"` in release | as stated | same | V |
| S2 strict canonicalization call sites | 112 | **91** (112 counted `use` lines and doc mentions); typed-value sites roughly 2,764 including tests | C |
| S2 strict form used by market/finding ingress, none of the security TCB crates | as stated | same | V |
| S3 tenant-scoped tables; unscoped statements | 64; 72 | 64; 72 across 27 files, 17 of them in `finding_pool_ledger` singleton tables | V |
| S3 keyring derives its id at `enterprise_receipt.rs:414`; tool receipt id provenance unresolved | as stated | same, still open | V |
| S4 triggers at `open.rs:1361,1376,1379,1400`; value verified at `checkpoint.rs:1946`; export cross-check `:463`; columns bare `TEXT` | as stated | same | V |
| S5 vendored forks | "14 forks" | **12 forks**, plus `nono-upstream-chio` (unmodified upstream mirror) and `provenance/` (records), which are not forks | C |
| S5 `serde_json` 128 recursion default intact; broker bounds at `protocol.rs:15-24` | as stated | same | V |

### Pass 5 (T)

| Claim | Verified | Status |
| --- | --- | --- |
| 169 `Verified*`/`Authorized*` named-field structs; 116 private, 4 crate-visible, 45 all-`pub`, 3 mixed | re-run with `pub` and `pub(crate)` split | V |
| 18 all-`pub` in TCB crates; 4 derive `Deserialize` | re-run | V |
| Two error-code registries; security-types has no `chio-errors` dependency; 5 ad-hoc codes; 114 registered (pass 7: 117 counted three registry-metadata constants) | direct reads | V |
| 7 escape-hatch functions | direct grep | V |

## How the errors happened

Recorded because the error types are more reusable than the individual fixes.

1. **Head-truncated lists reported as totals.** Q5 (`head -12` became "roughly
   twelve"), P2 (per-path sums over a `head -18` list). Three counts, all
   undercounts, one of them five-fold.
2. **Unit confusion.** P6 reported `rg -c | wc -l`, a file count, as a site count.
3. **Lines counted instead of call sites.** S2 (imports and docs inflated 91 to
   112); S1 (`catch_unwind` undercounted 61 as 36 by a different miscount).
4. **Sample generalized to population.** Q6 spot-checked 4 of 59 escapes and
   stated a result for all 59 (it held); Q6 checked one of two
   `deny_unknown_fields` gap files and stated a result for both (it did not hold).
5. **Inference presented as search result.** P8 stated "I could find no check"
   after searching for the wrong identifiers. The check exists twelve lines below
   the line I had read.
6. **Lock identity conflated.** S1 counted every `into_inner()` in a file as
   connection-poison recovery. None was.
7. **Truncated enum read.** R2 counted the first 12 variants of a 17-variant enum.
8. **Verification scripts with their own bugs, caught in this pass.** A stale
   rustfmt output format produced 24 files and an invalid cross-reference (true:
   18, all uncommitted); a Python escaping error produced "232 unterminated" (true:
   14 of 232 distinct). Both were noticed because the numbers disagreed with the
   pass they were checking.
9. **Off by one.** R4 unterminated 13 versus 14.
10. **Definition counted as a call site.** Q3 "six" included `fn
    require_execution_mode` itself.

Every one of these is a convention-enforced check that failed, which is the defect
class the whole lineage is about. The remedy is the same: where a number matters,
the script that produced it is kept, re-run, and asserted against, not typed into
prose from a terminal.

## Claims that remain as stated, with their labels

- The per-operation cost model (Ed25519 and `fsync` dominate) is general knowledge
  and unmeasured; P2 says exactly that and 9.1 exists to measure it.
- S3's `chio_tool_receipts.receipt_id` provenance is unresolved by design; Packet
  10.3 resolves it before scheduling remediation.
- S2 deliberately does not claim a live bypass; the finding is the absence of a
  policy.
- R1's guard survey covers four sampled subtractions, not all 632
  `saturating_*`/`wrapping_*` occurrences; correction 3A owns the sweep.
- Codex's five P1 findings and remediation claims were verified only where sampled
  (cage `prlimit64`, broker `credential_version`). The rest remain Codex's
  self-review, as every pass has said.

## Net effect on conclusions

- **Q1** stronger: the rustfmt blind spot is measured (21 of 36 fragments), not
  inferred.
- **Q5** stronger by five times: 60 files and 80 sites, not twelve.
- **P1** stronger: the full scan is observed in the planner, not argued from the
  predicate shape.
- **S1** simpler and stronger: zero connection guards recover; the receipt store's
  `catch_unwind` wrap is the working pattern to copy, not a poison-recovery site.
- **R2** sharper: a source-preserving variant existed in the same enum and the new
  code bypassed it with `map_err(|_|)`.
- **P8** retracted to Low. Correction 2B in the addendum reduced to compile-time
  typing and test-helper drift.
- Everything else stands at the corrected numbers.
