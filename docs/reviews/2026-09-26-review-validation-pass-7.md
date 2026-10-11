# Review validation, pass 7, September 26, 2026

A second validation pass over passes 1 to 6, including pass 6 itself. Candidate
`3cd73631a18a6ec169b1e1a5bbd3ebe8bcb00130` plus the uncommitted Packet 1 tree,
which pass 7 confirmed has not changed since 2026-09-25 23:42 (33 dirty code
entries then and now, newest modification time 23:42:26, `HEAD` unchanged).

Pass 6 re-derived numbers. Pass 7 checked the record mechanically: every cited
`file:line` was tested for the token it claims, every tabulated figure was
recounted, both of pass 6's empirical results were re-examined for artifacts, and
pass 6's own arithmetic was audited. Corrections are applied in place in the
earlier documents; this is the record of what changed.

**Result: 127 line citations checked, 123 exact, 1 off by one, 3 wrong. Eleven
figures corrected that pass 6 had marked verified or introduced itself. One
finding (S1) becomes substantially stronger; one (P2) needs a qualifier on its
headline row; P8's retraction stands. Pass 6 committed three of the ten error
types it catalogued, including in its own headline.**

## Mechanical citation check

127 `file:line` citations across the seven documents, each tested for the token
the surrounding text attributes to it, with a tolerance of two lines.

| Outcome | Count | Detail |
| --- | --- | --- |
| Exact | 123 | |
| Off by one | 1 | `state_machine.rs:687`: the inverse *condition* is at `:686`, the `return` at `:687`. Wording changed to `:686-687`. |
| Wrong | 3 | `sandbox.inc:1074` should be `:1077` (inherited from the September 25 review and never checked; pass 6 repeated it). `sandbox.inc:1090` was a probe of mine, not a documented citation; the documented range `:1086-1094` is correct (`"seccomp_constraint"` is at `:1093`). `trait_impl.rs:1040` was likewise my probe; the documented `:1037` is exact. |

Everything else cited in passes 1 to 5 points at what it says it points at.

## Pass 6's empirical results, re-examined

| Pass 6 claim | Possible artifact | Re-check | Result |
| --- | --- | --- | --- |
| `rustfmt --check` would reformat 21 of 36 fragments | a non-zero exit could be a parse failure on a standalone fragment, not a format diff | classified stderr per fragment | 15 clean, **21 genuine format diffs, 0 parse failures**. Holds. |
| `EXPLAIN QUERY PLAN` shows `SCAN r` on the production shape | the DDL regex could have captured a legacy or migration variant of the table | counted `CREATE TABLE IF NOT EXISTS chio_tool_receipts` in `open.rs` | exactly one (`:548`); the six indexes are at `:579-589`. Holds. |
| All 59 lint escapes are test-scoped | one was matched by heuristic only | read `router.rs:806-813` | `#[cfg(all(test, unix))]`. Holds. |

## Corrections pass 6 missed or introduced

| Finding | Pass 6 state | Pass 7 | Kind |
| --- | --- | --- | --- |
| **Pass 6 headline** | "61 claims, 44 verified" | **53 rows tabulated: 36 V, 12 C, 1 R, 4 U.** The headline was written from memory, not counted. | pass 6 error, type 1 |
| **S1 receipt store row** | "connection poison mapped to error: yes" | `SqliteReceiptStore` holds `pool: Pool<SqliteConnectionManager>` (`receipt_store.rs:112`) and **has no connection mutex**. Its four `.lock()` sites guard `health.*`. Pass 6's correction of this row was itself wrong. | pass 6 error, type 6 |
| **S1 opening sentence** | "Every SQLite store wraps its connection in `std::sync::Mutex<Connection>`" | **18 of 31 store structs (22 files) do; 13 use a pool.** All 26 connection lock sites in the 18 map poison to a permanent error; none recovers. The 18 include the admission-operation, budget, revocation, security-state, serving-owner and tool-outcome stores. S1 is much stronger than "four stores" and its "inconsistent" framing was wrong: it is uniformly unrecovered. | overgeneralization, then undercount |
| **S2 file list** | "the files using the strict form are the market and finding ingress paths" plus four examples | **43 production files**, from a `head -12`; concentrated in `chio-cli` (10), non-security control-plane paths (7), `chio-finding` (4). Two are in `chio-store-sqlite`'s finding-market stores. **The central claim holds:** none in `chio-security-types`, `chio-quarantine`, `chio-secret-broker`, `chio-kernel` or `control-plane/src/security`. | pass 6 error, type 1 |
| **P2 headline row** | "Receipt append \| 0 prepare() \| benchmarked" | `receipt_store.rs` has zero; the append **path** reaches one `.prepare()` in `checkpoint_projection.rs:563` (`validate_adopted_claim_log_delta`), but only on the stale-head branch (`pre_delta > 0`, another writer adopted rows). The code's own comment at `receipt_store.rs:2830` documents the flat per-append cost in the single-writer case. Row qualified; conclusion unchanged. | file claim generalized to path |
| Q6 `deny_unknown_fields` | "94 sites" | **614 sites across 94 files.** `rg -c \| wc -l` counted files. | unit, type 2 |
| Q1 allowlist | "79 allowlist entries" | **77.** The count included the `def allow(` line and a ratchet-writer f-string template. | type 10 variant |
| T2 registry | "117 `ErrorCodeSpec` constants" | **114.** Three of the 117 `pub const` items are `REGISTRY_SCHEMA`, `REGISTRY_VERSION`, `REGISTRY_UPDATED_AT`. | type 2 |
| P1 scope | one query described | the `json_extract` financial aggregate appears in **four queries** in `analytics.rs` (`:35-36`, `:77-78`, `:131-132`, `:184-185`). The summary query is the one analyzed. | under-scoped |
| P8 line | `sandbox.inc:1074` | `:1077` for `map_or(&[][..], Vec::as_slice)`. The retraction's substance is unaffected. | inherited |
| Q3 line | `:687` for the inverse rule | `:686` (condition) and `:687` (return). | off by one |

## Re-verified without change

Every other figure recounted exactly: 57 / 46 assembled modules; 208 `include!`
sites; 79 fragments; 6 nested fragments; 112 `map_err(|_|)` (26 / 21 / 16 / 12 /
10 by file); 17 `StateMachineError` variants; 213 / 239 / 91 assertions; 243
domain declarations, 232 distinct, 8 duplicated, 14 unterminated; 420 / 0
`prepare` / `prepare_cached`; 43 / 55 / 13 / 11 / 8 per-path `prepare`; 121 / 80
hex-compare sites / files; the P7 allocation table (90 / 71 / 26 / 29 and the
other three rows); SAFETY ratios (11 / 11, 3 / 3, 38 / 39, 23 / 23, 22 / 25); 60 /
80 `SystemTime::now` files / sites; 64 / 72 tenant tables / unscoped statements;
61 `catch_unwind` call sites; 7 escape-hatch functions; 169 / 116 / 4 / 45 / 3
`Verified*` visibility split; the five `Verified*` spot reads
(`VerifiedCapability` 7 / 7 pub, no `Deserialize`; `VerifiedSecurityEvent` 9 / 9,
`Deserialize`; `VerifiedIsolationEvidence` 2 / 2, `Deserialize`;
`VerifiedApprovalSetBody` 12 / 12, `Deserialize`; `VerifiedCapabilityJson` 7 / 7,
`Deserialize`); `nono-upstream-chio` carries upstream's own README and layout,
consistent with an unmodified snapshot.

## Still unverifiable locally

`serde_json`'s default recursion limit of 128 (S5) is taken from the crate's
documentation. The locked version is 1.0.149 and its source is not in the local
cargo registry, so the constant was not read from source. The claim stands with
that label.

## Environmental note

Pass 7 first reported a resident `codex` process (pid 1648241) in
`/tmp/arc-security-launch`. That was wrong: `pgrep -f codex` matched the
orchestrator's own `zsh -c` wrapper, because the command text contained the word
"codex" in an `echo`. No Codex process is running; pass 1's statement was correct.
The tree is unchanged since 2026-09-25 23:42:26 (33 dirty code entries then and
now). The lesson is the one this lineage keeps relearning: a check whose search
term appears in its own command line is a check that matches itself.

## Net effect on conclusions

- **S1** is the substantive change: from "four stores brick, three recover" to
  "eighteen mutex-guarded stores including the authorization hot path, uniformly
  unrecovered; thirteen pooled stores including the receipt store are not exposed."
  Packet 10.1 and Packet 9.4 are updated to the census, and the pooled shape
  already in the tree is named as the target.
- **P2**'s conclusion (the benchmark measures the well-engineered path and the
  unmeasured paths are the hot ones) stands; its headline row now says "zero in
  steady state" rather than "zero".
- **S2**'s conclusion stands at 43 files; the TCB-absence claim survived the
  recount that could have killed it.
- **P8** stays retracted. **P1**, **Q1**, **Q5**, **R2** stand at pass 6's
  corrected values.

## On the method

Pass 6 catalogued ten error types and then committed three of them: a headline
figure written from memory (type 1), a `head -12` file list presented as complete
(type 1 again), and a lock-identity conflation in the very row it was correcting
(type 6). The lesson from pass 6 was "keep the script that produced a number and
assert against it." Pass 7 adds the corollary: **a correction is a claim, and gets
the same treatment as the claim it replaces.** The mechanical citation check
above is the first artifact in this lineage that could be re-run by someone else
without re-reading any of it, and it should be kept with the documents.
