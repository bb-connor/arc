# Execution review, pass 9, October 1, 2026

Review of everything executed against the September 26 plans: `07e963e8f5..a2630c20a1` on
`packet/3-retention-accounting` (112 commits including one merge, 4,493 files,
+341,132/-101,281 lines, of which `crates/` is +153,365/-97,596). The plans are the
[unrepresentable-defects design](../superpowers/specs/2026-09-26-unrepresentable-defects-design.md),
the [hardening toolchain spec](../superpowers/specs/2026-09-26-hardening-toolchain-spec.md), the
[FROST round-2 envelope design](../superpowers/specs/2026-09-26-frost-round2-envelope-design.md),
the [engineering excellence addendum](../superpowers/plans/2026-09-26-security-engineering-excellence.md),
the [dispatch plan](../superpowers/plans/2026-09-26-security-execution-dispatch.md), the
[working queue](2026-09-28-remaining-security-work.md) and the 21 batch plans dated September 28 to
October 1, each with its execution record.

Method. Twelve reviewers each took a disjoint slice: eleven reviewed commits against their plans and
execution records, and one audited the program as a whole. Each slice review is a separate document
below, with findings prefixed by slice. Every High finding and the Mediums with the widest blast
radius were then re-verified by an independent verifier instructed to refute them; two verifiers
ran probe tests and the real `chio` binary, and the orchestrator reproduced the CI failure. Every
verified finding survived, several with corrected details, recorded inline as "Independent
verification". Findings cite `path:line` at `a2630c20a1` unless they name another commit.

**Judgment: The security-critical cores are sound, the evidence around them is not yet proof, and
the reader census has stopped paying for itself. A simulated or unbound plan cannot reach live
dispatch; the lock-poison fence cannot be bypassed; budget transitions are checked and atomic in
SQL; uncaged native launch is gone with no flag that restores it; prepared broker calls are bound
to route, audience, process and arguments; the module refactors preserved behavior test for test.
Against that, no commit after `f25cd61f49` has run in hosted CI, and the last hosted run of the
required job was red before any new gate executed. The campaign introduced its own outages: five
High findings, of which four are regressions it created (a store that used retention cannot accept
receipts after the schema 7 upgrade, a remote MCP host that cannot restart after a crash, seven
provider adapters that refuse ordinary floats, five relay workflows broken by a key-file reader)
and one, a tip that did not compile the control plane, is already repaired. The reader campaign
proved four real tamper-evidence gaps in its first two days and none after the workspace-wide
census began; its headline metric can be driven to zero by editing a JSON file. Stop the census
outside the TCB, fix the regressions, and get the branch green in hosted CI before another batch.**

## Slice reviews

| Slice | Review | Commits | H | M | L | N | Verdict |
| --- | --- | --- | --:| --:| --:| --:| --- |
| Gates and toolchain | [GT](2026-10-01-execution-review-gates-toolchain.md) | 14, including `d51afb4a5f` | 0 | 5 | 7 | 2 | Sound gate design, not in effect: the required job is red at the tip and Miri, sanitizer and native lanes have never run |
| Response path | [RP](2026-10-01-execution-review-response-path.md) | 19 | 0 | 3 | 4 | 2 | Live-dispatch property holds; mechanism C undone at the kernel seam a day after it landed; recovery-side guards untested |
| Store and retention | [SR](2026-10-01-execution-review-store-retention.md) | 20 | 1 | 3 | 6 | 3 | Poison fence, exact analytics and writer accounting sound; schema 7 strands archived stores |
| Accounting and clocks | [AC](2026-10-01-execution-review-accounting-clocks.md) | 11 | 0 | 3 | 2 | 1 | Accounting sound and tested on real write paths; "one injected clock" not true yet |
| Signed input and FROST | [SF](2026-10-01-execution-review-signed-input-frost.md) | 8 | 0 | 1 | 6 | 2 | Parser closes duplicate keys and precision aliases at every depth; gate cannot see which mode a reader calls |
| Reader closures | [RC](2026-10-01-execution-review-reader-closures.md) | 3 | 0 | 2 | 7 | 0 | Authority core sound and mutation-checked; dispositions are boilerplate; one clock migration enables backdating |
| Module ownership | [MO](2026-10-01-execution-review-module-ownership.md) | 17 | 0 | 0 | 8 | 2 | Behavior-preserving; compiler now enforces owner privacy; helper crate short of minimal |
| Protocol boundaries | [PB](2026-10-01-execution-review-protocol-boundaries.md) | 7 | 1 | 5 | 8 | 0 | Bypasses closed; every task done with a defect; remote host cannot restart after a crash |
| Native consumers | [NC](2026-10-01-execution-review-native-consumers.md) | 6 plus native parts of 3 | 0 | 3 | 5 | 0 | Enforced launch and broker binding sound; native CI lane cannot pass |
| Product, CLI and provider readers | [PR](2026-10-01-execution-review-product-cli-provider-readers.md) | 4 | 2 | 4 | 3 | 1 | Real network-edge fixes; mass strict-decoder substitution broke providers and relay fixtures |
| Trust, guard, platform and economy readers | [TR](2026-10-01-execution-review-trust-guard-platform-economy-readers.md) | 4 | 1 | 3 | 8 | 1 | About ten real repairs; unplanned VirusTotal policy reversal; tip did not compile (repaired) |
| Campaign audit | [CA](2026-10-01-execution-review-campaign-audit.md) | all 112 | 0 | 9 | 3 | 1 | Value concentrated early; gates self-certifiable; status documents stale; branch unmergeable as one unit |
| **Total** | | | **5** | **41** | **67** | **15** | 128 findings |

## The five High findings

| ID | Claim | Introduced by | Verification |
| --- | --- | --- | --- |
| SR1 | A receipt store that rotated evidence into an archive before schema 7 stops accepting receipts after the upgrade; neither `retention_repair` nor `audit --repair` reopens it | `995b9f1c74` | Reproduced at runtime against a control case by the slice reviewer |
| PB1 | A remote MCP host that crashed holding a Ready session cannot restart once that session's idle deadline passes, and every later restart fails the same way | `cacaf69fc9` | Confirmed by independent trace; no test restarts after expiry |
| PR1 | Seven provider adapters parse responses, streamed arguments and tool results with the signing canonicalizer, so `21.0`, `0.0` and integers above 2^53-1 fail valid calls, including Chio's own serializer output | `6ef28e8f4d` | Confirmed by probe test and through `AnthropicAdapter::lift` |
| PR6 | Relay key files must be byte-canonical JSON at 0600; the committed fixture key and the xtask writer are pretty-printed at 0644, so five relay workflows fail | `82eec927b2` | Confirmed by running the real `chio` binary |
| TR1 | The tip did not compile `chio-control-plane` (two exhaustive matches missed new variants) | `a2630c20a1` | Repaired after the review tip in `66e9ecc5bd`; consumer check through `chio-cli` passed in `f6c8c39067`. Closed |

## Cross-cutting conclusions

### 1. Nothing in this range has been proven in hosted CI

The required `Build, lint, test` job runs the new gates, Clippy, the build and the tests in one job.
Its structural step fails at the tip before any of them run: `check-review-slices.py` rejects four
unclassified paths this range added, and the domain-separation and lint-parity self-tests fail
(GT1, CA1, reproduced by the orchestrator). The last hosted run, at `f25cd61f49` on PR #1160, was
red. The executing branch has no pull request, so the 64 commits after that have never run in
hosted CI. The Miri lane is not on `main` and has never run (GT3), the TSan lane covers none of the
concurrent code named for it (GT9), and the native fixture action cannot succeed (NC1). Every test
count in the execution records is a local count. The records' counts are accurate where sampled;
what they establish is local qualification, not enforcement.

### 2. Decode mode was chosen by habit, not by who produced the input

Measured by an independent probe against the real functions:

| Decoder | Rejects | Accepts |
| --- | --- | --- |
| `canonicalize` / `decode_external` | `21.0`, `0.0`, `10.00`, `1e+16`, integers above 2^53-1 | `0.50`, `1e-05`, `1e-5` |
| `decode_signed` | `10.00`, `0.50`, `1e-05`, `1e-5` | `21.0`, `0.0`, `9007199254740993` |
| `decode_document` | no numeric spelling | every valid number |

Neither strict mode accepts what ordinary serializers emit: Python `json.dumps` writes `1e-05`
(refused by `decode_signed`) and serde writes `10.0` for an `f64` (refused by `canonicalize`). The
later batches nonetheless applied strict modes to provider responses (PR1), SSE, MCP frames and
OpenAPI JSON (PB2), sidecar requests and operator policies (PR2), and unsigned key files (PR6),
with no positive test built from a real producer's output. The trust-boundary gate pins where an
`UntrustedJsonText` is constructed, not which method is then called, so a reader switched to
`decode_document` passes the gate (SF1), and a reader given the wrong strict mode passes it too.
The mode belongs to the producer: signed records Chio writes take `decode_signed` or
`decode_canonical`; third-party and operator documents take duplicate-key rejection with ordinary
numbers. Making the three contracts distinct types (SF8) would let the compiler hold that line.

### 3. The gates measure spellings, and the progress numbers inherit that

`check-trust-boundaries.py` passes after its JSON inventory is edited alone; setting all 45
remaining baseline entries to reviewed reports no errors (CA2). The census cannot see axum
`Json<T>` extractors, the main network ingress for signed documents in the control plane (CA3).
The clock gate misses function-path forms, `UNIX_EPOCH.elapsed()`, aliases and `SystemClock`
adapter calls (AC3), and the September 28 clock fix introduced seven `SystemClock` helpers it
cannot see (RC9). The hardening, wire-schema and hygiene gates each have lexical bypasses (GT6,
GT7, GT8). The design's acceptance count of hollow `Verified*` types was met partly by renaming
(CA5, RP8). The figures "447 to 45 baseline files" and "154 ambient clock sites" are counts of a
pattern, not of the problem.

### 4. The campaign created outages while closing plausible gaps

Besides the four High regressions above: a clock fault now ends every live MCP edge session (PB3);
an NTP step back is an API-protect outage for its duration (PR3); compliance certificates fail
above 4,096 receipts (PR5); a provider response with a repeated `Vary` is refused after the
provider acted, consuming a one-shot capability (NC2); a VirusTotal "never seen" now opens the
circuit breaker after five unseen URLs (TR2); challenge submission reads time before the body, so a
filing can be recorded up to about 30 seconds before it arrived (RC1); a production thread-local
fixed-time override now precedes every kernel authority-time read (AC1). Structured rejection was
undone at the kernel seam (RP2), and the secret broker gained 62 new cause-discarding `map_err`
sites against an explicit plan rule (CA6). The common cause is strictness added at an interface
without a positive test that exercises the interface's real callers or producers.

### 5. Over-production

About 10,000 of the 25,000 lines in the September 28 closures are inventory JSON whose per-owner
dispositions are mostly one repeated sentence (RC2); 164 lint allows share one boilerplate reason
(GT5); per-crate input helpers now repeat the same limits and readers across the workspace (31
such readers), and the copies already disagree on decode mode (PR4, TR4). The range commits 1,531 evidence files (18 MB) to a public repository, carrying local
home paths, Oracle Cloud instance and volume identifiers, a worker's private IP and a Tailscale IP
(CA10, NC6); no keys or tokens were found. Most of that evidence adds little proof beyond a
handful of summaries and manifests.

### 6. What is solid and should be preserved

The live-dispatch property and its type-enforced entry points (RP); the phase-aware poison fence,
91 real recovery cases (SR); checked budget transitions with SQL compare-and-set, tested against
real write paths (AC); the token-preserving parser itself, which rejects duplicate keys and
precision aliases at every depth (SF); the sealed FROST round-2 envelope with its full negative
matrix (SF); the enforced native launch path and prepared broker binding (NC); the closed
discovery and ACP/A2A passthrough bypasses (PB); the terminal authorization proof and its four
runtime-killed mutants (RC); the module refactors, with 845 test bodies and 219 selectors preserved
(MO); and the four tamper-evidence repairs listed below.

## The reader campaign: continue or stop

Packet 10.2 and the batches it spawned ran from `1e791271dc` (September 26) to `a2630c20a1`
(October 1): 18 commits that disposed 402 baseline reader files. Four pre-existing reader defects
were demonstrated with failing-first tests, all by September 27 and all inside the original S2
scope: stored receipt `raw_json` verified with a shadow duplicate key; forty signed economy export
readers that never verified on read; signed lineage returning another child's valid statement; and
keyring readers accepting noncanonical encodings. None is exploitable by an unprivileged party;
each needs write access to the store or keyring files, and each is a real gap in the product's
tamper-evidence promise. After the workspace census began at `f16d4e781c`, the reader batches
demonstrated no further pre-existing defect, closed about 45 plausible ones, and spent roughly
47,000 crate lines and 70,000 lines of evidence and documentation doing it (CA value tally). The
most security-relevant catch in that period, a Vertex guard that allowed content Vertex had
blocked, was found by reviewing the guard, not by the census.

Recommendation: finish the 13 baseline files inside TCB libraries, which are the original S2 scope
(CA4); reclassify the 22 tooling and observability files; stop the census for the rest. Spend the
effort instead on the network ingress the census cannot see (CA3) and on distinct decode-contract
types (conclusion 2).

## Before another batch

In order:

1. Make the required job green on a pull request for this branch: classify the four paths, repair
   the two self-tests, then fix whatever Clippy, build and test failures follow (GT1, CA1). Until
   then no gate in this range is enforced.
2. Fix the High regressions: SR1 (migrate or tolerate archived predecessors), PB1 (expire Ready rows
   before restore), PR1 and PB2 and PR2 (decode by producer, with positive fixtures from Python
   `json.dumps`, serde `f64` and pretty-printed operator files), PR6 (update the fixture key and
   the xtask writer, or relax canonical equality for unsigned seeds). TR1 is closed.
3. Fix the Medium regressions in conclusion 4, starting with RC1 and AC1, which weaken
   authority-time checks.
4. Make the trust-boundary gate pin the decode method per reader and stop it accepting inventory-only
   edits (SF1, CA2).
5. Decide what to do about the committed evidence identifiers before anything else is pushed
   (CA10, NC6), and keep raw logs out of the tree from now on: commit summaries and manifests,
   archive logs elsewhere.
6. Split the branch into stacked pull requests by plan before anyone attempts to merge it (CA9,
   RP9).
7. Bring the status documents back into agreement with the inventories, including
   `signed-json-boundaries.md`, which still describes three decode modes (CA8, TR10).

## Verification record

| Finding | Verifier verdict | Corrections |
| --- | --- | --- |
| SR1 | Confirmed (runtime reproduction with control) | None |
| PB1 | Confirmed, High | Fatal restore predates the range (`7e54c14a60`); `cacaf69fc9` made the constructor fallible |
| PR1 | Confirmed, High | Seven adapters, not six; rule is `canonicalize`; integer ceiling 2^53-1 |
| PR6 | Confirmed, High | Five workflows, not four; iroh half has no CI impact |
| TR1 | Confirmed; repaired in `66e9ecc5bd`, consumers verified in `f6c8c39067` | The broken commit was not pushed |
| GT1 | Reproduced by the orchestrator | None |
| PB2 | Confirmed, Medium | Exact site list recorded |
| PR2 | Confirmed, Medium | Guard policy loader (YAML) not affected; the affected JSON inputs are listed |
| RC1 | Confirmed | Enables backdating of a filing by up to about 30 s; verifier rates Low to Medium |
| NC2 | Confirmed, Medium | Repeated `Set-Cookie` is dropped, not rejected; `Vary`, `Cache-Control`, `Link` are rejected |
| TR2 | Confirmed, Medium | High for a deployment that selects `CircuitOpenVerdict::Allow` |
| SF1 | Demonstrated by the slice reviewer (in-memory mutation of three readers; gate passed) | None |
| CA2 | Demonstrated by the slice reviewer (inventory-only edit; gate passed) | None |

## Where the reviews attach

Each plan named above now ends with an "Execution review (October 1, 2026)" section that links the
slice review covering it, states its conformance verdict, and lists the open findings against it.
The working queue carries the ordered list above.

## Compliance and product-truth review (October 1, 2026)

The [compliance and product-truth review](2026-10-01-compliance-product-truth-review.md) re-verified at `122414b48e` the product defects behind the repository's compliance, security and supply-chain claims: 69 findings, 3 High. It is a separate review of product claims rather than of this range's execution, and it attaches to the same plans.

None of its findings duplicates a pass 9 finding; related IDs are cross-referenced inline (SR1, SR3,
SR6, SF4, PB6, PB9, PR5, AC6, CA2, CA9, GT1, GT10). Its High findings are AP1, KG1 and RL1.
