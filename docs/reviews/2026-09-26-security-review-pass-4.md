# Security review, pass 4, September 26, 2026

Reviewed candidate: `3cd73631a18a6ec169b1e1a5bbd3ebe8bcb00130` on draft
[PR #1160](https://github.com/bb-connor/arc/pull/1160).

Fifth review in the lineage. New ground: panic and lock-poison recovery,
canonical-serialization entry-point discipline, multi-tenant query scoping,
parser differentials on signed data, and the vendored forks inside the TCB. Prior
passes: September 25 boundary review (P1/P2 series, retained outside the tree),
[quality pass 1](2026-09-26-security-code-quality-review.md) (Q),
[pass 2](2026-09-26-security-code-quality-review-pass-2.md) (R),
[performance pass 3](2026-09-26-security-performance-review-pass-3.md) (P).

Findings are numbered `S`.

**Judgment: this pass found the strongest single piece of engineering in the
codebase and the weakest form of a property it already gets right. The canonical
JSON implementation defeats the render-A/sign-B signature class deliberately and
documents why, which is better than most production cryptographic code. The
recurring weakness is the same one every pass has found in a different costume: a
correct primitive plus a hand-discipline requirement about where to use it.**

Four of my working hypotheses this pass turned out to be wrong on inspection, and
each is recorded as such. The code is repeatedly better than the suspicion.

---

## S1. Medium-high: every mutex-guarded store (18 of 31) maps connection poison to a permanent error, and none recovers

Eighteen of the 31 SQLite store structs (22 files) wrap a single connection in
`std::sync::Mutex<Connection>`, which poisons when a thread panics while holding
it. The other 13, including the receipt store, use a `Pool<SqliteConnectionManager>`
and are not exposed to this (pass 7 census; the first two versions of this finding
said "every store" and then "four stores"). After poisoning, every subsequent
`lock()` returns `Err` forever, for the life of the process.

The handling is not uniform:

| Connection strategy | Stores | Connection poison recovered | Connection poison mapped to a permanent error |
| --- | --- | --- | --- |
| `std::sync::Mutex<Connection>` | 18 structs, 22 files, 26 lock sites: admission-operation, budget, caller-execution ledger, channel lifecycle, channel release publisher, economic-state cache, enterprise migration state, finding challenge, finding market, finding purchase, finding recovery, finding status, fiscal, FROST, revocation, sealed decoy registry, security state (incl. participant source), serving owner, tool outcome | **0** | **26 of 26** (for example `fiscal_store.rs:177`, `finding_purchase_store.rs:397`, `sealed_decoy_registry.rs:58`, `finding_challenge_store.rs:658`) |
| `Pool<SqliteConnectionManager>` | 13 structs, including `SqliteReceiptStore` (`receipt_store.rs:112`), approval, batch approval, dead letter, encrypted blob, execution nonce, finding operator bundle, finding payload, finding pool ledger, governed approval replay, IOU envelope, memory provenance | not applicable | not applicable; the receipt store additionally wraps writer jobs in `catch_unwind` (`:1184`, `:1252`, `:1508`, `:1980`, `:2243`) |

(Pass 6 corrected the first table, which had credited `authority.rs`,
`receipt_store.rs` and `finding_status_store.rs` with poison recovery on locks that
were not the connection. Pass 7 replaced pass 6's table in turn: its receipt-store
row said "connection poison mapped to error: yes", and the receipt store has no
connection mutex. The census above is the third version. **No SQLite connection
guard in any store recovers from poisoning, and the exposed set is the
authorization hot path, not four peripheral stores.**)

`fiscal_store.rs:177` maps a poisoned lock to
`invariant("fiscal store lock is poisoned")` and nothing ever clears it.
`sealed_decoy_registry.rs:58` maps it to `PortError::unavailable()`. So one panic
anywhere inside a fiscal-store critical section permanently disables the fiscal
store, and the same for the purchase store, the decoy registry and the challenge
store. Pass 7's census extends this to all 18 mutex-guarded stores, including the
admission-operation, budget, revocation, security-state, serving-owner and
tool-outcome stores on the per-authorization path. `panic = "unwind"` in the release profile guarantees the poison actually
happens rather than the process aborting and restarting clean.

This is fail-closed, which is the correct direction, and it is also a total
unrecoverable denial of service on a money path that requires operator
intervention to clear.

**The part that matters most, and it is a correction to my own earlier advice.**
Pass 2 finding R1 recommended `overflow-checks = true` in the release profile.
That recommendation stands, but applied on its own it **adds panic sites to
arithmetic inside store critical sections**, which converts a silent budget wrap
into a permanently bricked store. A silent wrap grants authority and a bricked
store denies service, so the trade is still worth making, but the two changes
belong together: enabling overflow checks without fixing poison recovery in these
four stores would trade a correctness bug for an availability bug rather than
eliminating one.

**What is not wrong, and is a correction to my working hypothesis:**
`catch_unwind` is used at **61 production call sites**, including five in the
receipt store writer actor (`receipt_store.rs:1184`, `:1252`, `:1508`, `:1980`,
`:2243`), the kernel security dispatch (`security_dispatch.rs:12`), the
orchestration supervisor and the native flow adapter. The "whole-store
`catch_unwind` gap" recorded by the earlier infra readiness review was genuinely
closed. Poison recovery through `into_inner()` is also a known idiom here, applied
to the authority store's public-key cache (`authority.rs:694-730`). So both
patterns that would fix this are present in the codebase; neither is applied to
any connection guard. The receipt store is not exposed at all: it
uses a connection pool (`receipt_store.rs:112`), its four `.lock()` sites guard
`health.*` counters, and its writer jobs are wrapped in `catch_unwind`. Pooled
connections plus panic containment is the shape to copy, and 13 stores already
have the first half.

**Fix:** decide the policy once and apply it uniformly. Either recover with
`into_inner()` where the guarded state is known-consistent after a panic (the
`authority.rs` shape), or wrap the critical section in `catch_unwind` so the panic
becomes one failed operation (the `receipt_store.rs` shape). For a SQLite
connection the state genuinely is recoverable, because an aborted transaction
rolls back, so recovery is defensible and should be the default. Add a test per
store that panics inside the lock and asserts the next operation succeeds.

**Confidence:** high. Counts and mappings are direct reads. The severity depends
on a panic being reachable inside those critical sections, which today requires a
latent defect, and which R1's change would make more likely.

---

## S2. Medium-high: canonical JSON has a strict entry point, an excellent one, used at 91 of roughly 2,850 call sites, with no gate saying which paths require it

`crates/core/chio-core-types/src/canonical.rs` is the best code I have read in
this repository. It provides two paths, and its doc comment states the distinction
precisely:

- `canonical_json_bytes<T: Serialize>(value)` canonicalizes an already-typed Rust
  value.
- `canonical_json_bytes_from_str(input)` validates **untrusted JSON text** before
  signing, and rejects: duplicate object keys (explicitly named as the
  "render-A / sign-B" vector, because `serde_json::Value` collapses them
  last-wins); integers outside the I-JSON safe range; integers written in float
  form (`1.0`, `1e2`); and fractional literals carrying more significant digits
  than an `f64` holds, because serde_json silently rounds them onto a double that
  canonicalizes identically to a shorter literal.

That is a complete and correctly reasoned defense against a signature-equivalence
class that most implementations get wrong, with the reasoning written down where
the next maintainer will find it.

**The finding is the distribution.** The strict form appears at **91**
production call sites (112 lines if `use` statements and doc mentions are
counted, which the first version did). The typed-value form appears at roughly **2,764**. The strict form is used in **43 production files** (the first version listed 12,
from a truncated list), concentrated in `chio-cli` (10), non-security
`chio-control-plane` paths (7), `chio-finding` (4) and the market ingress crates,
for example `chio-finding-challenge/src/ingress.rs`,
`chio-finding-verifier/src/verify.rs`, `chio-finding/src/validate.rs`,
`chio-core-types/src/capability/caveat.rs`. Two are in `chio-store-sqlite`'s
finding-market stores.

The security TCB crates appear in **none** of them: not
`chio-security-types`, `chio-quarantine`, `chio-secret-broker`, `chio-kernel`, nor
`chio-control-plane/src/security`.

That may well be correct. The strict form is only required where JSON *text*
crosses a trust boundary and is then signed or digested, and it is possible every
such boundary in the security TCB happens to be covered. But:

- Nothing states which boundaries require the strict form.
- Nothing enforces it.
- A reviewer cannot answer the question by inspection at 2,764 call sites, and
  neither could I. That inability is the finding, not a specific defect.

The security properties the strict parser protects are exactly the ones the
active-response work in Packet 1 depends on: signed deployment configuration,
signed cage manifests and signed simulation reports are all JSON that arrives
from outside the process and is then bound by a digest.

**Fix:** make the distinction a type rather than a convention, which is the same
remedy as findings Q2 and Q3. An `UntrustedJsonText(String)` newtype constructed
at every wire, file and database read boundary, whose only canonicalization method
is the strict one. Typed-value canonicalization then cannot be reached from
untrusted text without an explicit, greppable, reviewable conversion. Until then,
at minimum: enumerate the boundaries where signed JSON text enters the security
TCB, state for each which entry point it uses and why, and gate on that list.

**Confidence:** high on the counts and on the absence of a policy. Deliberately
not claiming a live bypass: I did not find a security-TCB path that canonicalizes
untrusted text through the typed form, and I also could not rule one out.

---

## S3. Medium: multi-tenant isolation rests per-table on identifier unguessability, with no classification and no gate

64 tables declare a `tenant_id` column. **72 production statements read, update or
delete from one of those tables with no `tenant_id` predicate.**

Most of the samples are defensible on inspection, and fall into three groups:

- **Content-addressed or unique identifier:**
  `iou_store.rs:169` `SELECT canonical_json FROM iou_envelope WHERE receipt_id = ?1`,
  `receipt_store.rs:4553` on `chio_tool_receipts WHERE receipt_id = ?1`,
  `encrypted_blob.rs:1231` `DELETE FROM chio_encrypted_blobs WHERE blob_id = ?1`,
  `finding_operator_bundle_store.rs:1749` on `chio_finding_payloads WHERE finding_id = ?1`.
- **Singleton metadata:** `finding_pool_ledger.rs:1353`, `:1366`, `:1405`, all
  `WHERE singleton = 1`.
- **Global counters and diagnostics:** `receipt_store.rs:3559`
  `SELECT COALESCE(MAX(seq), 0) FROM chio_tool_receipts`.

The first group is where the isolation property actually lives, and it holds only
if the identifier is globally unique **and** unguessable. That varies by
subsystem, and nothing records which guarantee each table relies on:

- The keyring derives its identifier: `enterprise_receipt.rs:414` computes
  `domain_hash(RECEIPT_ID_DOMAIN, &canonical)?.to_hex()`, so it is
  content-addressed and unguessable. Correct by construction.
- `chio_tool_receipts.receipt_id` is an opaque string whose test fixtures look
  like `"rc-parent-1"`. I did not establish whether production values are derived
  or assigned, which is itself the problem: if any subsystem ever assigns a
  sequential or caller-influenced receipt id, every one of those tenant-free
  lookups becomes a cross-tenant read, and no test or gate would notice.

So this is not a claim that a cross-tenant read exists. It is a claim that the
system's tenant boundary currently depends on a property that is undocumented,
varies by table, and is enforced nowhere.

**Fix:** classify each of the 64 tenant-scoped tables as either "tenant predicate
required" or "globally unique unguessable identifier, derivation named". Record the
classification next to the schema. Add a gate that fails on a statement touching a
predicate-required table without a `tenant_id` predicate. Add a test matrix that
attempts a cross-tenant read by identifier against every table in the second
class. Where an identifier is supposed to be unguessable, make its derivation a
typed constructor rather than a `String`, as finding P6 already recommends for
digests.

**Confidence:** high on the counts and the absence of a policy. The severity is
genuinely unresolved and should be resolved by the classification, not by
argument.

---

## S4. Low: SQL triggers re-derive a signed field with a second JSON parser, into columns with no shape constraint

`receipt_store/bootstrap/open.rs:1361`, `:1376`, `:1379` and `:1400` extract the
transparency-log chain link from signed bytes using SQLite's JSON parser:

```sql
CAST(json_extract(NEW.statement_json, '$.previous_checkpoint_sha256') AS TEXT)
```

and write it into three tables (`checkpoint_publication`,
`checkpoint_predecessor_witnesses`, `checkpoint_publication_metadata`). A second
trigger at `receipt_store/support/checkpoint_validate.rs:42` and `:45` uses the
same extraction for presence checks.

So a security-critical chain link is derived by SQLite's parser from a payload
whose authenticity was established by Rust's verification over canonical bytes.
Two parsers, one signed payload.

**This is low severity, and the reason is a correction to my hypothesis.** I
expected the chain-link *value* to be unverified. It is verified:
`chio-kernel/src/checkpoint.rs:1924-1946` computes
`checkpoint_body_sha256(&predecessor.body)` and fails on
`previous_checkpoint_sha256 != predecessor_sha256`. The trigger at
`checkpoint_validate.rs:28` onward independently enforces real append-only
structure (sequence strictly increasing, first checkpoint has no predecessor,
later checkpoints must have one, the predecessor row must exist), and
`evidence_export.rs:463` cross-checks the Rust value against the persisted one at
export. Three layers, all present.

What remains is a design smell with two concrete edges:

1. The projection columns are declared `previous_checkpoint_sha256 TEXT`,
   nullable, with **no `CHECK` constraint** on shape. Contrast `cost_charged_be
   BLOB` at `open.rs:569`, which carries a proper
   `typeof(...) = 'blob' AND length(...) = 8` check. `CAST(... AS TEXT)` of a
   missing key or a non-string value produces something rather than failing.
2. Defense in depth is being implemented with a parser differential rather than a
   bound parameter. The Rust writer has the verified typed value in hand and could
   pass it as a parameter; deriving it again in SQL adds a second parser to the
   trust base to gain nothing the parameter would not give.

**Fix:** bind the chain link from the verified typed struct as a parameter and let
the trigger copy the column rather than parse the JSON. Add the `CHECK`
constraint on the hex shape. Keep the append-only trigger exactly as it is; it is
good.

---

## S5. Verified clean, including two things worth protecting

- **Canonical JSON strictness (see S2) is exceptional.** Preserve the doc comment
  verbatim through any refactor; it is the only place the render-A/sign-B
  reasoning is recorded.
- **Vendored fork management is well run.** 12 forks under `third_party/`, plus an
  unmodified `nono-upstream-chio` mirror and a `provenance/` directory (pass 6
  corrected the first version's "14 forks"), each fork with a README, `nono-chio` carrying a `PATCHES.md`, a `third_party/provenance/`
  directory, exact upstream pins (`nono = "=0.53.0"` under version
  `0.53.0-chio.2`), and a separate `nono-upstream-chio` checkout that makes
  divergence diffable. For forks of a Landlock binding and a regex engine sitting
  inside the TCB, this is the right shape. The outstanding `aws-lc-rs 1.18.1`
  cargo-vet gap is a separate, already-tracked assurance item, not a management
  failure.
- **JSON recursion depth: no finding.** I expected an unbounded-nesting stack
  overflow. `serde_json`'s default 128-level recursion limit applies and the
  `unbounded_depth` feature is not enabled anywhere. The `max_depth` values in the
  codebase are domain limits (delegation chain depth, blast-radius query depth),
  which is a separate and correctly handled concern.
- **Wire size bounds are comprehensive.** `chio-secret-broker/src/protocol.rs:15-24`
  bounds wire bytes, body bytes, response bytes, header name and value bytes,
  nonce, identifier and path-and-query lengths, and validates them. This is the
  discipline finding S2 wants applied to serialization entry points.
- **`catch_unwind` coverage (see S1) closed a previously recorded gap.**
- **The checkpoint chain is verified at three independent layers (see S4).**

---

## S6. Absences worth naming

- No test panics inside a store's connection lock and asserts the next operation
  succeeds. Four stores would fail such a test today.
- No gate identifies which boundaries require strict canonicalization, so S2
  cannot regress detectably.
- No cross-tenant read attempt exists as a test, for any of the 64 tenant-scoped
  tables.
- No `CHECK` constraint on the projected chain-link columns, while the adjacent
  financial column has one.

---

## Sequencing

S1 must land **with** pass 2's R1, not after it. Enabling release overflow checks
while four stores brick permanently on a panic trades a correctness bug for an
availability bug. Both changes are small; they belong in the same packet.

S2's enumeration is cheap and should happen before Packet 1 wires the signed
simulation report, because that report is new signed JSON crossing a boundary and
is the natural place to get the entry point wrong. The `UntrustedJsonText` newtype
is the durable fix and can follow.

S3's classification is the prerequisite for deciding whether S3 is severe. Do the
classification before scheduling any remediation.

S4 is small and belongs with Packet 3's storage work.
