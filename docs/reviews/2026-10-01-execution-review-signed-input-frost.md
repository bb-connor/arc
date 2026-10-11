# Execution review: signed input, readback, keyring, tenant reads and FROST sealing, October 1, 2026

Scope: commits `1e791271dc` (lossy signed JSON), `a9ae42ed69` (keyring canonical
records and snapshot synchronization), `18be6b39be` (signed economy and lineage
readback), `93277b4209` (its checkpoint record), `21c831d396` (constrained input
type, tenant read contracts, FROST plaintext split), `19ac62c13a` (envelope design
correction), `60555a64da` (sealed FROST ceremony) and `253be7fe04` (September 28
signed readers), reviewed at the tip `a2630c20a1` against base `07e963e8f5`. The
primitive is reviewed as it stands at the tip, including methods added later
(`decode_canonical_with` in `a3217b9145`, `SharedUntrustedJsonError` in
`d51afb4a5f`, `decode_document` in `377ee5b773`). Plans: umbrella correction 1F,
Packet 10.2 boxes 1 to 4, 10.3 and 10.4; mechanism B of the unrepresentable-defects
design; the FROST round-2 envelope design; the contracts
`docs/security/signed-json-boundaries.md` and `docs/security/tenant-read-contracts.md`.
Records: `2026-09-27-signed-readback.md`, `2026-09-27-trust-boundary-execution.md`,
`2026-09-27-frost-sealed-ceremony-execution.md`,
`2026-09-28-reader-accounting-recovery-execution.md`. Method: source reading at the
tip and through each diff, an in-memory mutation of the trust-boundary gate, a rerun
of the gate and of the independent FROST vector verifier, and inspection of the
retained `/tmp` evidence logs the records cite. No cargo run was needed: no High or
Critical finding depended on runtime behaviour.

**Judgment: the core of this slice is sound and better than its plans in two places.
The token-preserving parser rejects duplicate keys at every depth (after unescaping)
and every lossy numeric lexeme, depth is bounded, Debug and Display are redacted, the
keyring snapshot is a real single-transaction read with a red/green and mutation
record, and the sealed FROST ceremony implements the design's suite, context-first
opening, encrypt-then-sign and durable equivocation handling with vectors an
independent Python implementation reproduces. The most important defect is in the
enforcement around the primitive rather than the primitive: the trust-boundary gate
pins constructor sites but not the decoding contract, so changing any of the 464
sites from `decode_signed` or `decode_canonical` to the permissive `decode_document`
passes the gate (SF1, confirmed by mutation). The remaining findings are Low: a
zeroizing encoder whose output buffer leaks its own growth reallocations, economy
readback that verifies signatures but not row keys, non-strict Ed25519 on the sealed
envelope with weak roster keys accepted, an incomplete plaintext inventory claim,
correction 1F's plan text left unchecked and silently superseded, and evidence kept
only in `/tmp`. The work was worth its cost; the inventory machinery around it is
heavier than the assurance it delivers.**

## Plan conformance

| Plan item | Recorded status | Verified status | Evidence |
| --- | --- | --- | --- |
| 1F: enumerate TCB JSON text boundaries | `[ ]` | Done for the named set, not ticked | `signed-json-boundaries.md` table covers deployment config, manifests, broker, `statement_json`, `raw_json`, simulation report |
| 1F: record entry point and reason per boundary | `[ ]` | Done, not ticked | Same table, "Disposition" column |
| 1F: fix typed form on untrusted text (P1) | `[ ]` | Done for receipts, manifest, economy, lineage, keyring | `receipt_verify.rs:166-170`, `admission.rs:801`, `signed_readback.rs:8-12`, `chio-keyring/src/lib.rs:989-1000` |
| 1F: strict form for simulation report inputs | `[ ]` | Deviated: native `decode_signed`, recorded only in the contract doc | `signed-json-boundaries.md` "Simulation report" row; plan text unchanged (SF6) |
| 1F: preserve `canonical.rs` doc comment verbatim | `[ ]` | Done | `git diff 07e963e8f5 a2630c20a1 -- canonical.rs` adds only `#[allow]` attributes and the escape-writer rename |
| 10.2.1: introduce `UntrustedJsonText<'a>` | `[x]` | Done; contract weakened later by `decode_document` on the same type | `untrusted.rs:12-100`; SF1, SF8 |
| 10.2.2: migrate 1F's receipt, export, lineage, manifest, keyring, broker, authority readers | `[x]` | Done | 40 economy call sites (18 + 18 + 4), lineage and receipt readers, keyring `from_bounded_json`, broker `provision.rs` readers |
| 10.2.3: gate constructors and raw decoders, pin census, calibrate bypasses | `[x]` | Done as a lexical inventory; blind to the decoding contract chosen | Gate passes at tip (464 constructors, 85 tables, 170 SQL contracts); SF1 |
| 10.2.4: September 28 signed-reader batch | `[x]` | Partly in scope: `253be7fe04`'s federation, passport and broker readers verified; `f16d4e781c` not in this slice | `chio-federation-authority/src/input.rs:5-55`, `provision.rs` |
| 10.3: classify 85 tables by enforcing principal | `[x]` | Done (63 tenant-predicate, 22 administrative, no bearer class) | inventory `tables`; counts identical at `21c831d396`, `60555a64da`, `253be7fe04` |
| 10.3: contract beside each schema, pin 170 statements | `[x]` | Done (lexical) | `check-trust-boundaries.py:150-166,216-219` |
| 10.3: exhaustive per-table negative tests | `[ ]` | Open, honestly recorded | `tenant-read-contracts.md:93-95` |
| 10.3: machine-checked runtime-family mapping | `[x]` | Done; the gate checks that a named test function exists, not that it touches the table | `check-trust-boundaries.py:200-215` |
| 10.3: receipt IDs are lookup keys; sealed context | `[x]` | Done for user-facing reads; "sealed" means non-deserializable with private fields, every constructor is public | `store_impl.rs:6-53`, `receipt_query.rs:43-85` |
| 10.3: remove strictness switch and NULL fallback | `[x]` | Done | `store_impl.rs:20-21`; gate check `check-trust-boundaries.py:239-240` |
| 10.4: typed predecessor column, CHECK constraints, trigger without JSON parser | `[x]` | Done (in `995b9f1c74`, outside this slice's commits) | `checkpoint_validate.rs:26-65`, `evidence_retention.rs:1041-1104` |
| 10.4 exit: no signed field re-derived by a second parser | not claimed | Not true workspace-wide | `reports/billing.rs:32-63` and `reports/cost_attribution.rs:38,67` still `CAST(json_extract(r.raw_json, ...) AS INTEGER)` on signed fields |
| FROST design step 1 (type split, redacted Debug, named accessor) | done | Done; accessor returns `&[u8]` instead of `Zeroizing<Vec<u8>>`, which is better | `sealing.rs:88-121` |
| FROST design step 2 (keys, suite, binding, replay, opening order, tests) | done | Done; leakage assertion uses `compile_fail` doctests instead of `assert_not_impl_any!` | `sealing.rs`, `keys.rs`, `inbox.rs`, `sealing/tests.rs`, `tests/support/frost_round2_inbox.rs` |

## SF1. Medium: the trust-boundary gate cannot see which decoding contract a site uses, so a signed reader can be downgraded to the permissive path without a gate signal

`UntrustedJsonText` carries five decoding contracts on one value: strict I-JSON
(`canonicalize`, `decode_external`), native signed (`decode_signed`), exact canonical
(`decode_canonical`, `decode_canonical_with`) and, since `377ee5b773`, unsigned
documents (`decode_document`, `untrusted.rs:60-65`). `decode_document` skips
`validate_number_tokens` entirely, so it accepts `0.123456789012345678901` and rounds
it, which is precisely the render-A / sign-B precision alias that S2 named and
correction 1F exists to prevent. The workspace-wide enforcement is
`scripts/check-trust-boundaries.py`, and it pins only the constructor:
`check-trust-boundaries.py:139` records `path::owner::new|from_wire`. Which method is
then called is not recorded anywhere in `trust-boundary-inventory.json`.

I loaded the gate, replaced its `sources` with an in-memory copy in which
`signed_readback.rs:10` and `receipt_verify.rs:169` call `.decode_document()` instead
of `.decode_signed()` and `chio-keyring/src/lib.rs:998` calls `.decode_document()`
instead of `.decode_canonical()`, and ran `check()`. It returned no errors. The
failure scenario is a one-token edit at any of the 464 pinned sites (production code
calls `decode_signed` at 348 places and `decode_canonical` at 79) that reintroduces lossy signed parsing while
the gate, the inventory and its calibrations all stay green. What would catch it is
the owner's own regression where one exists: the signed-readback precision test
(`tests/signed_readback.rs:29-45`) and the keyring alias test would fail for these
three, but most migrated owners have no precision-alias regression. The seven to
nine calibrations exercise unregistering an owner, unscoped SQL and a raw
`serde_json` decoder; none exercises a contract downgrade.

This is also where mechanism B's contract drifted. The design says "the only path
from here to canonical bytes is the strict parser; the permissive typed-value
canonicalizer is unreachable without `into_raw_for_storage`, which is gated." The
implementation put the most permissive decoder on the same type as the strictest one.
Fix, in order of preference: give the contracts distinct types chosen at construction
(`SignedJsonText`, `CanonicalJsonText`, `DocumentJsonText`), so the contract appears
in signatures and the compiler, not a regex, separates them; or record
`path::owner::constructor::method` in the inventory, fail on any change, and forbid
`decode_document` in files listed under `reviewed_*_owners`; and add a calibration
that performs exactly the downgrade above.

**Confidence:** Confirmed. The gate was run against the mutated sources and passed.

## SF2. Low: the zeroizing canonical encoder frees unwiped copies of its own output while it grows

`canonical_json_bytes_zeroizing` (`canonical/secret.rs:12-17`) wipes the intermediate
`serde_json::Value` tree and returns `Zeroizing<Vec<u8>>`, but writes into
`Zeroizing::new(String::new())` with zero capacity. Every `push`/`push_str` in
`write_canonical_value` and `write_escaped_json_string` grows that `String` through
`RawVec` reallocation; `Zeroizing` wipes only the final buffer on drop. Each earlier
buffer, holding a prefix of the canonical output, is returned to the allocator
unwiped whenever `realloc` moves it. For the authority custody export
(`chio-federation-authority/src/input.rs:106-138`) the sorted keys put
`governanceAuthoritySeeds` and `leaseAuthoritySeeds` first, so the freed prefixes
contain seed hex. The reader path has the same shape because `decode_canonical`
re-exports through this function. The execution record
(`2026-09-28-reader-accounting-recovery-execution.md:21-27`) says "the custody API
covers these owned buffers"; this buffer is owned by the function and is not covered.
The unit test `private_canonical_output_matches_public_bytes_and_wipes_all_tree_strings`
counts wiped tree strings only.

Fix: size the output before writing (a first pass into a counting sink, or a
conservative `with_capacity` from the tree), or write into a small zeroizing buffer
type that wipes the old allocation when it grows. Whether residue actually survives
depends on the allocator moving the block; the absence of any wipe on growth does not.

**Confidence:** Confirmed for the code path (no wipe on growth, traced through
`secret.rs:14-16` and `canonical.rs:199-258`); residue in freed memory is
allocator-dependent.

## SF3. Low: signed economy readback verifies each body's signature but not that the body belongs to the row it was read from

`18be6b39be` made 40 economy readers verify the embedded signature on read, to stop
"an altered stored body" reaching reports or workflow comparisons
(`2026-09-27-signed-readback.md:18-24`). For lineage it also bound the decoded
`child_receipt_id` to the requested key (`signed_readback.rs:39-44`), precisely so a
valid statement for another child cannot be substituted. The economy readers got no
equivalent binding. `record_liability_quote_request` loads the provider row by
`provider_record_id` (`liability_market.rs:310-325`) and then checks only
`provider.body.report.provider_id` and the policy list (`:333-354`); it never
compares `provider.body.provider_record_id` with the requested record id. The list
reports (`underwriting_credit.rs:508-570` and peers) do not read the row key at all.

Failure scenario, under the same storage-alteration threat the readback addresses:
copy the `raw_json` of a valid signed provider record R2 (same `provider_id`, broader
jurisdictions) into R1's row. The quote request records R1 while its policy check
ran against R2's signed policies, and the signature check passes. Copying one
facility's `raw_json` into a second row makes `query_credit_facilities` count it
twice. The same gap exists, pre-existing, in the privileged receipt point loaders
`load_chio_receipt` and `load_chio_receipt_row` (`store_impl.rs:143-163`,
`:654-676`), while the batch loader (`:207-214`) and the user-facing point read
(`:32-37`) do bind the id. Severity is Low because an actor who can rewrite rows can
also rewrite the unauthenticated lifecycle columns, which the record states plainly.

Fix: in `decode_verified_signed_export`, take the expected record id (or a closure
that extracts and compares it) the way `decode_verified_lineage_statement` does, and
add the id comparison to `load_chio_receipt_row`.

**Confidence:** Confirmed by source trace of the readers named above.

## SF4. Low: sealed envelopes are verified with non-strict Ed25519, and roster validation accepts weak transport keys

`SealedFrostRound2Package::verify_context` calls
`sender.transport_public_key.verify(...)` (`sealing.rs:231-235`), which reaches
`ed25519_verification::verify(..., strict = false)` (`crypto.rs:440-445`).
`validate_config` checks that transport keys are Ed25519 and unique
(`frost_ceremony.rs:724-744`) but not `is_weak_ed25519()`, although `chio-core`
documents that weak keys "must not identify artifact issuers" (`crypto.rs:421-433`).
For a roster entry whose transport key is the identity point (`01` followed by 31 zero
bytes), the signature `R = identity, s = 0` verifies for every message under
cofactorless verification; `crypto.rs:1314-1332` uses exactly that forgery to test
`verify_strict`. Anyone can then encrypt a well-formed share to a recipient's public
sealing key and sign it "as" that participant. Delivered after the participant's
real envelope, it is an authenticated, decryptable conflict, and
`accept_round2_package` durably fails the recipient's ceremony (`inbox.rs:42-59`);
delivered first, it is accepted. The trigger needs a roster entry with a weak key,
which an honest keypair never produces, so this widens a malicious participant's
reach to third parties rather than creating a new attacker. Round one has the same
call at `frost_ceremony.rs:875`.

Fix: reject `is_weak_ed25519()` transport keys in `validate_config` and use
`verify_strict` for both rounds.

**Confidence:** Confirmed by source trace; the forgery primitive is the one the
crate's own test exercises.

## SF5. Low: the FROST plaintext inventory claims two extraction sites, but the share also leaves the type through a direct field read the gate cannot see

The design requires that "every place the share leaves the type is greppable and is
the complete inventory". The gate counts `.secret_bytes(` occurrences in
`frost_store/ceremony/inbox.rs` and pins two (`check-trust-boundaries.py:234-242`),
and the record says "Two production byte borrows remain, both in the encrypted inbox
custody owner" (`2026-09-27-frost-sealed-ceremony-execution.md:32-33`). But
`FrostRound2Package::bytes` is `pub(super)` (`sealing.rs:90`), and
`complete_frost_ceremony` reads it directly:
`round2::Package::deserialize(&package.bytes)` (`frost_ceremony.rs:454`). That is
the share's final and most important exit, into `dkg::part3`, and it is invisible to
the inventory. The read itself is correct; the claim of a complete inventory is not.
Fix: route it through the accessor (or a consuming `into_frost_package`) so the gate
counts it, and update the pinned count.

**Confidence:** Confirmed by source.

## SF6. Low: correction 1F's plan text was left unchecked and its strict-form rule was replaced without a recorded decision, while the records disagree about what the parser is

All five correction 1F boxes remain `[ ]`
(`2026-09-26-security-engineering-excellence.md:406-420`) although
`signed-json-boundaries.md` performs the enumeration. Box 2 says the strict form "is
required wherever the bytes originated outside this process" and box 4 says to use
it for the simulation report's inputs. The implementation chose the native
`decode_signed` contract for manifests, receipts and the simulation report, with a
reason (full-width `u64` and whole-valued floats in existing signed formats), and
Packet 10.2 box 1 later blessed three contracts. That choice is defensible: the
parser admits only the serde display or RFC 8785 spelling of each parsed number, so
no lossy alias survives, and signatures are checked over the reconstructed typed
body. But the plan was never amended, so a reader of 1F still sees an unmet P1 rule.

The naming changed without the behaviour changing. `1e791271dc` introduced
`parse_legacy_signed_json`, documented as a "compatibility contract only for existing
formats"; `2026-09-27-signed-readback.md:26` calls it "the existing compatibility
parser"; `f25cd61f49` renamed the file to `signed_json.rs` with a 17-line diff; and
`signed-json-boundaries.md` now says "This is the production numeric contract, not a
backwards-compatibility decoder." The second description is the accurate one; the
record and the plan should say so, rather than leaving two documents that contradict
each other about a forbidden category. Fix: tick 1F's boxes with a pointer to the
contract doc, record box 4's deviation and its reason in the plan, and correct the
readback record's wording.

**Confidence:** Confirmed from the plan, both records and `git show f25cd61f49`.

## SF7. Low: this slice's evidence lives only in `/tmp`, including the scripts that performed a scripted rewrite

Every record in this slice cites logs under `/tmp/chio-execution-batch-20260926/`,
`/tmp/chio-trust-boundaries-20260927/`, `/tmp/chio-frost-sealed-20260927/` and
`/tmp/chio-boundary-followthrough-20260928/`. They exist on this host today, and the
samples I checked match their claims (see below), but none is committed; later
batches moved evidence under `docs/reviews/artifacts/`. A host cleanup erases the
red logs, mutation logs and candidate hashes that the records rely on for "failed
before repair". The FROST directory also holds `migrate_readers.py`,
`rewrite_store.py`, `rewrite_authority.py` and `rewrite_tests.py`;
`migrate_readers.py` rewrote every `serde_json::from_slice` under `frost_store/` to
`decode_record` by regex. I checked that the store's writers are canonical (no
`serde_json::to_*` in `frost_store/`), so the rewrite is consistent, but the record
does not mention that the migration was scripted, which the design's "one boundary at
a time" discipline would want disclosed. Fix: copy the cited logs, hashes and scripts
into `docs/reviews/artifacts/2026-09-2{6,7,8}-*` and state the scripted rewrite in the
FROST record.

**Confidence:** Confirmed by listing the directories and the repository.

## SF8. Note: the constrained type is a call-site wrapper, not a value that flows

Only one function signature in the workspace takes or returns `UntrustedJsonText`
(`chio-finding-market-store-postgres/src/validation.rs:36`). Everywhere else the raw
`&str`, `String` or `Vec<u8>` flows to the reader, which wraps it and decodes on the
same line. `new` is a `const fn` over any `&str` with no bound
(`untrusted.rs:27-29`), and the two database readers in this slice use it on
unbounded SQLite text (`receipt_verify.rs:168`, `signed_readback.rs:9`); the doc's
"`new` marks an already bounded owner buffer" is a convention, not a check. So the
type does not make wrong parsing unrepresentable; it gives the parsing decision a
name, and the guarantee comes from the lexical gate plus owner tests. That is a
reasonable engineering outcome, but the design and the plan describe a stronger
property than was built, and SF1 is the consequence.

## SF9. Note: economy verify-on-read buys corruption detection, not tamper resistance

`decode_verified_signed_export` verifies against the embedded `signer_key`, and the
insertion path accepts any self-signed artifact (`underwriting_credit.rs:8-15`). A
party able to rewrite rows can re-sign with its own key. The record says this
("integrity against the embedded signer; it does not establish an external trust
root"), so this is not a truth problem. It does bound the value: every list report
now performs one Ed25519 verification per stored row with no SQL limit
(`underwriting_credit.rs:508-560`), which is a cost the thread-local verification
cache does not absorb on scans. If tamper resistance is the goal, bind the signer to
an authorized key set; if it is not, say in the reader that the check is a corruption
guard.

## Execution-record claims checked

| Claim (record:line) | Verdict | Evidence |
| --- | --- | --- |
| "Forty economy export readers now validate original JSON tokens and verify" (`2026-09-27-signed-readback.md:18`) | True | 18 + 18 + 4 production calls of `decode_verified_signed_export` |
| "All 23 focused tests passed: seven new signed-readback regressions and 16 existing" (`signed-readback.md:54`) | True | 7 `#[test]` at `18be6b39be`; `signed-readback-final.log` 7 passed, `-existing.log` 16 passed |
| "A valid statement for a different child can no longer be returned" (`signed-readback.md:33-34`) | True | `signed_readback.rs:39-44`; test `:228-288` covers ordinary and retained lookups |
| "The shared reader uses the existing compatibility parser" (`signed-readback.md:26`) | Contradicted by the later contract doc | SF6 |
| Keyring "alias regression failed before repair; all 79 keyring tests pass" (`signed-json-boundaries.md`, keyring row) | True | `keyring-canonical-red.log` fails at `tests/event.rs:28`; `keyring-snapshot-full.log` sums to 79; snapshot mutation red log present |
| "the 18 signed-input constructor sites" (`2026-09-27-trust-boundary-execution.md:41-42`) | True | inventory at `21c831d396` has 18 constructors |
| "The nonempty runtime suites total 150 distinct passing cases" (`trust-boundary-execution.md:81`) | True | 60 (`focused-tests-3.log`) + 5 (`tenant-final.log`) + 85 (`library-tests-final.log`) |
| "Its seven calibration cases exercise actual source mutations" (`trust-boundary-execution.md:43-44`) | True but incomplete | none exercises a contract downgrade; SF1 |
| "inbox-final.log: all 12 cases pass" (`frost-sealed-ceremony-execution.md:53`) | True | 9 inbox + 3 rotation cases, 12 passed |
| "Python cryptography independently reproduces all 20 signatures and ciphertexts" (`frost record:58`) | True | Reran `scripts/verify-frost-sealing-vectors.py`: passes; it recomputes agreement, HKDF, AEAD and signatures without Chio code |
| "`outbound-regression-red.log` reproduces acceptance of freshly resealed outbound messages" (`frost record:74`) | True | the named test fails at `frost_round2_inbox.rs:468` in that log |
| "Two production byte borrows remain, both in the encrypted inbox custody owner" (`frost record:32-33`) | Incomplete | third exit at `frost_ceremony.rs:454`; SF5 |
| "The signed-input inventory grows from 22 to 44" (`2026-09-28-reader-accounting-recovery-execution.md:9`) | True | inventories at `60555a64da` and `253be7fe04` |
| "The custody API covers these owned buffers" (`reader-accounting-recovery:21-27`) | Overstated | output growth reallocations are unwiped; SF2 |

## Verified clean

- **Duplicate keys.** `StoredValueVisitor::visit_map` (`signed_json.rs:93-102`)
  deserializes keys as unescaped `String`s and rejects a repeat at every object, and
  recursion through `visit_seq` reaches objects inside arrays. The test
  `[{"x":false,"x":true}]` (`tests/signed_json.rs:30`) covers the escaped case
  inside an array. `decode_canonical` rejects duplicates either through serde's
  duplicate-field error or through byte inequality with the re-export.
- **Numeric lexemes.** `validate_number_tokens` accepts a token only if it equals the
  serde display or the RFC 8785 rendering of the parsed number. Traced through
  serde_json's parser: `-0` parses as `-0.0`, renders `-0.0` / `0`, rejected; `1E2`
  renders `100.0` / `100`, rejected; `1e400` fails parsing as out of range; `1e-999`
  underflows to `0.0`, rejected (tested); `01` is a parse error; `18446744073709551616`
  and `-9223372036854775809` become `f64` and fail both renderings, rejected (first
  tested); `1.0` is accepted as an `f64` and then refused by serde for an integer
  field. This matches `signed-json-boundaries.md`.
- **Feature unification.** `cargo tree --workspace -e features -i serde_json` shows no
  `arbitrary_precision` (which would break the visitor); `unbounded_depth` is present
  through `cargo_metadata` but only adds an opt-in method.
- **Depth.** All entry points parse through `serde_json::from_str` or
  `Deserializer::from_str`, whose default 128-level recursion limit applies to
  `deserialize_any`; the token scanner is iterative. No stack-overflow path.
- **Redaction and API surface.** `UntrustedJsonText` Debug prints only the byte
  length; `UntrustedJsonError` Debug and Display print only the registered URN; all
  six URNs are in `spec/errors/registry.yaml:2581-2661`. No raw accessor, no serde
  implementation, borrowed lifetime. Parser messages remain reachable through
  `source()`, as documented.
- **Canonical writers.** Keyring production code has no `serde_json::to_*`; FROST
  store records are written canonically; the broker's replaced `canonical_bytes()` is
  `canonical_json_bytes(self)`, so `decode_canonical` checks the same bytes the writer
  produced.
- **Keyring snapshot.** `synchronization.rs:19-61` reads events, checkpoints,
  activation commits and the clock inside one deferred SQLite read transaction and
  derives head, epoch and stage from that snapshot; the audit binary consumes the
  snapshot (`chio-keylog-audit.rs:274-277`). The test injects a concurrent append
  through the clock, and a mutation log shows it failing against the old shape.
- **FROST sealing.** Separate X25519 keys; non-canonical and low-order keys rejected
  (`keys.rs:14-28`); context, recipient, sealing key, sender and transport key checked
  before any cryptography (`sealing.rs:191-237`); HKDF salt is the decoded roster
  digest and info is the canonical metadata, which is also the AAD and signing prefix;
  plaintext, shared secret and derived material are `Zeroizing`; frost-core 3.0.0's
  `round2::Package` is `ZeroizeOnDrop`. The negative matrix in `sealing/tests.rs`
  follows the design, including a loop over every metadata field.
- **FROST durability.** Acceptance inserts the encrypted share, envelope digest and
  projection commit in one fenced transaction; an equal digest is idempotent after
  rechecking custody; a different authenticated, decryptable envelope commits
  `Failed` before returning; `Failed` is refused by `begin_ceremony`,
  `advance_ceremony` and acceptance through `verify_exact_config`
  (`ceremony.rs:897-899`); completion requires the recorded round-one transcript, the
  committed outbound envelopes and exactly the accepted inbound ones. Commit-then-sync
  failures leave a durable state that the next call returns idempotently.
- **Tenant reads.** The context point read binds the receipt id, applies the exact
  tenant in SQL, rechecks the signed tenant, and runs in one transaction with the
  checkpoint check (`store_impl.rs:6-53`); invalid tenant strings, foreign and
  unattributed ids, and a forged projection are tested (`tests/tenant_isolation.rs:21-110`).
  The gate passes at the tip, and the 85 / 170 counts are identical at the three
  commits that touched them.
- **House rules.** No em dashes in any file these commits touched; no `unwrap` or
  `expect` added to production code (the added `expect` calls are in `#[cfg(test)]`
  modules); no process vocabulary in added code comments at the tip (the "legacy" and
  "historical" wording from `1e791271dc` was renamed away). Touched modules are under
  the 2,000-line cap.

## Recommendations for the remaining plan

1. Close SF1 before migrating more readers: either split the contracts into distinct
   types or pin the method per site, and add a downgrade calibration. Every further
   reader migrated under the current gate inherits the blind spot.
2. Fix SF2 in the shared encoder, since every canonical reader and the custody export
   go through it; add a test with a custom allocator or an instrumented buffer that
   observes growth.
3. Give `decode_verified_signed_export` and `load_chio_receipt_row` the row-key
   binding the lineage reader already has (SF3), and switch FROST transport
   verification to `verify_strict` with weak-key rejection in the roster (SF4).
4. Amend correction 1F in the plan (SF6), commit the `/tmp` evidence (SF7), and make
   the FROST inventory count the `complete_frost_ceremony` exit (SF5).
5. For Packet 10.4's exit, either migrate the billing and cost-attribution reports
   off `json_extract` on signed `raw_json`, or narrow the exit criterion to
   checkpoint fields and record the reports as an accepted second parser.
6. Keep 10.3's exhaustive item open as recorded; the family witnesses are real tests
   but the gate verifies only that a named function exists.
