# Execution review: structural remediation and module ownership, October 1, 2026

Scope: commits 4c82a9178e, 29ec6dd424, 951d52009e, d2b721ea24, ff682ac69c,
572c0a1052, c5ca13ddd3, 445fb2e28d, cb91af8aa9, 68acb34aca, 938b76c311,
8c8677470b, 040244e3a6, 619a60e577, 2916c7040c, e1e016f4d0 and a3669c03d1, on
`review/2026-10-01-execution-review` (base `07e963e8f5`, tip `a2630c20a1`).
Plans: umbrella Packet 7, `docs/superpowers/plans/2026-09-29-security-module-boundaries.md`,
and the test-ownership half (Task 2) of
`docs/superpowers/plans/2026-09-29-native-clock-test-ownership.md`. Records:
`docs/reviews/2026-09-29-security-module-boundaries-execution.md` and the
kernel-test parts of `docs/reviews/2026-09-29-native-clock-test-ownership-execution.md`.
Method: every relocation commit was reduced to a normalized multiset diff
(whitespace, visibility prefixes, `use`/`mod`/`#[path]`/`include!` lines removed)
so that only non-move lines remain, and every residual line was read; formatting
commits were compared token-by-token; `#[test]`/`#[ignore]` attributes were
counted per crate before and after each commit; selectors in scripts and
workflows were resolved against the tip; the helper graph was measured with
`cargo tree --offline` (metadata only, no build). No code was compiled or run.

**Judgment: the four production cuts (ranks 1-4) and the kernel test cut (rank 5)
are what the plans asked for and are genuinely mechanical: after normalization
the ports, broker, SQLite and control-plane relocations leave 2, 13, 0 and 47
residual lines, every one of them a `cfg` attribute on a new `mod`
declaration, an `impl` header, a path or method-resolution rewrite forced by
the new module depth, or a `#[cfg(test)]` accessor; no test was dropped,
renamed away or ignored, and no item was widened to `pub` or `pub(crate)`. The
weakest part of the slice is the helper extraction, c5ca13ddd3: one 62-file
commit that mixes relocation, API changes, vendored-dependency surgery,
fragment concatenation and gate rewrites, produces a "minimal" helper whose
graph is still two-thirds `chio-core-types` (49 of 72 packages, for two
functions), and silently leaves nine `[patch.crates-io]` trees dead. I found no
Critical or High defect and no behavior change in authority-bearing code apart
from the labelled reservation-sealing fix, which is correct but duplicates the
store's validator. The work was worth doing; the 6.4 MB of committed terminal
logs that accompany it were not proportionate.**

## Plan conformance

| Plan item | Recorded status | Verified status | Evidence |
| --- | --- | --- | --- |
| Boundaries T1: relocate ports without logic changes | Done | Done | 4c82a9178e: 3,420/3,418 normalized lines, 2 residual (`#[cfg(feature = "std")]` on split items) |
| T1: restrict construction, explicit re-exports | Done | Done | `ports.rs` uses explicit `pub use alerts::SecurityAlertPort` etc. (`crates/security/chio-security-types/src/ports.rs:21`) |
| T1: no-default-features check | Done | Done at tip; failing for three commits | ff682ac69c's explicit imports leave names whose only users are `std`-gated (for example `PortResult` in `ports/alerts.rs`) as unused imports under `no_std`, which fails strict Clippy; repaired in 445fb2e28d (MO9) |
| T2: broker relocation, typed rejection and deadlines retained | Done | Done | 29ec6dd424: 13 residual lines, all `cfg` attributes and `impl BrokerService` headers; Linux prepared tests keep `cfg(all(test, target_os = "linux"))` |
| T2: secret-bearing fields stay with owner | Done | Done (after 68acb34aca) | `RetainedPreparedDispatch` private to `service/custody.rs:12`; compiler probes in `artifacts/.../compiler-privacy-green.json` |
| T3: SQLite relocation, SQL byte-for-byte | Done | Done | 951d52009e: 6,171/6,171 normalized lines, zero residual |
| T3: connection custody private | Done | Done | `fn connection` is private at `crates/platform/chio-store-sqlite/src/security_state.rs:369` |
| T4: control-plane relocation, no dropped tests | Done | Done | d2b721ea24: 47 residual lines (path depth, `#[cfg(test)]` accessors at `event_consumer/coordinator.rs:1012-1023`); test counts unchanged |
| T1-T4: separate relocation, privacy, format commits | Done | Mostly | Separate commits exist; the format commit 572c0a1052 also deletes nine gate markers (MO9) |
| T5: shared plan crate, child bootstrap in `chio-cage-init` | Done | Done, with ownership caveat | Shared validation lives in the helper crate and the parent depends on it (MO10) |
| T5: measure graph, exact ceiling, denials, codec exception | Done | Done as written; minimality overstated | 72 packages confirmed; 49 arrive only through `chio-core-types` (MO1) |
| T5: helper recipes and packaging | Done | Done | 938b76c311 fixes `release-binaries.yml:276` and adds a red/green source gate |
| Plan global: separate mechanical relocation, visibility, formatting | Implied for T5 | Not done for T5 | c5ca13ddd3 combines all categories plus dependency surgery (MO3) |
| Plan global: no duplicate validator | Required | Violated once | `reservation.rs:196-224` restates `response_outbox.rs:136-156` (MO5) |
| Packet 7: name modules after responsibility, not sequence | Required | Done for ranks 1-5; not for `chio-cage` | No `part_NN` names remain; `chio-cage` fragments were concatenated into `lib.rs` (1,839 lines) and `launch/linux.rs` (1,987 lines) (MO4) |
| Packet 7: add rule 9.4/9.5 comments before moving | Required | Not done; mitigated | No comment ties the three `KillProcess` checks together; `SeccompDefaultAction` has one variant (`chio-cage-plan/src/model.rs:279-283`), so the invariant is structural. No `pre_exec` closure moved in this slice |
| Packet 7: shrink allowlist through `--ratchet` | Required | Done; side effect | Nine entries dropped, 43 shrunk, none raised; the same run extended eight unrelated deadlines (MO6) |
| Clock plan T2: save inventory, convert includes | Done | Done | 44 root `include!`s at 040244e3a6^ (counted), zero remain anywhere in `kernel/tests` |
| Clock plan T2: separate relocation, visibility, format | Done | Done | 040244e3a6 (0 residual), 619a60e577 (6), 2916c7040c (format and `mod` reorder only), e1e016f4d0 (split plus selectors) |
| Clock plan T2: separate common fixtures from scenario tests | Done | Partial | Receipt and revocation stores moved to `tests/fixtures/`; 32 items from ten scenario modules are still re-exported through the root (MO8) |
| Clock plan T2: compare inventories and bodies | Done | Done | 845 test attributes before and after; leaf-name multiset of 1,491 identical plus one regression |
| Clock plan T2: migrate selectors atomically | Done | Done at tip | All 219 `kernel::tests::` selectors in `scripts/` and `.github/` resolve (211 by resolver, 8 by hand); 040244e3a6 alone would have broken them until e1e016f4d0 |

## MO1. Low: the "minimal" helper still carries 49 packages it uses two functions from, and the gate locks that in

`crates/security/chio-cage-init/Cargo.toml:3` describes the crate as "Minimal
descriptor-bound Linux confinement bootstrap". `cargo tree -p chio-cage-init
--target x86_64-unknown-linux-musl -e normal --features real-linux-enforcement`
gives 72 unique packages, matching the record. The same tree with
`--prune chio-core-types` gives 23. The 49-package difference arrives through
`chio-cage-plan`'s single dependency on `chio-core-types`
(`crates/security/chio-cage-plan/Cargo.toml:13`), which the plan crate uses for
exactly `canonical_json_bytes`, `sha256_hex` and its error type
(`crates/security/chio-cage-plan/src/lib.rs:30`, `src/error.rs:7`). Those 49
include `chio-security-types`, the Ed25519 stack (`ed25519-dalek`,
`curve25519-dalek`, `signature`, `rand_core`, `getrandom`), about 28 crates for
`url`, `idna` and ICU normalization, and five procedural-macro crates
(`curve25519-dalek-derive`, `displaydoc`, `yoke-derive`, `zerofrom-derive`,
`zerovec-derive`) that execute at build time when the privileged helper is
compiled. About ten of the 49 (`sha2` and its digest stack, `hex`, `ryu`) are
genuinely needed by the codec.

Pass 8's U2 was the HTTP client; that is gone, and the record discloses the
remaining codec cost as ruling 5, so this is not a hidden regression. The
defect is in the gate. `scripts/check-dependency-budget.py:84` sets the ceiling
at the measured 72, and the denial list (`:55-75`) names runtime, network,
regex, tracing, TLS and database crates but none of `url`, `idna`,
`ed25519-dalek` or `chio-security-types`. A future change that starts *using*
URL parsing or signature verification inside the bootstrap adds no package and
passes. Separately, `real-linux-enforcement` is an empty feature in the helper
(`Cargo.toml:11`) and no source references it, so the "release feature set" the
budget measures is the default graph.

Fix: give the canonical encoder and SHA-256 hex helper a dependency-free home
(a `chio-canonical` crate, or a `default-features = false` slice of
`chio-core-types` that excludes signing and URL support), set the helper
ceiling at the resulting floor of roughly 33 packages, and add `url`,
`idna`, `ed25519-dalek` and `chio-security-types` to `HELPER_DENY`.

**Confidence:** Confirmed. Both counts were measured with `cargo tree` at the tip.

## MO2. Low: removing upstream `nono` left nine vendored patch trees dead, and the record does not say so

c5ca13ddd3 removed `nono = "=0.53.0"` from `third_party/nono-chio/Cargo.toml`.
Upstream `nono` was the only path through which nine `[patch.crates-io]` entries
entered the lock graph. At c5ca13ddd3^ `Cargo.lock` has no `[[patch.unused]]`
section; at the tip it has nine (`Cargo.lock:16705-16739`): `cmpv2`, `crmf`,
`ignore`, `nono`, `regress`, `sigstore-crypto`, `sigstore-merkle`,
`sigstore-trust-root` and `sigstore-verify`. Every Cargo invocation now prints
nine "patch was not used in the crate graph" warnings. The workspace comments
that justify those trees are now false: `Cargo.toml:232` still says the
Sigstore verifier is "compiled through nono", and `Cargo.toml:228` describes a
"filesystem grant provenance repair" that nothing compiles. The trees, their
`supply-chain/reviews/*.md` entries and their gate references
(`scripts/check-stub-surfaces.py`, `scripts/check-rust-file-hygiene.py`) remain
as maintenance cost.

I checked for the dangerous variant, where a patch stops applying because of a
version mismatch and the unpatched registry crate is used instead. It does not
happen: none of the nine names has a registry entry in the tip lock except
`regress 0.10.5`, which was also present, unpatched, before this commit. The
execution record's ruling 7 mentions only `nono-upstream-chio`.

Fix: delete the eight unused patch entries and their trees in a reviewed
supply-chain change (keep `nono-upstream-chio` only if its provenance role is
real), correct the workspace comments, and record the removal in the
supply-chain README.

**Confidence:** Confirmed. Lockfile sections compared at both commits; warnings
reproduced with `cargo tree --offline`.

## MO3. Low: the helper extraction is one 62-file commit that mixes every category Packet 7 told the batch to separate

The plan's global constraint is "Separate mechanical relocation, visibility
restriction, and formatting commits", and Packet 7 says "Do not combine a cut, a
visibility change, a format pass and a logic fix in one commit." c5ca13ddd3
(`refactor:`) contains in one diff: the relocation of about 2,400 lines of
bootstrap code into a new crate; about 60 visibility changes from private to
`pub` (required by the crate boundary, but unreviewable in this volume); new
accessor APIs (`SeccompProfilePlan::profile`, `FileIdentity::new`) replacing
field access; deletion of the upstream `nono` dependency with a vendored ABI
probe (`third_party/nono-chio/src/abi.rs`) and removal of the
`Error::NetworkBaseline` check; concatenation of `chio-cage`'s `lib_parts` and
`linux_parts` fragments (MO4); rewrites of `scripts/check-dependency-budget.py`
(145 changed lines) and `scripts/check-linux-enforcement-stack.py` (150); and 755
lines of lockfile churn across two workspaces. It also broke the release recipe
until 938b76c311.

I reviewed the residuals and found the semantics preserved: the removed
`NetworkBaseline` check tested a set the constructor had just built with
`block_network()`, so it could never fire; the new `filesystem_access`
mapping is the old one with the derivable `AccessMode` argument removed; the
vendored `detect_abi` matches
`third_party/nono-upstream-chio/src/sandbox/linux.rs:18-90` in probe order,
`HardRequirement` mode, probe steps and caching, differing only in its return
and error types and a dropped `debug!` call; `send_descriptors` and `receive_descriptors` differ only
in the error type; `read_status`, `validate_prepared_launch_contract` and the
seal-mask comparison are unchanged. The cost of the mixing is therefore review
cost, not a defect, but it fell on the one commit in the slice that touches the
privileged confinement path.

Fix: none now. For the remaining Packet 7 owners, split a crate extraction into
(a) the move with the minimum visibility the boundary forces, (b) API
reshaping, (c) dependency changes, and (d) gate updates.

**Confidence:** Confirmed. Commit contents enumerated from `git show --stat`
and the normalized residual diff.

## MO4. Low: `chio-cage` fragments were concatenated, not given module boundaries, and its allowlist entry now describes code that no longer exists

Before c5ca13ddd3, `chio-cage/src/lib.rs` assembled `lib_parts/part_01.rs` and
`part_02.rs`, and `launch/linux.rs` assembled `linux_parts/part_01.rs` and
`part_02.rs` by `include!`. The commit moved the bootstrap out and then pasted
the remaining fragment text into the parents: `crates/security/chio-cage/src/lib.rs`
is now one 1,839-line library root (the lib-root limit is 1,000) and
`crates/security/chio-cage/src/launch/linux.rs` is one 1,987-line module, 13 lines
under the 2,000-line production cap, mixing launch supervision, seal checks,
the `CageTargetFdBindingMutation` conformance harness and tests. The
`launch/linux.rs` allowlist entry was dropped by the ratchet because the file
now sits under the cap. The `lib.rs` entry survives at
`scripts/check-rust-file-hygiene.py:568-572` with the rationale "cage crate
surface assembled from include! fragments; capped until the fragments become
modules", which is now false: there are no fragments, and they did not become
modules.

This is the inverse of the mistake Packet 7 names ("Do not split a file merely
to satisfy a line count"): the textual assembly is gone, which is real
progress, but the responsibilities inside the files were not separated, and the
size gate now reports green on a file one screen short of its limit.

Fix: when `chio-cage` is scheduled as a Packet 7 owner, split `launch/linux.rs`
into supervision, seal and descriptor verification, and the mutation harness,
and split the `lib.rs` root into model and admission modules. Correct the
allowlist rationale now.

**Confidence:** Confirmed. Fragment layout at c5ca13ddd3^, file sizes and
allowlist text at the tip.

## MO5. Low: reservation sealing added a second copy of the store's publication validator, and it runs after the publication has already driven recovery

68acb34aca correctly moved construction of `ReservedAttestedFindingResponsePlan`
into its owner, `event_consumer/reservation.rs`, and the compiler probe shows
siblings can no longer set its fields. To construct it from durable state it
added `reconstruct` and `from_publication`
(`crates/platform/chio-control-plane/src/security/event_consumer/reservation.rs:175-224`),
which check publication presence, batch id, ordinal and binding against the
record, canonical bytes, body hash, schema version, the ordinal bound, the five
plan-to-binding equalities and `validate_shape`. That predicate already exists
in the store and runs on every decode:
`crates/platform/chio-store-sqlite/src/security_state/response_outbox.rs:136-156`
and `:188-193`, invoked from `:464`. Only the call to
`validate_authoritative_finding_binding` is new and properly control-plane
owned. The module-boundaries plan forbids exactly this ("No compatibility implementation or duplicate validator"), and the two
copies already differ in order and error mapping, so they will drift.

If the second copy is meant as defense against a port implementation that does
not validate, it is in the wrong place. `recover_record` takes the publication
at `recovery.rs:514`, compares its execution mode, and on the
dispatch-committed path passes `publication.body.response_plan` to
`recover_committed` (`:571`) and `terminate_prepared_never_committed` (`:581-582`),
and checks its expiry (`:599`), all before `reconstruct` runs at `:632`. A
non-validating store would reach those effects unchecked. If the store is
trusted, the new checks are redundant. Either way the boundary is not
coherent. A smaller consequence: `bind_admission_artifacts` now rejects a
digest mismatch (`reservation.rs:238-243`), which makes the `Some(_)` arm at
`recovery.rs:657` unreachable.

The behavior on valid records is unchanged (the store rejects anything the new
code would reject), and the added test
`event_consumer/tests/real_adapter/reservation_ownership.rs` would fail if the
new checks were reverted to the previous direct construction (mutations 0, 1, 3
and 4 would then reconstruct), so this is a design defect, not a correctness
one.

Fix: give `AttestedFindingResponseOutboxRecord` one validating accessor in
`chio-security-types` (for example `validated_publication()`), call it from the
store's decoder and once at the top of `recover_record`, delete the
control-plane copy, and remove the dead arm.

**Confidence:** Confirmed. Both predicates and the call order were traced at the tip.

## MO6. Low: running `--ratchet` pushed back eight unrelated allowlist deadlines

The hygiene script's docstring (`scripts/check-rust-file-hygiene.py:26-31`)
says "Hand-editing an entry to raise a cap or extend an expiry without
shrinking the module defeats the gate." The batch followed the rule and used
`--ratchet` in cb91af8aa9, but the ratchet itself re-buckets every entry into
waves computed from today's date (`:1322-1422`). In this run eight entries
outside the slice moved later with no change in size: four that were due
2026-10-31 (`chio-runtime-core/tests/runtime_buyer_review.rs`,
`chio-web3/src/settlement_proof.rs`, `chio-wall/src/commands.rs`,
`chio-finding-verifier/src/verify.rs`) moved to 2026-11-30, and
`chio-cli/tests/certify.rs`, `chio-cli/tests/proof_cli_contract/support.rs`,
`chio-runtime-core/tests/runtime_admission.rs` and
`chio-store-sqlite/src/budget_store/tests.rs` each gained a month. Six others
moved earlier. Because the earliest wave is always the end of the following
month, running the ratchet at least monthly means no entry can ever reach its
deadline, which is the outcome the docstring forbids.
The `chio-cage/src/lib.rs` entry (MO4) is due 2026-10-31 and will be renewed
the same way.

Fix: the ratchet should keep each entry's existing expiry unless its cap shrank
in the same run, and assign a wave only to new or re-capped entries. The gate
design belongs to the toolchain reviewers; the effect is recorded here because
it happened in this slice's commit.

**Confidence:** Confirmed. Allowlist entries parsed and compared at
cb91af8aa9^ and cb91af8aa9.

## MO7. Low: the kernel test split deleted test-scope documentation and left broken comment fragments

e1e016f4d0 replaced the header comments of eight scenario modules with the
same line, "Shared fixtures are imported from the parent test module."
(`crates/kernel/chio-kernel/src/kernel/tests/approval_flow.rs:4`,
`compliance_score.rs:4`, `constraint_variants.rs:4`, `emergency.rs:4`,
`federation_cosign.rs:4`, `memory_provenance.rs:4`, `multi_tenant_receipt.rs:4`,
`plan_evaluation.rs:4`). Removing the stale "Included by `src/kernel/tests.rs`"
sentences was right, but the edit also removed the paragraphs that state what
each suite proves, including security properties: "the tenant tag is never
read from the `ToolCallRequest` itself" (multi-tenant receipts), "missing peer
pin fails closed" (federation co-signing), "hash-chain tamper is detected by
verify_entry" (memory provenance), and the HITL scope rationale. It also cut
sentences in half: `approval_flow.rs:6-9` now reads "...are already brought
into / paths intentionally resolve through `crate::approval*`...", and
`emergency.rs:6` is the orphan "// already imported.". The repeated line is
itself meta-narration about module wiring, which the house rules discourage.

Fix: restore the coverage paragraphs from e1e016f4d0^, drop the boilerplate
line, and repair the two fragments.

**Confidence:** Confirmed. Diff of e1e016f4d0 read in full for these files.

## MO8. Low: cross-scenario fixtures still live in scenario modules and reach every sibling through the root glob

The clock plan's Task 2 asked to "separate common fixtures from scenario tests".
Receipt and revocation stores did move to `kernel/tests/fixtures/`. But the root
`crates/kernel/chio-kernel/src/kernel/tests.rs:178-283` still re-imports
fixtures defined in scenario modules (`approval_flow`, `multi_tenant_receipt`,
`federation_cosign`, `execution_nonce`, `dispatch_credentials`,
`durable_admission`, `chio_runtime`, `invocation_context`,
`hot_path_deadlines`, `sim_payment`), and every scenario module begins with
`use super::*;`, so those fixtures are visible to every module under
`kernel::tests`. The root re-imports 32 items from ten scenario modules.
Examples:
`durable_admission_fixture` (defined in `durable_admission.rs`) is used by
`threshold_issuance.rs`, `boot_receipts.rs` and `chio_runtime/pre_dispatch_cleanup.rs`;
`handshake_and_pin` (in `federation_cosign.rs`) by `durable_admission/recovery.rs`
and `chio_runtime/admission_gates.rs`; `oauth_auth_with_enterprise_tenant`
(in `multi_tenant_receipt.rs`) by `session_reports.rs` and
`receipt_scope_isolation.rs`. Deleting or editing one scenario file therefore
breaks unrelated suites, which is the coupling the cut was meant to remove. The
record's phrase "narrow shared fixtures" overstates the result. No fixture is
`pub(crate)` (counted: zero), so this is reviewability debt, not a privacy leak.

Fix: move the cross-scenario fixtures into `kernel/tests/fixtures/` or
`support.rs`, and have scenario modules import named items instead of
`super::*`.

**Confidence:** Confirmed. Definitions and users located with `grep -rlw` at the tip.

## MO9. Note: commit discipline slips inside otherwise clean commits

The style commit 572c0a1052 also deletes nine `// tenant-read-contract:` gate
markers from `security_state.rs` that ff682ac69c had duplicated into the
schema modules (marker counts traced at 951d52009e, ff682ac69c, 572c0a1052). The
strict `no_std` Clippy check of `chio-security-types` (unused imports under
`-D warnings`) fails from ff682ac69c through 572c0a1052 and c5ca13ddd3 until
445fb2e28d, so three consecutive commits fail the T1 check the plan marks done
(traced from source for `PortResult`; not compiled).
445fb2e28d then combines that import repair with two test-logic changes (the
ledger-corruption expectation and the active-defense panic injection), and
leaves a doubled `#[cfg(feature = "std")]` at
`crates/security/chio-security-types/src/ports/containment.rs:1-2`. None of
these change behavior at the tip.

## MO10. Note: the bootstrap export moved rather than disappeared, and shared validation is owned by the helper

T5 says "remove the broad cage binary and bootstrap export". `chio-cage` no
longer exports `run_cage_init`, but `chio-cage-init` exports it as a safe `pub
fn` (`crates/security/chio-cage-init/src/lib.rs:87`), and `chio-cage` depends on
`chio-cage-init` on Linux (`crates/security/chio-cage/Cargo.toml:28`). The
function takes ownership of descriptor 0 with `File::from_raw_fd` when an
environment variable says so (`src/bootstrap.rs:17-38`); a parent that called
it would create a second owner of its own stdin. This is pre-existing (the old
`chio-cage` export had the same body). The shared parent/child validators
(`verify_received_descriptor_identity`, `helper_identity_and_binding_match`,
`seccomp_profile_is_fail_closed`, descriptor transfer) also live in the helper
crate, not in `chio-cage-plan`, so the parent links the helper library and
the helper's public surface is wider than its binary needs. Consider moving the
shared validators into `chio-cage-plan` and marking `run_cage_init`
`#[doc(hidden)]` or moving it into the binary target. Separately,
`FileIdentity::new` (`crates/security/chio-cage-plan/src/model.rs:55-75`) is a
new public constructor; it grants nothing new because the type already derived
`Deserialize`, and its only non-test caller is the public conformance mutation
harness (`crates/security/chio-cage/src/launch/linux.rs:1087-1097`).

## Execution-record claims checked

| Claim (record:line) | Verdict | Evidence |
| --- | --- | --- |
| Boundaries record:25 "The privacy pass removes 142 unnecessary helper-function visibilities" | Approximately confirmed | ff682ac69c: 110 fn and 24 const items narrowed from `pub(super)` to private, plus 2 `pub(in ...)` to `pub(super)`, by line pairing (136); exact 142 not reproduced |
| Boundaries record:29-30 facade sizes 293, 260, 604, 151, 153, 181 | Confirmed | `wc -l` at 8c8677470b matches all six |
| Boundaries record:35-38 helper graph 72 packages, ceiling 72, retired denials | Confirmed | `cargo tree` gives 72 unique name/version pairs; denials at `check-dependency-budget.py:67-75`. Undisclosed: 49 of 72 via `chio-core-types` (MO1) |
| Boundaries record:40-44 ABI probe extracted from reviewed upstream; upstream runtime dependency removed | Confirmed, incomplete | `abi.rs` matches upstream `sandbox/linux.rs:18-90`; nine patch trees became unused and are not mentioned (MO2) |
| Boundaries record:77-82 three ownership gaps fixed in 68acb34aca; probes first accepted, then rejected | Confirmed | `compiler-privacy-red.json` (exit 0, no diagnostics) and `-green.json` (E0603/E0616 on the private items); code at `authorization.rs:403-420`, `custody.rs:8-22`, `reservation.rs:104-114` |
| Boundaries record:83-84 "One new response test verifies successful reconstruction and five corrupt or rebound inputs" | Confirmed; calls `reconstruct` directly, not the recovery path | `reservation_ownership.rs`; under the previous direct construction mutations 0, 1, 3 and 4 would reconstruct, so it guards the change |
| Boundaries record:87-90 release workflow fixed with a red-then-green gate | Confirmed | 938b76c311; gate at `check-linux-enforcement-stack.py:554-565`, hostile fixture in `check-linux-enforcement-stack.test.sh` |
| Boundaries record:92-96 test-name multisets preserved (1,179 / 1,890 / 181 / 24) | Confirmed | Before/after inventories in `artifacts/2026-09-29-security-module-boundaries/` reconcile through `test-path-relocations.json` with zero missing; one added control-plane test. Per-commit `#[test]` counts unchanged except c5ca13ddd3 (cage 90 to 84, plan 0 to 5, helper 0 to 2) and 68acb34aca (+1); `#[ignore]` count 46 throughout |
| Boundaries record:105-107 "all 1,263 baselined negative assertions at 1,180 sites" | Confirmed | `negative-assertions-baseline.txt`: 1,180 rows summing to 1,263 before and after the batch |
| Boundaries record:113-119 two tests already failed pre-batch (ledger diagnostic, unconsumed `panic_once`) | Confirmed | The `panic_once` consumer was removed by 00536cc902, which precedes the batch start d51afb4a5f |
| Boundaries record:24-25 relocation, visibility and formatting are separate commits | Confirmed for ranks 1-4, with MO9 exceptions | Residual counts: 2, 13, 0, 47 |
| Clock record:26-27 "Forty-four hand-maintained root includes became responsibility-named modules" | Confirmed | 44 `include!` lines in `kernel/tests.rs` at 040244e3a6^; zero under `kernel/tests` after |
| Clock record:31-33 "All 845 original test bodies and 1,491 original compiled tests survive" | Confirmed | 845 test attributes before and after 040244e3a6..e1e016f4d0 (846 at tip); leaf-name multiset of `kernel-tests-before.txt` equals `kernel-tests-after.txt` minus `clock_failure_during_emergency_stop_cannot_resume_execution`. The two path-mapping files omit 185 renames (for example `kernel::tests::authority_profile::*`), so the leaf comparison, not the mapping, is what holds |
| Clock record:28-29 "mutable database internals and treaty signing keys remain private" | Confirmed | No `pub(crate)` or `pub` in `kernel/tests`; `fixtures/receipt_store.rs` exposes only `pub(in crate::kernel::tests)` type and methods; treaty keypairs reached through accessors (619a60e577) |
| Clock record:27 "with narrow shared fixtures" | Overstated | MO8 |
| Clock record:60 "182 default-feature selectors resolve" | Not counted; consistent | All 219 `kernel::tests::` selectors in `scripts/` and `.github/` resolve at the tip |

## Verified clean

- **Production relocations are moves.** The normalized multiset diff of
  4c82a9178e, 29ec6dd424, 951d52009e and d2b721ea24 leaves no residual line in
  a function body, SQL string, error mapping, canonical encoding or signed-byte
  projection. The SQLite cut is exact (zero residual over 6,171 lines).
- **Formatting commits are formatting.** 572c0a1052 and 2916c7040c change only
  whitespace, import grouping, `pub (super)` spacing and `mod` order (MO9
  aside).
- **No visibility widening.** Across 4c82a9178e..8c8677470b in the four owners,
  every changed declaration went from private to `pub(super)` or `pub(in ...)`
  (477 and 14), which is the scope the textual include already had; none went
  to `pub(crate)` or `pub`. Test accessors added for moved tests
  (`test_prepared`, `test_request`, `synthetic`, `test_from_publication`) are
  all `#[cfg(test)]`. `SeccompProfilePlan::test_unchecked` and its siblings are
  behind `enforcement-mutants`, which both new crates refuse to build without
  `debug_assertions`.
- **cfg predicates preserved.** Broker prepared-connection tests went from
  `cfg(target_os = "linux")` inside `cfg(test)` to
  `cfg(all(test, target_os = "linux"))`; every removed `cfg` line in the cuts
  has a matching added one.
- **Broker sealing is behavior-neutral.** 68acb34aca's broker half moves the
  retained-dispatch map behind `RetainedDispatchCustody` with the same
  poison-to-`Invariant` mapping and replaces direct field reads with
  `revocation_set()` and `into_revocation_set()`.
- **Helper bootstrap semantics preserved.** Descriptor transfer, status
  reading, envelope validation, seal-mask comparison, the three
  `KillProcess` assertions (`chio-cage-plan/src/seccomp_plan.rs:360`,
  `chio-cage-init/src/validation.rs:50`, `chio-cage/src/launch/linux.rs:820`)
  and the filter default in `chio-cage-init/src/seccomp.rs:95` are unchanged
  apart from error type and accessor syntax. The entrypoint still exits 127 on
  every failure and on non-Linux targets.
- **No unpatched crate reintroduced.** MO2's dead patches did not cause any
  registry version of a patched crate to enter the lock.
- **Selectors.** Every kernel selector in CI and scripts resolves at the tip,
  and the exact-inventory runners would fail on a mismatch rather than run zero
  tests.
- **House rules.** No em dash and no unwrap or expect in production code was
  added by these commits; the new crates deny `indexing_slicing`, `panic` and
  `as_conversions` outside tests; new comments carry no process vocabulary
  apart from MO7's boilerplate line.

## Recommendations for the remaining plan

1. Before scheduling the next Packet 7 owners, put `chio-cage` on the list
   (MO4) and split crate extractions into move, API, dependency and gate
   commits (MO3).
2. Extract the canonical codec so the helper ceiling can fall to its real floor,
   and deny the crypto and URL stacks explicitly (MO1). Remove the dead patch
   trees in the same supply-chain review (MO2).
3. Replace the duplicated publication validator with one accessor on the shared
   port type and call it before any use of the publication in recovery (MO5).
4. Fix the ratchet so renewal requires shrinkage before the 2026-10-31 wave
   fires (MO6).
5. Restore the deleted coverage comments and move cross-scenario kernel
   fixtures into `fixtures/` (MO7, MO8).
6. Stop committing full terminal logs as evidence. The two artifact directories
   for this slice hold 6.4 MB (`security-module-boundaries` 1.2 MB,
   `native-clock-test-ownership` 5.2 MB, about 47,000 lines). A digest, the
   command, the exact counts and a short excerpt of each failure carry the
   same assurance at a fraction of the repository cost.
