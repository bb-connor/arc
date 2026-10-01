# Execution review: signed readers, kernel admission readers and authority boundaries, October 1, 2026

Scope: the three September 28 closure commits on `packet/3-retention-accounting`:
`f16d4e781c` (signed readers and tenant-scoped readback), `a3217b9145` (kernel and
SQLite admission readers) and `a76864ad1a` (four-owner authority boundary
closure). Plans reviewed:
[signed-reader tenant closure](../superpowers/plans/2026-09-28-signed-reader-tenant-closure.md),
[kernel admission reader closure](../superpowers/plans/2026-09-28-kernel-admission-reader-closure.md)
and [authority boundary closure](../superpowers/plans/2026-09-28-authority-boundary-closure.md).
Execution records reviewed:
[signed-reader tenant execution](2026-09-28-signed-reader-tenant-execution.md),
[kernel admission reader execution](2026-09-28-kernel-admission-reader-execution.md)
and [authority boundary closure](2026-09-28-authority-boundary-closure.md).
Base `07e963e8f5`, tip `a2630c20a1`. Method: read each diff, then the resulting
code at the tip, prioritizing authority-bearing owners over test and inventory
churn; traced every finding to its callers; sampled the retained evidence logs
under `/tmp/chio-{reader-tenant,kernel-sqlite,authority-boundaries}-20260928/`
for the strongest record claims. No code was run.

**Judgment: The authority-bearing core of this slice is sound. The terminal
authorization proof is sealed and re-verified on every read, registry and IOU
readback now bind identity to the stored record, DSSE and JWT segments are
bounded before base64 allocation, runtime-core readback binds index and digest,
and the a3217b9145 and a76864ad1a mutation evidence is genuine (hashes and
failing-test logs match). The most important defect is a regression introduced
by the a76864ad1a clock migration: Finding challenge submission now samples
trusted time before a client-paced body upload of up to 30 seconds, so the signed
filing window is enforced against a stale time (RC1). The second problem is
honesty of the inventory: the "semantic dispositions" that close the 73 and 76
owner sets are mostly one repeated sentence and a uniform 64 MiB bound, which is
a mechanical census rather than the per-owner provenance and bound
classification the plans required (RC2). Of roughly 25,000 inserted lines, about
10,000 are inventory JSON and most of the rest is mechanical reader substitution
and test relocation; the defensible security value sits in perhaps a dozen
owners, and the largest single closure (authorization consumption) hardens a
participant that no production operation can carry (RC3).**

## Plan conformance

| Plan item | Recorded status | Verified status | Evidence |
| --- | --- | --- | --- |
| Signed-reader T1: broaden decoder gate to unregistered files, imported spellings, custom decoding; calibrate | Done | Done, lexical only | `scripts/check-trust-boundaries.py` `json_decoders` and exact-equality census; calibrations for unregistered reader, imported alias and custom deserializer exist (`scripts/tests/check-trust-boundaries.test.py:82-104`). No explicit "permitted conversion accepted" calibration. |
| Signed-reader T2: credentials, passport/issuance/certification registries, Finding readers | Done | Done with gaps | Map-key identity bound for all four registries (`passport_verifier.rs` loaders, `certify/registry.rs:46-49`); passport `updated_at == 0` rejects. Certification entries still accept zero `published_at`/`revoked_at` (RC8). Registry negatives cover wrong map key and duplicate keys, not invalid signature or wrong signer. |
| Signed-reader T3: DSSE, FROST slot, iroh transport, tool outcomes, admission evidence | Done | Done, one diagnostic regression | PAE and payload bounds correct (`bilateral_dsse/types.rs:322-347`); embedded-receipt noncanonical code regressed (RC6). Transport decodes after bounded frame read and peer gate. |
| Signed-reader T4: 85-table tenant matrix | Done (84 + 1 gap) | Done as recorded | Sampled new isolation tests present A's exact IDs under B and after reopen (e.g. `tests/capability_set_suspensions/tenant_isolation.rs`). |
| Signed-reader T5: direct production-source mutation calibration | Done | Weaker than planned | Calibration compiled `signed_input.rs` with its own unit test in an isolated `rustc` harness and ran two SQL literals in Python `sqlite3`; no crate test of a repaired reader was mutation-checked (see claims table). |
| Kernel T1: retained admission inputs, v4 only, remove v1-v3 | Done | Done; break undocumented | `retained_request.rs:16,223-236`. Existing v1-v3 rows brick store open (RC5). |
| Kernel T2/T3: terminal, output, delivery and SQLite reader owners with semantic dispositions | Done | Migrated mechanically; dispositions are boilerplate | 63 of 73 `reviewed_kernel_sqlite_owners` entries carry one identical contract sentence; 64 of 120 migrations use the literal `64 * 1024 * 1024` rather than the owner bound (RC2). |
| Kernel T4: 264 arithmetic and 112 clock dispositions | Done | Spot-checked only | `receipt_analytics.rs` checked repair and u128 ratio verified; the arithmetic and clock inventories belong to the accounting-clocks review. |
| Kernel T5: durable authorization-consumption coverage | Done | Done as specified; unreachable in production | Production `verify` and `commit_signed_terminal_projection` driven with re-signed substitutions, replay, reopen and sidecar tamper (`admission_operation_store_tests/authorization_consumption.rs`). No production operation sets the requirement (RC3). |
| Kernel T6: precise provenance, real bypass calibration | Done | Partly | Two genuine runtime mutants killed. All eight substitution variants share `TerminalProjectionBindingMismatch`; double consumption surfaces as `Unavailable` SQLite prose (RC4). |
| Authority T1-T4: classify and harden 76 owners | Done | Migrated mechanically; dispositions mostly boilerplate | 51 of 77 `reviewed_authority_owners` entries share one sentence; 100 of 114 migrations use the 64 MiB literal; 30 sites carry the `from_wire((x).as_bytes(), ...)` regex artifact (RC2). |
| Authority T5: 37 arithmetic, 51 clock occurrences | Done | Done with a regression | Fallible sampling removes `unwrap_or(0)` time; seven file-local `SystemClock` helpers, not injected; challenge submission sample moved before body read (RC1, RC9). |
| Authority T6/T7: regressions, four bypasses, gates | Done | Verified | `mutant-results.json` and per-mutant logs show the named test failing at runtime for all four. |
| Open items: 447/374/298 baseline files, broad census | Open | Correctly open | Records do not claim correction 1F closure. |

## RC1. Medium: Finding challenge submission enforces the signed filing window against a time sampled before a 30-second client-paced upload

`a76864ad1a` moved the trusted-time read in `handle_submit_finding_challenge`
from the point of use to handler entry
(`crates/platform/chio-control-plane/src/trust_control/finding_challenge_handlers.rs:253`).
Between that sample and its use at `:406` (`executor.submit(..., clock_now)`) the
handler streams the body with `collect_challenge_body(..., FINDING_CHALLENGE_BODY_READ_DEADLINE)`
(`:280`), a deadline of 30 seconds (`:41`) that the client controls by pacing
its upload. Before the commit the sample was taken inside `spawn_blocking`,
after the body was read.

The coordinator treats that value as the venue's receipt time:
`submission.rs:111` calls `require_filing_window(&terms.body, body.filed_at, now)`,
and `governance_pins.rs:492` rejects only when `received_at > deadline`. The
same value becomes `submitted_at` (`submission.rs:213`), the dispute-lock
reservation time (`:253`) and the historical audit-role liveness time (`:63`).

Failure scenario: terms close the filing window at T. A challenger signs a filing
with `filed_at = T - 1`, opens the request at T - 1 and dribbles the body so it
completes at T + 29. `clock_now = T - 1`, both window checks pass, and the
filing is accepted and recorded as submitted at T - 1, 29 seconds after the
seller-signed window closed. A role revoked in that interval is likewise judged
live. No test drives a slow body, so the suite cannot see this.

The same entry-sampling pattern applies to handlers that await
`forward_post_to_leader` before using the sample (`passport_handlers.rs:1050`
then `ensure_federated_delegation_policy_active(policy, now)` at `:1070`;
`authority_handlers.rs:467`). There the staleness only arises when forwarding
fails and leadership moves to this node mid-request, bounded by two 15-second
client timeouts (`service_types/paths.rs:255`, `report_rendering.rs:300-338`).

Fix: sample after the body is collected and after any forward, immediately
before the authority decision. Fail early on clock outage with a cheap
availability probe if desired, but never reuse that probe as decision time.
Add a regression that delays the body past the window and asserts
`FilingWindowClosed`.

**Confidence:** Confirmed for the challenge path by step-by-step source trace of
the diff and the coordinator; the leader-forward instances are Plausible because
they need a mid-request failover.

**Independent verification:** Confirmed, with a sharper consequence and a narrower bound. The
`governance_pins.rs:469-478` comment says `received_at` exists to stop a caller backdating a
freshly signed filing. With the time read before the body, a client can open the request at T-1,
sign a filing dated T-1 at about T+28 (it satisfies `filed_at <= now`, `submission.rs:73`) and
stream it in; it is accepted and recorded as submitted at T-1. No router-level timeout shortens
the 30 s body window. The verifier rates it Low to Medium because the extension is bounded by
that window plus blocking-pool queueing; it stays Medium here because it inverts the stated
purpose of an authority-time check.

## RC2. Medium: The kernel and authority "semantic dispositions" are a repeated sentence and a uniform 64 MiB bound, not the per-owner classification the plans required

The kernel plan required each baseline owner to be dispositioned "against its
current producer and consumer", distinguishing "signed/digested artifacts,
unsigned configuration, custom typed deserialization and test-only fragments"
(kernel plan Task 3) and classified "by actual input provenance, numeric domain,
bound and validation sequence" (Task 1). The authority plan repeats this.

At `a76864ad1a`, 63 of the 73 `reviewed_kernel_sqlite_owners` entries in
`docs/security/trust-boundary-inventory.json` carry the identical contract text
("Bounded native JSON decoding ... the owner retains exact canonical equality
where required and its existing signature, digest, identity, tenant, operation
and mirrored-column checks"), and 51 of 77 `reviewed_authority_owners` entries
share another single sentence. "Where required" is precisely the per-owner fact
the plan asked to be recorded. Of the recorded migrations, 64 of 120
(kernel/SQLite) and 100 of 114 (authority) use the literal `64 * 1024 * 1024`
rather than the owner's real bound. Thirty `a76864ad1a` sites read
`UntrustedJsonText::from_wire((json).as_bytes(), 64 * 1024 * 1024)`, the
parenthesized residue of a regex rewrite (`chio-runtime-core/src/treaty.rs:20-37`,
`trust_control/finding_handlers.rs:233,247,290,707`). The workspace now carries
243 production occurrences of that literal.

The uniform bound is not harmless where an owner bound exists. In
`verify_stored_terminal_projection`
(`crates/platform/chio-store-sqlite/src/admission_operation_store/projection.rs:1062-1071`),
introduced by `f16d4e781c`, every stored terminal record is parsed into a
`serde_json::Value` under the 64 MiB bound and only afterwards checked against
`MAX_TERMINAL_RECORD_BYTES` (1 MiB, same file). This runs at every store open
for every terminal operation. The same `tool_outcomes` row is read with the
1 MiB owner bound in `tool_outcome_store.rs:1217` and with 64 MiB in
`admission_operation_store/participant.rs:1089`. Database reads are allocated by
rusqlite before any of these bounds apply, so for SQLite owners the bound is a
parse limit only, which the dispositions do not say. Two near-identical bounded
file and stream readers were also added to one crate (`signed_input.rs` in
`f16d4e781c`, `json_input.rs` in `a76864ad1a`).

Consequence: the gate now refuses to let these 150 owners return to the
baseline on the strength of text that does not record their provenance or bound.
A later reviewer reading the inventory will believe a classification exists.
Fix: replace the generic sentence with the owner's actual input class and bound,
use the owner's existing `MAX_*` constant at every migrated site, check SQL
`length()` before reading untrusted blobs where the row can be externally
written, and fold `json_input::read` into `signed_input`.

**Confidence:** Confirmed by counting the committed inventory at `a3217b9145` and
`a76864ad1a` and by source reading of the cited sites.

## RC3. Low: The authorization-consumption closure hardens a participant that no production operation can carry

`VerifiedAuthorizationReceiptConsumption::from_signed_source`
(`crates/kernel/chio-kernel/src/admission_operation/projection/authorization.rs:37`)
is now `pub` and genuinely verifies source and consumer signatures, request,
capability, policy, tool, tenant, parameter and outcome bindings before the proof
exists. Its only callers are tests. The kernel coordinator's sole production
`AdmissionCompletedProjection` sets `authorization: None`
(`kernel/admission_coordinator/terminal.rs:1839`), and completion requires
`completed.authorization.is_some() == requirements.authorization_consumption`
(`admission_operation/projection.rs:1134`). No production code sets
`authorization_consumption: true` in `AdmissionParticipantRequirements`
(`identity.rs:233` is the only literal, `false`). The verifier is reachable only
through `commit_signed_terminal_projection` from a peer that constructs both the
operation and the envelope outside this codebase.

The records state that ordinary local completion supplies no participant
(kernel record line 157), so this is not a false claim. It is a proportionality
problem: about 700 lines of verifier and fixture close "the last uncovered
SQLite table" for a participant whose producer, the ACP proxy authorization
receipt format the verifier mirrors (`chio-acp-proxy/src/kernel_signer.rs`), is
not wired to the kernel. Either wire the producer and requirement, or remove the
participant and its table, and record which.

**Confidence:** Confirmed by exhaustive grep of `from_signed_source`,
`authorization:` construction and `authorization_consumption:` requirement
literals outside tests.

## RC4. Low: Double consumption of an authorization receipt is reported as a transient store outage

The second consumption of one `authorization_receipt_id` is refused only by the
table's UNIQUE constraint. The insert maps the error through `sqlite_error`
(`admission_operation_store/projection.rs:398`), which turns every non-decoding
rusqlite error into `AdmissionOperationStoreError::Unavailable`
(`admission_operation_store.rs:1622-1629`), and the admission authority maps that
to the wire `Unavailable` code (`service_runtime/admission_authority.rs:803`). The
regression enshrines the prose:
`Err(AdmissionOperationStoreError::Unavailable(message)) if message.contains("UNIQUE constraint failed")`
(`admission_operation_store_tests/authorization_consumption.rs:472`).

A permanent replay refusal therefore looks retryable to the remote kernel, leaks
the table and column name, and violates standard sections 3.1 and 3.4. Relatedly,
all eight signed substitution variants assert the single
`TerminalProjectionBindingMismatch`; only the tenant variant was shown by
mutation to reach its own rule. Fix: pre-check or map the constraint to a typed
`AuthorizationAlreadyConsumed` conflict and give the substitution rules a
rejection payload.

**Confidence:** Confirmed for the classification by source trace; the retry
behavior of the remote caller is Plausible.

## RC5. Low: Removing v1-v3 retained requests makes any database containing one fail to open, with no schema step and no recorded break

`RetainedToolAdmissionRequestV1::from_canonical_bytes` now accepts only
`chio.retained-tool-admission-request.v4` with a mandatory profile
(`crates/kernel/chio-kernel/src/admission_operation/retained_request.rs:16,223-236`).
At every open of a current-version store, `verify_admission_operation_invariants`
walks every admission operation and calls `load_retained_request_tx`
(`chio-store-sqlite/src/admission_operation_store/schema.rs:70-71,552-557,854`).
Retained request rows are immutable and undeletable by trigger
(`admission_operation_store.sql:84-95`). One v1-v3 row, including on a long
completed operation, therefore fails the whole serving owner open with an
invariant string, permanently, and the supported schema version (34) was not
advanced to give the refusal a named step.

The formats never reached `main` (`bd94b09a7b` and `7e54c14a60` are not ancestors
of `origin/main`), and the plan forbids compatibility paths for unshipped
formats, so the break itself is acceptable pre-launch. What is missing is the
statement: neither the record (line 16) nor the plan says existing development
databases become unopenable, and `docs/security/launch-plan.md:7084` still says
v1-v3 bytes "remain readable". Fix: bump the schema version with a step that
refuses pre-v4 retained rows by name, and record the break.

**Confidence:** Confirmed by source trace of the open path and triggers.

## RC6. Low: A noncanonical embedded DSSE receipt now reports a code outside the normative set

`f16d4e781c` replaced the explicit canonical comparison in
`decode_embedded_receipt` with `decode_canonical` mapped to
`format!("receipt json: {e}")`
(`crates/trust/chio-federation/src/bilateral_dsse/verify.rs:610-615`). The
previous message began `predicate.schema_invalid:`, which
`BilateralCoSigningError::code` maps to `predicate.schema_invalid`. The new
message matches no prefix and falls through to `canonical_json.invalid`
(`crates/trust/chio-federation/src/bilateral.rs:345-351`), which is not among
the codes `spec/CHIO_BILATERAL_COSIGN_INVOCATION.md` (section 7.1, lines 440-450)
says MUST be surfaced. The record (line 58) says the established
noncanonical-statement diagnostic was preserved; the receipt one was not, and no
test asserts it. Fix: keep the `predicate.schema_invalid:` prefix for every
embedded-receipt rejection and add the code assertion.

**Confidence:** Confirmed by source trace of the message and the code mapper.

## RC7. Low: The "shared strict" JWT reader leaves header policy to each caller, and three of four verifiers do not check `alg`

`decode_compact_jwt_without_signature`
(`crates/trust/chio-credentials/src/jwt_decode.rs:10-81`) bounds each segment
before base64, rejects duplicate header and payload keys, and returns the
original `header.payload` preimage. That part is correct. Header policy is left
to callers: SD-JWT requires `alg == "EdDSA"` and its `typ`
(`portable_sd_jwt.rs:415-420`), but `verify_signed_oid4vp_request_object`
(`oid4vp.rs:610-623`) and `verify_oid4vp_direct_post_response` (`oid4vp.rs:893-902`)
check only `typ`, and `verify_chio_passport_jwt_vc_json`
(`portable_jwt_vc.rs:116-123`) accepts a missing `typ`. A token with
`"alg":"none"` or `"alg":"HS256"` is accepted if its Ed25519 signature verifies
under the configured key. That is not a forgery, because the key type is fixed,
but it contradicts the "shared strict header/payload reader" entry in
`docs/security/signed-json-boundaries.md:121`. The reader also uses the native
`decode_signed` contract for third-party tokens (and for Azure MAA and Google
attestation JWTs in `attestation/verification.rs`), where that document assigns
external text to strict I-JSON (lines 10-13). Fix: move `alg == EdDSA` and
`crit` rejection into the shared reader and choose the external contract
deliberately.

**Confidence:** Confirmed by source reading.

## RC8. Low: Certification registry readback accepts zero lifecycle timestamps

`CertificationRegistry::load` now binds the map key to `artifact_id`
(`crates/platform/chio-control-plane/src/certify/registry.rs:46-49`), but
`verify_certification_registry_entry` (`certify/verify.rs:32-99`) checks only
presence of `revoked_at` and `superseded_at` and accepts `published_at = 0`,
`revoked_at = Some(0)` and `superseded_at = Some(0)`; `revoke` accepts a
caller-supplied `Some(0)` (`registry.rs:172-176`). The passport status registry,
by contrast, now rejects a zero `updated_at` and `published_at`. The record's
claim of rejecting zero lifecycle timestamps (line 46) is accurate for passports
only. Fix: apply the same nonzero rule to certification entries and to the
revoke and dispute inputs.

**Confidence:** Confirmed by source reading.

## RC9. Low: The trust-control clock migration replaces one ambient read with seven ambient helpers, and six tests now pass vacuously on clock failure

`a76864ad1a` removed the `unwrap_or(0)` time defaults, which is a real fix
(`reputation.rs` previously evaluated with `now = 0` on clock failure). But the
replacement is seven file-local helpers that each construct `SystemClock` at the
call site (`passport_verifier.rs:1433`, `underwriting_and_support/policy_support.rs:950`,
`finding_operator_purchase.rs:1702`, `issuance/util.rs:1`, `evidence_export.rs:320`,
`certify/helpers.rs:9`, `reputation.rs:24`). The clock is still ambient and
unfenced in trust-control, contrary to standard section 6.1, and the clock gate
cannot see it because it matches only `SystemTime::now` and `Utc::now`
(`scripts/check-security-clocks.py:54-57`). Six tests now begin
`let Ok(clock_now) = unix_timestamp_now() else { return; };` and pass without
asserting anything when the clock fails (for example
`trust_control/cluster_and_reports.rs:280`). Fix: inject the service clock
through `TrustServiceState`, delete the helpers, and make the tests fail on
clock error.

**Confidence:** Confirmed by source reading and grep.

## Execution-record claims checked

| Claim (record:line) | Verdict | Evidence |
| --- | --- | --- |
| Signed-reader:18, 114 constructors, 556 decoder-bearing files | True | 447 + 86 + 14 + 9 = 556 in the `f16d4e781c` inventory. |
| Signed-reader:40, IOU readback verifies signature and mirrored columns | True | `iou_store.rs` `decode_envelope` and `get_by_receipt_id`; the issuer is self-anchored, as the record says. `get_by_receipt_id` has no production caller. |
| Signed-reader:46, registry keys bound; zero lifecycle timestamps reject | True for passports, partial for certification | RC8. |
| Signed-reader:52, reputation JSON no longer falls through | True | Signed shape chosen by `body`/`signature` keys; plain policy is `deny_unknown_fields`, so a malformed signed document cannot parse as a plain policy. |
| Signed-reader:54, SD-JWT checks EdDSA and bounds before base64 | True | `portable_sd_jwt.rs:399-420`, `jwt_decode.rs:25-35`. Other JWT verifiers do not check `alg` (RC7). |
| Signed-reader:58, DSSE bounds before base64 and PAE; diagnostic preserved | True for statement, false for embedded receipt | RC6. |
| Signed-reader:121, credentials 58 passed | True | Log shows 58 passed; `#[test]` count went from 56 to 58 across the module move, so no tests were lost. |
| Signed-reader:163, all 38 matrix references have terminal passing logs | True | `matrix-runtime-evidence.json` maps each reference to a passing test name. |
| Signed-reader:179, production-source calibration | True as worded, weak as evidence | `calibrate-readers.py` compiles the 51-line `signed_input.rs` with its own unit test in a standalone harness and evaluates two SQL literals against a hand-written schema in Python. No regression test of a repaired reader (IOU, registry, SD-JWT, DSSE) was mutation-checked. The new registry tests assert unique `RecordBinding` variants, so they would fail on revert, but that is by construction, not demonstrated. |
| Kernel:16, v4 required; old acceptance removed | True | RC5 covers the undocumented consequence. |
| Kernel:20, proof verifies source and consumer; readback reruns; deserialization never builds the proof | True | `authorization.rs:16-27` private `Wire` DTO; `from_canonical_record_verified` reruns `from_signed_source` and compares exact bytes; SQLite readback calls it (`projection.rs:1389`). The expected kernel key is the stored consumer receipt's own key, anchored at commit by the `kernel:<signer>` claimant check (`participant.rs:186-192`). |
| Kernel:53, 536 kernel tests passed | True | `kernel-focused-final.log`. SQLite cohorts with failures are reported as failed, with targeted reruns, as stated. |
| Kernel:76, eight re-signed substitution variants | True | `authorization_consumption.rs:288-354`; all assert the same variant (RC4). |
| Kernel:100, all 85 tables map to exercised families | True in the narrow sense | The authorization family is exercised only through a test-built projection (RC3). |
| Kernel:111, two runtime bypasses killed, sources restored | True | `runtime-mutations.json`; restored hashes `c522b3ea...` and `f9f51a8e...` equal the committed blobs; mutant logs fail at the named tests. |
| Authority:13, 114 decoder calls migrated | True, mechanically | RC2. |
| Authority:21, runtime admission and swarm readback bind index and digest | True | `store/sqlite/admission_replay.rs`, `swarm_authority_bundles.rs`; treaty artifacts bind digest only, as recorded. |
| Authority:28, 15 ambient clock reads replaced | True, still ambient | RC9; one move introduced RC1. |
| Authority:59, 153 distinct tests | True | The table rows sum to 153. |
| Authority:63, four production bypasses killed | True | `mutant-results.json` and logs: each named test fails at runtime. The policy-version mutant removes a pre-existing check, so it calibrates a strengthened test rather than a repaired defect. |
| Authority:95, baseline 374 to 298 | True | 374 minus 76 reviewed owners. |

## Verified clean

- Authorization proof sealing: `VerifiedAuthorizationReceiptConsumption` has
  private fields and derives only `Debug`, `Clone` and `Serialize`; the
  deserializable `Wire` is private. A proof placed in another operation's
  projection is re-validated by `validate_against`, which reruns
  `from_signed_source` against the consuming operation
  (`authorization.rs:176-204`).
- SQLite authorization readback cannot rebuild the proof without re-verifying
  signatures; it reconstructs only the historical predecessor, using the same
  four fields `apply_terminal_projection` changes (`projection.rs:1945-1951`).
- DSSE PAE matches the DSSE v1 construction, uses byte lengths, and the payload
  bound precedes base64 decoding (`bilateral_dsse/builder.rs:13-37`,
  `types.rs:327-347`).
- Federation transport: frames are bounded by `read_frame`, the peer gate runs at
  handshake, and strict decoding precedes signature and treaty verification in
  the bilateral, fanout, revocation and catchup lanes.
- Tenant readback: the only `(?n IS NULL OR tenant_id = ?n)` statement in
  production SQLite (`receipt_store/support/store_impl.rs:21`) receives `NULL`
  only for `ReceiptReadBoundary::AdminAll`; tenant contexts always supply the
  tenant (`receipt_query.rs:215-235`).
- OID4VP stored requests and passport challenges now bind ID, issue and expiry
  projections on fetch (`passport_verifier.rs` `fetch_active` paths), with a
  reopen regression that substitutes a valid foreign challenge.
- Attenuation witnesses now require exact canonical scopes before
  interpretation (`capability/attenuation.rs:902-911`).
- No em dashes, no new production `unwrap`/`expect`, and no process vocabulary in
  comments were added by the three commits.

## Recommendations for the remaining plan

1. Fix RC1 before any further clock migration, and audit every handler that now
   samples time at entry for an intervening body read or network await.
2. Rewrite the reviewed-owner dispositions so each states input provenance,
   signed or unsigned class and the owner's real bound; make the gate reject the
   generic sentence and the bare `64 * 1024 * 1024` literal in migrated sites.
3. Decide the fate of the authorization-consumption participant: wire the ACP
   authorization producer and requirement, or delete it.
4. Give replay and substitution refusals typed variants (RC4) and restore the
   normative DSSE code (RC6) before external federation partners test against
   section 7.1.
5. Inject one trust-control clock and remove the file-local helpers; extend the
   clock gate to direct `SystemClock` construction outside composition roots.
6. For future calibration claims, mutate the repaired production owner and run
   its crate test, as `a3217b9145` and `a76864ad1a` did; an isolated harness of
   a helper's own unit test does not demonstrate regression sensitivity.
