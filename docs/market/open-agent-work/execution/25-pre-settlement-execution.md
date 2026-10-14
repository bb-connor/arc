# Native execution evidence before settlement

The original funded operation can now produce a signed execution receipt before
claim submission or payment. The actual Finding verifier checks that receipt and
its checkpoint against the authority profile committed in the original agreement.
The independent W0 checker then determines whether the submitted result merits
payment. Execution evidence never supplies financial backing by itself.

This delivery builds on `df2e7ef0ed1e1ba3ba5ef244e2247347b2c0f3e0` in
`feat/funded-native-admission`. The [evidence manifest](26-pre-settlement-execution-evidence.json)
binds qualification commands, source objects, executable bytes and public results.
The [previous delivery](23-registered-work-finding-acceptance.md) remains a
historical record of the earlier empty-evidence profile.

## Original execution authority

`ChioKernel::export_durable_execution_evidence` authenticates the exact retained
request and emits one immutable `ChioReceipt` with semantics
`chio.pre_settlement_execution.v1`. The closed `chio.execution_evidence.v1`
metadata commits the original authority, operation, request, hold, authorization,
raw outcome, resolved output, complete post-return evaluation, guard verdict and
pricing verdict. The phase is `execution_confirmed`.

The first export requires a Finalizing operation, a complete native Value return,
a resolved allow verdict and the originally retained signer. Streams, caller
delivery, federation, security release and incomplete outcomes are unsupported.
Export does not dispatch, settle, release output or terminalize the operation.
The receipt has no financial or budget-authority blocks and creates no settlement
observer work item. The later payment receipt keeps its existing financial role.

Signing runs outside the mutation sequencer. The kernel revalidates the original
claim, live lease, fence and request afterward. The SQLite participant reloads
the exact retained sources and checks fresh time after acquiring its write lock.
Only a kernel-qualified, non-deserializable token can authorize the projection.
The exact additive v3-to-v4 migration preserves existing security-release data.
Projection bytes are covered by the admission participant commitment and the
external rollback anchor. Retained raw sources cannot be compacted away.

Restart and post-payment export authenticate the first receipt and return its
exact bytes without invoking a replacement signer. Current cryptographic floors
still apply. Tests cover signer panic, callback reentry, lease expiry, changed
source/fence, unsupported provenance, row deletion, self-consistent replacement,
and restoration of an older database under a newer external anchor.

## Finding acceptance and checkpoint custody

The new local context v2 pins production, checkpoint, status and governance keys
before both parties sign the agreement. Governance standing is fixed at bootstrap;
production and checkpoint standing are signed after those artifacts exist. Keys
are separated into private fixture directories, but remain under one operator.

The native SQLite receipt log retains its same-signer checkpoint rule. A separately
pinned one-leaf execution log uses the existing checkpoint builder over the exact
kernel receipt. Its first checkpoint and complete evidence bundle are retained
in the original funding journal. This bounded profile permits one allocation per
native authority and one checkpoint at sequence 1. Legacy context v1 retains its
existing capacity and semantics.

The Finding references the original receipt and `local-log-<key digest>#1`
checkpoint. Agreement, submission, dependency and decision wire versions remain
unchanged from the registered-work delivery. Both new claims and decision replay
use the exact retained bundle; disappearance after Finding issuance fails closed.

| Facet or authority | Result and boundary |
| --- | --- |
| Artifact integrity | Verified by actual Finding validation and issuer signature. |
| Receipt authenticity | Verified against the original production signer, strict execution semantics and standing. |
| Checkpoint membership | Verified against the pre-agreed checkpoint authority, exact receipt bytes and inclusion proof. |
| Guarantee consistency | Verified against the actual complete facet draft. |
| Metered exposure and settled spend backing | Unavailable. Execution receipts cannot establish either facet. |
| W0 result acceptance | Requires original input/output bindings and the independently pinned Python checker. |
| Payment or refund | Requires the existing observed claim, original signed decision or timeout, and original allocation. |

Invalid or unavailable execution authority cannot mint either a positive or a
negative financial decision. An authenticated but incorrect submitted output can
produce a signed rejection and refund. If an agreement additionally requires
unavailable financial backing, no decision is minted and timeout refund remains.
An already accepted decision replays its complete assessment at the original
evaluation time, so Finding expiry cannot erase earned payment authority.

## Independent public verification

The public [Rust witness](pre-settlement-evidence/execution-witness.json) contains
the signed agreement and submission, original public context, execution bundle
and output. [External pins](pre-settlement-evidence/execution-pins.json) are a
separate input. The Python verifier checks canonical bytes, signatures, authority
roles and standing, original bindings, the output commitment and checkpoint.
Its mutation tests use valid signatures as well as malformed envelopes.

Run `examples/federated-work/execution_evidence.py WITNESS --pins PINS
--evaluated-at TIME` with the pinned buyer Python environment. For the retained
witness, TIME is `evaluatedAt` in
[execution-assessment.json](pre-settlement-evidence/execution-assessment.json).
The manifest records the exact executed command. Historical evaluation is an
artifact verification result, not a statement of present funding eligibility.

The allocation pin must come from an independent funding observation. This checker
does not derive the EVM allocation or verify chain funding. It authenticates the
waiver argument through the bilateral agreement but does not independently grant
financial waiver authority. Private source preimages are not all public;
`sourcePreimagesRecomputed` and all financial-backing flags remain false.

## Qualification

Selected Rust suites pass 803 tests: 62 standalone example tests, 406 core-type
tests, 279 Finding/verifier tests, 23 SQLite outcome tests, 24 native SQLite
integration tests and nine signer-boundary tests. Two Finding fixture-regeneration
helpers remain intentionally ignored. Python passes 102 tests, and independently
verifies the actual Rust-produced public witness. Node passes 19 contract/inventory
tests and two canonical wire tests; both parsers agree on 57 shared vectors and
the schema differential check passes 126 cases.

All 52 owned chain and process scenarios pass on the final executable, including
41 SIGKILL events. Standalone and full-workspace Clippy pass with warnings denied,
and all 30 fuzz targets compile. Formatting, schema registration, file hygiene,
formal-source mirrors and generated proof coverage checks pass. The accompanying
manifest retains exact commands, source objects, executable and artifact hashes,
and separates development failures from required successful checks. Existing funding,
payout/refund, capture-waiver and earned-child scenarios remain regression gates.
Five additional SIGKILL cases cover before/after native evidence projection,
checkpoint retention and bundle custody, including rejection recovery. Every
retained evidence digest must survive restart unchanged with one operation,
one hold, one execution and one evidence projection.

Independent review identified invalid-standing rejection being treated as a
financial decision and fresh-time checks blocking earned decision replay. Both
paths now have regression coverage. Actual Rust-to-Python verification also
exposed the original waiver argument and checkpoint reference conventions; the
independent checker now handles both and rejects signed substitutions.

The final chain regression found that the original-source audit called the new
evidence-export path, reacquiring a finalizer lease on a financial-resolution
handle. The audit now reads only retained source records. Its regression asserts
that auditing cannot change authority commits and that the valid original refund
can still authorize the waiver. All owned scenarios are rerun on the rebuilt
executable after this correction.

The existing drop-guard model does not model this nonterminal evidence projection.
Its abstraction note and reviewed source bindings are refreshed; generated proof
coverage records current inputs. No new formal proof or fuzz campaign is claimed.

## Remaining delivery gate

This establishes pre-settlement native execution and checkpoint evidence within
the local funded-work profile. It does not establish a Finding purchase, bond,
challenge result, runtime assurance tier, full source replay or cross-company
administrative independence. Journal custody is distinct from the native authority
database's external rollback protection.

Next, use independently administered buyer, provider, verifier and checkpoint
operators with separately controlled keys and state. Require the second
implementation to consume the published artifacts, test custody loss and signer
rotation, and measure useful work and verification cost against the matched
baseline. Expand capacity only with a qualified multi-allocation checkpoint log.

This delivery ends at local qualification and commit. Public activation, remote
CI, release qualification and real funds remain separate gates. The original
paper checkout and all earlier evidence directories are preserved.
