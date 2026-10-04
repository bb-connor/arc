# PR #1173 code review and repairs

This review follows the executable changes in the verifiable-work session,
including native admission and settlement, delegated continuations, federation,
protocol adapters, the funded-work and comparison programs, and the evidence
tooling. The W1-W4 design plans remain plans. Their acceptance criteria are not
treated as implemented functionality.

The initial candidate was `c3b423557727129f374f7711e498f1e4bce756e0`.
It contained 575 source or tooling paths among 2,879 changed paths against its
original merge base. Integration with the current security and retention branch
is part of this review. The retained records distinguish historical failures,
focused repaired runs, and the final source-bound native qualification.

## Confirmed findings

| Priority | Defect | Repair and regression boundary |
| --- | --- | --- |
| P1 | The native security participant reader rejected supported admission schema 36, blocking ordinary native operations. | Accept the supported successor schema without changing the native catalog digest; reject unsupported versions and verify the live catalog. |
| P2 | An already resolved checked-output denial could be stranded when output authority expired before recovery. | Resume its exact retained zero-charge obligation without fresh output release; retain frozen transform, decision, pricing, digest and settlement checks. Allow replay still requires live guards. |
| P2 | Unknown-payment release could use a backdated caller timestamp to accept expired consent. | Qualify fresh consent against owner time and reject decisions before issuance; already accepted obligations remain recoverable. |
| P2 | Combined native admission omitted an earlier receiver-side governance deadline. | Intersect both signed presentation windows into the native dispatch deadline. |
| P2 | The example HTTPS server accepted unbounded request headers before authentication. | Bound the complete header block before the HTTP parser, require explicit framing and close semantics, and retain bounded bodies. Test oversized single and aggregate TLS headers. |
| P2 | Buyer accounting counted released reservations as still reserved. | Exclude released reservations and assert exact available, reserved and spent balances. |
| P2 | Future and reversed issue times defeated the comparison receiver's maximum token lifetime. | Use checked time arithmetic and reject invalid issuance windows before dispatch. |
| P2 | Missing or malformed comparison amounts silently became zero. | Reject absent, null, fractional, negative and nonnumeric amounts in both profiles. |
| P2 | Federation experiment heartbeats could install a fresh root with missing or stale revocation subjects. | Require an origin-signed complete subject snapshot bound to the exact root before publishing or accepting each epoch; reject conflicting, incomplete and mixed batches atomically. |
| P2 | Second-rounded federation timestamps could already be stale under the current millisecond authority clock. | Use the exact publish time under the existing freshness policy. |
| P2 | The experiment counted rejected or mismatched root acknowledgements as delivery. | Accept only the exact acknowledged epoch. |
| P2 | The admission timing wrapper omitted the store's atomic trust-floor method, denying valid network calls. | Forward the atomic operation and the related retained-source lookups unchanged; test predecessor rejection without mutation and a valid successor. |
| P2 | Hosted live C++ conformance lacked the enforcing host fixture required by the current CLI. | Prepare and qualify the existing native fixture and build the real-enforcement CLI before the five live consumers. Hosted x86 evidence remains necessary. |
| P2 | New A2A v1 tests used the old parsed-value ingress API and failed to compile against the security base. | Serialize the test requests and exercise the bounded original-byte API. |
| P2 | Caller custody treated a configured single-approval authority as selected for every call, rejecting unused sources and threshold-only calls. | Read original requirements and matching cumulative grants, retain the verified typed threshold proposal for new reservations, and still require and validate actual selected single-approval custody. |
| P2 | The three-owner experiment still relied on the old implicit approval roster and did not bind the current policy and tenant context. | Configure each approval roster explicitly, keep capability issuance local to the receiver, and bind the intent through the kernel before the external approver signs it. |

Integration also repairs schema-migration fixtures, shared-clock fixture wiring,
module size violations, schema registration, and security-reader inventory drift.
The named reader witnesses are finite lexical regression tripwires. Their source
checks supplement the owning Rust tests; they do not prove authentication or
whole-program dataflow. No raw-input baseline is promoted merely to pass a gate.

The caller repair preserves committed historical frames. Previously affected
threshold reservations with a configured single-approval source could not
publish a valid caller frame. An old live `ReadyToDispatch` reservation keeps
its existing refusal and expiry/compensation path; the repair does not invent
missing historical selection evidence or rewrite its commitment. Legacy
threshold commands and exact replay retain their two-attachment representation.

The pinned ERC-8183 capture is stored as deterministic gzip. Its decompressed
41,976 bytes and original SHA-256 are unchanged. The artifact checker validates
that pin, rejects invalid metadata and confined-path violations, and limits
decompression before accepting the source.

## Hosted integration follow-up

The hosted run at `93a2552c3a6eb15ac2756129f199f5714390e794` exercised additional
consumers after the security-base merge. Its failures remain historical evidence;
the subsequent repairs do not change that run's result. Its terminal snapshot
contains 47 successful, 23 failed, 10 skipped, and two cancelled jobs. Installed
native consumer recovery passed, while its aggregate process gate correctly
failed on the separate host-test and worker failures. Source comparisons in
`test-integration-attribution.json`, `inherited-ci-inputs.json`, and the native
HTTP fixture record distinguish inherited integration defects from session code.

- Process crash recovery now configures an explicit approval roster and signs
  the kernel-bound intent before the first dispatch. Reopening still loads the
  original persisted request. Unbound intents, changed arguments, and unlisted
  approvers deny before either effect log exists. All 91 process tests and
  warning-denied Clippy passed.
- The threshold suite reuses the existing admission-checking test server through
  an explicit module import. Its exact inventory includes five already-existing
  session-scope tests. The original 42-versus-47 inventory failure remains
  recorded; corrected threshold, session-report, and receipt-isolation inventories
  passed 47, 16, and 6 tests respectively, without removing any expected case.
- SDK and PostgreSQL workflows prepare the existing enforcing host fixture.
  SDK parity restores the enforcing CLI after the HTTP example build and before
  all five native C++ consumers. Seventeen checker tests protect those sequences.
  PostgreSQL's direct database connection and proxy subprocess still need an
  approved native transport boundary; fixture preparation does not establish that
  adapter's compatibility.
- CLI signing fixtures use private files from their first write. The Drogon
  example uses temporary private signing custody outside group-writable checkout
  ancestors. Cleanup retains the sidecar receipt database and its WAL companions
  after services stop, including after an assertion failure. A retention error
  fails cleanup and preserves the private source for recovery. The sidecar
  receives an explicit private signing seed, and both allowed requests carry
  capabilities. The export reads the canonical receipt store, retains complete
  signed kernel rows, and checks the HTTP projections against their response IDs
  and exact POST bytes. The full
  Drogon, proof-package, and runtime-policy gates passed. Initial failures from
  unsafe checkout ancestry, missing signing custody, anonymous GET assumptions,
  and the legacy receipt query remain retained alongside the corrected runs.
- The verdict matrix issues a valid nonce, advances the shared injected clock,
  and requires an actual expiry error. Its three targets passed 47 tests and
  warning-denied Clippy. Standalone lockfiles follow the current local dependency
  graph; retained registry versions and checksums are unchanged. Two stale vector
  manifest entries were corrected without changing vector JSON; all 109 hashes
  now match. Fuzz inventories retain all 34 targets, including the previously
  omitted threshold target. Both response-security corpora now run through their
  existing assertion-bearing drivers in the default smoke suite. The locked
  fuzz replay passed all 38 tests (10 unit and 28 smoke tests).
- Native HTTP fixtures authenticate their exact loopback proxy, refuse missing
  and incorrect proxy credentials, and check malformed initialization before
  session creation. Existing sessions also deny fresh admission after issuer-pin
  drift. An explicitly repinned node first succeeds, then observes cross-node
  revocation. An invocation marker checks that neither denial dispatches a tool.
  These scenarios require the qualified Linux x86_64 fixture; local aarch64 source
  review is not native runtime qualification. Both changed CLI test targets
  compile and pass warning-denied Clippy on aarch64; their native execution
  remains a supported-host CI requirement.
- The older programmable-sovereignty artifact has an explicit historical
  validation mode. It authenticates immutable measured-source and assembly
  identities while checking the retained manuscript, results, and outputs. One
  original aggregate-digest defect has a documented one-field erratum. Fifteen
  tamper/provenance tests passed; strict current-source validation still rejects
  the evolved checkout. No historical measurement was reassigned to new code.

Independent automated reviews found no further P0/P1/P2 issue in the reviewed
process, historical-artifact, workflow, lockfile, or native HTTP fixture repairs.
These reviews do not supply missing supported-host execution or human approval.

## Evidence and limits

`MUTATION-TRIAGE.md` records the exact hosted survivor review. No current-source
security defect was established by the surviving mutations. The federation
report is advisory; the runtime campaign was cancelled with three mutations
unfinished. The retained archive preserves those outcomes and original diffs.
Eleven added regressions and stronger existing assertions passed in four targets
(88 tests total): exact verified evidence requirements, matching malformed
receiver records with valid signatures, persisted unused continuation state after
refusal, and exact object/array/mixed nesting limits. Production guard logic did
not change in response to this triage.


`logs.json` inventories retained diagnostic streams with uncompressed hashes.
Initial failures and partial campaigns remain present. The HTTPS summary covers
19 scenarios. The federation summary is a small debug network smoke with real
loopback peers, denial cases, duplicate races, and revocation/cut recovery; it is
not a performance benchmark or independent operation.

The current source-bound native qualification is maintained at
`docs/research/dynamic-delegation/evidence/qualification.json`. The final integrated run passed all 21 terminal commands against 37,217 source
files and retained 48 output artifacts, including actual parent SIGKILL and
stable child collection replay. Historical native inventories and benchmark
results retain their original revisions. The six
chain-dependent tests ignored by the default funded-work suite are explicitly
opt-in tests. A separate configured run passed all six; the default suite's
original six skips remain recorded. Ganache used its JavaScript fallback on
this aarch64 host. This run makes no native-binding performance claim.

The initial JavaScript work-claim campaign had 148 passes and 25 failures before
fixture startup because the command omitted `CHIO_W0_PYTHON`. The corrected run
selected the locked checker and freshly built binary explicitly and passed all
25 affected tests. The six funded-fit tests also passed. This setup failure is
preserved rather than removed from the campaign history.

The broad library campaign at the first repair revision retained 1,526 kernel
passes and two failures that exposed the caller selection problem. SQLite
retained 1,961 passes, two child-process failures, and three default skips. A
concurrent build unlinked the running SQLite executable, so those two failures
were `ENOENT` while spawning `current_exe`, not failed recovery assertions.
Both affected tests then passed from an immutable copy of the original running
binary. Its hash is retained in `store-binary-retention.json`. The two optional campaigns with one million receipts each remain skipped.
The third skip is the child helper that the passing parent test invokes
explicitly. The failed broad campaign is
preserved, with corrected runs recorded separately. On the repaired source,
all 1,532 kernel library tests passed. Focused final checks also passed: 22
caller tests, one actual durable approval test, six cumulative-budget tests,
and 16 physical SQLite threshold tests. The final test binaries were copied
to immutable paths before execution; their hashes are retained in
`custody-test-binaries.json`. A separate automated review of the resulting
approval repair found no further P0/P1/P2 issue. The three-owner fixture then exposed
three setup failures under the current explicit approval API. After repairing
its receiver and approver configuration and intent binding, all five tests
passed, including every parent-finalization crash cut and mutation control.
Its targeted Clippy check passed, and a separate automated review found no
additional issue.

To reproduce the additional chain checks after installing the contract lockfile
and the hash-locked Python requirements, set `CHIO_FUNDED_PYTHON` to that Python
interpreter and `CHIO_W0_BINARY` to the built `chio-federated-work` executable:

```sh
cargo test --locked --manifest-path examples/federated-work/Cargo.toml -- --ignored --test-threads=1
CHIO_W0_PYTHON="$CHIO_FUNDED_PYTHON" node --test --test-concurrency=1 contracts/scripts/work-claim-*.test.mjs
node --test contracts/scripts/funded-work-fit.test.mjs
python3 -B docs/papers/verifiable-work/tools/qualify_dynamic.py --record
```

This review does not establish external operation, production deployment,
release qualification of the complete workspace, or the whitepaper's open
economic and foundational claims. `publish_ready` and `breakthrough_established`
remain false. Exact-head hosted status must be read from the PR after the repair
commit is pushed; local aarch64 checks cannot qualify the x86 enforcing fixture.

Known foundation gates remain open: the genuine AWS-LC source audit required by
Cargo Vet; reported Wasmtime and JavaScript dependency advisories; the Kani
compiler's incompatibility with the current crate MSRV; and PostgreSQL adapter
qualification under the native confinement profile. No audit exemption,
containment relaxation, skipped required check, or unsupported production claim
is introduced to make those gates appear green.
