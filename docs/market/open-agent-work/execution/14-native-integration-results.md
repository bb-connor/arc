# Funded work and Security M4 integration

Status: selected local integration gates passed. Task 3 closes with this
reviewed local commit; native funding Task 4 has not begun. This report does not authorize an upstream
merge, release or public activation.

The [machine-readable evidence](15-native-integration-evidence.json) pins the
selected source trees, test selections, observed inventories and retained
[public logs and process summaries](integration-evidence/). It distinguishes
reproduction commands from a verbatim shell transcript, preserves the initial
failures, and names their passing replacements. Private fixture directories
and signing keys are excluded.

## Selected source

The first parent is Security M4 local acceptance commit
`5d1a9ec0d900bd03ce55de903919d972be852d79`. Its clean local, remote and
draft PR #1117 heads matched when selected on 2026-09-14. The committed
[M4 report](../../../security/m4-local-acceptance.md) closes its local acceptance
gates; the full hosted serial/MSRV lane remains unqualified.

The research input is `926e1aa8411e3b516fe737988dd1a0989c447d08`.
Their shared ancestor is `f5566d9a765c21cb36652a99c79de64968a656bf`.
The candidate lives on `integration/funded-work-m4` in a separate worktree.
Both source worktrees are preserved. The exact rehearsal found nine code
conflicts and one generated coverage conflict.

A later read-only refresh found the security agent advancing its own worktree:
HEAD `94ebe454e39535dcee1a40dfe5becb749ef4bbe2` adds the process/security
execution plan, and 458 paths were changed during an uncommitted process
integration. The committed delta from the selected M4 input is documentation
only at that observation. That active work was not copied into this candidate. The selected M4
commit remains its immutable first parent.

The later GitHub identity refresh still finds [PR #1117](https://github.com/bb-connor/arc/pull/1117)
open and draft at the selected `5d1a9ec` input. GitHub reports `MERGEABLE` and
`BLOCKED`; this is not exact-head CI/review qualification or merge approval.
The newer process-integration branch is a separate source checkpoint.

The reviewed active diff changes joint recovery claims, budget authorization,
tool-return recording and post-return finalization in files also touched here.
Once that process candidate is committed and qualified, a separate merge
rehearsal must preserve both those joint writes and this candidate's checked
output, v35 migration and monetary-successor behavior. The process candidate's
future evidence does not qualify this candidate, or vice versa. No sync of
its dirty working tree is appropriate.

A subsequent read-only observation on 2026-09-14 found the process integration
committed as `deb9b8a85623f7eb4bebd65eeb608af76f11d125`, followed by the
remaining-gates report `2c48e6231a45e4a3c01c9cf6459bd2d38d41dc61` and worker
completion/cleanup repair `f3cfc890c39f01260cf353be6135172d298124c5`.
Six process-host paths were still dirty. The other report leaves its full
foundation qualification open. Those commits are not imported here. Its
caller-snapshot review concerns the same custody code in the selected M4
source. Local verification distinguishes configured authority from the
credentials actually required by the original call; see the follow-up below.

The final pre-commit refresh found the process worktree clean at
`3b926837372f2a878169671911e613968455f553`. Its new delta changes eight CLI
worker/container source, test and documentation files, preserving observed exits
through supervision failures. It does not alter the shared caller-custody
reader or close the remaining process-foundation gates. This is a suitable
committed input for a read-only rehearsal after this candidate is committed,
not evidence that the process stack is ready to adopt.

The process delta through `f3cfc89` changes 462 paths relative to the selected M4
input. Twenty-one paths overlap this candidate, including five Rust files:
the admission coordinator, terminal path, SQLite admission store, its test
module and recovery tests. This is a path-overlap inventory, not a conflict
count. A later merge rehearsal must preserve joint mutation claims, checked
output and unknown-payment successors together.

The source review confirms that the process branch replaces separate recovery
claims with joint claim/write ports for budget authorization, capture, returned
work and evaluation start. It also batches pending pure-result digests with
terminal finalization. A later sync must rerun checked-output denial and
zero-charge recovery against that batching, plus expiry oracles proving that a
refused joint claim cannot advance the operation, custody or commit history.
The process branch's stable authority UUID accessor is relevant to funded-work
journal identity, but importing the optional runtime remains a separate task.

## Native custody and schema decisions

| Boundary | Candidate behavior |
| --- | --- |
| Authenticated return | Keep M4's validated return context and captured grant. Retain raw work before the paper's output evaluation. Recording a return grants neither output-release nor payment authority. |
| Checked output | A configured zero-charge contract can produce a signed, redacted denial and release its original reversible hold. Ordinary security guard failures do not gain refund authority. A retained rejection cannot become success on replay. |
| Caller custody | Keep the original authenticated start, nonce, caller context and native release/declassification checks. An eligible late report settles the same operation after authority expiry. |
| Financial successor | Preserve the original `OutcomeUnknownAfterDispatch` operation and payment journal. Separately authorized monetary successors retain exact fenced global coverage and original hold correlation. |
| Admission schema | Introduce native version 35. The version-34 base SQL remains byte-identical, with SHA-256 `c5c5a28235e852408a2b85b424c856da218dc516f198dbc35ecd6cd81df9e63d`. The release table and immutable barriers live in a separate SQL extension. |
| Historical migration | Validate the exact v34 catalog and retained data before the admission migration writes. Earlier supported security migrations retain their own historical catalog builders. The admission migrator rejects every pre-v35 release namespace, including the incompatible research v10 lineage. |
| Native flow history | Admission v35 retains the existing v29 native flow catalog and digest. Future admission v36 is still unsupported. |
| Global history | Add the payment-resolution kind to the exact predecessor migration chain. Preserve original row bytes, chain digests and anchored history; reject unexpected catalogs or smuggled future projection kinds. |

Authenticated external callers can remain in `AwaitingCallerReport`. They are
not converted into execution-unknown merely to obtain financial release.
The monetary-successor port still requires its original stored unknown state.
Native funded admission must preserve this distinction when connecting contract
deadlines to native custody.

No operator database was migrated. Migration and corruption tests use disposable
fixtures, including an actually authenticated waiting caller. The historical
research v10 database has no automatic migration path in this candidate.

## Provider and source reconciliation

The provider signs the current manifest schema and registers it against the
configured provider key before constructing its A2A edge. This example selects
the public-only local policy. Its existing DPoP profile claims no independent
replay authority. Neither choice asserts enforced native flow or confinement
for the example's optional subcontract worker.

The standalone lockfile retains the research dependency versions and adds the
19 packages required by the combined path dependencies. Its Rust checker and
Python checker/protocol bytes remain unchanged, preserving the existing pinned
artifact profile. Previous financial experiment evidence remains historical;
it is not relabeled as qualification of this source.

Moved security helpers were retained during conflict resolution. Six oversized
files were split into modules for the combined-source hygiene gate, preserving
test identities and corpus entries. The obsolete revocation-file size allowance
was removed. Generated coverage was refreshed after source reconciliation.

## Selected verification

Selected Rust checks use three build jobs, incremental compilation disabled,
debug information disabled and serial test execution. This is a local selected
test profile, not the default full-workspace or hosted qualification profile.

- The untouched M4 provisioning baseline passed before native source edits.
- The new admission-v35 and global-predecessor tests failed before their
  migrations were implemented. The combined schema suite then passed all 105
  selected tests, including historical and damaged-catalog regressions.
- All 1,440 kernel library tests and all 18 SQLite-backed kernel integration
  tests passed after the module splits. These include checked-output denial,
  zero-charge release, redaction, replay and unknown-payment successor recovery.
- The final authenticated-caller gate passed all 34 caller cases, including
  migration of a waiting authenticated operation, nine durable executor cases
  and 19 native host-custody cases. The restart gate passed all 47 process
  scenarios and five ownership cases.
- All 30 standalone Python participant unit tests passed. The consumer SDK gate
  passed its Python, TypeScript and Go inventories, including 15 Python cases.
  Rust consumer qualification is separate.
- The combined Rust file hygiene check passed after module extraction.
- All 506 selected admission-store tests passed. Runtime admission passed 88
  tests, the final predicate corpus passed all ten tests, A2A passed 102,
  federation verifier conformance passed seven and the iroh library passed 190.
  Runtime agreement-context scanning passed 12 and binding substitution passed
  37. The A2A client/edge interoperability fixture passed both tests.
- The provider's Rust suite passed 11 tests. The paid-work process suite passed
  11 scenarios, the final Python buyer suite passed 18 and mutual release
  passed seven. The final HTTPS suite passed all 19 scenarios after the
  client timeout change. The full subcontract suite passed all ten scenarios; its public
  summary retains the individual crash and hostile-worker observations.
- The composed baseline passed nine tests and its executable completed with
  five measured calls per profile. These small smoke measurements are not a
  latency comparison claim. The outcome-ledger comparison passed all nine
  experiments after the recovered Git-hook repair described below.
- All four protocol code-generation lanes are in sync. All 225 formal source
  anchors match after review of the nine changed entries. The full formal gate
  passed its Lean build, placeholder scan, elaborated assumption audit
  regressions and proof-manifest/theorem-inventory checks.
- Both `cargo check --workspace --all-targets --locked --offline` and
  `cargo clippy --workspace --all-targets --locked --offline -- -D warnings`
  passed. All 29 fuzz binaries compile under the locked offline profile; this
  is compilation coverage, not a fuzz campaign. The standalone provider also
  passed its strict all-target Clippy check.

The full consumer gate passed all 38 exact inventories, protocol-peer
negotiation, structured mediation and HTTP egress checks. The full flow gate
passed all 69 exact inventories, both WASM checks and the positive/negative
Apalache calibration before the caller-custody follow-up. Its native enforcement
inventory passed all 133 cases; affected final-source checks are recorded below.
The completed local closeout is recorded in
the [integration plan](../../../superpowers/plans/2026-09-14-funded-work-m4-integration.md)
and [native funding gate](06-native-integration.md). Native funding, observer
finality, funded-claim/native-hold correlation, Finding facets and independently operated
companies remain beyond this checkpoint.

## Formal source review

The combined formal-mirror gate reported nine changed source anchors for
`PostAdmissionDropGuard`. Each was reviewed before refreshing recorded hashes:

- Admission selection forces checked-output contracts through structured
  durable custody and requires a reversible rail. Unsupported mixed contracts
  deny before acquisition.
- Treaty evidence verification now receives the locally resolved continuation,
  receiver clock and store. Executed substitution tests preserve the stronger
  receiver-owned issuer and governance checks.
- Terminal return, recovery and finalization retain authenticated context and
  raw work before evaluation; only the configured checked-output contract gains
  zero-charge authority.
- Admission migration, catalog validation, native catalog version mapping and
  the supported-version constant implement exact v34 to v35 migration.
- Global catalog, predecessor migration and projection references add the
  separately authenticated monetary successor without rewriting history.

The live drop-guard model does not prove durable checked-output settlement,
financial successors, caller custody or SQL migration. Its scope comment now
explicitly includes those exclusions. A refreshed source hash records this
review and does not establish semantic equivalence or expand the theorem.

The Lean admission classification was stale relative to four stronger Rust
checks: the lease issuer and governance issuer/hash fields now belong to the
receiver-state equality class. The updated census is 27 equality-bound, one
domain-bound and eight uncompared leaves; the other classes are unchanged.
The Lean module builds, and its leaf-for-leaf Rust parity check passes. The
older proof narrative is explicitly marked historical pending a full paper
reconciliation.

## Clean-checkout and process compatibility

The research checkpoint omitted `examples/composed-baseline/src/bin/run_composed_baseline.rs`
because `examples/**/bin/` ignored Rust source along with generated .NET output.
The candidate restores the reviewed file from the preserved source checkout and
adds a narrow ignore exception. The recovered source SHA-256 before formatting
was `91e3a7ead5fa0e20387ede0fad62adee1eeef46b7ad6706761791038c49ef40b`.
No other explicitly declared example binary/test target was absent in the scan.
The outcome comparison's request explicitly carries no declassification grant;
it does not fabricate native declassification authority.

The first release-process restart exceeded the harness's five-second readiness
window. Reopening that same retained fixture measured 4.804 seconds under load.
The harness now uses a bounded 30-second monotonic deadline. The three-party
review also executed both parent and child before the Python client's original
five-second response timeout. Its bounded wait now matches the receiver's
30-second connection lifetime. Timeouts still preserve execution uncertainty;
no automatic effect replay or authority extension was added. Final process
regressions exercise that client. Checker/protocol profile bytes are unchanged.

The original dirty checkout's head, porcelain status and all 3,688 recorded
file hashes and modes matched the preserved snapshot during this run. Private
process fixtures and signing seeds remain outside the repository. Public
summaries and test logs are selected separately for evidence.

The source-boundary inventory also rejected 11 unclassified research sites.
The reviewed six constructors and five dispatch sites are now C30-C35 and
D087-D091, with explicit benchmark, controlled experiment or public-only
provider profiles in `docs/security/consumer-support.md`. No site gained a
native flow, declassification or production deployment claim. The structured
mediation check passes with 35 constructor and 91 dispatch identities. The
benchmarks and artifact/federation examples explicitly carry no declassification
grant when constructing the current request type.

## Recovered Git-hook repair

The outcome comparison initially passed three cases and failed six repair
experiments because actual Git hooks fired. Both committed inputs lacked the
Git-hook repair present in the preserved dirty checkout. The candidate ports
only the reviewed shared helper, Hermes entrypoint application and their four
focused test files. The source checkout remains unchanged.

The actual-hook regressions first reproduced five shared-helper failures and
two Hermes failures, while the positive control confirmed that `--no-verify`
still permits prepare-commit-msg, post-commit and reference hooks. The helper
now applies a final `core.hooksPath=/dev/null` override after caller global
options, remains idempotent, and is applied to both dedicated and generic Git
commit entrypoints. Other Git operations and non-hook execution mechanisms
remain outside this helper's contract. The checker was not weakened.

The full adapter-base suite passed 205 tests in its frozen development
environment. Hermes passed 196 tests with four existing live-sidecar tests
skipped because `CHIO_INTEGRATION=1` was not selected, in its separate
frozen environment. All nine outcome experiments then passed against the
ported source. These are additional integration changes beyond the two
committed inputs, with provenance in the preserved source snapshot.

The workspace compiler also found an older A2A client/edge interoperability
fixture. It now signs the current manifest, registers against its configured
fixture publisher and chooses the public-only local profile. Both interop
tests pass with the original ordinary-request and counted-denial behavior.

The runtime context scanner's fixtures also needed the receiver-owned admission
bundle now required before scanning. Installing the actual request binding
restored coverage of smuggled trust roots and nested authority assertions. The
benign control reaches the next missing-treaty-scope denial. Production
admission order and the negative assertions remain unchanged.

The first consumer-gate run inherited shell `umask 002`. Its ordinary MCP
startup control stopped at private-directory ancestry validation before the
expected absent launch-policy sentinel. Running the same compiled test under
`umask 022` passed both ordinary and flow-required branches. The consumer
script now selects `022`, matching the native and flow gates; it does not
change CLI permission validation or the startup assertions. The full consumer
inventory subsequently passed, with the initial failure retained as evidence.

The merge-wide whitespace check reports 16 unchanged research evidence files
(CSV line endings and raw test-log whitespace). Their original bytes are
retained. The code-only whitespace check passes; new integration documents
are checked separately from those historical records.

## Caller-custody follow-up from the process review

The other review proposes rejecting a caller snapshot whenever an originally
configured runtime, approval or DPoP authority has no participant ledger.
The approval and DPoP parts need a narrower predicate. The original authority
profile records configured sources, while `run_pre_budget_admission` acquires
approval only for a presented single approval and DPoP only when required by
the matching grants. Configuration alone is not a selected credential.
An unconditional approval/DPoP check would reject valid calls.

The focused regression therefore distinguishes configured but unused authorities
from DPoP required by the original matching grants. It exercises the custody
reader with validated request/operation bindings. It does not manufacture a
physical ledger or claim a demonstrated end-to-end authorization bypass.
The focused test failed before the guard: four compatibility controls passed
and the required-DPoP omission was accepted. After the guard, all 1,445 kernel
library tests and the updated 35-case frozen-context inventory passed. The
34 caller lifecycle, nine durable executor and 19 native caller cases passed.
The physical DPoP expiry/restart regression and final workspace all-target
check and strict Clippy passed. Formatting, hygiene, all 225 formal source
anchors and regenerated coverage also passed on the final source.

The existing fresh-credential and native-capture paths independently verify
actual claims. Optional approval selection cannot be inferred from the profile;
a broader invariant would need explicitly retained selection evidence and its
own migration and compatibility review.

Ordinary provider attempts do not enter the caller-custody branch in
`freeze_durable_tool_return_context`. The standalone provider's negotiated
profile is unchanged. Its process evidence therefore remains a separate broad
integration run; the final rerun targets the changed caller path.

The broad gate evidence predates this final defensive check. The evidence
manifest retains those source objects separately from the affected checks on
the final source. No older log is relabeled as execution against changed code.

The changed custody reader is also a `PostAdmissionDropGuard` review anchor.
The new check only refuses a snapshot; it cannot release credentials, refund a
hold, authorize dispatch or change an unknown outcome. The model already
excludes authenticated caller custody and exact durable credential history.
Its abstraction remains unchanged. The refreshed anchor records this review,
without adding a formal proof claim for the new predicate.

## Next native admission interface

The read-only interface review found a concrete constraint for Task 4.
`chio-settle/src/channel/funding.rs` binds the legacy `EscrowCreated` event and
its channel-specific terms. The experimental claim contract emits `Funded`
with an allocation ID, agreement digest and payer; the remaining work terms
must be checked against the contract state at the pinned observation. These
are distinct encodings. Task 4 must not relabel a claim allocation as existing
channel evidence or weaken the legacy event decoder to accept it.

`chio-web3/src/settlement_proof.rs` separately requires signature, deployment,
order, chain snapshot, independent head, finality, witness and dispute checks.
Those requirements provide the validation checklist for the experimental
funding observer; a successful mock-chain transaction or payer summary is not
equivalent evidence. The first native funding slice should establish the
strict experimental allocation encoding and receiver-owned observer pins,
then test wrong-domain, unfinalized, mismatched and reused allocations before
any native reservation or dispatch. Durable allocation-to-operation/hold
correlation remains required before the paid process path is enabled.

The current contract fixture starts its private chain at a fixed historical
clock and advances it explicitly. Those deterministic vectors remain useful
for ABI parity, but cannot be imported as fresh native funding observations.
The next fixture must keep chain-time eligibility, receiver observation age
and the original native capability deadline explicit; an old deposit or a
frozen development-chain clock must not renew dispatch authority.

The existing provider uses `SqliteFindingOperatorPaymentAdapter` for its local
credit rail. Its successful native settlement is not an ERC20 transfer from
the experimental contract. Task 4 must correlate the original native hold
with the funded allocation while independently reconciling contract decisions,
withdrawals and token balances. A crash between the example journal and native
admission must recover the same namespace/request/operation identities, not
create a second reservation under a new request ID. The allocation agreement
and receiver policy must also pin the native authority identity so that opening
a fresh store cannot discard the anti-reuse history.

This interface review adds no native funding implementation or public finality
claim. It makes the next admission tests concrete after Task 3 closes.
