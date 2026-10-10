# Fixture lifecycle and SDK readiness

Commit `c5f53a96dbfc836bfc42805c2fee2d393dd78821` installs the reviewed eleven-file Python
fixture and SDK repair. The [installation record](../../../../../target/recovery-pr/current-review-followup/runtime-integration-successor-20261009/local-sdk-fixture-validation/installation.json)
binds the exact source selection, final reviews and owning results. Confidence is
high for this bounded local scope. The runtime remains unqualified.

## Installed evidence

| Recorded check | Actual result | Scope |
| --- | --- | --- |
| Maintained SDK/framework suite | 1,438 passed, exit 0 | 634 input hashes unchanged before/after and current at accounting |
| Composed fixture suite, normal Python | 56 passed, zero errors/failures | 643 input hashes unchanged before/after and current at accounting |
| Composed fixture suite, optimized Python | 56 passed, zero errors/failures | Same 643-input boundary, with `-O` |
| Independent SDK quality | 25 focused plus 33 integrated cases in each mode | Installed CrewAI 0.203.2 and LangGraph 1.2.12 import maintained SDK source |
| Independent campaign quality | 23 cases in each mode | Harmless Python children and controlled provider host |

The 56 composed cases comprise the 33 fixture and 23 campaign cases; the separate
review counts are not additional coverage totals. Every recorded run above uses
local controlled transports or harmless children, with zero recorded network
attempts. No new installed SDK wheel, native binary, live provider, matched live
campaign, Linux, formal or hosted acceptance is established.

A later broader fixture discovery gate remains **failed**: 130 tests ran, with
129 passing and one assurance-map error, `assurance.missing_owner_or_cutpoint`.
The [actual record](../../../../../target/recovery-pr/current-review-followup/runtime-integration-successor-20261009/fixture-environment-continuity/normal.json) uses the catalog's five-value
environment and supported Python 3.12 wrapper, with 644 stable source inputs and
zero remote attempts. Its command differs from the catalog's direct module
invocation as explicitly recorded. This does not erase the focused passes above,
close `QF-04`, or establish a new finding before scope diagnosis. The original
focused QF-04 control passed; broader gate acceptance remains pending.

The final run records preserve the exact repeatable command arrays, interpreter,
runner hashes, environment and selectors: [SDK/framework](../../../../../target/recovery-pr/current-review-followup/runtime-integration-successor-20261009/local-sdk-fixture-validation/maintained-sdk-framework-successor.json),
[normal fixtures](../../../../../target/recovery-pr/current-review-followup/runtime-integration-successor-20261009/local-sdk-fixture-validation/composed-fixtures-final-normal.json) and
[optimized fixtures](../../../../../target/recovery-pr/current-review-followup/runtime-integration-successor-20261009/local-sdk-fixture-validation/composed-fixtures-final-optimized.json).
The fixture commands use the recorded interpreter with `-I`, and with `-I -O`
for the optimized run. No tests were rerun for this accounting update.

| Essential evidence | SHA-256 |
| --- | --- |
| [Installation](../../../../../target/recovery-pr/current-review-followup/runtime-integration-successor-20261009/local-sdk-fixture-validation/installation.json) | `2539e2f1bd87d33b75beb2dcd89f7a666b5ba31f5747b98d327951370cbcbdeb` |
| [Final source selection](../../../../../target/recovery-pr/current-review-followup/runtime-integration-successor-20261009/local-sdk-fixture-validation/final-source-selection.json) | `b696b51a9df4f6a5bbf216dcae104234d8ddf5171a4c420933ace2f909a61d4d` |
| [Final SDK SPEC_PASS](../../../../../target/recovery-pr/current-review-followup/runtime-integration-successor-20261009/host-response-metadata/readiness-successor/teardown-successor/late-cleanup-successor/spec-review.json) | `9a619a6055dd7286027f670f9e9b3b38477549c9f5825df2818997713a32fdff` |
| [Independent SDK QUALITY_PASS](../../../../../target/recovery-pr/current-review-followup/runtime-integration-successor-20261009/host-response-metadata/readiness-successor/teardown-successor/late-cleanup-successor/quality-review.json) | `1a46619de95b4dcd8fd0564285567015ebae5cb7ee3818cf466ba3c8cdab97de` |
| [Campaign SPEC_PASS](../../../../../target/recovery-pr/current-review-followup/runtime-integration-successor-20261009/campaign-child-cleanup/interruption-successor/spec-review.json) | `932f7da5de47fe000f9e165f4f23a4c93f7eee60f589e534e7c91d21ceca8920` |
| [Campaign QUALITY_PASS](../../../../../target/recovery-pr/current-review-followup/runtime-integration-successor-20261009/campaign-child-cleanup/interruption-successor/quality-review.json) | `103702bd0392e6cff853f243642751a44fecef06b8ba5f43744b357da170aced` |
| [EOF-only quality continuity](../../../../../target/recovery-pr/current-review-followup/runtime-integration-successor-20261009/local-sdk-fixture-validation/formatting-successor/quality-continuity.json) | `663da4b1375c081efb8e2a732b2aa8aa12d1e75eb697995af6eb1d622fe921ec` |

The source-selection packet retains its historical pending status. The subsequent
installation and final runs supersede that status without rewriting the packet.
The final formatting correction removed one surplus EOF newline from
`test_host_response_metadata.py`; independent QUALITY_PASS verifies unchanged
syntax and the other reviewed inputs. Original reviews, failed runs and their
hashes remain intact. Full evidence and log pins are in the register's additive
`fixture_lifecycle_sdk_evidence` block.

## Six findings and corrective scopes

All six use stable register keys and null assigned finding IDs. Authentic reviewer
labels remain attached; no canonical identity is invented.

| Register key suffix | Priority and original location | Accepted corrective scope |
| --- | --- | --- |
| `sdk-sync-admission-readiness` | P2, existing maintained SDK | One additional maintained finding with both inherited readiness facets: immediate replay can race admission release, and drained late cleanup can leave admission BUSY behind unrelated teardown. Release follows actual owned-task drain and precedes unrelated teardown; stale workers cannot clear a successor. Bounded local closure is installed. |
| `campaign-body-interruption-retention` | P2, uncommitted candidate | Preserve the primary interruption, stop admission before slow row handling and aggregate already written rows. |
| `campaign-scheduler-interruption-abort` | P2, uncommitted candidate | Stop admission, cancel unstarted work, drain active children, retain an honest incomplete abort and rethrow the original interruption. |
| `fixture-cooperative-success-grace` | P2, uncommitted candidate | Use deterministic cumulative cleanup bounds and adequate cooperative readiness/grace; preserve the negative separate-wait control. |
| `fixture-stale-lifecycle-imports` | P3, uncommitted candidate | Remove stale lifecycle imports and patch the actual owning launch module in tests. |
| `sdk-completed-delivery-teardown` | P2, first uncommitted handoff repair | Deliver a completed outcome within the selected bound while unrelated default-executor teardown is held. |

The last five retain `candidate_only` classification although their independently
approved repairs are now installed. They were not maintained defects when found.
The maintained readiness finding preserves both authentic report labels and all
failed evidence. Its immediate facet has a deterministic maintained-source RED;
the late facet was probed on a successor and traced to the inherited finalizer
ordering by source comparison. It is not represented as a second maintained
reproduction or double-counted as another defect.

Campaign ownership tests include an explicit test rescue after production cleanup
refuses unresolved work. That rescue is not credited as production cleanup.
Disk-persistence failure and provider-thread cancellation remain outside this
bounded fixture scope.

## Existing obligations and source continuity

The Python host pin changes from `e7c9f732e6d9f01524f23c64503c60cdb392240cfef40d572e91a7d4285874bb`
to `30dba8c8ca16e4f694eb50b17cee9ac30c45bdc0061a4d81c9b1dd07538e1e77`.
The original historical `9fd234399433151aabd5198db8298df6279bc834447859953a3305a095f5f899`
pin remains recorded. Independent quality maps the exact contracts and selectors
under `historical_contract_continuity`; the register appends successors without
changing historical dispositions or pretending the old pins match.

| Existing ID | Preserved original scope |
| --- | --- |
| `H-SDK-08` | Running-loop synchronous Crew tool returns one bounded outcome, one request and one spent attempt, without an unawaited coroutine. The exact original selector passed in both focused modes. |
| `H-SDK-09` | Setup defaults to 120 seconds, other routes to 20; integer overrides 1..120 and one total request/body/cleanup bound remain. No dedicated elapsed-120-second or settlement timing oracle is claimed; old CLI/TypeScript evidence remains historical. |
| `SDK-INDEPENDENT-03` | The original deadline bounds delivery, actual unfinished request/close retains admission until drain, and cancellation neither retries nor changes an already delivered outcome. Named original selectors and immediate/late readiness controls passed in both modes. |

`H-SDK-01`, `H-SDK-04` and `QF-07` remain open and unchanged. Metadata for controlled
success/replay/refusal and local framework paths does not complete the original
all-state native projections. Optimized harmless-child controls do not qualify
native preflight/host request counts. Local failure-row retention does not execute
the required source-bound matched live framework campaign. No PAC or SFE finding
receives cross-credit. The stopped Capture work remains parked, with no retry or
new investigation performed here.

## Hosted status and accounting

The preserved [hosted snapshot](../../../../../target/recovery-pr/current-review-followup/runtime-integration-successor-20261009/hosted-state-c5f53a96d.json)
is for source `c5f53a96dbfc836bfc42805c2fee2d393dd78821`: PR 1179 is open and draft,
with 64 queued checks and two skipped. The [thread snapshot](../../../../../target/recovery-pr/current-review-followup/runtime-integration-successor-20261009/hosted-review-threads-c5f53a96d.json)
contains two unresolved threads:

- [P1 settlement capacity](https://github.com/bb-connor/arc/pull/1179#discussion_r4206947954)
  maps to existing open `PR-SETTLEMENT-CAPACITY-01`, distinct from `C1-06`.
- [P2 large-database coverage](https://github.com/bb-connor/arc/pull/1179#discussion_r4206947962)
  is marked outdated but unresolved. It remains an existing `R2-X-resources-01`
  facet with distinct related `R2-X-authority-03`; the thread priority does not
  replace either canonical priority or its original obligations.

No duplicate record, reply, thread resolution or new implementation disposition
is added for these threads. This is a source-bound snapshot, not current hosted
qualification or a claim that all P1 findings are resolved.

The register grows from 388 to 394 records: one maintained P2 plus five candidate
findings. Current counts are 76 scoped closed, 231 open, 42 needing revalidation,
44 candidate-only and one prerequisite. The original 117 historical scoped
closures and 231 unclosed findings remain intact; the added bounded SDK closure
brings the expanded maintained/support inventory to 118 scoped closures among
349 findings. All original canonical closure counts remain unchanged.
