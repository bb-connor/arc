# Model-response parsing acceptance

All four original local `SF-R02` parser controls pass on the exact maintained
source. No implementation change was needed. Confidence is high for this bounded
local result. Companion [spec](../../../../../target/recovery-pr/current-review-followup/runtime-integration-successor-20261009/model-response-validation/accounting/spec-review.md)
and [quality](../../../../../target/recovery-pr/current-review-followup/runtime-integration-successor-20261009/model-response-validation/accounting/quality-review.md)
reports cover only this bounded local acceptance.
`SF-R02` remains **open**, and every register count is unchanged.

| Original control | Current evidence |
| --- | --- |
| Missing completion-token count | Reused maintained seven-case exact-category method in both current 133-test runs. |
| Negative completion-token count | Same method and exact original input. |
| Invalid UTF-8 output (unpaired surrogate) | Same method and exact original input. |
| Valid positive output | Unchanged original `test_valid_response_positive`, one new pass in each Python mode. |

The three negatives are checked by
`ModelBoundaryTest.test_malformed_provider_usage_or_content_has_a_fixed_counted_refusal`
at `test_campaign_runner.py:78`. Its passing identity appears at line 65 in both
installed-successor logs. It requires exact `campaign.response_invalid`, one
request and spent attempt, no completion or output-token metadata, and a subsequent
budget refusal without another request. All seven malformed-input subcases ran.

The reused runs passed **133 normal and 133 optimized tests** on 663 identical
before/after input pins, with zero recorded external attempts. All three relevant
parser/test/helper hashes match those inventories and the original independent
review. The existing positive snapshot test checks returned content and prompt
isolation, but does not assert the original request-count and attempt metadata.
Only that missing assertion set was rerun, preserving the original test body and
assertions: exactly one fake create, returned `OK`, `attempt_error` null and
`output_tokens` 1. The runner selected that one test through unittest loading;
import failure cannot count as success. No negative or broad suite was rerun.

The profile is the existing supported CPython 3.12.11 venv. The reused fixture
runs disclose their audit/runpy wrapper, relative fixture/SDK import roots,
CrewAI 0.203.2 and LangGraph 1.2.12 profile; they are not literal catalogue command
equality. The new positive controls use `-I -B` and `-O` for the optimized mode,
an empty launch environment, explicit maintained fixture imports, and denied
networking. No provider/framework modules were imported in those new controls;
all recorded network-attempt lists are empty. No keys or provider services are
inputs: completion responses are ordinary in-memory synthetic objects.

| Maintained input | SHA-256 |
| --- | --- |
| `fixtures/recovery-product/campaign_runner.py` | `b7b29a576a6d78d00a57049fc84aefe0823c59b80342f7bdc873d44f1ceacc93` |
| `fixtures/recovery-product/test_campaign_runner.py` | `a7f39b952d4c5aa243cf96a534f9bd3949ab930c02ce95ff0b3a7cec69b316a8` |
| `fixtures/recovery-product/qualification_runtime.py` | `6eb20a2724ab2c033b6c5e33c4dcdf4871c0bfa31a268c233f3b22a7cbc49271` |

| Evidence | SHA-256 |
| --- | --- |
| [Acceptance and exact input crosswalk](../../../../../target/recovery-pr/current-review-followup/runtime-integration-successor-20261009/model-response-validation/acceptance.json) | `51392b3eae14360e9776f43f1bb920199fa762d5b96ea1fc545ba90e61558163` |
| [Frozen local evidence manifest](../../../../../target/recovery-pr/current-review-followup/runtime-integration-successor-20261009/model-response-validation/evidence-manifest.json) | `3adfd737e022d980baea2072c377e6df15d02e9ca65ded0d8115dbd2f8b0ba91` |
| [Reused normal 133-test record](../../../../../target/recovery-pr/current-review-followup/runtime-integration-successor-20261009/fixture-environment-continuity/installed-successor/normal.json) | `a8d6557f9ceea7725968cefb965ffe0890a04f2965190b035affc35105b0a16c` |
| [Reused optimized 133-test record](../../../../../target/recovery-pr/current-review-followup/runtime-integration-successor-20261009/fixture-environment-continuity/installed-successor/optimized.json) | `26815164ce5dc57841df0c075180f5da2fa628cbd40f47382e17f5fc47c132bc` |
| [Missing positive normal](../../../../../target/recovery-pr/current-review-followup/runtime-integration-successor-20261009/model-response-validation/positive-normal/verification.json) | `d127f837fe2d2824e3f2dc0e5c0c580e95c17e8c3b49146734fb238ac37f85e0` |
| [Missing positive optimized](../../../../../target/recovery-pr/current-review-followup/runtime-integration-successor-20261009/model-response-validation/positive-optimized/verification.json) | `782b83b0cc86b35a05f9f6caf6fcb3caaec0d4c737c54a35ee26e285bdeb5afd` |

The original parsing-defect acceptance uses fake completion records and
`ModelBudget` only. It requires no live campaign, native or Linux execution.
Separately, the current selected owner catalogue still requires model-free native
preflight, matched live cohort, and applicable final-source/primary-lane checks.
Those obligations and `remaining_obligation_refs` remain intact. No provider,
native, Linux, hosted, primary or whole-runtime qualification is credited, and no
whole-finding closure is claimed. The original review's SF-R02 local pass remains
historical; its overall changes-required verdict is not rewritten.

This update changes only SF-R02's current explanation and adds a bounded
successor preserving its exact previous status and reason. The other 394 record
bodies, all original fields and historical counts, prior 26 current updates,
source inventories and pin audits are unchanged. One current update is appended.
Preimages, the four-document diff and preservation validation are retained in
`target/recovery-pr/current-review-followup/runtime-integration-successor-20261009/model-response-validation/accounting/`.
