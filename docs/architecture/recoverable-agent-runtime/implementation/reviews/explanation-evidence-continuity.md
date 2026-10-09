# Explanation evidence continuity review

Verdict: **A-planner-07 remains closed within its original source-only scope.** Confidence: high. Reviewed October 9, 2026. `qualified: false`.

Original finding: **P2 records overstate or mis-anchor some explanation claims** (P3). Original obligation: "Resolve current anchors, exercise template permutation in determinism acceptance, and review exact work/privacy/domain claims against the asserting source."

The original `current_complete_disposition` in `target/recovery-pr/current-review-followup/current-reviewed-dispositions.json` closes durable historical-to-current source routing and corrected advisory claim meanings. This review re-adjudicates that obligation against maintained source. It does not reopen or grant acceptance to other findings and does not change the register.

## Document drift and current anchors

The disposition contains 21 direct source pins, including README. Twenty remain exact; only README changed. Its accepted hash was `ccc9004889045b0aebb4d17d76939f056958e3861dd196b759e42f7c502eda35`. The exact accepted README was reconstructed from Git revision `77006b86fd320738ca0eff4371d90aec6bd349d4` plus the recorded one-line source-note navigation, then checked against that accepted hash. The entire subsequent diff adds three lines linking `implementation/current-reproduction.md` and describing separation of source/command correspondence from archived audits and P6 metadata redactions. The accepted source-note link and source-only qualification sentence remain byte-identical. The new destination exists and explicitly retains the current unqualified status.

All 20 original A07 acceptance-anchor routes were checked: 19 resolve to unique current Rust function definitions with their accepted source hashes; the remaining historical `effect_dependency` marker is explicitly classified as synthetic. Both named current dependency-test successors exist and are not credited as the old result. Every relative path in `current-source-anchors.md` resolves. The five historical phase-record hashes preserved by the accepted review also remain exact, including P2 OPERATIONS and requirements coverage.

## Asserting-source checks

- **Work:** `evaluation.rs` normalizes inputs before constructing `Work`, charges one unit per bounded label operation and charges fact/template/dominance visits. `projection.rs` performs visibility and dependency filtering before projected search without charging those membership visits to `Work`. The installed note corrects the historical all-membership wording and keeps structural bounds distinct from search metering.
- **SIM-02:** `mixed_versions_and_all_truth_assignments_preserve_fail_closed_meaning` changes truth values. The separately named `original_basis_is_required_even_when_changes_leave_the_advice_identical` changes the fact version, influence basis and registry cost and requires refusal against the old signed basis. The current note routes the version claim to that asserting test.
- **SIM-07:** `runtime_acquisition.rs` calls `revalidate_operation_owned_for_native_capture` on the retained live intent and checks returned validity. `admission_hook.rs` performs the owning revalidation. Advisory explanation observations are not described as that execution boundary.
- **Determinism:** `basis.rs::permutations_are_canonical_without_claiming_store_atomicity` enumerates all six orders of three templates, reverses fact order and each dependency order, and compares the complete typed view/report payload tuple. The production report digests commit normalized canonical inputs. This supports canonical pure payloads; it does not assert a separate direct serialized-byte comparison or store atomicity.
- **Privacy:** `projection.rs` excludes inaccessible fact/template/disclosure dependencies before ranking. `report.rs` constructs the public view without protected snapshot/registry/evaluation commitments and treats restricted-view expiry separately. The unchanged privacy tests assert equal public payloads/signatures across 64 hidden worlds, restricted-view expiry independence, hidden-search exhaustion isolation and secret-disclosure ranking exclusion. The historical operations text explicitly excludes a constant-time claim; this review adds none.
- **Domains:** the catalog identifies the four active explanation digest inputs, the separate influence digest and the report/view signature domains. Their exact names agree with `domains.rs`, the signed types and the producers in `report.rs` and `explanation/native.rs`. The retained `chio.recovery.explanation.v1` registration is distinguished from an active producer; no `RecoveryDigestDomain::Explanation` producer call was found in current Rust source.

## Preserved evidence and limits

The accepted independent review, installation record, crosswalk, pure log and all four source-continuity amendments were read and their recorded SHA-256 values verified. The amendments preserve source-anchor meaning through additive semantic test registration; their final semantic source pin matches maintained source.

The verified pure log contains `ok` results for the owning permutation, original-basis and advisory-authority rejection selectors; its explanations group records 20 passed and one explicit fixture-regeneration ignore. This retains the already accepted pure evidence for the original source-only disposition. No test was rerun, no current dependency-graph execution was inferred, and no native binary/image or old native result was credited. Maintained source supplied this review; no selected-candidate source substitution was needed. Broader native, compiler, provider, Linux, hosted and release qualification remain separate.

## Current maintained source pins

Paths are relative to the checkout root. Only the README hash supersedes an original direct pin.

| Path | SHA-256 |
|---|---|
| `docs/architecture/recoverable-agent-runtime/implementation/current-source-anchors.md` | `2c6203a275d57bd68ecc65f944d0ee4aa48734042308048616f184e56b92c8bb` |
| `docs/architecture/recoverable-agent-runtime/README.md` | `304bb513277829dcb96af7e3361730752db6bd93b56c54277a643079d444a41c` |
| `crates/platform/chio-control-plane/src/recovery/explanation/tests.rs` | `cf25a7593c1941901238a8fd15b8dad534607364c3a4b5cfb081fca53a76d9d9` |
| `crates/security/chio-recovery/tests/explanations/basis.rs` | `5669983f2886c505627b5a17343f4b99211c8bcdae0a837f5be25cd73e9bf58a` |
| `crates/security/chio-recovery/tests/explanations/verification.rs` | `e9278982d4fe6e62834842a19db943b6b5fbb250e67de37f5efd675960cffe6a` |
| `crates/platform/chio-control-plane/src/recovery/tests/explanations.rs` | `3d1877c8edd74ebebdae1127a5e0d8153629a1956de2f95a1e6ea69d71aa184a` |
| `crates/security/chio-recovery/tests/explanations/privacy.rs` | `8b38f0230411cdf7263eb0fd57e9a62ed801943f8cccc6e3500d4165cf6e403d` |
| `crates/platform/chio-control-plane/src/recovery/tests/semantic/authority.rs` | `5158eb3dc7f0705fb9d580794304289d6d015c56fe1c616e6c6fe00dbb414500` |
| `crates/security/chio-semantic-contracts/tests/semantic_contracts.rs` | `2f3910944730cf92fefd729fcd9ca574ad741a289fd259e4c0c17cb9510e59e1` |
| `crates/platform/chio-control-plane/src/recovery/tests/semantic/chains.rs` | `6396e9e62e4f694af55f6758ead91aed60ee8d9107e46126f4d4964f2c7e71d2` |
| `crates/platform/chio-control-plane/src/recovery/tests/semantic.rs` | `57815c545e1621a9c5481b62026858f6ef332d9feb1d2cbb3cf53b3b6088b12d` |
| `crates/platform/chio-control-plane/src/semantic/http/tests.rs` | `cd16e34c2f030c21de0c4a03fe4038c6783f510df0575602324ee8a54ac91b4d` |
| `crates/security/chio-recovery/src/evaluation.rs` | `94e0ed2f663c952b2a79407b20bdaa0a491976cfe480b89b584a629449ea7556` |
| `crates/security/chio-recovery/src/projection.rs` | `ad7c6925c4b43d3e9623ab2373cabbec270e28b4a46b078c29b7ed7c4d0602e6` |
| `docs/architecture/recoverable-agent-runtime/11-contract-catalog.md` | `759da42a05a5447723d820284ed201ef55be7418504e56149a55d652d2c83962` |
| `crates/core/chio-core-types/src/recovery/domains.rs` | `be36ed0117e2fcba8de542d622f6301bc0548cf67a35c95ccdb5e8e40d1a43ff` |
| `crates/core/chio-core-types/src/recovery/explanation.rs` | `3164f31b8bc39ad1fa1ac4e72bb5ee34bc5c534c4ebaae9cc41c713f7572d72c` |
| `crates/security/chio-recovery/src/report.rs` | `49b9ae202f7f416eda60cace282b649e53c956e876f08c53b56d56b840681258` |
| `crates/platform/chio-control-plane/src/recovery/explanation/native.rs` | `69f39307ecf9ec03b3145878dd725960b35d3e2038aa04c98c27140657f08279` |
| `crates/kernel/chio-kernel/src/kernel/admission_coordinator/runtime_acquisition.rs` | `8d68ccef46aeb346431c51758d91c9bee51124c48fdfebfdaaccdea40ab1984e` |
| `crates/kernel/chio-runtime-core/src/admission_hook.rs` | `0136250c6d7bf701771b61614c5664f894bd3a03b27ab9d0ec097e34f80e49d5` |

## Verified review records

Paths below are relative to `target/recovery-pr/current-review-followup/`.

| Record | SHA-256 |
|---|---|
| `durable-source-anchors-independent-review.json` | `aa96fe0bab9c87e3b4bb46bd9a2d0dfbac9a12d5e460a9c12b39ed79584b7a62` |
| `semantic-planner-anchor-note-source/INSTALLED.json` | `59e1f23b5adee8747f40d309c5c63923278f2c7db63300ce1f58c99cbae016e7` |
| `semantic-planner-anchor-crosswalk.json` | `870ea0c92a26ea5c890d0cbb8e5e5d3c0a4bc28d3f43eaef15f25d11870e490e` |
| `pure-recovery-semantic-current.log` | `c93edf573ad46f024f9678528342ea4e3bbfbe4b3d534e9412c6781046e5cbb2` |
| `durable-source-anchors-static-trace-amendment.json` | `7c56b045fbd028b9f2d51152d756c70ac18fb84e8b587a3a1056231c256c8562` |
| `durable-source-anchors-registration-amendment.json` | `b3da935480d5b84e64035d787d5b4e5069fda16273cee2ada9934bc14a564dcc` |
| `semantic-generation-registration-independent-source-continuity-amendment.json` | `32a7a2d68d549a9f3dcf794ed1a8b53b220c199fc6c31f535e7be8721e7b7088` |
| `semantic-compatibility-registration-independent-source-continuity-amendment.json` | `2d8ee04326c6f0b64b618ca6d1dab509065a5ea067bcb388360b921cc77b9dad` |

Additional inspected navigation destination: `docs/architecture/recoverable-agent-runtime/implementation/current-reproduction.md`, SHA-256 `daf31e31ecb1254e99e37225972c6413757b020f3e9b761e31185ce90e24c0a5`.
