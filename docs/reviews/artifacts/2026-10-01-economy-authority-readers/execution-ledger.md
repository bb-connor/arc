# SDD ledger - plan: docs/superpowers/plans/2026-10-01-economy-authority-readers.md
Base: 593b642da96bba939e4ae26055f2ebe26b06668c.
Task 1: complete, pre-review-packages exit 0.
Task 2: complete; owner tests and 19-consumer compile passed.
Task 3: complete; owner tests, 19-consumer compile and seven Rekor conformance cases passed.
Task 4: review, accounting and qualification complete; authorized publication is the final handoff action.
Pre-flight: shared original-input and clock contracts already exist in core-types
and security-types. Each package owns its error conversions; direct consumers
must compile after added native cause variants. No cross-task helper depends on
an unimplemented public API.
Ruling: approved spec and explicit execution request authorize implementation and
publication; no redundant design or branch approval is needed. Existing isolated
worktree remains the source owner; preserve output links and unrelated worktrees.
Ruling: preserve existing external numeric restrictions and canonical equality;
use native decoding only for native signed owners. Existing CCIP fixture-only
reader is classified, not wrapped as production input.

Task 1: owner suite green in owning-packages-accepted (949 total batch tests, zero failed/ignored); native helper numeric controls included.
Task 2: owner suite green in owning-packages-accepted; alternate response overrun, source preservation and zero-attempt regressions pass. Existing tests now assert typed source codes.
Task 3: owner suite green in owning-packages-accepted. Additional original JSON-RPC ordinary-float compatibility and fixed hash-shape diagnostics are under regression verification before final review.
Ruling: exact original output digest remains over all caller-owned predicate bytes, including rejected oversized output; the byte bound prevents parsing/projection allocation and cannot change the existing signed output identity.
Ruling: per-owner native and external numeric profiles stay separate. Factor/IOU semantic safe-integer restrictions remain in their body validators; generic native canonical helpers preserve full-width integers.
Ruling: JSON-RPC is an unsigned transport document and must retain ordinary float spellings in ignored metadata. A positive 0.10 control reproduced over-restriction in the first shared-reader migration; decode_document now guards original keys before Alloy RawValue projection.
Pre-review correction: malformed Rekor hash text must reject before public hash-mismatch diagnostics, with a fixed shape error. numeric-and-diagnostic-red reproduces both this acceptance bug and the JSON-RPC regression.
Task 1-3: pre-review-packages ran the complete eight-owner test command, exit 0, 950 passed, zero failed/ignored across 49 test/doc targets. Preserve this unified terminal run instead of redundant per-task test reruns.
Final review: starting one independent read-only review of the source commit; direct consumer and Clippy qualification continue separately.
Consumer integration: the 19-package compile found missing new error variants in two control-plane mappings. After mapping the closed families, consumer-cause-red reproduced loss of the original cause through both actual kernel-facing adapters (0 passed, 2 failed). The fix retains an optional local source in FindingDenial, excludes it from public Debug/equality, and preserves it through prefix/clone. Recovery also retains nested purchase and base64 causes. No denial family or positive authorization decision changes.

Independent review: complete, read-only range 593b642da96bba939e4ae26055f2ebe26b06668c..66e9ecc5bda75b15cf2e60d67a220a0c4bb396b2; no material findings. Seven declined judgments are recorded with root rulings in review.md. No unresolved minor findings and no re-review.
Post-consumer owner qualification: post-consumer-packages exit 0, 950 passed, zero failed/ignored across 49 test/doc targets on source commit 66e9ecc5bda75b15cf2e60d67a220a0c4bb396b2.

Tasks 2-3: direct-consumers-2 exit 0, all 19 direct consumers compile with --all-targets.
Qualification repair: hygiene-final found the updated native-cause assertion took market tests.rs one line above its unchanged cap. Moved the unchanged canonical-input/authentication test into tests_parametric_input.rs. hygiene-accepted passes with no cap increase; final Clippy and a complete market package rerun qualify the relocation. Production source is unchanged from the independent review.

Qualification repair: clippy exit 101 identified FindingDenial Error::source trait-object as coercion under the existing as_conversions deny. Replaced it with an explicitly typed closure return and implicit coercion. No allowance or semantic change. Final scoped Clippy, kernel denial tests and both production adapter cause tests qualify this post-review one-line correction.

Qualification repair: clippy-accepted also exited 101 (the label is not a success claim), finding a pre-existing single-element loop in the settlement rail domain fixture. A direct binding preserves every canonical/digest assertion. The final Clippy run and that fixture execution qualify this test-only cleanup. No independent re-review claimed.

Feature qualification repair: the kernel-only test graph disables chio-link web3 and exposed an unused crate-private OracleRequestError::new constructor. Gate that implementation under its actual web3 owner, retaining the public error type and variant in both configurations. Default and no-default-feature all-target chio-link Clippy runs qualify the feature gate without an allowance. Existing default-feature behavior is unchanged.

Final qualification: 950 passes in the complete eight-owner campaign; 79 market passes after unchanged test relocation; one settlement identity fixture pass; five kernel denial passes; two actual adapter custody passes; seven Rekor conformance passes. Zero failed/ignored in accepted runs. All 19 direct consumers compiled; ten-package all-target Clippy and both oracle feature configurations pass with -D warnings. Source gates pass without allowances or cap increases. Review found no material findings; four subsequent qualification cleanups have bounded evidence as recorded in qualification.json.
Final publication: complete source/evidence prepared for the already authorized non-force push on packet/3-retention-accounting. The final user handoff verifies the exact remote commit; the containing commit owns final source hashes and terminal metadata. The machine-local output link and unrelated worktrees stay outside scope.
