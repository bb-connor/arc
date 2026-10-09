# Installed SDK source continuity

Verdict: retain the original scoped dispositions for `H-SDK-03`, `H-SDK-08`, `H-SDK-09` and `SDK-INDEPENDENT-03`, with the source changes explicitly recorded. Confidence: high for the pin comparison and bounded evidence mapping. This is an independent read-only continuity audit, not a new runtime or whole-finding qualification.

The audit binds maintained HEAD `5a7f5563c0fb32e30ffc93f41b44c2a8a1a4198e` and the 17-file SDK/provisioning installation. It verified all installed before/after hashes and checked overlap with the 99 canonical plus 18 additional historical scoped closures. Six distinct changed SDK path/hash pairs produce 11 finding-pin associations across these four IDs. None overlaps the existing 47 revalidation flags; neither Store provisioning path occurs in the closure pins. The other 113 historical closures have no direct overlap with this installation.

## Scoped continuity

| ID | Changed direct pins | Preserved original contract |
| --- | ---: | --- |
| `H-SDK-03` | 1 | Only the projection test file changed. The four Python/CLI transport and CLI proxy-control pins still match; the test edit adds expected state/error metadata. Preserve the historical CLI loopback result and its explicit absence of a Python real-socket oracle. |
| `H-SDK-08` | 3 | Existing independent reviews preserve CrewAI execution, bounded worker ownership and one-action behavior. The running-loop test adds only the fixed error-code expectation, retaining the exact one-request/one-attempt assertion. |
| `H-SDK-09` | 4 | Existing reviews preserve deadline selection, cancellation and cleanup timing. Changed tests retain timeout values, elapsed-time and action-count assertions. Seven route/CLI/TypeScript pins still match. No elapsed-120-second or dedicated settlement oracle is added. |
| `SDK-INDEPENDENT-03` | 3 | Existing reviews establish that session methods except the projection boundary are AST-identical and preserve retained task ownership, cancellation and cleanup timing. The synchronous transport pin still matches; affected tests add metadata expectations. |

The spec and quality reviews approved the bounded `H-SDK-01` projection facet and explicitly checked preservation of these transport/lifecycle behaviors. This audit maps those preservation findings to the four earlier contracts. The recorded maintained Python suite passed 1,435 tests with the exact 15 installed SDK paths unchanged before/after, including the affected owning files. No test was rerun by this auditor. No additional behavioral rerun is identified solely from these installed changes.

## Evidence binding

Paths below are relative to `target/recovery-pr/current-review-followup/runtime-integration-successor-20261009/`.

| Evidence | SHA-256 |
| --- | --- |
| `installed-pin-continuity.json` | `b44f6e14ac63a0c5dcc8b21b15d848910d2f17c6373af9d4493045b18d3e70b5` |
| `sdk-recovery-states/source-freeze.json` | `f5229968b24565689fad61359a3fe4eded6a7d60a0a6dad113d2b5c7863157b5` |
| `sdk-recovery-states/spec-review.md` | `9785b62c05382ab96f8b0200b6a5b669a20cd12154ea0e24f48e2ef670d624a1` |
| `sdk-recovery-states/quality-review.md` | `395a27f937cc8c501a63efc13d958f2d4bd596173bbb40b9678aeb363149f482` |
| `sdk-recovery-states/maintained-sdk-and-framework.json` | `dbc09c78a1e017428b15e47437eeeb7c7085e8d1ed9ee37b8819a2f4253b6baf` |

The pinned audit JSON contains all six exact historical expected/current hashes, the original catalog pointers, verified unchanged companion pins and installation-manifest bindings. Those historical expected pins remain authoritative evidence of the earlier reviews; they are not replaced with new hashes. The register's old `pin_check` fields remain the historical audit, while `current_continuity` records this later mapping.

All four classifications remain `recorded_scoped_closed`. The original 117 scoped closures, 231 historically unclosed findings and 47 existing revalidation flags are unchanged. H-SDK-01 remains open. This continuity record does not establish Native/provider execution, Linux, hosted or complete runtime acceptance, and it does not turn the separately failed strict Store Clippy result into a pass.
