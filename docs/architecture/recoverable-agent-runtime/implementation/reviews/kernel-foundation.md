# Kernel foundation successor evidence

The bounded compatibility successor has independent **SPEC_PASS** and **APPROVE**
source verdicts. Confidence is high. The original P1 ordinary-admission finding
and P2 Loom gate finding remain candidate-only records with their original
severity, disposition and failure evidence. The reviewed 22-path foundation is
installed at `b7d71059ccefa740f0036b7e0734d2dd280fc37c` with bounded local checks.

The P1 repair checks the actual configured Native selection before permitting
ordinary absence of a retained original. Selected Native authority still refuses
that absence before preparation, nonce issuance or dispatch. The P2 repair gates
`native_finishing` with `cfg(not(loom))`, matching the Session-only configuration.
Unsupported producer defaults remain closed.

Evidence is under
`target/recovery-pr/current-review-followup/runtime-integration-successor-20261009/kernel-foundation/`.
The register's `candidate_review_evidence.files` pins each review, manifest,
diff and candidate result/log. Installed gate records and logs are pinned by the
separately hashed maintained verification. The controlling source evidence is:

| Evidence | SHA-256 |
| --- | --- |
| Original 20-path `source-manifest.json` | `f84111594f21d2fc354c5e449b1c4e37c1fab6710c1aa6ed26608275f73b09aa` |
| Four-path `compatibility-repair/postimage-manifest.json` | `89ed5eb1158f123df1f409cc2c11b2fb5a4342a77ad074871aed5141425f26f2` |
| `compatibility-spec-review.md` | `d7c611243d42860fbb05ec32a907b58b64b2ab2999ebceac4d7434e852b94a6d` |
| `quality-review.md` | `b828a2dd14208861149ea7d5227fa67e566858b2f9f83263aa66d492f7baa241` |

The successor replaces two production paths and adds two owning control paths,
forming the reviewed 22-path foundation selection. The original negative spec
report remains intact. `eligibility-corrected-before` reproduced ordinary Deny
versus expected Allow while the exact selected-Native refusal passed: one passed,
one failed, exit 101. The earlier `eligibility-before` fixture setup failure is
retained without credit as defect reproduction. `loom-compilation-before`
retains exit 101 and 30 compiler errors, with no tests executed.

The recorded local successors all exited zero:

| Result under `compatibility-repair/` | Passed | Failed | Ignored |
| --- | ---: | ---: | ---: |
| `eligibility-after.json` | 2 | 0 | 0 |
| `kernel-library-after.json` | 1469 | 0 | 0 |
| `loom-after.json` | 18 | 0 | 0 |

The positive owning case checks Allow, exact output, Completed state, one
invocation and exact replay without a second invocation. The negative checks the
exact missing-original error, unchanged operation, no budget authorization and
no dispatch. Loom used `RUSTFLAGS=--cfg loom` and `LOOM_MAX_PREEMPTIONS=3`;
its passes provide bounded model coverage. The spec reviewer sealed before the
green results; the quality reviewer inspected them without rerunning them.

These runs used the full composed candidate, including the separately approved
atomic-ledger successor in `admission_operation.rs` and
`admission_operation/store.rs`. The foundation source selection uses frozen
preimages for those two overlaps. The runs establish composed-candidate
compatibility, not a separately executed foundation-only or maintained install
build. The maintained installation separately used the selected frozen preimages
for those overlaps and imported no atomic overlay, Store or Process implementation.

The sealed `installation/maintained-verification.json`, SHA-256
`4b84c8ec0c147f49fa914933e7b7e3596a8c7caa87ada4b978085f46d8ac479d`,
confirms all 22 reviewed postimages and unchanged `ReceiptStore`. Its eight
root-produced gate records and logs were read back and their hashes verified:

| Maintained check | Result |
| --- | --- |
| Kernel library | 1,468 passed, 0 failed, 0 ignored |
| Kernel doctests | 25 passed, 0 failed, 0 ignored |
| Session-only Loom, preemption bound 3 | 18 passed, 0 failed, 0 ignored |
| Format, source names, recovery boundaries | Passed |
| Strict Kernel Clippy `--lib` | Passed |
| Strict Kernel Clippy `--all-targets` | Exit 101 in Store development dependency, 248 diagnostics |

`installation/library-scope-comparison.json` confirms both eligibility controls
are present; the excluded atomic-ledger callback regression is the sole test
behind the 1,469 versus 1,468 difference. `installation/clippy-comparison.json`
confirms the exact multiset of all 248 primary message/file/line/column signatures
matches the prior maintained Store run, with no added or removed signatures.
This preserves the all-targets failure rather than claiming broad strict lint
acceptance. The original applied-selection snapshot still records tests pending;
the additive verification records their eventual outcomes.

Concrete Store and Process implementations, funded Capture, strict all-targets
lint, broader platform and whole-runtime acceptance retain their separate
obligations. The runtime remains unqualified. The
[review register](../review-register.md) preserves every historical closure and
the historical closure/unclosed counts; its total increased separately for the
ReceiptStore candidate finding.
