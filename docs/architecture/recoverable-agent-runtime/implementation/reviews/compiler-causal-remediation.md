# Compiler evidence causal repairs

Four original P1 findings are locally closed: `CR-01`, `CR-02`, `CR-03` and
`QP-SECRET-01`. This does not qualify the runtime or close `CP-F01`.

| Finding | Required acceptance completed |
| --- | --- |
| CR-01 | Original selected-rustc parent traversal case refuses before dispatch in both wrapper modes, with no outputs or excluded source retention. |
| CR-02 | Original stale nominal-output case refuses before dispatch; fresh output ownership and concurrent-owner controls pass. |
| CR-03 | Original real-filesystem subprocess publication substitutions cannot replace the verified descriptor with a consumer-usable record/completion pair. |
| QP-SECRET-01 | The exact credential filename remains metadata-only without body reads or hashes; excluded links are not followed and source archives omit their bytes. |

The independent causal specification review is retained at
`target/recovery-pr/current-review-followup/p1-integration-20261009/host-compiler-gate/causal-spec-review.json`.
The earlier independent source quality review remains at
`target/recovery-pr/current-review-followup/p1-integration-20261009/host-compiler-gate/quality-review.json`.
After the user stopped sub-agent execution, root completed the final causal
quality disposition and narrow source-delta review in
`target/recovery-pr/current-review-followup/p1-integration-20261009/host-compiler-gate/causal-quality-review.json`.
That final review is root review, not an additional independent reviewer.

Current recorder validation ran 125 tests in each Python mode, with two existing
Linux-only skips each. The original selected-rustc refusal controls are included;
they prove pre-dispatch refusal, not successful compilation. The unchanged verifier
has 159 passing tests in each mode. Fourteen original privacy selections passed;
the initial wrong-directory launch remains recorded as failed. The four public
secret-name constants remain equal. No private credential content was inspected.
Exact commands, logs and source pins are retained in `target/recovery-pr/current-review-followup/p1-integration-20261009/final-recorder-controls/`
and `target/recovery-pr/current-review-followup/p1-integration-20261009/host-compiler-gate/host-lint-arguments/`.
The final host-only retention batching preserves all original operation order;
its structural check and repeated owning passes are in
`target/recovery-pr/current-review-followup/p1-integration-20261009/host-compiler-gate/batched-unit-retention/`.

Source integration commit: `e7ee2b317a4e30ef9a3c630a35501be691547fd4`.
Original findings, historical counters, prior qualification records and failed
attempts remain unchanged. Additive successors in the canonical register record
only these four causal dispositions, with `qualified: false`.

## Remaining observed dependencies

The real contracts campaign at `dc13d38d126f92731f390d03b3e1062df58425a0`
failed when the recorder rejected Cargo's long lint arguments for libc. Its
before/after source manifests match. The current repair accepts validated host
lint selectors and preserves deliberate nonzero compiler-probe outcomes, while
rejecting instrumentation failures. The next unchanged contracts command must
pass the original inspector, positive profile and aggregate consumers, and both
unrelated-subject refusal controls before `CP-F01` can close.

The real known-return, emergency-stop and annotation cases now pass authenticated
empty-import initialization, native first input, retained configuration reopening
and action framing. They still fail before dispatch because the selected SQLite
store inherits the unsupported `prepare_original_native_finishing` method.
Their required before-effect physical Prepared account is missing. Import
controls pass 2/2, and owning Control Plane strict Clippy passes. These prerequisites
do not satisfy any of the original effect, crash, settlement or capacity obligations.
Exact current failures and reviews are in `target/recovery-pr/current-review-followup/p1-integration-20261009/semantic-framing/repair/`.

Parked Capture work and the excluded native-controller, Linux, cloud and provider
campaigns remain outside execution. Their required gates stay open. Current-source
hosted CI for this source also remains unverified. The prior dc13d38d1 run
executed and failed: Store warning-as-error builds, workspace structural checks,
a Kani compiler panic, a yanked dependency and missing GH_TOKEN wiring were
observed. Its complete failed-job logs remain in `target/recovery-pr/current-review-followup/p1-integration-20261009/ci/`.
There is no production-readiness claim.
