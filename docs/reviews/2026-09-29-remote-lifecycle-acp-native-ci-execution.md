# Remote lifecycle, ACP boundaries and native CI execution

Date: September 29, 2026. Base: `723bf9ee97222bf64c7d8122ac704ed30bfde808`.
Branch: `packet/3-retention-accounting`, worktree: `/tmp/arc-security-launch`.
Plan: [remote lifecycle, ACP and native CI](../superpowers/plans/2026-09-29-remote-lifecycle-acp-native-ci.md).

The four planned implementation tasks and final-review repairs are delivered.
Focused local verification passes. Native execution on an enforcing Linux
x86_64 host, Docker/provider-dependent mini-SWE campaigns and hosted CI remain
open. The local host is aarch64 with uid 1000. Compilation and portable fixture
tests do not qualify native enforcement, a release or M5 acceptance.

## Task completion

| Task | Delivered behavior | Acceptance state |
| --- | --- | --- |
| 1. Remote lifecycle and clocks | Five ambient production readers now use an injected, shared, fenced clock. OAuth grants, DPoP replay state, session renewal/recovery, rate windows and counters fail closed on clock, expiry, overflow and persistence errors. Kernel and local/SQLite authority composition share the configured clock. Session state is persisted before live authority is published. | Implementation and focused local verification complete. |
| 2. ACP bypass removal | Removed `compatibility-surface`, the direct server wrapper, the ACP compatibility lifecycle variant and unused shared synchronous bridge. Notification and asynchronous invocation use kernel admission. Retained task results have bounded custody and fenced expiry. Behavioral scenarios use kernel execution or explicit test mocks. | Implementation, owning suites and no-bypass gate complete. |
| 3. ACP original-byte ingress | Edge ingress bounds original bytes before duplicate-aware projection. Proxy callers construct an opaque bounded message; malformed, truncated or oversized frames poison the reader. Capability projection is separately bounded. Parser, transport, capability and kernel-checker causes remain typed locally; wire responses stay redacted. | Implementation, owning suites and reviewed-owner source contracts complete. Broader semantic error taxonomy remains queued. |
| 4. Native consumer CI and fixtures | A shared action builds the enforcing helper, requires a terminal privileged discovery probe and then provides independent anchors, identity and explicit read grants. Ordinary process-worker tests remain separate. SDK, recovery, repository-review, shared-resource, AI SDK and conformance callers receive explicit tool data/module grants and isolated writable state. | Wiring, portable tests and affected consumer compilation complete. Real native consumer campaigns and hosted qualification remain open. |

The native action requires exactly one successful discovery test, not a skipped
or zero-test result. The fixture excludes authority, anchor and checkout
metadata paths from grants. Individual consumer campaigns retain separate
terminal evidence even if an earlier consumer fails. Its 64 MiB signed artifact
ceiling is below the existing 256 MiB provisioner maximum; no source-gate size
cap was raised. File-hygiene caps were tightened and their existing expiry
dates retained.

The ACP clock inventory now includes six preexisting calls: three production
receipt/compliance owners still queued and three fixtures. This expansion is an
explicit inventory disposition, not a claim that those production clocks were
migrated by task 1.

## Final review and repairs

One independent read-only reviewer inspected the implementation without running
builds or spawning additional agents. Its [record](artifacts/2026-09-29-remote-lifecycle-acp-native-ci/review.txt)
identifies two substantive findings:

1. `Ready` and `touch` could publish extended authority before persistence
   failed. Both now prepare a proposed snapshot, complete checked signing and
   persistence with the original fenced observation, then publish under the
   lifecycle lock. Tests cover counter exhaustion without initialization or
   extension, and transitions using a single observation.
2. Several native consumers omitted copied tool modules, corpus or publication
   state from their grants. Callers now grant those exact paths and keep writable
   tool data separate from retained authority. Packaged repository-review kits
   explicitly grant their extracted modules.

Obsolete compatibility rustdoc was also removed. The root implementation agent
verified the repairs; the reviewer did not perform a second review. No post-fix
independent approval or native-host qualification is inferred.

## Terminal local evidence

All Cargo commands below used `CARGO_INCREMENTAL=0`. Logs and the progress
ledger are archived under [the evidence directory](artifacts/2026-09-29-remote-lifecycle-acp-native-ci/).
`SHA256SUMS` records exact artifact bytes. The source manifest records changed
production, test and workflow inputs independently of generated evidence.

| Check | Terminal result | Log |
| --- | --- | --- |
| `cargo test -p chio-mcp-remote -p chio-acp-edge -p chio-acp-proxy --lib --no-fail-fast` | ACP edge 96, ACP proxy 201, remote MCP 98 passed; zero failures | `owning-tests-5.log` |
| `cargo test -p chio-store-sqlite --lib authority::` | 22 passed; zero failures | `sqlite-authority-tests.log` |
| `cargo test -p chio-cross-protocol --lib` | 35 passed; zero failures | `cross-protocol-tests.log` |
| `cargo test -p chio-conformance --lib runner::native_launch` | 4 passed; zero failures | `conformance-launch-tests.log` |
| `cargo test -p xtask --bin xtask adapter_no_bypass` | 28 passed; zero failures | `no-bypass-tests-final.log` |
| SDK `test_launch.py` | 6 passed | `sdk-launch-tests.log` |
| Native fixture tests | 2 passed | `native-fixture-tests.log` |
| AI SDK qualification portable tests | 2 passed | `ai-sdk-tests.log` |
| Shared-resource `test_*.py`, locked LangGraph dev/process environment | 33 passed | `shared-resource-tests-2.log` |
| Repository-review `test_snapshot.py` and `test_adaptive.py`, same locked environment | 38 passed | `repository-review-tests.log` |
| Security-clock gate calibration | 3 passed | `clock-calibration.log` |
| `cargo check -p chio-cli --features real-linux-enforcement --test process_host_native --bin chio` | Exit 0 | `native-consumer-check.log` |

Totals: **484 Rust tests, 81 Python owning tests and 3 clock-gate calibration
tests passed**. Remote tests named `hosted_tests` use local in-process HTTP
fixtures; they are not hosted CI results. The four conformance tests validate
launch inputs and grants, not the native conformance campaign.

| Source/style check | Terminal result | Log |
| --- | --- | --- |
| `target/debug/xtask check adapter-no-bypass` | Structured mediation contracts passed | `no-bypass-gate-qualified.log` |
| `python3 scripts/check-trust-boundaries.py` | 370 constructors, 85 tenant tables, 170 explicit SQL principal contracts | `trust-gate-final.log` |
| `python3 scripts/check-security-clocks.py` | 157 occurrences at 152 keys; no additions outside the reviewed inventory | `clock-gate-final.log` |
| Negative-assertion ratchet | 1,260 assertions at 1,177 sites; no increases | `assertion-gate-final.log` |
| Rust file-hygiene ratchet and final read-only gate | 12 tightened entries, no cap increases; final gate passed | `hygiene-gate-final.log`, `hygiene-qualified.log` |
| `python3 scripts/tests/check-process-ci-inventory.test.py` | Passed | `native-ci-inventory.log` |
| Changed Rust source formatting | 69 files passed | `rustfmt-final.log` |
| Changed Python parsing, Ruff formatting and lint | 25 files passed using their workflow configurations; formatting preserved every AST | `python-style-qualified.log` |

The final Python check uses the SDK's 100-column configuration for SDK callers,
the isolated shared-resource configuration, and each other file's normal
configuration. An earlier uniform-format check did not match those workflow
settings; its failure is retained. No functional Python change followed the
passing owning tests. No full-workspace build, test suite, Clippy campaign or
privileged native execution was run for this batch.

## Superseded and interrupted evidence

Historical logs are retained alongside terminal passing results:

- `owning-tests.log` was interrupted by a daemon restart before test results.
- `owning-tests-recovery.log`, `owning-tests-final.log` and
  `owning-tests-2.log` through `owning-tests-4.log` contain intermediate caller,
  typed-error and expectation failures. In the fourth attempt, an oversized
  whitespace capability bypassed decoding and a clock test expected the wrong
  native error variant. Both were corrected before `owning-tests-5.log` passed.
- `shared-resource-tests.log` records the old database fixture path and missing
  project dependencies. The path was corrected and the tests passed in the
  locked owning project environment.
- Earlier no-bypass logs failed because the newly introduced clock builder and
  its fully qualified call targets were absent from the reviewed constructor
  inventory. The scanner, calibration tests and explicit inventory were fixed;
  `no-bypass-gate-qualified.log` is the terminal result.
- Earlier compile, format and inventory logs are development evidence. Their
  presence does not make them passing candidate checks.

## Next substantial batch

1. Finish native consumer dependencies and broker-backed Docker/provider access
   for mini-SWE. Run discovery, recovery, packaged SDK/examples and conformance
   on an enforcing Linux x86_64 host, preserving exact terminal evidence for
   each campaign.
2. Migrate ACP proxy receipt, kernel-signer and compliance timestamps to a
   configured fallible clock, with checked expiry, rollback and restart tests.
3. Replace remaining string-only semantic errors in remote MCP and ACP with
   domain variants and registered codes, preserving local sources through
   caller responses, completion and receipt generation.
4. Extend original-byte bounds and error provenance to the OpenAPI/MCP bridge
   and its conformance callers.

The [remaining-work queue](2026-09-28-remaining-security-work.md) preserves the
wider reader, arithmetic, structural, declaration, retention, formal, supply
chain and release acceptance work. This batch does not close those queues.
