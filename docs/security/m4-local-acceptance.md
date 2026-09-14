# M4 local consumer-boundary acceptance

Status: M4 local consumer-boundary acceptance is complete on 2026-09-14 UTC.
All required local execution gates, final documentation review, source graph
refresh and verification-script calibrations passed. The
hosted serial profile passed all 17 previous control-plane regressions, then
exhausted the outer four-hour job limit during SQLite. Its complete lane remains
unqualified. The bounded CI-capacity correction passed its full local calibration.
Local acceptance is not all-PR success, merge approval or release authorization.

The repaired Rust/SDK/schema/dependency source is
`8738bdfd7be8c43a0543ca0ce468541529c47add`. Later CI and proof-report repairs
change verification inputs only; their separate qualification is recorded below.
Current results include 45 exact M4 cases, 61 exact M3 cases, all 69 flow
inventories, 17,187 workspace tests, normal build, strict all-target Clippy,
supported compatibility/portable profiles, four-language consumers and explicit
C++/FFI/live/Drogon acceptance. The 48 existing workspace ignores are unchanged;
no required M4 test is ignored. Earlier failed runs and their repairs remain
recorded below, but do not replace these current passing gates.

## Final review repairs and composed qualification

The receipt-origin repair updates both authoritative receipt schemas and all
four generated languages through xtask. The shared protocol corpus now has 38
cases, including valid internal origin and invalid unknown/null origins. A Rust
test constructs and verifies actual signed receipts for all four native origins,
then proves that changing origin invalidates the signature. The shared corpus's
illustrative receipt signatures establish schema parity only, not authenticity.
The public Node HTTP and AI SDK consumers retain their independent verification
requirement. Internal origin is provenance, not permission. Go's public enum
decoder rejects invalid values without replacing a prior valid value.

The attachment repair removes only the stale independent cardinality limit.
Strict ascending uniqueness over the closed slot vocabulary still bounds every
set. A regression drives normal operation transitions to 17 retained attachments,
appends the outcome, round-trips all 18 through persistence, and rejects a
duplicate. It does not enable an unsupported combination of caller authorities.
Both defects failed focused regressions before their repairs. Their 37-case M4
Rust gate passed. The subsequent readiness repair extended the required inventory
to 45 named cases; that complete gate also passed on `8738bdfd7b`.

The fixes are committed and pushed as
`5a2d612573f78377d4682f08dc1f72ce8fa11d3f`, followed by shared vectors and reviewed
proof inputs in `6f76501a3eb2f6fa286ce44c449e5905b37ba000`. Together they contain
the source and fixture bytes under current qualification. Focused acceptance includes
38-case four-language parser parity, 193 Python SDK cases, 199 adapter-base
cases, the complete Go HTTP package, 78 Node HTTP cases, 105 TypeScript
conformance cases and 42 AI SDK cases. No TypeScript case was skipped. The
conformance run exposed old HTTP mock receipts and a 48-case assertion against
the actual 72-case verdict corpus. The fixtures now model the complete
verification response, count verification calls, and deny untrusted verification
without reaching either application's route. These mock-sidecar tests do not
claim native cryptographic verification. The verdict test compares every unique
scenario identity as well as the reviewed 72-case count.

The formal mirror check initially reported the earlier retained-request
heap-ownership repair. Review against `PostAdmissionDropGuard.tla` established
that the four changed symbols alter private storage and decoding placement, not
canonical bytes, credential exclusion, request binding or modeled lifecycle
transitions. Only those four symbol hashes and their aggregate were refreshed.
All 225 mirror entries then matched. This is reviewed source binding, not a new
proof of serialization, caller custody or crash recovery.

Scope and acceptance requirements are in the
[M4 execution plan](m4-consumer-qualification.md). The
[support ledger](consumer-support.md) defines supported profiles and authority
owners; the [migration contract](m4-consumer-migration.md) records intentional
source and wire changes.

## Requirement-to-evidence map

This map links the expanded M4 requirements to completed local execution for
supported profiles in the consumer ledger. It closes M4's local acceptance,
not unsupported profiles or the separate release requirements.

| Requirement | Acceptance evidence |
| --- | --- |
| M4.0: composed baseline | Final full workspace configuration includes the original native nonce, MCP retained-profile and dependent proof-fixture regressions. |
| M4.1: complete consumer inventory | The calibrated adapter source contract accounts for 29 construction and 86 dispatch references; the support ledger additionally classifies P01-P10 portable, protocol, caller and operator-effect roots. |
| M4.2: construction and trusted context | Exact factory/early-launch denials, flow installation and authority-profile tests, public host positives, and workspace suites cover required stores, context, ordering and explicit ordinary/unsupported profiles. The readiness helper validates before child launch. |
| M4.3: negotiation and manifests | All 12 peer identities, the strict manifest inventory, signed registry/policy tests and portable denials preserve host-bound negotiation and reject missing, substituted or unnegotiated authority. |
| M4.4: protocol transformation and dispatch | Eight real durable native/MCP/A2A/ACP-Client cases cover aggregate and threshold profiles independently, one effect, signed receipts and restart; full provider, batch/stream and projection suites retain the shared authorization envelope. |
| M4.5: caller and native-host delivery | All 61 M3 identities, the full native-flow inventory and Python caller tests cover signed start/report, durable executor replay, original expiry and required native release/declassification custody. |
| M4.6: wire and FFI parity | The 38 protocol and 14 manifest vectors, actual Rust/Python/TypeScript/Go parser and serialization suites, four-language generation, binding lanes, browser checks and explicit C++/FFI/live/Drogon gates cover their advertised boundaries. |
| M4.7: executable coverage | The 45-case M4 gate, strict peer and SDK inventories, source contracts and isolated mutation calibrations require named tests and reject dropped, renamed, ignored or skipped required coverage. Proof-report readers bind the physical inventory and reject 85 calibrated source/inventory mutations each. |
| M4.8: composed closeout | The repaired-source gate table records the final workspace/build/Clippy, portable, fuzz-compilation, formal/source binding, formatting and hygiene results. Migration and support documents retain the M1 and M5-M11 boundaries; the documentation-only handoff records exact SCM state separately from hosted qualification. |

## Candidate and environment

- Current local verification source: `fdc70f6fce9b45df1f5586bb2789db009415c967`.
  Rust, SDK, schema, formal-model and dependency source match `8738bdfd7b`.
  The closeout commit changes only the five M4 status/support/acceptance
  documents. Its exact SHA, clean-tree state and local/remote/PR head comparison
  are recorded in draft PR #1117 and `/tmp/chio-m4-final-scm.log` after the push.
  Hosted checkpoint `6bb648b613b44ff5aaf1853768f2747bff166077` reached a terminal
  MSRV result before that push, preserving the observation below. Historical
  hosted successes do not qualify the documentation closeout head.
- The following implementation hashes describe the retained sequence, not
  alternate final candidates.
- M4 implementation: `348b7ae4c221e59cd4c867dd4a3a77c718dd7003`.
- Generator dependency correction: `4290972a7fea90503607295bc6b03842a2cd2152`.
  This changes only the generator lockfile's `js-yaml` package from 4.3.1 to
  4.3.2; the `json-schema-to-typescript` generator remains pinned to 15.0.4.
- Restart repair: `15ceaa7af313193430acd9c53767af45d26ab819`. Remote MCP restore
  re-derives its retained negotiated authorization through the same handshake
  helper, compares the exact authenticated profile, and never upgrades legacy
  sessions. Validation precedes upstream acquisition. Errors omit bearer session
  identifiers. The native caller fixture hands off promptly after signed start;
  production authorization, expiry and deadline checks are unchanged.
- Drogon runner prerequisites: `cfbeaced5b`; dependent proof fixtures:
  `edc60b0d66c28636898df4bf94c61c437ea24e9a`. Both are committed and pushed.
  Rust and protocol SDK source remain unchanged from the restart repair. These
  fixture and qualification-setup changes preceded the final workspace run.
- Threshold CI inventory correction: `dfde384719afe9c0ecc0c030c05c087092fa5fe8`,
  committed and pushed. This adds one existing regression to the required
  workflow list; it changes no Rust source or test command and does not
  invalidate the running workspace dependency closure.
- Durable lifecycle CI inventory reconciliation:
  `d4cb9646d40f3e1462d8ef6acb6144386f77fc89`, committed and pushed. Existing nonce,
  caller and cumulative-approval test lists now require 17, 33 and 9 identities.
  This also changes only workflow expectations, not Rust or qualification commands.
- Python/Docker qualification inputs:
  `740f359cccd65bfc829591e018ba64a31021edc9`, committed and pushed. This provisions
  the schema checker's Python dependencies, regenerates the Docker workspace
  lockfile and binds the security image to the reviewed current root lockfile.
  Rust source and the root lockfile remain unchanged.
- Branch: `security/launch-integration` in `/tmp/arc-security-launch`, carried in
  [draft PR #1117](https://github.com/bb-connor/arc/pull/1117). Earlier M1-M3
  checkpoints remain historical evidence, not the current source revision.
- Linux/aarch64, Rust 1.94.1, three Cargo build jobs, incremental compilation
  disabled, locked offline Cargo resolution. The shared target directory is
  `/tmp/chio-security-target.rHKDaO`.
- SDK tools: Python 3.11.15, Go 1.26.4, Node 24.16.0 and npm 11.19.0;
  CMake/CTest 3.28.3, GNU C++ 13.3.0 and cbindgen 0.29.2. TypeScript
  qualification uses the installed npm workspace. Bounded formal checks use
  Apalache 0.50.1; proof-report reader fixtures separately passed system Python
  3.13 and CI-compatible Python 3.12.3. Native Rust target:
  `aarch64-unknown-linux-gnu`; browser check: `wasm32-unknown-unknown`.
- `umask 022`; deliberate abort tests cannot produce core dumps. `RUST_MIN_STACK`
  is unset. The final workspace and exact milestone gates use one Rust test
  thread. Tests' explicit concurrency remains intact. This does not enlarge the
  default stack or any security deadline.
- Resolved workspace metadata and features are retained in
  `/tmp/chio-m4-final-workspace-metadata.json` and
  `/tmp/chio-m4-final-workspace-features.log`.
- When free disk space fell to 2.2 GB, Cargo cleaned only the separate unused
  `/tmp/chio-security-target.rHKDaO/kani` and `static-pie` build caches, reclaiming
  about 1.7 GiB. The running debug target, source, test data and evidence logs
  were untouched. These generated caches can be rebuilt; neither is selected
  by the remaining M4 qualification commands. The cleanup log is
  `/tmp/chio-m4-auxiliary-cache-cleanup.log`.

An earlier workspace run was interrupted after the caller corpus test source
changed, and the initial frozen-source run was interrupted before test execution
to select four test threads. Neither is reported as final workspace acceptance.
Cargo lock waiting contributes to command wall time; it is not test duration.

The four-thread workspace run was also stopped after its test binary became stale
following the native handoff repair. It had 2,454 passing tests and two MCP
ready-session startup failures across 134 completed result blocks, with 14 ignored
cases. Those startup failures preceded interruption and were real defects.
This interrupted run is not final workspace acceptance.

The native gate passed 33 caller/store, 9 executor-ledger and 18 of 19 native
custody cases. The failed combined-credential restart case reached the executor
outside its signed execution interval. The same-binary isolated rerun passed in
239.80 seconds; that rerun alone does not close the failure. The fixture now
provisions its independent executor before timed admission and performs unchanged
retained capture diagnostics after execution, before report reconciliation. No
execution deadline, signature check or late-execution rejection is relaxed.
The repaired exact four-profile restart case passed in 230.20 seconds
(`chio-m4-native-caller-restart-handoff-fix.log`). The complete final M3 gate then
passed all 61 cases, including the 19 native cases in 1,141.65 seconds
(`chio-m4-m3-qualified-final.log`).

The broader flow inventory subsequently failed the six-profile combined native
caller case. Its same-binary isolated rerun passed in 283.32 seconds
(`chio-m4-native-combined-profile-diagnostic.log`), and it passed in the complete
final M3 gate. The broader target finished with 132 passed and one failed in
4,254.61 seconds. Its captured error identifies the combined egress profile:
the caller authorization was outside its execution interval. The executor's
live checks precede the effect and retain the original nonce, capability and
native-custody bounds. No execution window or verification check is changed.
The final workspace run also passed this entire six-profile test and the
four-profile original-delivery restart/expiry test. The complete workspace test
command then passed. That workspace result did not substitute for the remaining
flow inventories or their selected feature profiles.

The full failed checkpoint and all subsequent flow inventories required a
serial rerun after the owned workspace qualification sequence. This prevented
overlap with our other heavy qualification jobs; it is not a claim of exclusive
access to the shared host. A 31-69 resume script was prepared but never executed.
The final review repair changes the kernel dependency closure, so the entire
`scripts/check-flow-security.sh` was rerun on the repaired source, including
all 69 inventories, bounded formal checks and portable checks. The first run's
30 successful inventories remain historical evidence only. Its failed native
caller case was not waived. The final repaired-source run passed all 69
inventories, 668 named cases and bounded formal/portable checks, as recorded below.

The MCP diagnostics exposed exact retained-profile re-validation failure, not a
slow server. The shared negotiation repair passed its new unit regression and
both public ready-session restart tests (70.01 seconds) in
`chio-m4-remote-restored-authorization-qualified.log` and
`chio-m4-mcp-ready-restart-fixed.log`. The final workspace run then passed the
whole HTTP MCP target: 43 passed, zero failed and one pre-existing ignored
TTL-restore race case. Both repaired restart cases passed in that target. The
complete workspace command subsequently passed as recorded below.

Exact-head hosted checks also found two stale dependent fixture groups: the
standalone selective-disclosure proof differed from the already verified package,
and the pheromone deposit still bound the previous workflow receipt. The repair
extracts the package's existing proof and uses the existing generator's
`--pheromone-package` command against that same committed package. The four-file
diff changes only 23 lines of dependent hashes and signatures. Transit policy,
trust windows, query results and negative controls are unchanged. The package is
not replaced with the generator's distinct static profile. Local proof-package,
pheromone-runtime and transit gates passed for this correction.

## Earlier-source completed local gates

This table preserves pre-review command results. References to final source in
these rows describe that earlier serial run, not the later `5a2d612573` repair.
Current repaired-source qualification is tracked separately below.

All rows in this section have terminal successful results. Artifact paths below
are relative to `/tmp/`; they are local retained logs, not hosted artifacts.

| Gate / command | Result | Evidence log |
| --- | --- | --- |
| `cargo build --workspace --locked --offline` | Final source passed in 6 minutes 20 seconds | `chio-m4-build-qualified-final.log` |
| `cargo clippy --workspace --all-targets --locked --offline -- -D warnings` | Final source passed with no lint waivers in 5 minutes 43 seconds | `chio-m4-clippy-qualified-final.log` |
| `bash scripts/check-consumer-boundaries.sh` | All 35 named Rust cases passed: 8 live, 13 filtered single cases, 2 whole single-test targets and 12 peer cases; source contracts passed | `chio-m4-consumer-qualified-final.log` |
| `bash scripts/check-authenticated-caller-delivery.sh` | All 61 passed: 33 caller lifecycle, 9 executor ledger and 19 native caller; no failures or ignored cases | `chio-m4-m3-qualified-final.log` |
| `cargo test --workspace --no-fail-fast --locked --offline` | Passed including documentation tests: 17,178 passed, zero failed, 48 existing ignores across 1,062 outer result blocks. One nested helper result is excluded from the total | `chio-m4-workspace-qualified-final.log`, `chio-m4-workspace-summary-qualified.log` |
| Full control-plane library in the final workspace configuration | 1,134 passed, zero failed/ignored at the default stack limit; 5,511.60 seconds. Includes the original nested-nonce regression and both previously failing native caller cases | `chio-m4-workspace-qualified-final.log` |
| Full SQLite library in the final workspace configuration | 1,653 passed, zero failed, three existing ignores; 3,088.23 seconds. Subsequent caller 33-case, cumulative 9-case and nonce 17-case integration targets also passed | `chio-m4-workspace-qualified-final.log` |
| Full pheromone-runtime suite after dependent fixture repair | 35 passed, including all five cases that failed against stale workflow evidence | `chio-m4-pheromone-dependent-fixture-tests.log` |
| `bash scripts/check-chio-proof-package.sh` after dependent fixture repair | 95 passed plus real CLI verification/authority issuance; one existing historical-schema case ignored, outside required M4 acceptance | `chio-m4-dependent-proof-gate.log` |
| `cargo xtask check fixtures transit` | 35 passed; generated pheromone fixtures match the committed workflow package | `chio-m4-dependent-transit-gate.log` |
| Drogon prerequisite contract and affected workflow lint | All four Linux bootstrap jobs provision UUID; contract and workflow syntax passed | `chio-m4-drogon-prerequisite-contract.log`, `chio-m4-uuid-workflow-lint.log` |
| Threshold CI inventory correction | The 11-name required list accepts the actual hosted list/run transcript; the old 10-name list still rejects it. Workflow lint and shared inventory calibrations passed | `chio-m4-threshold-ci-transcript-verification.log`, `chio-m4-threshold-ci-original-list-negative.log`, `chio-m4-threshold-ci-workflow-lint.log`, `chio-m4-threshold-ci-inventory-calibration.log` |
| Remaining durable lifecycle CI inventories | All six remaining non-PQ lists match the compiled test executables. Corrected 17-case nonce and 33-case caller lists also pass against actual successful transcripts; the 20 boot-signing identities match source, not local PQ runtime evidence | `chio-m4-ci-inventory-check.f9ncyx/`, `chio-m4-remaining-threshold-workflow-lint.log` |
| Python CI prerequisites and Docker inputs | Full security-CI contract and mutation suite passed, including eight new missing/skip/failure prerequisite mutations. Four Rust vector tests passed with exact Python pins in a clean Python 3.12 environment. Docker regeneration/check and context contracts passed | `chio-m4-python-prerequisite-contract.log`, `chio-m4-python-prerequisite-calibration.log`, `chio-m4-python-prerequisite-rust-regression.log`, `chio-m4-docker-workspace-regeneration.log`, `chio-m4-docker-context-regression.log` |
| `bash scripts/check-consumer-sdk-parity.sh` | 15 Python, 7 Go top-level and 19 TypeScript exact identities; all 35 protocol and 14 manifest vectors | `chio-m4-sdk35-final.log` |
| Full `chio-sdk-python` pytest suite | 193 passed, including generated caller models sent through the HTTP client | `chio-m4-python-full-caller-final.log` |
| Full `chio-adapter-base` pytest suite | 199 passed | `chio-m4-python-adapter-base-final.log` |
| Full Go HTTP SDK suite, fresh execution | Passed, including transactional caller decoders and explicit null preservation | `chio-m4-go-caller-wire-final.log` |
| Rust generated protocol and authoritative wire-schema targets | 1 generated-shape and 9 schema tests passed | `chio-m4-rust-caller-wire-final.log` |
| Public Node HTTP package suite | 73 passed; public validator export also rebuilt and exercised by the 35-vector SDK gate | `chio-m4-ts-public-export-tests.log` |
| TypeScript caller corpus and typecheck | Both passed | `chio-m4-ts-caller-corpus.log`, `chio-m4-ts-caller-typecheck.log` |
| `bash scripts/check-bindings-parity.sh` | Rust, Python, TypeScript and Go legacy binding lanes passed; not a v2 manifest support claim | `chio-m4-legacy-bindings-parity.log` |
| `bash scripts/check-chio-cpp.sh` | 19 Rust FFI tests, generated header, C ABI/symbol smoke, 2 CTest cases and installed external CMake consumer passed | `chio-m4-cpp-consumer-gate.log` |
| `bash sdks/cpp/chio-cpp-kernel/scripts/check-with-ffi.sh` | 23 Rust tests and 1 CTest case passed | `chio-m4-cpp-kernel-consumer-gate.log` |
| Live C++ protocol gate with `CHIO_CPP_LIVE_CONFORMANCE=1` | All five passed, zero failures/ignores: authentication, MCP core, nested callbacks, notifications and tasks; fresh CLI and real C++ peer | `chio-m4-cpp-live-qualified-final.log` |
| `bash scripts/check-chio-drogon.sh` | Final library and example CTest cases plus live allow/deny/receipt smoke passed against pinned dependencies and a fresh CLI | `chio-m4-drogon-qualified-final.log` |
| A2A and ACP-Client `compatibility-surface` library suites | 97 and 93 passed; this feature is not an enforced fallback | `chio-m4-compatibility-profiles-final.log` |
| Core no-default-features and browser wasm target checks | Both passed; not mobile hardware or confinement qualification | `chio-m4-portable-no-std-final.log`, `chio-m4-browser-wasm-final.log` |
| Full current fuzz-bin compilation inventory | All 28 bins compiled; not a fuzz campaign | `chio-m4-full-fuzz-inventory-check.log` |
| Exact consumer, SDK inventory, peer and Drogon wrapper calibrations | Required missing, renamed, ignored, zero-match and skipped cases cannot silently qualify | `chio-m4-consumer-wrapper-caller-final.log`, `chio-m4-sdk35-inventory-calibration.log`, `chio-m4-peer-wrapper-caller-final.log`, `chio-m4-drogon-wrapper-caller-final.log` |
| Source inventory discovery and file hygiene | 29 construction and 86 dispatch references accounted for; hygiene passed | `chio-m4-caller-provider-inventory-discovery.log`, `chio-m4-hygiene-frozen-candidate.log` |
| Flow wrapper inventory calibration | Passed with the actual 24-case manifest inventory and 69 named inventories | `chio-m4-flow-inventory-selftest-final.log` |
| Earlier `graphify update .` | Completed after the fixture corrections: 167,036 nodes, 435,455 edges, 7,089 communities; final refresh follows the CI prerequisite repair | `chio-m4-graphify-fixture-closeout.log` |
| `cargo xtask gen proof-coverage --check` | Final source: 58 rows and 168 artifacts match after reviewed source-input hash regeneration | `chio-m4-proof-coverage-qualified-final.log` |
| Final formatting and Rust file hygiene | Both passed, with no new lint or size exceptions | `chio-m4-format-qualified-final.log`, `chio-m4-hygiene-qualified-final.log` |
| `make codegen-check`, schema registry and security dependency gates | All four generated languages match; registry and dependency checks passed after the generator lockfile patch | `chio-m4-codegen-caller-final.log`, `chio-m4-schema-registry-caller-final.log`, `chio-m4-security-dependencies-caller-final.log` |
| `cargo test -p xtask --locked --offline` and `cargo fmt --all -- --check` | 180 unit, 14 integration and 1 parity test passed; formatting passed | `chio-m4-xtask-caller-qualified.log`, `chio-m4-format-caller-qualified.log` |
| Generator and public Node runtime dependency audits | Both report zero vulnerabilities in their audited dependency scope after the generator patch | `chio-m4-codegen-node-audit-patched.json`, `chio-m4-node-http-runtime-audit.json` |

## Repaired-source qualification

These are acceptance requirements, not optional follow-up work.

| Gate / command | Current boundary | Evidence log |
| --- | --- | --- |
| Operator readiness repair, `8738bdfd7be8c43a0543ca0ce468541529c47add` | Committed and pushed after 33 egress-feature, 7 exact CLI readiness and 7 exact public lifecycle cases passed. Strict affected all-target Clippy, formatting, hygiene, structural checks and gate calibrations passed with unchanged source hashes | `chio-m4-operator-readiness-driver.log`, `chio-m4-operator-readiness-source.sha256` |
| M4 exact Rust gate | All 45 identities passed on `8738bdfd7b`, including both earlier review regressions, the operator-readiness cases, eight live consumers and all 12 peers. Adapter and HTTP-egress structural gates passed | `chio-m4-operator-final-consumer.log` |
| M3 exact caller gate, 61 identities | All 61 passed on `8738bdfd7b`: 33 caller lifecycle, 9 durable executor and 19 native custody. Zero failures/ignores; native stage completed in 1,168.99 seconds | `chio-m4-operator-final-m3.log` |
| Flow security's 69 exact inventories | All 69 inventories and 668 named cases passed on `8738bdfd7b`, including all 133 native-flow cases with zero failures/ignores in 4,205.69 seconds. Bounded formal positive/negative and portable checks also passed; no stack or deadline override | `chio-m4-operator-final-flow.log`, `chio-m4-operator-final-exact-driver.log` |
| Full workspace tests | Passed: 17,187 tests, zero failures and 48 existing ignores across 1,062 outer targets. One nested helper result is excluded. The full 1,134-case control-plane target passed in 5,338.55 seconds; SQLite passed 1,653 cases with three existing ignores in 2,977.45 seconds | `chio-m4-post-review-workspace.log`, `chio-m4-post-review-workspace-summary.log` |
| Normal workspace build and strict all-target Clippy | Both passed: build in 6 minutes 41 seconds and strict all-target Clippy in 6 minutes 7 seconds; no lint waivers | `chio-m4-post-review-build.log`, `chio-m4-post-review-clippy.log` |
| Explicit compatibility profiles | Both production-library checks passed. Feature-enabled A2A edge tests: 97 passed; ACP-Client edge: 93 passed. Zero failures/ignores; no enforced fallback claim | `chio-m4-post-review-compatibility-a2a-build.log`, `chio-m4-post-review-compatibility-a2a.log`, `chio-m4-post-review-compatibility-acp-build.log`, `chio-m4-post-review-compatibility-acp.log` |
| C++ consumer and kernel FFI gates | Consumer: 19 Rust tests, generated header, ABI/symbol smoke, 2 CTest cases and installed external consumer passed. Kernel: 23 Rust tests and 1 CTest case passed | `chio-m4-post-review-cpp.log`, `chio-m4-post-review-cpp-kernel.log` |
| Explicit live C++ and pinned Drogon | All five live C++ protocol cases passed with zero ignores. Drogon library/example CTest and real allow/deny/receipt smoke passed with pinned dependencies and a fresh CLI; no optional skip | `chio-m4-post-review-cli.log`, `chio-m4-post-review-cpp-live.log`, `chio-m4-post-review-drogon.log` |
| Core no-default-features, browser WASM and fuzz inventory | Both portable checks and full fuzz-bin compilation passed. Compilation is not a fuzz campaign or mobile/confinement qualification | `chio-m4-post-review-portable.log`, `chio-m4-post-review-browser.log`, `chio-m4-post-review-fuzz.log` |
| Legacy binding parity | All configured binding lanes passed. Some Go results were cached; the separate unchanged SDK HTTP suite has fresh execution evidence | `chio-m4-post-review-bindings.log` |
| Current SDK parser gate | Passed: 15 Python, 8 Go and 19 TypeScript identities; 38 protocol and 14 manifest cases | `chio-m4-post-review-sdk-parity.log` |
| Node HTTP, TypeScript conformance and AI SDK full suites | Passed: 78, 105 and 42 cases; all three typechecks passed | `chio-m4-post-review-ts-full-final.log`, `chio-m4-post-review-ts-types-final.log` |
| Code generation and schema registry | Passed all four languages and exact registry inputs | `chio-m4-post-review-codegen.log`, `chio-m4-post-review-registry.log` |
| Exact wrapper and SDK inventory calibrations | Passed with both new required Rust regressions and the expanded corpus | `chio-m4-post-review-boundary-calibration.log`, `chio-m4-post-review-sdk-calibration.log` |
| Formal source binding and proof-coverage generation | Final checks passed: 225 entries match; 58 rows and 168 artifacts match the reviewed report. No additional regeneration needed | `chio-m4-post-review-formal-mirrors-final.log`, `chio-m4-post-review-proof-coverage-final.log` |
| Security dependencies, formatting and file hygiene | All passed after the full execution sequence; no new lint or size allowances | `chio-m4-post-review-security-dependencies.log`, `chio-m4-post-review-format.log`, `chio-m4-post-review-hygiene.log` |
| Final source graph refresh | Passed after the final CI-capacity/proof-reader repairs: 167,104 nodes, 435,562 edges and 7,025 communities across 16,391 files. AST-only source extraction; optional HTML omitted for graph size | `chio-m4-msrv-capacity-graph.log` |
| Final bounded MSRV budget | Exact CI contract and complete mutation suite passed, including four new reason-checked outer-budget mutations; independent review found no issue. No test/security deadline or command changed | `chio-m4-msrv-capacity-contract.log`, `chio-m4-msrv-capacity-green.log` |
| Final document claims and independent review | Release-truth check and positive/negative calibration passed. Read-only review found no material issue in the five-document diff, requirement closure or unchanged migration contract; not independent test execution or hosted approval | `chio-m4-final-reviewed-doc-release-truth.log`, `chio-m4-final-doc-release-truth-calibration.log` |

The readiness repair added Rust files after the earlier proof-coverage report was
generated. A direct check reproduced the stale input digest with exit 1
(`chio-m4-operator-proof-coverage-red.log`). Regeneration changed exactly two
lines in `docs/formal/COVERAGE.md`: the Rust-file inventory hash and aggregate
input digest. The reviewed diff changes no proof rows, artifacts, model inputs
or lane postures. Both coverage and all 225 formal source bindings then passed.
The composed closeout driver repeated these checks successfully after workspace
qualification.

The first repaired-source driver completed workspace tests, build and strict
all-target Clippy, then exited 101 on a local command-selection error:
`chio-a2a-adapter` has no `compatibility-surface` feature. Its diagnostic is
retained in `chio-m4-compatibility-owner-red.log`. The manifests and feature-gated
exports identify `chio-a2a-edge` and `chio-acp-edge` as the actual compatibility
owners. No repository feature, source file or assertion was changed to accept
the incorrect command. The resumed driver ran a production-library `cargo check`
and `cargo test --lib` for each edge with `--features compatibility-surface`,
followed by every remaining original gate. It records each successful exit in
`chio-m4-post-review-remaining-closeout-driver.log` and itself exited zero with
`Post-review remaining qualification passed`. The original driver is not
reported as an entirely successful command. These checks supplement, rather
than replace, the default-profile adapter and edge suites in the full workspace.

`99171c38be62b89d949ee16a79eb39130b87d673` additionally fixes the hosted
log-redaction gate's false rejection of the fully qualified
`chio_log_redact::redacted!` macro. The accepted namespace is explicit, not a
wildcard. The real gate and 26 isolated positive/negative scope cases passed,
including a raw sensitive field beside a correctly redacted field. The
calibration runs in the existing CI structural lane. Runtime logging and the
Rust/SDK/fixture bytes under qualification are unchanged. The final graph refresh
also passed after this checker change.

The next exact-head hosted structural check exposed a real uncovered HTTP
consumer: the supervisor readiness probe used a raw reqwest client and dispatch.
The old executable also started the child for an invalid `file://` readiness
target, reproduced in `/tmp/chio-m4-readiness-red.8gdljP/command.log` with a
child-created marker. The repair prepares an immutable request/client/contract
before service launch, pins the operator's scheme and authority, disables
redirects and proxies, and caps both declared and streamed responses at 64 KiB.
Local or private service addresses must remain an explicit operator choice, not
request-supplied tool authority. Invalid URLs or bearer headers reject before
launch. The unchanged egress structural gate and its mutation suite pass
(`chio-m4-readiness-egress-structural.log`,
`chio-m4-readiness-egress-calibration.log`). The seven readiness unit cases
passed, including five new cases covering all five redirect statuses on
same/cross origins, exact/oversized body bounds, normalized targets and invalid
headers (`chio-m4-readiness-unit.log`). All seven public CLI lifecycle cases
also passed, including zero child launches on invalid configuration
(`chio-m4-readiness-integration.log`).
Those six regressions and the existing HTTP positive control are enrolled in the
exact M4 gate. Its expanded 44-case inventory calibration passed in
`chio-m4-readiness-boundary-calibration.log`. Independent review then identified
two gaps that these initial tests do not cover: the reused tenant egress
contract rejects operator-selected private IPv4 addresses, and its synchronous
DNS preflight is outside the reqwest timeout. Both failed in dedicated unit
regressions before correction (`chio-m4-readiness-private-unit-red.log`,
`chio-m4-readiness-dns-unit-red.log`). The compiled CLI also rejected the private
address before child launch (`chio-m4-readiness-private-red.GwNHgs/command.log`).
The user approved a distinct immutable operator-readiness GET helper, without
changes to serialized agent egress policy or lint exceptions.

`OperatorReadinessProbe` is now implemented in `chio-egress-contract`, with
private request/client fields, asynchronous DNS under the request deadline,
operator-selected private targets, no redirects/proxies and a streamed 64 KiB
limit. CLI supervision delegates to it. The DNS regression moved alongside the
helper to inject a pending resolver through its private production builder;
there is no runtime client/resolver override API. All 33 egress feature tests
passed, including the pending-resolver deadline and existing tenant
private-network denials (`chio-m4-operator-readiness-egress.log`). The private
address regression replaces the old internal-contract representation assertion
at the CLI boundary; redirect/response/invalid-input behavior remains tested.
The required M4 inventory is now 45 cases. Refreshed CLI acceptance and strict
affected Clippy passed; the full M4/composed gates subsequently passed. The first
focused Clippy run also caught an unchecked read
length in the test responder; it now handles EOF without a lint allowance.

The independent read-only review of the M4 planning baseline through committed
`99171c38be62b89d949ee16a79eb39130b87d673`, plus the uncommitted readiness
repair, is retained in `/tmp/chio-m4-closeout-review.EQ1yYO/review.md`. It
identified the two readiness findings above and no additional verified defect
in the sampled committed changes. The reviewer did not run tests, audit every
generated artifact or certify hosted CI, so this is not complete independent
verification or merge approval.

The targeted follow-up in
`/tmp/chio-m4-closeout-review.EQ1yYO/readiness-followup.md` found both readiness
defects corrected in source and no new blocking finding. It also verified the
locked reqwest total timeout continues through body polling. Its two stale
documentation references were corrected to name the separate operator profile.
This source review does not replace the separate behavioral qualification.

The final readiness repair adds the dedicated egress helper and wires CLI
supervision to it. Existing tenant egress functions and serialized contracts
are unchanged; the egress library root adds only the gated module and exports.
Full workspace, affected consumer acceptance and source/formal checks include
the new helper and passed. Its exact M4/M3 gates also passed; the final graph
refresh additionally includes the CI and proof-report reader repairs. Previous
graph results remain historical evidence.

During qualification, Cargo removed 380 reproducible `chio-fuzz` build artifacts
from the task-owned `/tmp/chio-security-target.rHKDaO/debug` cache after an
explicit package-scoped dry run. Source, fixtures, evidence logs and other
worktrees were preserved. The required fuzz-bin check subsequently rebuilt its
needed artifacts and passed.

The proof gate's pre-existing ignored case is
`tests::historical_v1_trust_bundle_is_not_strict_verifier_input`; its recorded
reason is that v1 is now the strict schema rather than a historical one. This is
not a newly ignored regression or a substitute for an M4 case.

### Existing workspace ignores

The current completed workspace profile records 48 ignored declarations: 39
library or integration declarations and nine documentation examples. The exact
target/name/reason inventory matches the earlier profile after normalizing only
compiled binary hashes. No required M4 case is ignored.
Comparing Rust changes against planning baseline
`3d0f5a0685a84907366705e4b040b47a605f1888` found no added `#[ignore]` attributes
or ignored documentation blocks. These declarations are not silently promoted
to passing acceptance cases.

| Existing category | Count | Boundary |
| --- | --- | --- |
| Child-process helper declarations | 3 | Invoked by their owning process-boundary tests where applicable, not independent acceptance |
| Fixture regenerators / rebless helpers | 14 | The checked-in corpora and their actual verification gates remain authoritative |
| Historical schema case | 1 | The strict v1 contract is described above |
| Timing, slow, retention and million-receipt scale cases | 7 | Includes the existing MCP TTL race, cluster/market timing cases and retention issue #1045; no new deferral or scale claim |
| Separate opt-in / external integration profiles | 14 | Guard-platform/Zot, live legacy encoders, deterministic sweeps, cross-version fetch/matrix and six TS guard component cases |
| Documentation examples | 9 | Existing ignored examples, not executable acceptance |

Exact enclosing targets, test names and recorded reasons are retained in
`/tmp/chio-m4-post-review-workspace-ignored.log`; the normalized comparison is
`/tmp/chio-m4-post-review-workspace-ignored-comparison.log`. The full workspace log retains
all declarations and terminal results. The current four-language M4 corpus,
M3 caller gate and explicitly enabled C++/Drogon gates are separate required
evidence; these existing ignores do not replace or weaken them.

The Drogon gate uses actual pinned dependencies, not the optional-dependency skip
path. `scripts/setup-drogon-test-deps.sh` also passed against its exact Drogon,
Trantor and jsoncpp pins. C++ live protocol tests are explicitly enabled because
the ordinary workspace test profile alone does not establish live peer coverage.
The live Drogon artifacts are retained under
`examples/hello-drogon/.artifacts/20260914T140515Z/`. The earlier
`20260914T020826Z/` run remains historical evidence. Final formal coverage checks
match the reviewed report; the proof rows, artifact inventory, lane postures and
limitations are unchanged.

## Hosted status observed during qualification

### Serial-profile checkpoint and proof-report compatibility

The serial-fixture CI repair is committed as
`2b3071e26cf94098beccafea1faf5b5a4772e736`; its documentation checkpoint is
`6bb648b613b44ff5aaf1853768f2747bff166077`. Local, remote and draft PR heads
matched at that push. Attempt 1 on the latter source passed
[SDK Parity](https://github.com/bb-connor/arc/actions/runs/34831061460), both jobs;
[C++ SDK](https://github.com/bb-connor/arc/actions/runs/34831061797), all eight jobs;
and [threshold/FIPS](https://github.com/bb-connor/arc/actions/runs/34831061655),
all three jobs. These observations do not qualify later commits or close the
separate release requirements below.

The [MSRV workspace job](https://github.com/bb-connor/arc/actions/runs/34831061957/job/103934272945)
completed on 2026-09-14 at 14:59:09 UTC with GitHub conclusion `cancelled`.
Its annotation explicitly identifies the maximum four-hour execution limit,
not a cancellation caused by another push. The full control-plane library
passed 1,134 tests with zero failures/ignores in 4,134.14 seconds. All 17
previously failed identities passed on this exact hosted source. The retained
log contains no failed test result or failed test identity before cancellation.
The SQLite library was incomplete, and the subsequent formal-diff compilation
and WASM library commands did not run. This is not a passing workspace lane or
acceptance of its unexecuted remainder.

Evidence is retained in `chio-m4-6bb-msrv-final.log`,
`chio-m4-6bb-msrv-final-annotations.json` and
`chio-m4-6bb-msrv-regressions.log`. The CI capacity correction changes only the
outer MSRV limit from 240 to 360 minutes, matching the existing main-workspace
failsafe. Commands, feature sets, serial fixture selection, explicit races,
test assertions and all production authorization deadlines are unchanged.
The checker pins the exact bounded value; isolated mutations require rejection
of its removal, shortening, enlargement or dynamic selection. The new live-budget
regression failed against the four-hour configuration
(`chio-m4-msrv-capacity-red.log`). The real contract and complete mutation suite
then passed (`chio-m4-msrv-capacity-contract.log`,
`chio-m4-msrv-capacity-green.log`), followed by source graph refresh. The repair
is committed as `fdc70f6fce9b45df1f5586bb2789db009415c967`.
Independent review found no issue, while noting that the complete six-hour hosted
lane must still pass. This is a capacity
adjustment, not evidence that six hours will suffice or a waiver of M10's
exact-candidate MSRV requirement.

That source's main CI
[build job](https://github.com/bb-connor/arc/actions/runs/34831061957/job/103934272852)
passed the exact security-CI contract and its complete mutation suite, then
failed the proof-report content fixture. Both proof-report readers still
required the old four-field adapter inventory, while M4's closed inventory also
requires `constructor_sites` and `dispatch_sites`. The unchanged fixture
reproduced the exact schema mismatch locally
(`chio-m4-proof-report-inventory-red.log`). Compilation and workspace tests in
that build job did not run.

The repair is locally committed as
`f1b88451527b2dec7314114b3b1e91cf101312cf`. Both readers now validate the six
inventory fields and closed site records, include every inventoried physical
source, bind both child validator modules, and hash the constructor scanner's
Rust/fragment candidate set. Conservatively hashing regular files below adapter
roots and contract-source parents includes literal descendant fragments even
with arbitrary extensions or test-named paths. Source symlinks deny. This binds
the input closure without replacing the Rust AST validator or changing the
report's trusted-generator, metadata-only and no-proof-replay boundaries.

The isolated content fixture passed under Python 3.13 and CI's Python 3.12,
including 85 negative cases per reader, exact intended denial reasons, reader
AST equality, physical source/validator tampering, descendant include closure
and a newly introduced unlisted candidate. Follow-up independent review found
no remaining defect after fixing a test-quality issue: unrelated symlinks must
not mask malformed inventory acceptance. Each link now exists only for its own
case. Logs are `chio-m4-proof-report-review-green.log` and
`chio-m4-proof-report-python312-full-green.log`. An initial Python 3.12 invocation
removed Rust from `PATH` and failed its tool-version probe; restoring the normal
tool paths produced the complete passing run. No assertion was relaxed.

The four structural commands following that fixture in CI also passed locally:
lane-gate calibration, liability-roster enforcement and its calibration, and the
off-chain broadcast boundary. Their logs use the `chio-m4-post-proof-` prefix.
Only three verification scripts changed in this repair. Rust, SDK, schema,
formal-model and dependency source remain identical to the readiness commit.
The compiled Rust dependency records contain none of the changed verification
scripts or CI workflow (`chio-m4-verification-script-rust-dep-info.log`); those
edits do not invalidate the binaries in the completed workspace test command.
The repair's push was held until the current MSRV job reached a terminal result,
so a new push did not cancel the serial-profile observation. This is not hosted
acceptance of the repair. Final source checks and the verification-script graph
refresh passed after the timing-sensitive workspace qualification.

### Readiness-source observations

Readiness source `8738bdfd7be8c43a0543ca0ce468541529c47add` was pushed
on draft PR #1117, with local, remote and PR heads matched at observation.
[SDK Parity](https://github.com/bb-connor/arc/actions/runs/34811945959) passed
on that exact head, including both the parity-contract and sidecar-control
authority jobs. Its
[cargo-vet run](https://github.com/bb-connor/arc/actions/runs/34811945865)
again reports 22 dependencies missing `safe-to-deploy` audits and exits 255
(`chio-m4-8738-cargo-vet-failure.log`). The
[enterprise controller](https://github.com/bb-connor/arc/actions/runs/34811943914)
fails during exact source/controller authorization
(`chio-m4-8738-enterprise-controller-failure.log`). Neither failure is waived,
and no audit or controller pin was changed. The main CI
[build job](https://github.com/bb-connor/arc/actions/runs/34811946216/job/103878752144)
passed the operator-readiness HTTP egress source check and its mutation suite,
then failed release-truth validation because security documentation used
ambiguous protocol names. The same failure reproduced locally. The documentation
now names ACP-Client explicitly, and the unchanged release-truth check passes
(`chio-m4-doc-release-truth-red.log`, `chio-m4-doc-release-truth-green.log`).
This correction does not change the Rust source under qualification. Hosted
compilation and workspace tests in that job were skipped, not passed. Other
candidate hosted checks remain under observation; this is not a terminal
exact-head CI qualification.

The same source's [MSRV job](https://github.com/bb-connor/arc/actions/runs/34811946216/job/103878752255)
built successfully, then failed the full control-plane library: 1,117 passed and
17 failed, with no ignores. The failed log is retained in
`chio-m4-8738-msrv-failure.log`. Nine process-recovery failures explicitly report
expired authentication before their required crash cutpoint. Non-disclosure
fixtures use a real 10-second flow fence; disclosure fixtures use 60 seconds.
The other eight failures expose generic capture or handoff denials, not enough
diagnostic evidence to attribute every failure to contention. All 17 identities
passed in the separate 133-case serial native-flow gate on the same Rust source;
that local success does not qualify hosted x86 execution.

CI previously serialized Cargo compilation but allowed libtest to overlap these
fixtures. The committed flow gate and M4 local recipe already require one test
thread. The workspace, MSRV and promoted-market CI steps now explicitly select
that same serial-fixture profile. Their exact environments and commands are
ratcheted by the CI contract, including mutations that remove the pin, change it
to two threads, make it dynamic or override it in the command. The initial new
regression failed because the workspace thread pin was absent
(`chio-m4-ci-fixture-profile-red.log`). This changes qualification configuration,
not Rust behavior: every test, security deadline, assertion and explicit
thread/process race remains intact. Independent review found the local full and
MSRV-excluded workspace profiles resolve identical package/feature sets, but
their executed target inventories still differ. The hosted serial-profile
rerun subsequently passed the full control-plane library and all 17 earlier
failures, as recorded above. It exhausted its outer job budget during SQLite,
so the complete MSRV lane remains required. No unrestricted parallel-fixture
guarantee is inferred.

The complete local CI contract and mutation suite passed after the profile
repair (`chio-m4-ci-fixture-profile-contract.log`,
`chio-m4-ci-fixture-profile-green.log`), as did release-truth validation and diff
hygiene. An additional actionlint 1.7.7 check reports the same unrecognized
`artifact-metadata` permission on the unchanged and repaired workflow; this is
not reported as passing lint or repaired by changing trusted permissions. The
AST-only graph refresh passed after the completed timing-sensitive workspace
tests, as required by the qualification recipe. Rust, SDK, schema, formal model
and dependency source remain unchanged from the readiness commit.

Attempt 1 of the same source's
[C++ workflow](https://github.com/bb-connor/arc/actions/runs/34811945780)
passed all eight jobs: sanitizers, macOS/Windows/Linux CMake packages, Conan/vcpkg,
Drogon, live C++ conformance and guard/kernel packages. Attempt 1 of
[the threshold/FIPS workflow](https://github.com/bb-connor/arc/actions/runs/34811945743)
also passed all three jobs: FIPS smoke, kernel-owned session reports and the
threshold approval crypto floor. These are exact-source hosted observations,
not closure of the separately recorded M10 compiler, locked-command or aggregate
release-qualification requirements.

The same source's
[CVE monitor](https://github.com/bb-connor/arc/actions/runs/34811945802)
passed its configured Rust advisory scan but failed OSV validation of the Bun
and TypeScript lockfiles. The retained artifact in
`/tmp/chio-m4-8738-cve.43lSmi/` reports five distinct advisory IDs across sharp,
Vitest/mocker, js-yaml and Next.js. The narrower generator-only and public Node
runtime audit results do not negate these findings. Their M10 release blocker
remains open; no advisory exception or dependency change was added during this
final-source qualification.

On `99171c38be62b89d949ee16a79eb39130b87d673`, attempt 1 of
[SDK Parity](https://github.com/bb-connor/arc/actions/runs/34802398700) passed.
The main CI [build job](https://github.com/bb-connor/arc/actions/runs/34802398953/job/103847930603)
passed the repaired log-redaction gate and its calibration, then failed the HTTP
egress source check on supervisor readiness. Compilation and workspace tests in
that job were skipped. This observation drove the final readiness repair above;
it is not an accepted structural waiver. The job log is
`chio-m4-991-build-failure.log`.

The same head's
[hosted cognition-market run](https://github.com/bb-connor/arc/actions/runs/34802398636)
passed its recorded four-language codegen, release-evidence tests and cargo-deny
checks, then stopped at cargo-vet with 22 dependencies missing `safe-to-deploy`
audits. Its failure is retained in `chio-m4-991-hosted-market-failure.log`.
No audit was fabricated or supply-chain check bypassed. This is an outstanding
release-qualification gate, not evidence of public hosted activation. These
observations must be refreshed after the final source and documentation push.

After the repair push, PR #1117's head matched
`edc60b0d66c28636898df4bf94c61c437ea24e9a`. On that exact source, attempt 1 of
[SDK Parity](https://github.com/bb-connor/arc/actions/runs/34780519817),
[Chio Proof Package](https://github.com/bb-connor/arc/actions/runs/34780519866),
[Chio Pheromone Runtime](https://github.com/bb-connor/arc/actions/runs/34780519811)
and [Chio Pheromone Transit](https://github.com/bb-connor/arc/actions/runs/34780519738)
completed successfully. The
[Drogon package job](https://github.com/bb-connor/arc/actions/runs/34780519863/job/103786574314)
also passed, followed by both complete C++ workflows, the
[PR lane](https://github.com/bb-connor/arc/actions/runs/34780519863) and
[push lane](https://github.com/bb-connor/arc/actions/runs/34780515833), on attempt 1.
These are
verified observations of this source, not all-PR success or exact-head
qualification for a later closeout commit.

The same head's threshold reservation job passed all 11 actual tests, but its
strict inventory rejected the extra
`oversized_threshold_proposal_is_not_an_absent_nonce_approval` identity. The
workflow's expected list omitted that existing regression. The correction adds
it to the required inventory without changing the test, command or strict
verifier. The corrected list passes against the actual hosted transcript; the
old list still fails. This validates the inventory repair but does not rerun the
hosted job. The original
[run](https://github.com/bb-connor/arc/actions/runs/34780519960) remains failed and
its subsequent skipped steps are not qualification evidence.

The next [run](https://github.com/bb-connor/arc/actions/runs/34784638168), on
`dfde384719afe9c0ecc0c030c05c087092fa5fe8` attempt 1, passed the repaired threshold
inventory, original-request retention and collector restart. It then passed all
17 nonce-lifecycle tests but rejected two existing security-identity restart
tests missing from its expected list. The remaining steps were inspected before
repair: caller and cumulative-approval lists also retained pre-M3 sizes, while
remote delivery, session ownership, signing forwarding and boot-signing names
matched. The correction adds all missing identities, preserves the full targets
and strict verifier, and changes no test command. This run's FIPS smoke and
kernel-owned session-report jobs passed; the overall workflow remained failed.
The subsequent [run](https://github.com/bb-connor/arc/actions/runs/34786650023) on
`d4cb9646d40f3e1462d8ef6acb6144386f77fc89` completed successfully: threshold
qualification, FIPS smoke and kernel-owned session reports all passed. This
closes the observed inventory failures on that source, including subsequent
caller, cumulative-approval and PQ-enabled boot-signing steps; it does not imply
all-PR success or qualification of a later closeout commit.

The main [CI run](https://github.com/bb-connor/arc/actions/runs/34786650176) on
that same head subsequently completed with failures. Its structural step found
one missing `chio-cross-protocol` edge in the generated Docker workspace lockfile;
the existing generator reproduced exactly that one-line repair and its `--check`
then passed. The MSRV lane built successfully but failed the generated security
vector target because the Python schema checker could not import `referencing`.
Both workspace jobs now explicitly provision the existing schema-checker version
`jsonschema==4.26.0` and `referencing==0.37.0`, alongside pinned PyYAML, before their
consumers. The Rust four-case target passes using a clean Python 3.12 environment
with those exact pins, including 86 positive and 259 negative semantic vectors.
This local reproduction is not a terminal rerun of hosted MSRV.

The security image's lockfile digest also retained the planning baseline. Review
of the full baseline-to-current root lockfile diff found exactly two added
internal dependency edges: conformance to cross-protocol, and reference tools to
core types. No third-party version or checksum changed. The image and its contract
checker now bind the actual root lockfile digest
`a4e631319b00c54f2cbc6457ad0149198a4a367db8dec060fcce376c98728b49`.
This does not change the protected controller pin, image base or authorization.
Evidence is in `chio-m4-docker-workspace-regeneration.log`,
`chio-m4-python-prerequisite-environment.log` and
`chio-m4-python-prerequisite-rust-regression.log`.

Installed actionlint 1.7.7 rejects the workflow's existing `artifact-metadata`
permission on both the unmodified pushed workflow and this repair, with the same
single diagnostic. No permission was removed to satisfy that older checker.
The exact Python security-CI contract and its complete mutation calibration pass.
Logs are `chio-m4-ci-actionlint-baseline.log`,
`chio-m4-python-prerequisite-workflow-lint.log` and
`chio-m4-python-prerequisite-contract.log`.

The preceding head `15ceaa7af313193430acd9c53767af45d26ab819` exposed the
following failures, retained as historical evidence:

- Proof-package, pheromone-runtime, relay and transit failures exposed the
  dependent fixture mismatch described above. Local proof/runtime/transit gates
  and the exact-head hosted workflows above now pass after the repair.
- The SDK parity lane failed because the pinned Drogon build lacked UUID headers.
  Every existing Linux bootstrap lane now installs `uuid-dev`, including both C++
  package jobs and the existing release workflow. Workflow lint and the calibrated
  prerequisite contract pass, as do the subsequent hosted SDK and Drogon jobs.
  No release workflow was dispatched.
- The enterprise controller rejected source/controller authorization; its
  downstream capture was not qualification. No controller pin or authorization
  check was changed.
- `cargo-vet` lacked required `safe-to-deploy` audits. Rust's advisory scan passed,
  while OSV reported advisories in the existing Bun and TypeScript development
  dependency closures. The generator-only and public Node runtime audits in the
  local table cover narrower scopes and do not negate these failures. Full
  supply-chain and exact-candidate hosted closure remain M10 requirements, not
  waived checks or claims that the PR is merge-ready.

Hosted logs are retained as `/tmp/chio-m4-ci-<run-id>-failed.log`; the advisory
artifact from run `34779120186` is in
`/tmp/chio-m4-ci-advisories.iXni1u/`. Final handoff must refresh the actual PR head
and terminal hosted status rather than reuse this observation.

## PR review disposition

The read-only PR review snapshot contained 12 unresolved threads. This report
does not resolve those threads or claim reviewer approval. Each finding is
reconciled against the accepted milestone contract:

| Finding | Disposition and owner |
| --- | --- |
| Retained attachment limit rejects a complete caller operation | Reproduced and repaired in `5a2d612573`; normal append, persistence round-trip and duplicate-negative regression required by M4 |
| Native internal receipt origin omitted from wire enums | Reproduced and repaired in the same commit across authoritative schemas, generated languages and runtime consumers; signed-origin and invalid-origin regressions required by M4 |
| Classification regex zero-width behavior, JSON-pointer construction and regex complexity (three threads) | Open M7 structured-classifier qualification work. The future `StructuredClassifier` is not the installed M4 native `ClassificationPort`; runtime invalid locations deny. No zero-width skip or weaker classification behavior was introduced to close M4 |
| Make every kernel default to `SecurityPreDispatchPolicy::Enforce` | Not applied globally: M4 explicitly retains ordinary, Disabled, Shadow and Enforce profiles. The trusted native factory owns required installation; ordinary factories reject flow-required manifests before launch/store acquisition. An ordinary constructor is not advertised as an enforced native host |
| FIPS compiler selection, unlocked smoke commands and release aggregation (three threads) | Open M10 exact-candidate qualification requirements. Repository toolchain selection still applies to Cargo; successful named FIPS jobs are not proof of locked, aggregate release qualification |
| Enterprise bootstrap should bypass missing verified Linux evidence | No bypass applied. Missing authoritative Linux evidence or exact controller/source binding remains a release blocker; bootstrap output cannot qualify an enforced profile |
| Document authenticated caller wire schemas | Already addressed by M3 in `spec/PROTOCOL.md`; both signed schema domains are generated and exercised in the current shared caller corpus |
| Require an approval/DPoP ledger whenever its authority is configured | Not applied as suggested. M4 explicitly distinguishes configured selection from credential use. `run_pre_budget_admission` selects approval when a token is used and DPoP when the grant requires it; dispatch verifies the exact owned claims. Caller decode compares the frozen episode snapshot with physical history. Runtime admission has different activation semantics. Optional unused credential families must not manufacture claim episodes |

The two repaired findings passed current-source exact and composed acceptance.
The M7 and M10 entries remain open in their owning milestones; they are not
waivers of a required M4 consumer profile or authorization to activate a release.

## Security and evidence boundaries

- Each of native, MCP, A2A and ACP-Client has a live aggregate-budget case and a separate
  cumulative threshold-approval case. Real durable stores, signed manifests,
  verified receipts and counted connectors establish one effect and one physical
  capture across restart. This does not qualify joint aggregate/cumulative roots.
- Signed caller authorization and delivery artifacts are represented in the
  38-vector wire corpus. Illustrative wire signatures are not cryptographic
  acceptance evidence; M3's real signed caller and native custody gate owns that
  claim. Required report output and cost nulls survive generated-model HTTP use.
- Schema and transport support in another language does not move release-owner,
  declassification, executor signing or durable custody authority out of the
  trusted Rust host. Reservation is never permission to execute.
- Go custom-decoder size limits apply to the JSON value after `encoding/json`
  removes surrounding whitespace. Hosts must separately bound the complete
  transport body; a decoder limit is not an HTTP request-size limit.
- Ordinary wrappers, legacy profiles, unsigned discovery and provider projections
  cannot negotiate themselves into stronger authority. Required unsupported
  features deny before their forbidden acquisition or effect.
- The source inventory is a finite AST contract, not a semantic proof of every
  network effect. Formal source-hash freshness does not prove new adapter or
  caller semantics. The existing bounded model and its deliberate mutant remain
  separate evidence.
- The generator-only `js-yaml` correction addresses
  [GHSA-2883-xcg3-v3hh](https://github.com/advisories/GHSA-2883-xcg3-v3hh).
  Passing these two npm audits is not a workspace-wide security audit or release
  qualification.
- M1's user-approved Linux x86_64 confinement deferral remains explicit. Local
  Linux/aarch64, portable builds and C++ smoke tests do not establish that profile,
  mobile hardware, an enterprise deployment or hosted production.
- No merge, package publication, operator migration, protected-controller repin,
  manual hosted dispatch or public activation is authorized by M4 acceptance.
  Exact-head hosted CI and M5-M11 retain their own acceptance requirements.
