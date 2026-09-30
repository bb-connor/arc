# Native consumers, ACP clocks/errors and OpenAPI execution

Source base: `cacaf69fc9d4b709ebe30fd9c549fc0eeffc12f9` on
`packet/3-retention-accounting`, `/tmp/arc-security-launch`.
The [plan](../superpowers/plans/2026-09-29-native-consumers-acp-errors-openapi.md)
has three completed owner tasks and one partially completed native-consumer
task. This record does not establish hosted, release or M5 acceptance.

## Task outcomes

| Task | State | Delivered boundary |
| --- | --- | --- |
| 1. Native consumers and mini-SWE transport | Partial | Restored OCI x86_64 qualification, repaired actual native discovery and recovery failures, and added explicit broker provisioning inputs. Full mini-SWE Docker/model transport remains open. |
| 2. ACP clocks | Complete | Shared fenced clock for audit logging, kernel receipt signing and compliance generation; checked timestamps and sequences; clock faults do not consume authorization custody. |
| 3. ACP and remote MCP errors | Complete for these owners | Typed semantic failures, retained local native sources, registered redacted diagnostics, and deferred task/receipt completion propagation. |
| 4. OpenAPI ingress | Complete | Bounded original bytes, duplicate-aware JSON/YAML decoding, local decoder causes, bridge/fuzz migration and production conformance callers. |

### ACP authority and errors

`AcpClock` owns the configured clock and one shared observation fence. Clones
serialize reads through that fence. Audit logging, receipt signing and compliance
generation reject clock failure, rollback, malformed/future audit time, time
overflow and sequence overflow. Signing validates these inputs before consuming
authorization or storing a receipt. Restart coverage rejects future persisted
audit evidence with a fresh owner; it does not claim a persisted global clock
high-water mark.

ACP edge request/transition errors and proxy receipt/authorization rejections
have domain variants. Deferred failures retain their original error owner and
do not redispatch. Required receipt-signing errors propagate; checkpoint health
retains its local typed error even when a receipt was already committed.
`RegisteredSourceError` carries downcastable native causes through CLI certificate
generation while its report, display and debug output use redacted registry
metadata.

Remote MCP OAuth and sender constraints retain native header, key-decoding,
canonical, clock and replay causes. Wire responses expose finite registered
codes. Original proof/header bounds precede decoding and replay consumption.
`SenderConstraintVerifier` groups the configured clock, replay owner and proof
policy without adding compatibility entry points.

### Original OpenAPI input

OpenAPI accepts original bytes with an 8 MiB limit before whitespace processing
or UTF-8 decoding. JSON rejects duplicate fields without losing integer
precision. YAML rejects duplicate/non-string map keys, nonfinite values and
multiple documents, with a depth limit of 64, 100,000 nodes and an 8 MiB expanded
string budget, including repeated aliases. The bridge, raw-byte fuzz caller and
actual conformance callers use this boundary. Typed `from_value` remains a
programmatic constructor; it cannot recover information already lost by a caller.

### Native qualification and repairs

The user authorized OCI provisioning through the Mac CLI. The retained x86_64
boot volume was restored as `chio-security-qualification-20260929`, an E4 Flex
worker with 8 OCPU and 64 GiB RAM. Its retained independent anchor volume is
mounted at `/mnt/chio-anchor`; neither volume was formatted. Tests ran as the
non-root operator except for the explicitly privileged discovery probe.

The worker initially remained running because the Mac hosting the OCI CLI went
offline on Tailscale before the stop command could execute. After the Mac
reconnected, both retained filesystems and the qualification checkout were
verified, and OCI confirmed `STOPPED`. The boot/anchor volumes, build cache and
evidence remain retained. `worker.json` records the terminal state and restart
instructions; the failed attempt and successful shutdown have separate logs.

The actual campaigns exposed and repaired these boundaries:

- The helper must be static musl and installed mode 0755. Group-writable cache
  output and the dynamically linked helper were refused as intended.
- The discovery fixture now explicitly allows a reviewed 64 MiB runtime
  artifact size. Its original 10-second identity observation and 20-second
  deadline checks remain. Profiling found debug SHA intrinsics dominating full
  executable authentication, so only the development/test `sha2` dependency is
  optimized. No release-profile or deadline relaxation was used.
- Discovery excludes output, runtime authority and anchor paths before launch.
  Signed deployment ceilings retain runtime/anchor exclusions without requiring
  the removed staging directory.
- The process recovery fixture is a static Rust MCP server with exact
  source/control-file reads and an exact output-file write. It synchronizes the
  effect before the test kills the owner. Python remains the external test
  orchestrator.
- Native profiles permit `fsync` on already-open descriptors. The signed seccomp
  plan represents bounded OR alternatives of ANDed argument constraints.
  `fcntl` permits `F_GETFD` and `F_SETFD(FD_CLOEXEC)`; descriptor duplication and
  clearing close-on-exec remain denied. Every `prlimit64`/`execveat` alternative
  must retain its target restrictions. Empty/duplicate branches are rejected.
- The schema, generated wire types and canonical positive vectors use that
  constraint shape. There is no old-shape decoding fallback.

The Python SDK now has an explicit broker provisioning API using reviewed tools
and authenticated peer bindings, with no filesystem grants, provider environment
inheritance or uncaged discovery. This is configuration support, not a completed
Docker/provider implementation. The mini-SWE dependency additions are also
insufficient to qualify its current direct Docker/provider callers.

## Verification

[Artifacts](artifacts/2026-09-29-native-consumers-acp-errors-openapi/README.md)
include terminal logs, compressed original Cargo streams, source/binary hashes,
worker identity, review disposition and earlier failures.

| Check | Terminal evidence |
| --- | --- |
| ACP edge, ACP proxy, remote MCP, OpenAPI, OpenAPI bridge | 513 tests passed: 98 + 205 + 99 + 59 + 52. |
| Sender-constraint review repairs and verifier refactor | 7 focused tests passed, including two newly added source/redaction cases. |
| Registered CLI source preservation | 1 focused test passed. |
| Actual OpenAPI conformance callers | 4 tests passed across two targets. |
| Owning protocol libraries, Clippy `-D warnings` | Passed. |
| x86_64 cage, cage-init, cage-plan libraries | 27 tests passed: 20 + 1 + 6. |
| Native provisioning authority-path regressions | 2 tests passed, including removed staging output. |
| Privileged native discovery | 1 test passed in 24.61 seconds; no ignored cases. |
| Native process host and worker recovery | 2 tests passed in 94.72 seconds; no ignored cases. |
| x86_64 cage libraries, Clippy `-D warnings` | Passed with real enforcement enabled. |
| Python launch helpers and native-fixture inputs | 7 + 2 tests passed. |
| Format, Rust hygiene, adapter no-bypass, trust-boundary, clock and negative-assertion gates | Passed. |
| Schema registry, wire-schema lock and security vectors | Passed; 90 positive and 270 negative vector cases. |

The native recovery campaign includes host death, worker restart, dependency
ordering, retry/resource bounds, cancellation, binding drift and uncertain
effects without redispatch. These are focused development-profile results, not
workspace-wide or hosted qualification.

Native source and final local source differ in the later remote sender-verifier
refactor, documentation, schema-manifest bookkeeping and canonical vector
updates. The affected native cage, helper, provisioner and recovery sources
match. The manifests enumerate every difference; native binaries are separately
hashed. The native result must not be relabeled as an exact final-commit binary
qualification. Local source manifests cover modified/new source and config over
the recorded base, excluding documentation, preexisting `output/` and scratch.

## Review and superseded evidence

One independent reviewer examined the implementation and native repairs. Its
substantive findings were repaired: CLI certificate errors had discarded their
native source; OAuth key/header paths still flattened causes; and a deployment
policy unnecessarily retained a staging-directory dependency. Focused regressions
cover all three. The final seccomp review also caught old-shape positive vectors;
the vectors and integrity manifest were migrated and rechecked. No source-size
allowance was increased. ACP tests and the cage syscall builder became ordinary
Rust modules where necessary.

Earlier Cargo migration, Clippy, hygiene and schema failures are retained as
development evidence. Native failed logs show the artifact ceiling, startup hash
cost, dynamic/group-writable helper, missing authority exclusions, and missing
`fsync`/restricted `fcntl` cases. The strace/perf diagnostics explain their
repairs. An incorrectly selected Python discovery glob ran zero tests; the
explicit fixture test command subsequently passed both tests. Zero-test runs
are not acceptance evidence. A stripped-binary trial did not fix the startup
failure and is not credited as a repair. A final Ruff invocation initially used
an absent configuration path; the corrected owning SDK configuration passed all
nine changed Python files.

## Remaining task 1 and next chunk

The current process-host broker admits one explicit broker route. Mini-SWE
needs both sandbox execution and model inference; its existing direct Docker
socket/provider callers cannot run under the intended native authority. Complete
the following as one integration batch:

1. Add explicit multi-route process-host broker composition, preserving each
   original signed request, quota/flow authority and terminal custody through
   restart and recovery.
2. Implement host-owned Docker execution and provider adapters. Caged tools
   receive their prepared authenticated broker streams; Docker sockets,
   credentials and ambient network authority stay outside the cages.
3. Migrate mini-SWE callers/campaign inputs and complete bounded interpreter
   dependencies for remaining consumers. The generic fixture's broad read-path
   suggestions are not evidence of a valid 64-resource dependency closure.
4. Qualify mini-SWE recovery, native-worker, provider/operator/session/public
   repository campaigns and packaged SDK/example/conformance consumers on the
   retained worker. Preserve each terminal result and rerun affected native
   regression boundaries.

The wider [remaining-work queue](2026-09-28-remaining-security-work.md) still
contains other readers, arithmetic, declarations, retention, formal, supply-chain
and delivery acceptance work. Task 1 and those queues are not closed by this
record.
