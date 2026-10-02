# Execution review: native launch and consumers, October 1, 2026

Scope: commits `f2889ea83c` (native launch gate and fixture alignment),
`9cb2ac5679` (enforced provisioning in native consumers), `723bf9ee97` (enforced
native record and evidence), `95f04d5d74` (OCI worker shutdown record),
`2a4c2fbe4f` (bounded broker routes and prepared consumer execution),
`7525fcdf0c` (prepared consumer qualification, host adapters and native CI), and
the native-launch parts of `93fbf2eb4d`, `cacaf69fc9` and `55e7439da3`; the
protocol halves of those three belong to another reviewer. Plans: the native
multi-route consumer plan, the native half of the enforced native and protocol
boundaries plan, the native CI half of the remote lifecycle, ACP-Client and native CI
plan, and the native consumer half of the native consumers, ACP-Client errors and
OpenAPI plan. Contracts: `docs/security/native-launch-examples.md`,
`docs/security/consumer-support.md` and `docs/security/broker-prepared-connections.md`.
Records: the four matching `docs/reviews/2026-09-29-*-execution.md` files and
their evidence directories. Base `07e963e8f5`, tip `a2630c20a1`. Method: source
reading at the tip, the GitHub API for workflow runs and the `main` ruleset, one
direct call into the fixture script's grant validator, and a decompress-and-scan
of all 787 evidence files in the slice. No cargo build or test was run.

**Judgment: The security core of this slice is sound and worth having: the uncaged
legacy launch path is gone with no flag, environment variable or default that
restores it, partial Landlock or seccomp enforcement still refuses launch, and the
multi-route broker binds each prepared invocation to its route, audience, process,
operation key and exact arguments with no replay or cross-route path I could
construct. The OCI campaigns are real evidence; every test count I sampled matches
its archived log. The most important defect is that the native CI lane the records
call "wired" cannot pass: its shared fixture action calls a script with no read
grants that the script itself rejects, and it depends on `rg`, which the runner
does not have; the lane is not a required check and has never run on GitHub. Two
smaller correctness regressions came with the broker work: a provider response that
repeats a header is now discarded after the provider has acted, and every native
MCP tool may now send 4 MiB frames into a 128-slot queue. The 787 committed
evidence files publish OCI identifiers and local paths and are far larger than
their value as proof.**

## Plan conformance

| Plan item | Recorded status | Verified status | Evidence |
| --- | --- | --- | --- |
| Enforced native task 1: remove `NativeMcpLaunch` and `LegacyNativeLaunchAuthorization`; migrate CLI, doctor, remote, hosted and test consumers | Complete | Verified | Neither symbol exists at the tip. `cage_policy.rs:823-852` refuses any stage other than Enforced or LegacyRemoved before composing a launch; `doctor/security/launch.rs` has no legacy probe outcome; `serving.rs` and `wrap.rs` take `CageRequiredLaunch` only. |
| Enforced native: Disabled provisioning is fixture-only; Shadow live discovery refuses before the target runs | Complete | Verified | `provision.rs:393-397` and `provision/discovery/launch.rs:18-22`; discovery itself launches through `chio_cage::launch`. |
| Enforced native follow-through (`9cb2ac5679`): shell helper, Docker entrypoint, Python SDK and conformance runner require Enforced inputs | Complete | Verified; tests build arguments only, as the record says | `scripts/lib/provision-mcp-launch.sh`, `examples/docker/mcp_demo_entrypoint.py`, `chio_process/launch.py`, `chio-conformance/src/runner/native_launch.rs`. The `rm -rf` of prior provisions was removed, so restarts revalidate authority instead of replacing it. |
| Enforced native task 5: reconcile inventories and docs | Complete | Mostly | Inventory retirements are moves into test directories. Two operator statements are stale (NC7). |
| Remote lifecycle task 4: explicit enforced fixtures for process-host, SDK/example and conformance jobs; ordinary worker coverage kept separate | Complete for wiring and portable checks; hosted open | Ordinary worker coverage is correctly separated. The fixture action cannot complete on its declared runner (NC1). | `.github/actions/enforced-native-fixture/action.yml:31`, `process-workers.yml:110` |
| Native consumers task 1: mini-SWE native dependencies and mediated transports | Partial | Verified as partial when recorded; closed later by the multi-route plan | Discovery log shows `1 passed ... 24.61s`; recovery log shows `2 passed ... 94.72s` (`native/native-*-final.log`). |
| Multi-route task 1: bounded verifier and participant routes | Complete | Verified | `kernel_admission/routes.rs:53-139` bounds to 1..=16 and rejects duplicate servers, audiences and sockets; `native_broker/config.rs:84-143` repeats this for host configuration; `tests/routes.rs` covers reorder, member change, duplicates and cross-audience substitution. |
| Multi-route task 2: host-owned Docker and provider adapters | Complete | Implemented; defects NC2, NC4, NC5 | `docker_adapter.rs`, `host_https.rs`, `generic_https/local_adapter.rs`, `repository_adapter.rs` |
| Multi-route task 3: consumer migration | Complete | Verified at source and test-count level | Python 441, repository-review 38, shared-resource 12, storage 123: all match their logs. |
| Multi-route task 4: native campaigns on the retained worker; update CI inputs | Complete for focused acceptance | Campaigns verified from archived reports; CI inputs do not run (NC1); native checkout was a base plus overlays, as disclosed | `continuation-20260930/reports/*`, `verification-index.json` |
| Multi-route constraints: 1..=16 routes, duplicate destinations rejected, full route set pinned; Docker sockets and provider secrets outside cages | Constraint | Verified | A destination is `{server_id, tool_name}` (`kernel_admission.rs:88-91`), so unique servers make destinations unique. The route-set digests cover every member. Only the prepared stream enters a cage. |

## NC1. Medium: the enforced native CI fixture cannot complete, so no native consumer lane can pass

Every native CI job (`process-workers.yml` `host` and `optimized-comparison`,
and `conformance-matrix.yml` `external-consumer-smoke`) starts with
`./.github/actions/enforced-native-fixture`. That action fails for two
independent reasons at the tip.

First, `7525fcdf0c` removed every `--read-path` argument from the fixture call
(`action.yml:36-40`) but left the script's requirement in place:
`scripts/prepare-enforced-native-fixture.py:16-17` raises `ValueError("native
fixture requires explicit read grants")` when the list is empty. Its own test
asserts that rejection (`scripts/tests/prepare-enforced-native-fixture.test.py`,
`test_empty_and_multiline_grants_are_rejected`). I called
`validate_grants([], [])` from the tip's script and it raised exactly that
error. The CI inventory test (`check-process-ci-inventory.test.py:76-84`)
checks that broad grants such as `/usr` and `$GITHUB_WORKSPACE` are absent. It
never checks that any grant is present, so it now locks in the broken call.

Second, the terminal discovery check is `rg -q 'test result: ok\. 1 passed; 0
failed'` (`action.yml:31`). The `host` job installs only `protobuf-compiler`
(`process-workers.yml:110`), as do the other two jobs, and the published
`ubuntu-24.04` runner image manifest does not include ripgrep. Every other
workflow that uses `rg` installs it explicitly (`ci.yml:70`, `spec-drift.yml:40`).
This defect predates `7525fcdf0c`: it was present when task 4 of the remote
lifecycle plan was marked complete.

Failure scenario: a pull request touches `crates/products/chio-cli/**`. In the
`host` job, the fixture step fails. Every native step is gated on
`steps.native_fixture.outcome == 'success'`, so the enforced recovery test, the
broker adapter build and every mini-SWE, repository-review, shared-resource,
package and AI SDK campaign is skipped, and the job goes red. Nothing native is
qualified. The red does no harm because nobody is required to look at it: the
`main-required-checks` ruleset requires only `Build, lint, test`, `MSRV build and
test`, `cargo-vet` and `cargo-deny`. The lane has also never run. The last
`process-workers` run (`36868648167`, at `f25cd61f49`) predates every commit in
this slice, and `origin/packet/3-retention-accounting` has no pull request. The
conformance job runs only on schedule or dispatch, and its header says it is
expected to fail until a Python peer is published, so a native failure there
would carry no signal either.

The multi-route record says "Native CI inputs are wired", and its plan checks
"update CI inputs". The remote lifecycle record says "the native action requires
exactly one successful discovery test, not a skipped or zero-test result". Each
statement is true of the YAML text and false of its execution. The static
inventory test is the only CI check run against these inputs, and it inspects
strings.

Fix: install ripgrep through `apt-install` or use `grep -q`. Either pass explicit
non-authority grants or let the fixture accept an empty set; the Python runtime
manifest supplies `CHIO_CAGE_READ_PATHS_FILE` immediately afterwards anyway. Make
the inventory test run the fixture script's argument contract rather than
grepping YAML. Push the branch to a pull request once and archive that run before
calling the lane wired. Once it is green, consider requiring a narrow native smoke
job.

**Confidence:** Confirmed. The empty-grant failure was reproduced by calling the
tip's validator. The `rg` failure follows from the job source and the runner-image
manifest.

## NC2. Medium: a provider response that repeats a header is now discarded after the provider has acted

`2a4c2fbe4f` added canonicalization to `sanitize_response_headers`
(`chio-secret-broker/src/generic_https.rs:614-625`). It sorts the retained
headers by name and rejects the response with `ResponseRejected` if any name
repeats. That function runs inside `dispatch_evidenced`, after the upstream
request has been sent and answered. The broker maps the error to
`HttpsDispatchFailure::Response`. `service/custody/execution.rs:596-611` then
moves the attempt from `DispatchCommitted` to `UnknownOutcome` and reports
`BrokerFailureOutcome::Failed` with `BrokerDispatchKnowledge::Committed`.

Failure scenario: a native session calls a model provider through a prepared
route. The provider (or its CDN) returns `200` with `Vary: Origin` and `Vary:
Accept-Encoding` as two lines, which RFC 9110 section 5.3 permits for list-valued
fields. `Link`, `Cache-Control`, `Via` and `Access-Control-Expose-Headers` behave
the same way. Only `set-cookie`, `www-authenticate`, `proxy-authenticate` and
`authorization` are stripped, at lines 598-603. The provider has charged for the
completion. The broker discards the body, the one-execution prepared capability
(`maximum_executions: 1`, `native_broker/preparation.rs`) is consumed, and the
operation waits for operator recovery. Before this commit the vector kept wire
order and duplicates. The signed `responseHeadersSha256` covers a vector, so
duplicates were representable. The archived campaigns could not catch this,
because the continuation README states that "No real provider account was called;
provider decisions are controlled HTTPS fixtures".

Fix: canonicalize with a stable sort (`sort_by`) and keep repeated names in their
original relative order, or combine list-valued repeats as RFC 9110 allows. Add a
regression with two `vary` lines that expects a delivered response.

**Confidence:** Confirmed for the code path; the existing unit test
`response_headers_are_canonical_before_receipt_persistence` asserts the
rejection. How often real providers trigger it was not measured.

**Independent verification:** Confirmed, Medium, with one correction. `set-cookie`,
`www-authenticate`, `proxy-authenticate` and `authorization` are dropped before the duplicate
check (`generic_https.rs:597-603`), so a repeated `Set-Cookie` is not rejected; repeated `Vary`,
`Cache-Control`, `Link`, `Via` and every other retained field are. RFC 9110 section 5.3 permits
repeated list-based fields. The transport dispatches first (`generic_https.rs:304-306`) and the
header check runs after the status, framing and body checks (`:376`), so the provider has acted.
The capture is not released, so the invocation stays consumed.

## NC3. Medium: every native MCP tool may now send 4 MiB frames into a 128-slot queue, a fourfold increase in host memory a confined tool controls

`7525fcdf0c` added `MAX_STDIO_MCP_RESPONSE_BYTES = 4 MiB`
(`chio-mcp-adapter/src/framing.rs:10`) and made `read_jsonrpc_frame` use it for
every upstream line (`framing.rs:20,31`). That function is the stdout reader for
every stdio MCP transport (`transport/utils.rs:264`), not only the brokered
route that needed it. The reader decodes each line into a `serde_json::Value` and
`try_send`s unsolicited notifications into a queue bounded at 128 messages
(`transport.inc:816`, `utils.rs:17`). The process host's `AdaptedMcpServer` never
calls `drain_notifications`, so queued notifications stay queued for the life of
the server.

Failure scenario: a caged native tool (the code the cage exists to distrust)
writes 128 notification lines, each just under 4 MiB of `[0,0,0,...]`. Each line
decodes to about 2.1 million `Value`s at 32 bytes each, about 64 MiB, so the host
retains about 8 GiB. Under the previous 1 MiB bound the same attack retained about
2 GiB, which was already too much. The cage confines the tool's syscalls, not the
host's memory: the cage README states it is not a cgroup boundary. The host
process can be OOM-killed by a tool it is supposed to contain.

The larger bound exists because broker bodies are encoded as JSON arrays of byte
values nested inside another JSON byte array. That encoding is also why
`MAX_EXECUTE_RESPONSE_WIRE_BYTES` is 16 MiB for a 512 KiB payload
(`protocol.rs`), why classification needed a separate 4 MiB owner, and why
public-repository attempts 4 and 5 exhausted their fence on repeated decoding.

Fix: scope the 4 MiB bound to the BrokeredNativeV1 transport. Bound the
notification queue by retained bytes rather than message count, or drop
unsolicited notifications on hosts that never drain them. Encode broker bodies
as base64 or raw framed bytes instead of number arrays.

**Confidence:** Confirmed mechanism, traced through the source from the read
bound to the retaining queue. The memory figures are computed from serde_json's
32-byte `Value`, not measured.

## NC4. Low: Docker output over 512 KiB turns a completed command into an unknown outcome, and output is decoded lossily

`docker_adapter/wire.rs:80` returns `unavailable()` as soon as cumulative
multiplexed output exceeds `maximum_output_bytes` (at most 524,288). Error
handling then drops the connection without a response, so the broker records a
transport failure and an unknown outcome. Meanwhile the exec keeps running in the
container, because nothing waits on `/exec/{id}/json` or stops it. The mini-SWE
environment forwards agent commands unmodified (`chio_mini_swe/environment.py:67-79`),
so one `cat` of a large file or a verbose test run stalls the session until an
operator intervenes. Separately, `docker_adapter.rs:288` converts output with
`String::from_utf8_lossy`, so binary output is altered before it is bound into
the receipt. This fails closed, but it charges an operator for ordinary agent
behaviour. Fix: drain to exit, return the known exit code with a truncation flag,
and carry bytes rather than a lossy string.

**Confidence:** Confirmed by source; the operational impact depends on agent behaviour.

## NC5. Low: the repository adapter's executable pin covers only the console-script launcher, not the code it runs

`RepositoryAdapter::start` hashes the configured executable, copies it into a
sealed memfd and executes the copy (`repository_adapter.rs:126-156`,
`repository_adapter/launch.rs`). The campaign configures
`<venv>/bin/chio-mini-swe-repository` (`examples/mini-swe-recovery/broker_campaign.py:297`).
That file is a pip console script (`sdks/python/chio-mini-swe/pyproject.toml:18`,
`chio_mini_swe.repository:main`): a shebang line plus an import. The interpreter
named in the shebang and every module it imports from `site-packages` are opened
by path after the check and are never hashed. The record says the memfd
"close[s] the check/exec replacement window". It closes that window for about 200
bytes of launcher, while every imported module, which is the code that drives
Docker, stays open to replacement. Fix: pin the interpreter and capture the
application into the content-bound archive that `chio_process.python_application`
already builds, or state the narrower scope of the pin.

**Confidence:** Confirmed by source.

## NC6. Low: the committed evidence publishes infrastructure identifiers and local paths, and its volume is out of proportion to its value as proof

The four evidence directories in this slice hold 787 files: 5.9 MB in git and
52 MB decompressed. Across the whole execution window, 1,531 artifact files
(17.9 MB) were added under `docs/reviews/artifacts/`. The repository is public,
and `origin/packet/3-retention-accounting` already contains this slice. A pattern
scan of every decompressed file found no private keys, seeds, bearer tokens or
API keys, which matches the records' statement that signing material stayed on
the worker. It did find:

- OCI instance, boot-volume and block-volume OCIDs (`us-ashburn-1`), the worker's
  private VCN address, and the Tailscale address of the operator's
  Mac, together with remediation notes ("Direct worker SSH
  remains available"). These appear in `native-consumers-acp-errors-openapi/worker.json:3-18`,
  two more copies of `worker.json`, `progress.md` and `native/worker-stop-unexecuted.log:1`.
- About 147,000 occurrences of the operator's and the worker's home directory paths and about 73,000
  of `/tmp/arc-security-launch`, mostly in 76 Cargo build JSONL streams.

The records do rely on these files. Every count in the four records points at a
log, and the sample in the next section matched. Much of the volume adds nothing
to that proof. Native logs are stored twice (plain `.log` and `.log.raw.gz`;
45 duplicates in one directory). Cargo build streams prove only which binary a
later command selected. `review-150f7bea8e..93fbf2eb4d.diff.gz` is an 813 KB
copy of a diff that git can regenerate. Fix: keep `verification-index.json`,
`SHA256SUMS`, source and binary manifests and terminal summaries in the
repository. Move bulk logs to CI artifacts or a private evidence store, and
redact the worker records.

**Confidence:** Confirmed by the scan.

## NC7. Low: operator contracts still describe the single-route broker and the uncaged demo

`docs/security/broker-prepared-connections.md:111` still says the broker profile
"requires Linux, one broker server". Its configuration example (`:132` onward)
puts `quota`, `broker_identity`, `revocation_authority_domain` and
`ipc_timeout_ms` at the top level, and `:193` names a single
`STATE/broker-authority.sock`. Host configuration is now
`native_broker.routes[]` with per-route `authority_socket_name`, under
`deny_unknown_fields` (`native_broker/config.rs:4-27`). An operator who follows
the document gets a load-time rejection. `provision/reference_runtime.rs:4` still
says "The demo provisioner authorizes a launch without confining it", which
`93fbf2eb4d` made false. `PROCESS_HOST.md` does describe the route list correctly.

**Confidence:** Confirmed.

## NC8. Low: preparation issues time-bound broker authority from an ambient clock, and the issuance path has no unit tests

`native_broker/preparation.rs:147-151` reads `SystemClock` directly to set
`issued_at`, `not_before` and the expiry cap `min(now + lifetime,
parent.expires_at)` for a signed broker capability. Engineering standard section
6.1 requires an injected clock on authorization paths. The `Preparer` has no clock
field, and `preparation.rs` has no tests. The parent-grant check, the expiry cap
and the refusal for an expired parent are exercised only by native campaigns. The
store-level tests in `chio-process/tests/processes.rs` drive closures, not
`Route::issue`. Fix: inject the composition root's clock and add unit tests for
expiry capping, an expired parent and an unmatched grant.

**Confidence:** Confirmed by source.

## Execution-record claims checked

| Claim (record:line) | Verdict | Evidence |
| --- | --- | --- |
| Multi-route: "Broker library: 173 pass" (`...-native-multiroute-consumers-execution.md:103`) | Verified | `continuation-20260930/local/chio-broker-consumers-final.log.gz`: `173 passed; 0 failed` |
| Multi-route: "MCP adapter: 122 pass" | Verified | `chio-mcp-final-response-after-2.log.gz`: `122 passed` |
| Multi-route: "a deterministic held-reader regression fails before the fix and passes after it" | Verified, with the source-identity caveat | `chio-final-response-before.log.gz` shows `completed_response_is_delivered_after_child_exit_before_stdout_decode ... FAILED`; the test exists at `stdio/final_response_tests.rs:35` |
| Multi-route: "The native history suite passes all 96 cases" | Verified | `native/history-followup-2.log.gz`: `96 passed`. The earlier `local/native-history-final.log.gz` shows 65 passed and 30 failed on a full disk; it is retained and superseded. |
| Multi-route: Python 441, repository-review 38, shared-resource 12, storage 123, SQLite outcome 26, kernel outcome 17, repository adapter 4, response budgets 2 | Verified | Each count matches its log |
| Multi-route: "Comparison passes all eight cases across two trials" | Verified; the earlier failure's cause cannot be checked | `comparison-followup-6-comparison.json` has 8 cases (2 scenarios × 2 modes × 2 trials). The attribution of `comparison-followup-4` to CPU contention rests on diagnostics left on the worker; the archived stderr ends at `execute failed; inspect private diagnostics`. |
| Multi-route: exact 500,000-byte ASCII and 79,000-byte escaped-NUL outputs | Verified by script | The report holds booleans only; `qualify_public_repository.py:148-171` asserts the exact strings before writing them |
| Multi-route: "Native CI inputs are wired" | Contradicted | NC1 |
| Multi-route: private keys and authority databases remain on the worker | Verified | No key, seed or token pattern in 52 MB of decompressed evidence |
| Enforced native: "three preflight tests pass" | Verified | `cli-final-security_preflight` failed 2 of 3 and is superseded by `preflight-final-tests.log.gz` (`3 passed`), as the README says |
| Enforced native: reference-runtime "12 passing cases ... plus a passing focused rerun" | Verified as stated | Full run 12 passed and 1 failed; the focused rerun passed 1. The other 12 were not rerun after the repair, and the record says so. |
| Native consumers: discovery `1 passed` in 24.61 s, recovery `2 passed` in 94.72 s | Verified | `native/native-discovery-final.log`, `native/native-recovery-final.log` |
| Remote lifecycle: "The native action requires exactly one successful discovery test, not a skipped or zero-test result" | True of the YAML text; the check cannot run | `rg` is absent on the runner (NC1) |
| Remote lifecycle: conformance native launch "4 passed" | Verified as configuration tests only | Disclosed as validating launch inputs, not a conformance campaign |

## Verified clean

- **No unenforced launch mode remains.** No production constructor yields a launch
  without `CageRequiredLaunch`; `spawn_test_process` is `cfg(test)`. The cage
  refuses launch unless the Landlock ABI meets the minimum and filesystem, network
  and seccomp status are all `FullyEnforced` (`chio-cage/src/launch/linux.rs:1188-1192`).
  Non-Linux platforms return `UnsupportedPlatform`. Namespaces and cgroups are not
  used, and the cage README says so (lines 167-172); nothing degrades when they are
  absent, because nothing depends on them. `real-linux-enforcement` gates tests
  only. `enforcement-mutants` is a `compile_error!` outside `debug_assertions`. No
  environment variable or configuration default selects Disabled or Shadow at
  runtime: both stages refuse launch and live discovery.
- **Discovery runs inside the cage** (`provision/discovery/launch.rs`), satisfying
  standard section 9.2. Discovery grants exclude the output, authority and anchor
  paths.
- **Route binding.** Each audience, server and socket is unique. The kernel computes
  the destination from the invoked server and tool. `verify` checks issuer,
  audience, parent, subject, invocation identity, provider adapter, destination
  and argument digest before any custody. `requires_registration` covers every
  tool on an installed server, so renaming the tool cannot evade registration.
- **Prepared invocation.** The binding hashes the route-set generation, server,
  tool, invocation identity (namespace, process, operation key) and exact
  arguments. It is committed once and returned verbatim. Changed arguments or
  configuration conflict. The capability allows one execution, with
  capture before dispatch. Expired envelopes are returned unchanged, so the broker
  refuses them rather than renewing them. A kernel redispatch derives a different
  request identity, so the broker refuses it rather than executing twice.
  Preparing the same arguments under another operation key yields a separate
  one-execution capability, still bounded by the parent's `max_invocations`.
- **Docker adapter pinning.** The daemon is pinned by peer pid, uid and gid plus
  its daemon ID. The container is pinned by ID, `StartedAt` and a configuration
  digest, and must be unprivileged, non-root, `NetworkMode none` and read-only.
  The resource is revalidated before exec creation, before start and after
  completion. There is no retry.
- **Host HTTPS endpoint.** It binds loopback only, compares the bearer in constant
  time, bounds the request head and body, and rejects `Transfer-Encoding`,
  `Expect` and `Upgrade`. The local adapter's TLS pin is verified before any
  credential byte is sent (`local_adapter_pins_endpoint_and_tls_before_credential_delivery`).
- **Repository adapter `pre_exec`** is allocation-free and re-checks the parent
  pid after `PR_SET_PDEATHSIG` (standard section 9.5).
- **Offline verification** selects the route from the trusted host configuration,
  not from the artifact (`call_evidence/broker.rs`).
- **House rules.** No em dashes in any slice commit. No `unwrap` or `expect` added
  outside test modules. No process vocabulary in added code or comments.
- **The `PreparedRecordInvalid` binding check** covers helper, target, plan,
  profile, filter and trace-session digests before exec.

## Recommendations for the remaining plan

1. Fix NC1, then run `process-workers.yml` once on a real pull request and archive
   that run before any record calls the native lane wired. Until a hosted native
   run exists, the "native CI" row in the remaining-work queue is open, not
   delivered.
2. Restore stable, order-preserving header canonicalization (NC2) before any live
   provider route is enabled.
3. Replace the JSON number-array byte encoding in broker responses with base64 or
   raw framing. That removes the 16 MiB wire ceiling, the separate 4 MiB
   classification owner, the global 4 MiB MCP bound (NC3) and the repeated-decode
   fence exhaustion seen in public-repository attempts 4 and 5. Until then, scope
   the larger bound to the brokered route.
4. Reproduce `comparison-followup-4` under deliberate CPU contention and archive
   the diagnostics. If a handoff can expire after dispatch commitment on a loaded
   host, decide whether a pre-execution handoff failure can be recorded as
   provably not executed instead of left uncertain.
5. Make `FullyEnforcedEvidence` and the enforcement receipt non-optional on the
   production stdio transport. The `Option` exists only for `cfg(test)`
   constructors, and the `require_enforced` branches in `process_host/serving.rs`
   are then dead and can go.
6. Adopt an evidence policy: summaries and manifests in the repository, bulk logs
   elsewhere, and worker identifiers redacted (NC6).
