# Enforced native and protocol boundary evidence

Base: `150f7bea8e`. Reviewed implementation: `93fbf2eb4d`.
Review repairs: `cbd78cd8b1`. Gate/fixture repairs: `f2889ea83c`.
Final consumer source: `9cb2ac5679`.
All five approved tasks are implemented and locally checked. Qualification is
focused evidence across implementation and repair snapshots, not an exact-head
full-workspace, hosted, privileged-native or release qualification.

## Terminal checks

`summary.json` selects terminal passing checks and retains their exact commands.
All Rust commands used `CARGO_INCREMENTAL=0`. The initial owning campaign covers
policy, MCP adapter/remote, hosted facade and A2A edge: 602 tests across 20 binaries.
The final A2A rerun passes 104 instead of the initial 102, giving 604 distinct
owning scenarios. Consumer coverage adds 53 active-response tests, 113 SQLite
budget tests and 49 selected CLI cases. The no-bypass calibration covers 27 tests;
its final expanded native phase mutation reruns separately.

Reference provisioning is deliberately reported as split evidence: the full run
passed 12 cases and failed its newly added Shadow rejection fixture because it
omitted `--server-id`. After supplying that required argument, the affected case
passes in `shadow-discovery-final-test.log.gz`. No full-suite rerun is claimed.

Strict Clippy passed for CLI, secret broker, policy, MCP adapter/remote, hosted
MCP, A2A edge and cross-protocol, and separately for xtask and conformance, all with all targets
and `-D warnings`. Trust, clock, negative-assertion, file-hygiene and adapter-
no-bypass source gates pass. Trust has 18 calibration tests, clocks three, and
file hygiene 30. Formatting covers 83 changed Rust files and two include fragments.

## Preserved failures and successors

The result JSON files preserve original exit codes. Earlier failures are not
rewritten as passing:

- `initial-owner-tests`, `owner-tests`: early contract and mock
  fixture wiring failures. Superseded by `owner-final-tests` and `a2a-final-tests`.
- `a2a-review-tests`: new regression omitted `targetSkillId`; corrected before
  `a2a-final-tests` (104 passing).
- `cli-cage-tests`: independent receipt-anchor directory needed explicit private
  mode; superseded by `cli-final-chio` (16 passing).
- `cli-provision-tests`: obsolete uncaged-discovery expectation; updated offline
  fixture contract passes in `cli-final-native_mcp_demo_provision` (nine).
- `cli-final-security_preflight`: fixture still supplied the removed demo
  discovery option; superseded by `preflight-final-tests` (three).
- `cli-final-reference_runtime_provision`: split evidence described above.
- `control-response-tests`: relocated nested modules needed explicit paths;
  superseded by `control-response-final` (53).
- `adapter-gate`, `adapter-final-gate`: stale physical fixture sites, injected-
  clock constructor and removed legacy launch obligations; superseded by
  `adapter-enforced-gate`, `adapter-enforced-tests` and the final calibration.
- `hygiene`: policy production includes still needed a reduced allowance;
  superseded by `hygiene-terminal`, with no cap increases.
- `native-check`: the policy condition fixture still used the previous context
  API; owning tests and strict Clippy pass after migration.
- `clippy`: a redundant test conversion; superseded by `review-final-clippy`.

`cli-final-build.jsonl.gz` records the generated CLI/test executables. Selected
CLI tests were executed directly against those binaries. `cli-test-artifact.json`
records stripping only debug sections from `target/debug/chio`, reducing it by
189,872 bytes from 389,151,936. No useful performance gain is claimed. The later
preflight and Shadow cases use Cargo's selected integration-test runners.

## Review and scope

`final-review.md` preserves the independent candidate review and author
responses. The reviewer requested changes for uncaged discovery and loss of
A2A local typed causes. Both were repaired and checked by the author; no second
independent review is claimed. No minor finding was deferred. The withdrawn
same-kernel rollback suggestion is distinguished from the additional deadline
custody repair.

The real enforcement/scaffold scenarios remain behind the existing privileged
Linux feature. These local fixture runs do not establish native x86_64
execution, hosted acceptance, M5/M11, integration, package publication or release.
The next queue is remote MCP clock/lifecycle completion, ACP edge/proxy
hardening and native consumer CI fixture integration. See the execution record and remaining-work queue for broader scope.

## Final consumer migration

The shell helper, Docker entrypoint, Python SDK helper and conformance runner
now request Enforced reference-runtime provisioning with explicit helper,
independent anchor and read-grant inputs. Shell/Docker reruns preserve existing
authority; Docker also retains its session keyring. The optional Docker profile
and runnable guides document the host prerequisites.

`consumer-expansion-results.json` records three Rust configuration tests and
15 Python/shell tests, conformance Clippy, the admin credential gate and syntax/
format checks. `consumer-expansion-gates.json` records the refreshed source gates.
`remote-tests.log.gz` is an earlier successful 88-case run, superseded by the
89 remote cases in the owning campaign.

The process-worker workflow and native SDK/example/conformance deployment jobs
still need qualified host fixtures and those enforcing inputs. Actual native
recovery scenarios are not claimed passing. No runtime bypass or blanket host
permission was added to make an ordinary worker job pass.

`SHA256SUMS` covers every other archived file, including compressed earlier logs.
