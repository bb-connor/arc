# Process and security review dispositions

The [machine-readable record](process-security-review-dispositions.json) accounts
for all 109 original review threads inherited by the process/M4 integration.
Its source candidate is `63239c56c9bfcbe71de65ac66af6889b46d66c6c`.
This is local source reconciliation, not remote thread resolution, full
qualification, merge approval or launch authorization.

There are 81 reproduced-and-repaired dispositions, 20 fixed-with-evidence
dispositions and eight technically-inapplicable dispositions. Repairs include
documentation and coverage corrections, not 81 distinct runtime vulnerabilities.
No original thread is omitted because it was outdated or already fixed.

Each entry records its original URL, owning file, source checkpoint, specific
disposition and applicable regression or complete test-file identity. A
checkpoint is an ancestor containing the cited implementation and evidence;
it is not necessarily the commit that first introduced the implementation.
Later changes still require the combined qualification in Task 5.

## Evidence groups

These are retained terminal results from the owning checkpoints, not a single
simultaneous test execution. Repeated tests and nested fixture processes must
not be added together as new test identities. Logs remain local; no local log
path is presented as publicly accessible CI evidence.

Rust commands use toolchain `+1.94.1`, `--offline --locked -j 2`, `umask 022`,
`CARGO_INCREMENTAL=0`, `RUST_TEST_THREADS=1` and no custom `RUST_MIN_STACK`.

| Group | Exact checkpoint | Executed scope and boundary |
| --- | --- | --- |
| 2 | `3b926837372f2a878169671911e613968455f553` | Eight native process-host tests, 19 runner tests and 27 Python process tests passed. Actual Docker host-loss remains separate. |
| 3 | `ac2ca99973f24048b57b87e78cae4b61fa1d1d65` | 1,722 Rust and 334 Python tests passed, including real original-artifact crash recovery, lineage, independent response verification and retained custody. The subsequent physical-clock repair is retained in group 4a. |
| 4a | `1f2c8c3e9d8c074d4e50181201ce4e788bc47d0d` | Original 1,651-case Rust coverage; after the relocation fix, six owning store tests, 24 control-plane tests, seven real administration groups and two runner relocation cases passed. Counts overlap earlier coverage. |
| 4b | `627dc589b28ab60ef391ad866009cefa31c44f5d` | 522 distinct covering cases passed: 399 Python, 52 LangGraph, 46 AI SDK, five Node process and 20 native runner. Selected installed AI SDK 6/7 scenarios passed; full swarm/supervision qualification was not completed here. |
| 4c | `bb338d9e5160cdad5984bf334b65bf2fc15ed34d` | Final socket-preflight fix passed 62 review tests. Earlier source `0def619be29c4da48a94d21f66b033c12a10b0ca` passed 371 mini-SWE, 46 review, seven artifact and six benchmark cases, plus native/installed qualifiers. Those older full qualifiers were not rerun for the two-file preflight fix. |
| 4d | `a6d3690a4250a1fc63b8d3989ca9680788b734b1` | 245 distinct Rust tests, eight FIPS contract, six evidence-binding and seven dependency-parser tests passed. Actual dependency trees, nested-manifest selection, strict owning Clippy, workflow lint, Rust formatting, no-bypass and hygiene passed. Full security source contract remains failed at the image-input digest gate. |

Core rerun entry points (add the common Rust settings above):

```sh
cargo test -p chio-cli --test process_host
cargo test -p chio-cli --bin chio process_host::runner
cargo test -p chio-process --features worker-server,mailboxes
cargo test -p chio-kernel-core --test signed_lineage
cargo test -p chio-cli --test process_response_verify
cargo test -p chio-store-sqlite --test execution_nonce_caller_execution --test threshold_kernel_lifecycle
cargo test -p chio-store-sqlite --lib serving_owner::tests::relocation
cargo test -p chio-control-plane --lib durable_admission::tests
cargo test -p chio-data-guards --lib
cargo test -p chio-conformance --lib
cargo test -p chio-kernel --lib payment
cargo test -p chio-kernel --test durable_admission_sqlite
python3 scripts/tests/check-process-dependencies.test.py
python3 scripts/tests/check-process-ci-inventory.test.py
python3 scripts/tests/check-fuzz-manifest-selection.test.py
python3 scripts/tests/check-fips-ci-contract.test.py
python3 scripts/tests/check-required-evidence-binding.test.py
```

Python suites use their owning locked environments and absolute source
`PYTHONPATH` entries when tests launch children outside the checkout. Linux
process fixtures require the real pidfd APIs. The repository-review suite is
`test_snapshot.py`, `test_adaptive.py`, `test_distribution.py` and
`test_qualification.py` under `examples/repository-review`. The mini-SWE suite
is `sdks/python/chio-mini-swe/tests`, with the comparison, session-environment,
optimized-build and container-attempt fixtures in `examples/mini-swe-recovery`.
Process Python tests use `python -m unittest discover -s
sdks/python/chio-process/tests`. TypeScript package tests run from
`sdks/typescript` with `npm test --workspace @chio-protocol/ai-sdk-process` and
`npm test --workspace @chio-protocol/process` after the owning build.

Installed-artifact evidence comes from `scripts/qualify-process-packages.py`;
native repository review uses `examples/repository-review/qualify.py` and
`qualify_adaptive.py`; the authorization oracle is
`examples/mini-swe-recovery/check_authorization.py`. These are actual qualifiers,
not parser-only substitutes. Full-fidelity private source/evidence remains
retained locally and must not be published without inspection and authorization.

## Final-only evidence and preserved contracts

The current-checkout closeout ran five focused Rust regressions and six Python
timeout/default/override cases successfully. Exact Rust identities are in the
record: rich native attachment persistence, signed caller schemas, original
native requirement retention, live native selection before Optional fallback,
and signed internal-origin/closed-vocabulary schemas. The first four ran in the
unchanged Task 4D test executable, SHA256
`05f0afb74c2a78ac348878e1c95ee998660b5058719af70fbdc0a965c796df82`.
The internal-origin test ran through Cargo on the current checkout.

- Optional legacy dispatch remains supported. Selected native dispatch still
  requires the original/live binding and Enforce before any legacy fallback.
- The richer attachment set is bounded by the closed slot vocabulary, not by
  an obsolete numeric cap.
- The current classifier has explicit rule, pattern, compiled/DFA, payload and
  finding limits. An unmeasured complexity suggestion is not a demonstrated
  backtracking vulnerability. Nullable-pattern and pointer defects were fixed
  separately, retaining runtime refusal.
- Overlapping PR topology did not create a duplicate xtask implementation.
  There is one tracked `xtask/src/support.rs`; PR 1140's `90914a3e` head is not
  an ancestor of the integration. Reapplying it is unnecessary.
- Historical CI timeout placement is not a runtime defect. Its 45-minute
  setting is retained without rewriting historical commits.
- The relocation file first appears at
  `7599eb9d1eb14a60d9d128a24f588f449458dd73`; its target-map trigger first appears
  at `92e6acc8058ae36634498b304e9067135fe3f80a`. The later reviewed relocation
  checkpoint is not misattributed as either creation commit.
- Current `fuzz/target-map.toml` SHA256
  `e6feb8c431c9eafc03666d30406555b9213c3ca540b869575dca0a3703be1879` matches the
  generated coverage metadata. This does not claim complete process proofs.

## Reconciliation review follow-through

The Task 1 path-coverage gap is closed by the owning Task 4a regressions:
`claimed_joint_budget_transactions_are_one_durable_write_each`,
`claimed_tool_return_and_post_return_begin_are_one_durable_write_each`, the
`approved_caller_replay_refuses_expired_lease_without_new_hold_or_event` test and
`reserved_terminal_stage_refuses_expired_active_claim_without_mutation`.
They exercise authority expiry at the store owner and require unchanged
participant, hold/event, claim, commit-chain and anchor state on refusal. The
complete combined native/caller lifecycle and rollback crash matrix still
belongs to Task 5; selected tests cannot replace it.

The coordinator's hard hygiene failure is repaired by unchanged payment-method
extraction at `f7b8b087066e39be1d77d042d2afa1deafbaa556`. Nonblocking repository
size warnings remain; no size threshold or exemption was raised. Task 2's
post-reap and attachment-error findings, Task 4a's committed-WAL/refusal-teardown
findings, and Task 4c's longest-socket-path finding all have committed repairs.
The standalone authorization check's ambient initialization, inherited
LangGraph typing/style issues, advisory/audit requirements and complete
installed-profile qualification remain Task 5 work.

The image-input Cargo.lock assertion still fails and has not been waived or
repinned. Trusted controller/source authorization, exact-head CI, normal
protected integration and the complete M5 artifact remain outstanding. No
GitHub review comment has been resolved by this document.
