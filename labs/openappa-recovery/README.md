# Recovery offers over current Chio security and process code

Local research, October 1, 2026. This isolated lab builds against the freshly fetched integrated process/security candidate. It changes no production implementation and imports no OpenAPPA runtime code. The companion process experiments are in [recovery_offer_binding_lab.rs](../../crates/kernel/chio-process/tests/recovery_offer_binding_lab.rs).

The experiment asks whether OpenAPPA's recovery experience can use Chio's existing authority primitives. It implements one narrow remedy: requesting an exact disclosure grant for a restricted support summary destined for a public issue sink. Fixture keys, labels, destination and budget are synthetic. No provider, model, approval UI or external tool is contacted.

## Implemented behavior

`plan` uses the real `chio-flow::prepare_pre_invocation` evaluator. A registered policy/manifest disclosure purpose and trusted authority may produce a 30-second approval offer after a policy or manifest flow denial. Other denials have no disclosure offer. Revocation and empty budget refuse; these are trusted-host fixture observations, not live kernel lookups.

The offer's canonical, domain-separated digest binds the full intent and observed host snapshot: operation, exact canonical bytes, capability, agent, source labels and generations, destination, purpose, policy, contract, authority keys, revocation, budget and operation state. Clock passage is excluded from the digest and checked independently. Changing any bound input requires replanning. A hash and private Rust fields do not make this an authenticated remote offer or an approval.

`prepare_approved_offer` rechecks that basis and a fresh clock, verifies a real `SignedDeclassificationGrant`, and returns the actual `PreparedFlowAdmission`. Verification binds the complete source join, exact request bytes, capability, tenant, principal, agent, session, destination, tool, purpose and authority. Preparing this exception preserves the restricted source state. Converting it directly to an admission without required grant consumption fails.

| Observed state | Lab decision | Preparation |
|---|---|---|
| Before admission | Evaluate flow and possibly offer exact approval | Revalidate and prepare |
| Frozen denial before dispatch | A linked continuation is required | Refused for the old operation |
| Pending | Wait for its outcome | Refused |
| Outcome unknown | Reconcile the original operation | Refused |
| Complete | Recover the original outcome | Refused |

`ContinuationRequired` is advice. The lab does not allocate a new operation, persist a workflow link, or establish that another continuation is absent. Production must resolve these states from authoritative records and coordinate continuation ownership.

## What the tests establish

The lab's flow/grant tests cover successful preparation, stale policy/contract/flow/revocation/budget/authority observations, content and destination substitution, expiry, backward time, missing clearance, unknown labels, pending/unknown/completed/frozen-denied operations, and unrelated operation identity.

Six consumption tests call the real engine protocol through a test-only in-memory store. They cover single use, fresh-clock expiry, unavailable/missing stores, unknown and failed outcomes, wrong authority, and grant substitution. That fixture is not the production durability or dispatch implementation.

The two new process experiments exercise the real process store and kernel with a counting local tool server. A capability-denied call stays immutable after reopening its process store; attaching a signed fixture conflicts before dispatch. Its original denial can still be recovered. A distinct continuation consumes another logical call and remains denied by the original narrowed capability. A completed call rejects a changed authorization extension and recovers its original result without another effect. The signed fixture tests request identity, not successful disclosure verification; this embedding does not install the native flow runtime.

Separately, selected existing native declassification tests exercise SQLite-backed custody and kernel dispatch. They validate one executed disclosure, unchanged inherited restrictions, refused grant reuse, required lifecycle selection, signed claim substitutions, output/final-commit faults, and composition with nonce, runtime approval and proof of possession. Their results remain separate from the lab's preparation and mock-store results.

See [test results](evidence/test-results.json), retained logs, [demo](evidence/demo.json), and [source manifest](evidence/source-manifest.json) for exact source and observed counts.

## Reproduce

Run from this checkout root with Rust 1.94.1. Give Cargo one owner at a time. The optional target directory may be any directory with sufficient free space.

```sh
export CARGO_TARGET_DIR=/private/tmp/chio-openappa-recovery-target
export CARGO_BUILD_JOBS=2
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
export RUST_TEST_THREADS=1

cargo +1.94.1 test --locked --manifest-path labs/openappa-recovery/Cargo.toml
cargo +1.94.1 run --locked --manifest-path labs/openappa-recovery/Cargo.toml
cargo +1.94.1 clippy --locked --manifest-path labs/openappa-recovery/Cargo.toml --all-targets -- -D warnings
cargo +1.94.1 fmt --manifest-path labs/openappa-recovery/Cargo.toml -- --check
cargo +1.94.1 test --locked -p chio-flow --features std
cargo +1.94.1 test --locked -p chio-control-plane --lib native_flow::support::declassification
cargo +1.94.1 test --locked -p chio-process --test recovery_offer_binding_lab --test processes --test crash_recovery
cargo +1.94.1 test --locked -p chio-control-plane --test response_dry_run
```

These are development-checkout commands, not public install or release instructions. The lab has its own lockfile and empty workspace declaration; the root workspace manifest and lockfile are unchanged.

## Production integration seam

The existing `NativeFlowResolver` constructs a borrowed `PreparedNativeFlowDispatch` bound to resolver, authority custody and manifest/policy basis. Its `capture_invocation` takes native dispatch capture authority, samples time again, validates custody, joins disclosure evidence and native retention, and captures through the existing ledger/budget authority. The returned historical custody is not a transferable permit. The narrower `commit_custody` helper does not provide complete budget, credential or dispatch-ledger authority.

Connect a remedy to this capture path. Do not use the test store as the live grant-consumption service, dispatch directly from `PreparedFlowAdmission`, or treat a signed simulation report as live authorization.

`ProcessRuntime::invoke_with_recovery` hashes the entire tool request, including signed extensions, under its original operation identity. A remedy adding a grant to a known, already denied call needs a new operation and retained parent-denial/workflow link. This does not permit a new operation for an uncertain effect. Existing lifecycle-specific pending approval transitions must keep their own native resume contract.

The next vertical slice is a durable workflow containing a denied support disclosure, an owner-approved continuation, exactly one native send, process restart, original-result recovery, grant reuse refusal and unchanged source taint. Its failure matrix must cut between offer retention, approval arrival, continuation allocation, native capture, external effect, outcome retention and receipt delivery. This lab does not yet implement that joined workflow.
