# Mac Native Enforcement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build independently testable ES and NE restrictive adapters and enable a native or managed profile only when its exact installed containment, identity and failure behavior passes qualification.

**Architecture:** The Rust native serving writer keeps all positive authority and produces authenticated derived restriction views. Swift providers apply only additional denials, retain actual OS identity/flow observations and report coverage gaps. Observation, native descendants and managed-host enforcement have separate permission, lifecycle and release gates; no provider-local approval ledger or sensor receipt replaces a kernel crossing.

**Tech Stack:** Rust shared controller/native-owner integration, Swift EndpointSecurity and NetworkExtension, SystemExtensions packaging, strict canonical JSON provider snapshots, signed Mac lab probes, Python evidence checks, controlled TCP/UDP/HTTP receiver.

---

Status: Proposed work. Nothing here claims implemented providers or installed enforcement. All listed Mac paths are proposed unless M1/M2 created the common scaffold. M0 native contracts and M6 recovery precede this track. M5 can proceed independently of the VM product after those dependencies; native-descendant and managed-endpoint release still depend on M8 distribution/qualification. The macOS 27 API investigation keeps its research/beta qualification gate: earlier research said beta, current Apple DocC metadata says `beta:false`, and final SDK/runtime/entitlement qualification has not been established. Preserve those separate facts.

Primary references and source pins: [Apple platform research](../../specs/2026-10-07-macos-integration/research/apple-platform.md), [ES contract](../../specs/2026-10-07-macos-integration/08-endpoint-security.md), [NE contract](../../specs/2026-10-07-macos-integration/09-network-extension.md), [reuse contract](../../specs/2026-10-07-macos-integration/18-clawdstrike-reuse.md). The inspected Chio baseline has no `integrations/macos/`; the checked Clawdstrike monitor subscribes to `AUTH_OPEN`, and its egress policy targets host/port. Neither is a complete native Chio task boundary.

## Files and ownership

| Proposed file/target | Responsibility |
| --- | --- |
| `integrations/macos/native/Sources/ChioRestrictions/RestrictionState.swift` | Monotonic restrictive state, TTL/conflict rules, no authority signing |
| `integrations/macos/native/Sources/ChioRestrictions/RestrictionDecoder.swift` | Bounded authenticated input bridge after native provenance verification |
| `integrations/macos/native/Sources/ChioEndpoint/EndpointClient.swift` | ES lifecycle, subscriptions and correct response ownership |
| `integrations/macos/native/Sources/ChioEndpoint/EndpointIdentity.swift` | Audit-token/incarnation/run mapping and explicit unknowns |
| `integrations/macos/native/Sources/ChioEndpoint/EndpointCoverage.swift` | Version-aware sequence/epoch/gap/mute accounting |
| `integrations/macos/native/Sources/ChioEndpoint/NativeLaunchBarrier.swift` | Trusted caller, clean child launch and independently verified containment |
| `integrations/macos/native/Sources/ChioNetwork/FlowIdentity.swift` | App versus process attribution and scoped mapping |
| `integrations/macos/native/Sources/ChioNetwork/FlowRegistry.swift` | Retained flow lifecycle, restrictive generation, revocation state |
| `integrations/macos/native/Sources/ChioNetwork/ContentFilterProvider.swift` | Actual NE allow/drop/update paths and bounded provider lifecycle |
| `integrations/macos/native/Sources/ChioEnforcementProbe/main.swift` | Signed installed ES/NE experiments and observation export |
| `integrations/macos/contracts/restrictions-v1.schema.json` | Proposed closed native-derived restriction transport shape |
| `crates/products/chio-desktop/src/platform/macos/enforcement.rs` | Native owner provenance/fence mapping and honest health projection |
| `crates/products/chio-desktop/tests/macos_enforcement_contract.rs` | Provider/native authority and multi-user integration tests |
| `integrations/macos/qualification/es-coverage.json` | Exact SDK event/call coverage matrix and observed exceptions |
| `integrations/macos/qualification/native-cases.json` | All ES/NE acceptance procedures and profile-specific environments |
| `integrations/macos/qualification/verify_native_evidence.py` | Outside-observer and native-proof composition checks |

Coordinate `integrations/macos/native/Package.swift` targets with the M1 operator and M3 VM owners. M8 owns signing/entitlement/extension bundles; this plan supplies target capability requirements, not ad hoc local signing exceptions. Native owner changes remain in M0's kernel/store modules. `RestrictionState` is an observation/restriction machine and cannot implement missing native approval, budget, stop or delegated authority.

### Task 1: Pin API feasibility and refuse unsupported native execution

**Files:** Create `integrations/macos/qualification/native-prerequisites.json`, `integrations/macos/tests/fixtures/enforcement/unavailable-native.json`, `integrations/macos/qualification/sdk-probe.c`.

- [ ] Capture `sw_vers`, `uname -m`, `xcodebuild -version`, and `xcrun --sdk macosx --show-sdk-path` into the future evidence bundle. Read the actual SDK headers for `es_new_descendants_client`, `es_set_deadline_miss_mode`, `es_sync_client`, event availability and message versions; retain SDK/header hashes. Do not infer availability from online metadata alone.
- [ ] Create a compile-only feature probe with complete source:

```c
#include <EndpointSecurity/EndpointSecurity.h>
int main(void) {
    (void)&es_new_descendants_client;
    (void)&es_set_deadline_miss_mode;
    (void)&es_sync_client;
    return 0;
}
```

Run `xcrun clang -fsyntax-only -Werror integrations/macos/qualification/sdk-probe.c`. Expected: explicit compiler failure on a missing SDK API; success establishes only header availability. Runtime and signed entitlement tests follow later.
- [ ] Create the closed unavailable fixture: `{"profile":"native-descendant-v1","final_sdk_verified":false,"entitlement_verified":false,"continuous_containment_verified":false,"installed_enforcement_verified":false,"expected":"profile_unavailable"}`. Test through M2 profile preparation that no native child starts and no substitute global ES client or remote task launches.
- [ ] Require M0's actual native provenance/current-fence owner, M6's original-operation recovery and M8's entitled signed installation records. Missing provenance means provider state cannot become usable. The profile remains unavailable if client death or inherited/delegated channels cannot be continuously contained.
- [ ] Run `cargo test -p chio-desktop --test macos_enforcement_contract unavailable_native_never_launches`. Expect failure until the gate exists, then zero launch/receiver effects. Commit only feasibility probe, fixtures and gate tests with `git commit -m "test(macos): gate native execution on platform feasibility"`.

### Task 2: Implement restrictive generation, conflict and expiry semantics

**Files:** Create `RestrictionState.swift`, `RestrictionDecoder.swift`, `restrictions-v1.schema.json`, `integrations/macos/native/Tests/ChioRestrictionsTests/RestrictionStateTests.swift`.

- [ ] Define the transport schema as `chio.macos.restrictions.v1` with exact authority/installation/user/provider epoch, run/launch references, policy digest, generation, canonical snapshot digest, native stop reference, authority expiry, non-extending elapsed validity and closed deny rules. Restriction provenance is verified through the actual native owner before constructing local verified input; a structurally valid JSON object cannot construct positive authority.
- [ ] Add the failing test and pure state implementation below. This state intentionally cannot output a semantic permit.

```swift
import XCTest
@testable import ChioRestrictions

final class RestrictionStateTests: XCTestCase {
    func testConflictAndExpiryCannotBecomeAllow() {
        var state = RestrictionState()
        XCTAssertEqual(state.install(generation: 8, digest: "a", expires: 100), .installed)
        XCTAssertEqual(state.install(generation: 7, digest: "b", expires: 200), .rejected)
        XCTAssertEqual(state.assess(now: 99), .restrictionCurrent)
        XCTAssertEqual(state.assess(now: 100), .closeManaged)
        XCTAssertEqual(state.install(generation: 8, digest: "c", expires: 200), .conflict)
        XCTAssertEqual(state.assess(now: 1), .closeManaged)
    }
}
```

Run `swift test --package-path integrations/macos/native --filter RestrictionStateTests`, expecting missing types initially. Implement:

```swift
public enum RestrictionInstall: Equatable { case installed, repeated, rejected, conflict }
public enum RestrictionAssessment: Equatable { case restrictionCurrent, closeManaged }
public struct RestrictionState {
    private var current: (generation: UInt64, digest: String, expires: UInt64)?
    private var quarantined = false
    public init() {}
    public mutating func install(generation: UInt64, digest: String,
                                 expires: UInt64) -> RestrictionInstall {
        guard !quarantined else { return .rejected }
        if let old = current {
            if generation < old.generation { return .rejected }
            if generation == old.generation {
                if digest == old.digest && expires == old.expires { return .repeated }
                quarantined = true
                return .conflict
            }
        }
        current = (generation, digest, expires)
        return .installed
    }
    public func assess(now: UInt64) -> RestrictionAssessment {
        guard !quarantined, let value = current, now < value.expires else {
            return .closeManaged
        }
        return .restrictionCurrent
    }
}
```

Here `now`/`expires` are an already verified elapsed deadline pair for the current provider epoch, not wall time or user input. The decoder/native bridge supplies the earlier absolute-authority/local deadline; loss of trusted time or wake invalidates this state until reconciliation. `restrictionCurrent` is only freshness. Rule evaluation can still deny and the native owner must independently admit every semantic effect. A new snapshot cannot be forged by directly calling this internal state helper from untrusted transport.
- [ ] Add tests for wrong authority/user/run, rollback after provider restart, equal generation changed expiry, wall-clock rollback and sleep past expiry. Decode rejects over 1 MiB, duplicate keys, over 32 nesting levels, unknown fields and noncanonical numbers before installation; cap 4,096 rules and 1,024 run bindings per snapshot as initial design limits. Overflow denies selected bindings and records degradation.
- [ ] Implement owner-scoped restriction composition in `RestrictionState.swift`: retain independently authenticated administrator and task contributions with distinct issuer, scope, generation and digest. Effective allowed transport is the intersection of all applicable restrictions, implemented as the union of their deny constraints over the verified scope. Install the complete composed view atomically, preserving the more restrictive view during handover. A task update, expiry or removal cannot delete an administrator contribution, and administrator removal cannot erase a task deny or confer native authority. Unknown task freshness still closes that task as specified; unrelated host traffic receives only its separately authorized administrator policy.
- [ ] Add composition tests for task-permits/admin-denies, task-denies/admin-permits, concurrent updates, same-generation conflict and independent issuer removal. Race new and retained flows against each transition and retain an unrelated-user control. The affected receiver must remain denied whenever either applicable owner denies; removing one contribution must preserve the other's restriction. Wrong-issuer removal and a task snapshot attempting global administrator scope must refuse before installation. Pass the authenticated composed digest to Task 6 rather than allowing the last snapshot to replace every owner's rules.
- [ ] Run the focused tests, verify authenticated view construction against M0, and commit with `git commit -m "feat(macos): enforce monotonic restrictive snapshots"`.

### Task 3: Implement ES client lifecycle and bounded response handling

**Files:** Create `EndpointClient.swift`, `EndpointCoverage.swift`, `integrations/macos/native/Tests/ChioEndpointTests/EndpointClientTests.swift`; populate `es-coverage.json`.

- [ ] Add a table-driven fixture with event type, SDK/OS availability, AUTH/NOTIFY, response function, required fields, mutation coverage and bypass probe. Include exec/fork/exit, open flags, create/rename/unlink/link/truncate, mmap/mprotect, NOTIFY write/close and delegated-service probes. Missing event/field is unavailable, not an empty default.
- [ ] Define internal `EndpointResponse` cases `denyFlags`, `denyAuth`, `restrictiveFlags(UInt32)` and `noAuthResponse`. The flags value can only further intersect an independently admitted operation's rights. Define `EndpointResponseResult` containing OS response return code, before-deadline boolean, response count and sensor event reference. An allow-like OS reply is not a native operation receipt.
- [ ] Write mocked callback tests for correct flags/auth responder selection, exactly-once response, no response to NOTIFY, retain/release balance when work is deferred, full queue and malformed message. Add a deliberately blocked UI/DB/XPC dependency; the callback must still issue bounded denial. Run `swift test --package-path integrations/macos/native --filter EndpointClientTests`, expecting failure before client implementation.
- [ ] Implement callbacks with a fixed bounded work queue, precomputed restrictive views, monotonic deadline checks and checked OS return codes. Start with `cache: false`. Do not call human/model/database/network services from the handler. Record denied-on-stale, unsupported-event, deadline/response failure and queue overflow distinctly. For macOS 27, select fail-closed deadline mode and check the setter result before untrusted launch; lack of mode cannot inherit the guarantee.
- [ ] Record `seq_num` only when message version is greater than 2, `global_seq_num` only when greater than 4, plus per-client sensor epoch. Compare per-type and global counters independently. Treat mute changes, subscription changes, failed responses and dropped telemetry as coverage events. A sync callback on deleted/null client never sets `drained_live`.
- [ ] Rerun component tests, compile against supported and unsupported SDK targets, then commit with `git commit -m "feat(macos): add bounded Endpoint Security adapter"`. These are component results; Task 9 proves actual OS effects.

### Task 4: Bind native launch identity and prove containment feasibility

**Files:** Create `EndpointIdentity.swift`, `NativeLaunchBarrier.swift`, `integrations/macos/native/Tests/ChioEndpointTests/NativeIdentityTests.swift`, corpus under `integrations/macos/qualification/native-escape/`.

- [ ] Define local `ObservedProcessIdentity` with boot/provider epoch, UID, full audit token, PID version/incarnation, executable identity and optional responsible/parent tokens. Native run/launch binding is an independently verified association, not a field trusted from the process. Test PID reuse, same-name processes, exec, fork, reparent and XPC-created work. A stale association cannot signal or grant a new process.
- [ ] Implement a minimal trusted caller with no task-supplied code loaded in-process. Create/configure the descendant client, install restrictive state and acquire the independent containment boundary before child execution. Caller actions are NOTIFY-only under the documented descendant client. Preexisting children are not used in production launch; the lab separately tests Apple's documented existing-child scope.
- [ ] Create an executable corpus that attempts inherited writable FD, socket, writable mmap, Mach send right, bootstrap lookup, launchd submission, existing XPC helper, Apple Events, Accessibility, setuid/setgid exec, sibling task access and process injection. Every probe writes a unique synthetic counter to a controlled outside receiver. The positive control performs the same operation with the lab boundary disabled.
- [ ] Keep unsupported inherited/Mach/service channels closed by a supported containment mechanism or mark `native-descendant-v1` unavailable. Closing new file opens or killing the child after detecting an effect does not pass. If native build phases use the runner, include package hooks/plugins and host build helpers in this corpus.
- [ ] Run `swift test --package-path integrations/macos/native --filter NativeIdentityTests`. Later Task 9 runs actual escape probes; do not let component passing set `continuous_containment_verified`. Commit identity and launch-barrier work with `git commit -m "feat(macos): bind native descendants to verified launch custody"`.

### Task 5: Implement NE attribution without global-policy accidents

**Files:** Create `FlowIdentity.swift`, `integrations/macos/native/Tests/ChioNetworkTests/FlowIdentityTests.swift`; extend Rust per-user enforcement tests.

- [ ] Use this complete explicit mapping vocabulary:

```swift
public enum FlowAttribution: Equatable, Sendable {
    case managedTask(runReference: String, launchReference: String)
    case broker(operationReference: String)
    case unrelatedHost(userID: UInt32)
    case ambiguous(reason: String)
}
```

These strings are opaque retained references, not new authority identifiers. Preserve both `sourceAppAuditToken` and `sourceProcessAuditToken` and validate incarnation against the host-enrolled binding. A source application token can differ from the process token for delegated networking; do not replace one with the other. Missing tokens cannot match all runs.
- [ ] Add fixtures for two identical Node processes, helper-created URLSession flows, old PID version, app/process conflict, absent tokens, two users and broker-owned networking. The mapper returns ambiguous for insufficient evidence. An unrelated host flow follows only explicit pass-through or independent managed policy; a selected worker must never reach that branch merely because its mapping failed.
- [ ] Test a worker whose unattributed helper can make a connection. Unless independent containment blocks it, profile preparation fails; do not fix the test by blanket host blocking. Run `swift test --package-path integrations/macos/native --filter FlowIdentityTests` and `cargo test -p chio-desktop --test macos_enforcement_contract user_scope_and_unknown_flow`. Expected: no cross-user leaks and no profile protection claim over unknown routes.
- [ ] Commit mapping/tests with `git commit -m "feat(macos): preserve scoped app and process flow identity"`.

### Task 6: Install NE restrictions and revoke existing flows

**Files:** Create `FlowRegistry.swift`, `ContentFilterProvider.swift`, `integrations/macos/native/Tests/ChioNetworkTests/FlowRevocationTests.swift`; add `integrations/macos/tests/fixtures/enforcement/flow-lifecycle.json`.

- [ ] Define the local flow registry API: `register(flow:identity:observedGeneration:)` retains the actual `NEFilterSocketFlow`; `apply(snapshot:)` installs an already native-verified view atomically; `closeManaged(runReference:generation:)` schedules drop updates for retained matching flows; `observeTerminal(flow:)` retires its handle; `snapshot()` returns requested/applied generations and remaining/unknown counts. Neither return from `apply` nor an empty locally lost table proves remote closure.
- [ ] Add failing tests that create existing/new flows during update, reject older generations, quarantine equal-generation conflicts, expire policy midstream and lose the controller. Assert both existing and new managed flows enter drop/closure, while unrelated flows remain under their own policy. Test table overflow and a lost flow handle; the affected guarantee must degrade rather than report zero remaining.
- [ ] Implement real content-filter verdict paths. Retain eligible socket-flow handles and use `update(_:using:for:)` with drop on current stop/revocation. Verify exact SDK support and actual behavior after initially allowing a flow; if the OS ceases to expose effective control, refuse that profile. Initial queue/table bounds are 4,096 managed flows and 1,024 pending updates per provider; exceeding either closes affected task routes and refuses new task launches.
- [ ] Require native broker connection ownership: per-run pools for independently stopped work. A shared HTTP/2 connection cannot be called per-task closed after one stream cancellation. Conservative shared-pool closure records every affected native operation and reconciles lost results. Retain bytes-released and remote completion/unknown state separately.
- [ ] If transparent proxy is selected in a later independently qualified candidate, managed traffic returns handled and is explicitly closed on failure. It must not return false to ask the OS to connect directly. Close both local and remote sides, use bounded buffers, and test stalls/half-closes. Content-filter evidence does not qualify this separate provider.
- [ ] Run `swift test --package-path integrations/macos/native --filter FlowRevocationTests` and `cargo test -p chio-desktop --test macos_enforcement_contract broker_pool_closure`. Expected: current tests prove provider control calls and state only; real remote byte counts await Task 9. Commit with `git commit -m "feat(macos): retain and revoke managed network flows"`.

### Task 7: Integrate authority, stop, health and recovery

**Files:** Create `crates/products/chio-desktop/src/platform/macos/enforcement.rs`; extend `macos_enforcement_contract.rs`; coordinate M6 projection and M1 health UI.

- [ ] Map actual native restrictive views to provider snapshots through authenticated, versioned controller-provider IPC. Reuse the M2 peer/canonical envelope rules but keep provider methods separate from public operator methods. Define only internal commands `replaceRestrictions`, `inspectAppliedGeneration`, `closeManagedFlows` and `exportSensorCoverage`; none submits an approval or issues a native operation.
- [ ] Add a fixture where ES/NE allows transport/open while the native owner denies changed artifact, destination, resource generation, budget or approval. Assert the actual broker target receives zero effect. Add a native intent committed before stop and release after stop; preserve possible precommitted effect, reject later release and retain original unresolved outcomes.
- [ ] Project separate installed, approved, activated, synchronized, effective, degraded, admission-fenced, worker-exited and flows-closed facts. Sensors include their own epoch/gaps; provider generation acknowledgements remain hints until reconciled. M6 owns original operation recovery; a provider reboot cannot reset a stop generation or renew TTL.
- [ ] Exercise controller/provider disconnect, permission withdrawal, failed activation, logout, user switch, lock, reboot and interrupted upgrade. Missing state closes selected task execution; managed global default follows its declared administrator policy. No profile is silently downgraded to observation or converted to host-wide blocking.
- [ ] Run `cargo test -p chio-desktop --test macos_enforcement_contract`. Expected: original authority remains exclusive; fake sensor crossing and fabricated provider success are rejected; all health facts remain independently reportable. Commit with `git commit -m "feat(macos): reconcile restrictive provider state with native authority"`.

### Task 8: Add destination/privacy/performance negative corpus

**Files:** Create `integrations/macos/tests/fixtures/enforcement/destinations.json`, `integrations/macos/native/Tests/ChioNetworkTests/DestinationTests.swift`, `integrations/macos/native/Tests/ChioEndpointTests/CoverageTests.swift`.

- [ ] Build destination cases with explicit expected canonical selectors and refusal outcomes: case/trailing-dot hostnames, IDNA, invalid ports, IPv6 scope/IPv4-mapped forms, CNAMEs, redirects and DNS rebinding. Keep protocol and actual resolved address provenance; textual host/port normalization cannot authorize a changed endpoint.
- [ ] Include WebKit/URLSession, alternate HTTP stacks, direct sockets, cached DNS, DoH/DoT and loopback/link-local probes. DNS/URL-filter candidates only claim their observed coverage; arbitrary native task protection requires an independently closed route for every bypass.
- [ ] Add ES sequence version tests: version 2 has no per-type counter, version 3 has per-type only, version 5 has both. Inject gaps and client restart; reject a sync callback after teardown as live drain. Include cache-clear failure, explicit mute and coexisting client tests.
- [ ] Flood sensitive synthetic paths/hostnames while reader/storage is stalled. Require queue/table/memory caps, redacted diagnostic outputs and loss counters; no content/payload capture by default. Proposed initial provider snapshot cap and callback budgets must be measured against the workload and tightened if required. Do not declare a latency target as a measured result.
- [ ] Run `swift test --package-path integrations/macos/native --filter DestinationTests` and `swift test --package-path integrations/macos/native --filter CoverageTests`. Expected: malformed destinations never widen scope and coverage gaps cannot produce a complete evidence claim. Commit with `git commit -m "test(macos): cover attribution destination and telemetry gaps"`.

### Task 9: Qualify actual installed denial, closure and restoration

**Files:** Create `ChioEnforcementProbe/main.swift`, `native-cases.json`, `verify_native_evidence.py`, `integrations/macos/tests/test_native_evidence.py`, controlled receiver `integrations/macos/qualification/network_receiver.py`.

- [ ] Define the installed probe CLI `ChioEnforcementProbe run --profile PROFILE --cases PATH --receiver URL --output DIRECTORY --installation-manifest PATH`. It supports only `observe-v1`, `native-descendant-v1` and `managed-endpoint-v1`, with separate result bundles; incompatible permissions/profile refuse. The signed binary/extension paths come from M8's actual installation manifest. Test automation never grants permissions or installs global policy just by running component tests.
- [ ] Enumerate every ES and NE acceptance ID with required outside observer, OS/architecture/profile and cutpoint. Run ordinary callbacks, missed deadlines, queue-full AUTH, client kill/disconnect/delete, subscription/permission loss, cache/mute changes and setuid/setgid behavior as separate cases. Do not merge client death into deadline-miss testing.
- [ ] Receiver protocol uses per-case random synthetic identifiers and monotonically increasing sequence numbers. Record server-observed timestamp, bytes and effect count independently from the provider. Network cases include new flow, long-lived TCP, keep-alive, HTTP/2 concurrent streams, UDP/QUIC, inbound/listener, both directions, buffered bytes and DNS rebind. The receiver must prove a positive control reaches it with the test restriction removed.
- [ ] Define each qualification row with `case_id`, `profile`, `os_build`, `sdk_digest`, `architecture`, `signed_component_digests`, `entitlement_result`, `provider_epoch`, `native_fence_ref`, `desired_generation`, `applied_generation`, `observer_digest`, `positive_control_passed`, `post_convergence_effect_count`, `unresolved_outcomes`, `continuous_containment`, `coverage_gaps` and `verdict`. `continuous_containment` is the independent experiment result, not a field trusted from the provider.
- [ ] Start the verifier with this complete core refusal predicate, then compose digest/signature/current-profile checks using the M0/M6 verifier:

```python
def continuous_native_case_passes(row):
    if row.get("positive_control_passed") is not True:
        return False
    if row.get("continuous_containment") is not True:
        return False
    if row.get("coverage_gaps") != []:
        return False
    observed = row.get("post_convergence_effect_count")
    if type(observed) is not int or observed != 0:
        return False
    desired, applied = row.get("desired_generation"), row.get("applied_generation")
    if type(desired) is not int or type(applied) is not int or desired != applied:
        return False
    return True
```

This predicate is necessary, not sufficient: a zero count after a claimed convergence point does not excuse an unguarded interval. `continuous_containment` must be independently established across the entire failure window, and the actual native stop contract still permits previously committed effects. The verifier classifies those original effects by native intent/fence evidence instead of wrongly treating all post-stop remote bytes as new unauthorized admission.
- [ ] Test missing observer, broken receiver, wrong architecture, mutated digest, lost coverage, provider-only receipt, same-generation conflict and mock-only entitlement. Example: `assert not continuous_native_case_passes({"positive_control_passed": True, "continuous_containment": False, "coverage_gaps": [], "post_convergence_effect_count": 0, "desired_generation": 3, "applied_generation": 3})`. Run `python3 -m unittest discover -s integrations/macos/tests -p 'test_native_evidence.py'`; all false-green fixtures must reject.
- [ ] On the explicit clean lab installation, run the probe once for each selected profile and tuple, then `python3 integrations/macos/qualification/verify_native_evidence.py --bundle output/macos-native-qualification --profile native-descendant-v1`. Expected: independently verified full coverage or nonzero `unqualified`; entitlement denial, unsupported SDK and client-death escapes remain precise unavailable reasons. The managed profile runs and verifies its own bundle, with multi-user privacy and unrelated-host positive controls.
- [ ] Demonstrate block then restore for harmless local canary operations and controlled network targets. Retain receiver logs, signed component/OS pins, native evidence and redacted sensor coverage separately. Commit probe/verifier/corpus source with `git commit -m "test(macos): qualify installed ES and NE enforcement"`; machine-specific results go to M8 evidence storage.

## Owned prerequisite closure and coverage

| Owner / task | Required result |
| --- | --- |
| M0 kernel owner / Task 1 | Actual native provenance, current fence, original operation and confinement-reference verification APIs with rejection tests; no local shim authority |
| M6 recovery owner / Task 7 | Original-effect reconciliation and truthful stop dimensions after crash/sleep/restore |
| M8 distribution owner / Tasks 1 and 9 | Real signed entitlement/activation record, clean-machine provider lifecycle, version/rollback handling |
| Native enforcement owner / Tasks 2-4 | ES generation, deadline/queue/cache/client-death and inherited-channel evidence |
| Native enforcement owner / Tasks 5-6 and 8 | NE attribution, existing-flow revocation, protocol/destination/failure coverage |
| Native enforcement owner / Task 9 | Independent observer qualification; unavailable profile if a critical gap remains |

| Task | Acceptance coverage |
| --- | --- |
| 1 | AT-MAC-ES-001, AT-MAC-ES-002, AT-MAC-NE-001 |
| 2 | AT-MAC-ES-010, AT-MAC-NE-005, AT-MAC-NE-006, AT-MAC-NE-007 |
| 3 | AT-MAC-ES-006, AT-MAC-ES-007, AT-MAC-ES-008, AT-MAC-ES-009, AT-MAC-ES-012, AT-MAC-ES-013 |
| 4 | AT-MAC-ES-003, AT-MAC-ES-004, AT-MAC-ES-005 |
| 5 | AT-MAC-ES-014, AT-MAC-NE-003, AT-MAC-NE-004, AT-MAC-NE-017 |
| 6 | AT-MAC-NE-008, AT-MAC-NE-009, AT-MAC-NE-010, AT-MAC-NE-011, AT-MAC-NE-012 |
| 7 | AT-MAC-ES-011, AT-MAC-ES-015, AT-MAC-ES-016, AT-MAC-NE-002, AT-MAC-NE-015 |
| 8 | AT-MAC-ES-018, AT-MAC-NE-013, AT-MAC-NE-014, AT-MAC-NE-016 |
| 9 | All preceding installed cases, plus AT-MAC-ES-017 and AT-MAC-NE-018 |

- [ ] Review every claimed ES operation against the actual SDK manifest and every NE route against an independent receiver. No compile/test/activation check may stand in for effective installed denial.
- [ ] Run focused Rust/Swift/Python checks; run `cargo fmt --all -- --check`, `cargo clippy --workspace -- -D warnings`, `cargo build --workspace`, `cargo test --workspace` on the final implementation head. Preserve unrelated working-tree changes and record unavailable checks honestly.
- [ ] Hand off separate component, signed-installation and qualified-profile records to M8. Keep observe, brokered, VM, native-descendant and managed-host claims separate. A successful managed endpoint demo does not qualify arbitrary native worker execution.
