# Shared Desktop Protocol and Mac Controller Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the authenticated Mac operator boundary over delivered native authority contracts, with closed message decoding, original-operation reconciliation and explicit unavailable features.

**Architecture:** A shared Rust `chio-desktop` controller owns protocol validation and projections. A signed Swift XPC bridge authenticates peers and carries bounded envelopes. Native kernel owners retain all positive authority and recovery obligations; native interfaces absent after M0 remain unavailable.

**Tech Stack:** Rust workspace, Swift Package `ChioDesktopContract`, XPC, JSON Schema 2020-12 contract vectors, RFC 8785 canonical commitments, native owner APIs delivered by M0.

---

Status: future implementation plan. This documentation change implements no product crate or Swift app. M0 supplies delivered native binding contracts. Read-only codec/UX work may proceed before M0 closes; mutation dispatch may not. Read [architecture](../../specs/2026-10-07-macos-integration/05-host-architecture.md), [wire contract](../../specs/2026-10-07-macos-integration/06-operator-protocol.md), and [M0](00-kernel-prerequisites.md). Coordinate the native package manifest with M1 instead of replacing it.

## File ownership

| Path | State and responsibility |
| --- | --- |
| `Cargo.toml` | Existing workspace; add the new desktop member after checking current conventions |
| `crates/products/chio-desktop/Cargo.toml` | Proposed crate manifest, minimal kernel adapter/codec dependencies |
| `crates/products/chio-desktop/src/operator/{mod.rs,codec.rs,correlation.rs,session.rs,dispatch.rs,events.rs}` | Proposed bounded protocol, correlation, peer session, native dispatch and hint projection modules |
| `crates/products/chio-desktop/src/platform/macos/{mod.rs,native_binding.rs}` | Proposed Mac bridge; binds only actual delivered native owner interfaces |
| `crates/products/chio-desktop/tests/{wire_vectors.rs,peer_session.rs,intent_recovery.rs,event_rebase.rs}` | Proposed contract and native integration regressions |
| `integrations/macos/native/Sources/ChioDesktopContract/` | Proposed generated Swift wire types and validated transport results; M1 UI consumes this target |
| `integrations/macos/native/Sources/ChioMacTransport/` | Proposed XPC service/client adapters and designated peer requirements |
| `integrations/macos/native/Tests/ChioMacTransportTests/` | Proposed connection/session/size/backpressure tests |
| `integrations/macos/contracts/` | Proposed build-consumed copy of reviewed operator schemas plus generation manifest linking their source digests |
| `integrations/macos/qualification/ipc.py` | Proposed installed peer/substitution/recovery test driver under the M8 harness |

### Task 1: Freeze reviewed wire inputs and build the strict codec

- [ ] Run the current document validator before scaffolding: `python3 docs/superpowers/specs/2026-10-07-macos-integration/verify.py --self-test`. Expected: document validation passes and runtime qualification is false. Record source schema and fixture digests in the generation manifest.
- [ ] Add the desktop crate as a workspace member and create an empty `operator::codec` module. Test first using reviewed vectors. The test imports the proposed public function `decode_request(bytes: &[u8]) -> Result<ValidatedRequest, DecodeError>`; these types belong in `codec.rs`, not in the native kernel ABI.

```rust
#[test]
fn duplicate_keys_fail_before_native_dispatch() {
    let body = br#"{"version":"chio.desktop.operator.v1","request_id":"one","request_id":"two","method":"health.get","params":{}}"#;
    assert!(chio_desktop::operator::codec::decode_request(body).is_err());
}

#[test]
fn oversized_envelope_is_rejected() {
    let body = vec![b' '; 65_537];
    assert!(chio_desktop::operator::codec::decode_request(&body).is_err());
}
```

- [ ] Run `cargo test -p chio-desktop --test wire_vectors`. Expected red: missing codec or failed rejection. Implement the codec using closed serde request variants generated from the reviewed method catalog, `deny_unknown_fields`, duplicate-aware map visitation before typed deserialization, explicit nesting and byte checks, integer-only JSON values, surrogate rejection, and checked `u64` decimal parsing. Match the document reference decoder's boundaries; do not rely on a generic JSON map that has already discarded duplicate keys.
- [ ] Define error variants `Size`, `Depth`, `Utf8`, `DuplicateKey`, `Number`, `UnknownField`, `UnknownMethod`, `InvalidReference`, and `Version`. Map them to safe operator codes; never include raw payloads. Add each reviewed invalid vector and the unsigned boundary `18446744073709551616` to the test loop.
- [ ] Run the same test for green and `cargo clippy -p chio-desktop --all-targets -- -D warnings`. Commit only the crate, workspace membership, generation inputs and tests with `feat: add strict desktop operator codec`.

### Task 2: Correlate replies and preserve native references

- [ ] Add response-substitution tests before implementation. A response must match the request's version, request ID and method; required task, operation, decision and subscription bindings must be present and agree. In particular, `task.stop` must echo the requested `task_id`, and `review.open` must echo the original `operation_ref`; absence is failure, not a skipped comparison. Include missing-binding and same-shape other-task/operation substitution cases, plus inline review content byte-count/digest checks. An error with an echoed operation must not substitute another native operation.

```rust
#[test]
fn approval_reply_cannot_change_decision() {
    let pair = fixture_pair("request-approval-submit", "invalid-decision-substitution");
    assert!(!pair.correlates());
}
```

`fixture_pair` is a test helper defined in `wire_vectors.rs`: read the named JSON files from the reviewed spec `examples/`, decode them with `decode_request` and the new `decode_response`, and return `ValidatedPair { request, response }`. Its `correlates` method calls the proposed `correlation::matches(&ValidatedRequest, &ValidatedResponse) -> bool`. It must not synthesize native references or mark fixtures as runtime evidence.

- [ ] Enforce the complete task-stop binding, including exact requested `scope`, and method-specific retry dispositions in generated clients and the codec. A method without an intent accepts only `never`/`reread`; mutation retries retain the original native tuple. Run every catalog method's checked-in negative fixtures, reject a catalog missing any declared positive/negative vector, and include same-task/different-scope and nonmutating `same_intent` controls before declaring wire coverage complete.
- [ ] Run `cargo test -p chio-desktop --test wire_vectors approval_reply_cannot_change_decision`. Implement the pure correlation function, then run the full fixture corpus for green. Keep native reference bytes and kind/issuer/generation/digest fields intact; actual native verification remains an adapter obligation.
- [ ] Add the `ChioDesktopContract` target to the Swift package coordinated with M1. Generate closed value types from the same reviewed schemas. Route untrusted envelope validation through the shared Rust codec before Swift UI projection; Foundation dictionary decoding alone does not satisfy duplicate-key rejection. Add a generated-input digest check to the build, failing if schemas change without regeneration.
- [ ] Run `swift test --package-path integrations/macos/native --filter ChioDesktopContractTests` and the Rust vector test against identical fixture digests. Commit with `feat: bind desktop replies to their original requests`.

### Task 3: Bind XPC peers, native principals and bounded sessions

- [ ] Create a `PeerBinding` value containing observed UID, audit-session identity, designated code-requirement digest and verified service identity. It is constructed only by the platform authenticator. Add a session state machine `Unauthenticated -> HelloComplete -> Closed`, with native principal binding supplied separately by the installed authority adapter.
- [ ] Write Swift transport tests for wrong signer, same-team unrelated app, changed audit session, service substitution, mutation before hello, repeated incompatible hello, 17th in-flight request and a 65th queued event. Use a disposable signed fixture app for installed identity tests; an injected identity struct is component evidence only.
- [ ] Run `swift test --package-path integrations/macos/native --filter ChioMacTransportTests`. Expected red before the checks. Implement designated peer requirements and fixed request/reply/event entrypoints; cap the data payload before copying; map peer loss to transport closure without discarding native obligations. Retain no bearer credentials in the bridge.
- [ ] In Rust, test the session boundary with the explicit rule below and implement it before dispatch:

```text
if peer is unverified: reject unauthenticated
if hello not completed and method != hello: reject unauthenticated
if hello repeats with conflicting nonce/version: close transport
if method mutates and native binding or selected profile is unavailable:
    reject prerequisite_unavailable before invoking a native mutation port
otherwise route through the typed method dispatcher
```

- [ ] Run `cargo test -p chio-desktop --test peer_session` for green. After M8 provides a signed installation, run `python3 integrations/macos/qualification/run.py --mode installed --case AT-MAC-IPC-001 --manifest /absolute/private/applied-profile.json --output /absolute/private/new-ipc-peer-run`. Expected: actual signed peer matrix passes; without signed fixtures it exits unavailable, never promotes component tests. Commit with `feat: authenticate Mac operator peers and sessions`.

### Task 4: Connect actual native owners and original-operation lookup

- [ ] Inspect delivered NK-01 through NK-09 artifacts from M0. Record each concrete native method/type and source path in `native_binding.rs` documentation. Do not introduce a trait implementation that returns fabricated allow/approval/completion when the owner is absent. The externally visible unavailable branch is a complete supported outcome.
- [ ] Define the adapter seam around the delivered native types: authenticate principal, inspect prerequisites, resolve native resource/reference, lookup original intent, admit a typed operation, inspect original operation, submit native endorsement, request native stop, and export evidence. The generated mapping must link each call to the crossing and stop census from spec 03. Avoid exposing native issuer internals as generic operator commands.
- [ ] Implement native reference resolution before any mutation: verify the registered kind and resource subtype, issuer, native ID, generation, digest, principal/session scope, current lifecycle, policy and stop applicability through the native owner. In `native_reference_matrix.rs`, independently mutate each field, swap workspace/input/grant/endorsement roles, and use foreign, stale, revoked and fabricated references. Assert zero mutation/secret/resource access before refusal, even for a schema-valid shape.
- [ ] Implement `task.create` attenuation against the native grant: require `project-change-v1`, the exact workspace and separately sealed objective, installed qualified profile, and cost/time ceilings no greater than the native parent allowance. Test unknown templates/profiles, incompatible or unqualified tuples, cross-principal inputs, mismatched input types, unavailable bootstrap influence, overflow and larger limits before readiness. Neither supplied limits nor a qualified-looking tuple may issue a grant; absent native checks refuse.
- [ ] Define an exhaustive native outcome-to-operator error mapping in `dispatch.rs`: definite refusal, unavailable prerequisite, stale reference, conflicting intent and unknown external outcome remain distinct closed codes/message keys. Permit only documented retry dispositions, and test every native branch with credential-bearing paths/errors; the serialized response/log must omit those canaries. Unrecognized native outcomes fail compatibility and never become a definite denial, success or fresh-intent retry.
- [ ] Add integration cases with native writer fault barriers and an independently counted resource sink. Two connections submit the same principal/method/intent/parameter commitment, then a changed commitment under the same intent. Drop the first successful reply after native dispatch. Expected: one original operation, one effect, changed retry conflicts, and recovered reply refers to the original. These tests require the delivered native store fixture from M0; absent fixtures make the integration group unavailable, not passed.
- [ ] Run `cargo test -p chio-desktop --test intent_recovery`. Implement only the mapping to real native interfaces and the read-only projection cache. Do not create a local authority journal. Repeat the test at before-intent, after-intent, after-effect and after-return barriers, and with stop/revocation/influence changes at the native writer. Commit with `feat: route Mac operator effects through native owners`.

### Task 5: Stable subscriptions, export and migration

- [ ] Write `event_rebase.rs` tests with two connections: pause publisher, acknowledge the stable subscription through the native owner, rebase another transport, then resume the stale publisher. Assert acknowledged state does not reappear and another subscription remains live. Run `cargo test -p chio-desktop --test event_rebase` for red.
- [ ] Before valid acknowledgement, test refusal for a still-live native subscription. Drop the first native end delivery, reconnect and require a `subscription.ended` replay before the client acknowledges its stable ID. Never synthesize that terminal from transport close or queue overflow; only the native retained end permits native acknowledgement.
- [ ] Implement and test principal/session-scoped pagination and cursor verification before reading records: reject page sizes above 100, invalid spelling, foreign/guessed/expired cursors, cross-session replay and excessive in-flight/queue use. Bind cursor scope/revision to the native subject or report a gap; no cursor can select another principal or silently discard native obligations. Run two-user pagination/subscription exhaustion with canaries and bounded memory observations.
- [ ] Implement bounded hint projection, explicit gaps, principal-scoped cursors and stable-ID acknowledgement through the delivered native owner. Define controller cursors as transport-only values. On restart, restore native binding or allocate a new transport subscription with a gap; never infer acknowledgement from an old sequence number. Rerun for green.
- [ ] Extend authoritative `task.get` and paginated task snapshots with full `stop_state` and native `durability`. Use the process-only, latch-only and durable fixtures, reject fenced process-only and missing durable reference, then disconnect after a lost stop reply and reread without a mutation. Native observations, not the prior local reply, determine the returned facts.
- [ ] Add evidence-export tests with an enrolled native destination, a forged path and a revoked destination. Route export through native release authority; retain unresolved external outcomes. Run the wire, native recovery and export cases together; no arbitrary filesystem destination is accepted by the protocol.
- [ ] Add an explicit Omarchy compatibility matrix fixture listing supported mappings by old/new version, method, identity, error and acknowledgement semantics. Run both adapters' vectors; unknown versions fail rather than alias. This task depends on the separately delivered Omarchy adapter; absent implementation keeps migration qualification unavailable without blocking the Mac codec's source tests.
- [ ] Commit with `feat: preserve desktop event and export authority across reconnects`. Hand M6 the exact native operation/subscription bindings and M1 the generated Swift contract, then run the combined M1/M2/M6 installed operator acceptance before enabling M3.

### Task 6: Add authenticated CLI equivalence without a second authority path

- [ ] Extend the existing CLI type and dispatch modules `crates/products/chio-cli/src/cli/{types.rs,dispatch/mod.rs}` with a proposed `desktop` subcommand and create `cli/desktop.rs` plus `tests/desktop_operator.rs`. The public command group is `chio desktop`; support `health`, `tasks`, `task show`, `task create`, `task stop`, `operation show`, `review`, `approve`, `events`, and `evidence export` by translating to the same closed operator methods. Preserve current CLI commands. Unknown flags/verbs fail parsing rather than invoking a shell or alternate kernel path.
- [ ] Use the packaged signed CLI identity and the authenticated XPC bridge from Task 3. The installed service separately enrolls that exact designated client requirement, verifies UID/audit session and resolves the native principal. An unsigned development CLI can exercise codec fixtures but receives unavailable for installed mutations. Do not grant every same-team binary service access. Add service-substitution, unrelated signer, foreign-user and expired-session cases before native dispatch.
- [ ] Add command parser fixtures with only explicit native IDs/references and canonical limits. Enrollment remains the trusted native resource-selection bridge; a CLI file path cannot become authority. `review` opens the trusted native review flow and prints its verified original-operation status; `approve` forwards a native-issued endorsement for that exact review and decision. There is no `--yes` mechanism that mints an endorsement and no token/secret on argv. Missing native UI/session support returns unavailable.
- [ ] Run `cargo test -p chio-cli --test desktop_operator`. Drive the same fixture operations through the native app and packaged CLI, compare canonical requests, per-field refusal, original-operation identity and observed native side effects. Force lost replies and repeated intents from both clients and require one effect and native reconciliation. Exiting either client does not cancel durable work. Installed signed CLI/app equivalence is an M8 case; parser/component success alone does not enable the profile.
- [ ] Commit only these CLI integration files with `feat: add authenticated desktop operator CLI`. Record the packaged CLI signature in the installed tuple and require an explicit client-identity update when it changes.

## Exit criteria

All MAC-ARC and MAC-IPC acceptance procedures have a named test or installed case, closed codec vectors pass, generated Swift/Rust contracts use the same schema digests, and native prerequisites remain unavailable unless actually delivered. A document or mocked test pass is insufficient for runtime mutation. M3 consumes the authenticated controller only after M6 recovery and the selected execution profile also qualify.
