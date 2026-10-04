# Inbound authority implementation plan

> Use superpowers:executing-plans inline, then one independent integrated review.

**Goal:** implement AP4-AP6 and the two threshold ingress repairs.
**Architecture:** explicit local route policy, proof-carrying session operations,
strict confirmation decoding and authenticated proxy transport context.
**Tech stack:** Rust, Axum, existing Chio cryptographic and replay primitives.
**Spec:** [design](../specs/2026-10-02-inbound-authority-design.md).
**Base:** `e84e53ae436ed8d8e2e5b85e62dea185cf7c33d6`.

## Global Constraints

Fail closed; preserve typed local causes and redacted wire errors. No new runtime dependency,
lint allowance, debt increase or weakened negative assertion. Existing publication
authorization applies. Root owns implementation, serialized Cargo and Git.

### Task 1: AP4 route authority

Files: API-protect evaluator, proxy configuration/spec loading, CLI API flags and
HTTP authority policy projection. New focused inbound-authority tests.
Interfaces: local anonymous-read opt-in and path plus SHA-256 pin; unconditional
unmatched denial survives HTTP authority projection and client route hints.

- [x] Reproduce unmatched GET/POST (with and without capability), anonymous known
  GET and upstream POST side-effect override. Assert 403 and zero upstream calls.
- [x] Implement deny-all unmatched policy, explicit anonymous opt-in, verified
  local spec provenance and conservative overrides. Wire CLI flags.
- [x] Verify honest matching capability, pinned override, hash mismatch, ambiguous
  source, approval-required and unknown-route denial even under opt-in.
- [x] Run `cargo test -p chio-api-protect --lib` and focused HTTP policy tests.
  Expected: all pass. Retain any unrelated original failures separately.

### Task 2: AP5 invocation proof consumers

Files: core session/message DTOs; kernel session adapter; control-plane kernel
composition; MCP edge metadata; HushSpec model/compiler/merge; HTTP/API projection
and CLI consumers where they normalize operations.
Interfaces: `ToolCallOperation.dpop_proof` and `_meta.chioDpopProof`; shared clock
and long-lived replay ownership. Unsupported projections deny proof-required grants.

- [x] Reproduce required-proof drops with signed honest proof and tool invocation
  count; verify missing/foreign/replayed proofs refuse without invocation.
- [x] Carry proof data through session, MCP and native consumers; install shared
  replay custody and compile/inherit `tool_access.dpop_required` on every grant.
- [x] Remove authority inferred solely from capability subject where a production
  authenticated principal exists; preserve explicit bearer-policy limitations.
- [x] Run changed policy/session/MCP/HTTP owner suites. Expected: pass, with honest
  success and rejection controls, no required proof silently downgraded.

### Task 3: AP5/AP6 transport sender authority

Files: MCP remote confirmation claims, verifier, HTTP authentication composition,
CLI/configuration, trusted transport module and actual request tests.
Interfaces: authenticated socket peer plus dedicated proxy credential produces
transport identity. Sender verifier never reads untrusted binding headers directly.

- [x] Reproduce signed jkt-only and unknown/empty confirmation acceptance, and
  self-set certificate/attestation header bypass. Expected: initial controls fail.
- [x] Reject unsupported confirmation; validate trusted proxy configuration and
  derive a typed transport context before JWT, introspection and local OAuth use.
- [x] Verify honest trusted-proxy and Chio sender proof flows; reject forwarded-IP,
  wrong/missing proxy credential, direct self-header, malformed and replayed proof.
- [x] Run `cargo test -p chio-mcp-remote --lib`. Expected: all owner tests pass.

### Task 4: Threshold ingress and integrated handoff

Files: API-protect approval handlers/tests, security reader contracts/inventory,
roadmap queue and execution record.
Interfaces: original-body strict reader before CreateThresholdProposalRequest and
SubmitThresholdApprovalRequest; response causes remain local and redacted.

- [x] Reproduce duplicate keys/numeric loss through actual protected routes;
  implement strict bounded body decoding and test honest success/no mutation.
- [x] Reconcile checked reader/clock/wire/hygiene contracts without debt growth.
- [x] Run affected owner suites, strict Clippy, formatting and source gates;
  retain commands, terminal exits, log/source/binary hashes and failed attempts.
- [x] Independent integrated review; fix important findings with RED/GREEN.
- [x] Commit/push, verify remote SHA, record task completion and next substantial
  batch from the live review queue. Expected: tracked clean and remote matches.

## Review Focus

- A valid broad capability must not bypass unknown-route denial, including
  synthetic /chio/tools paths and client-supplied route patterns.
- Pinning hashes original loaded bytes and cannot authorize inline/discovered
  content through ambiguous configuration or a second file read.
- Policy inheritance and wildcard compilation cannot erase required proofs;
  proof binding must cover exactly the executed capability, operation and args.
- Renewed JWTs, introspection and OAuth code/token paths use the same sender
  boundary; spoofed forwarding headers never supply a socket identity.
- Authentication, bounded original parsing and replay reservation order cannot
  permit mutations on denial or consume a proof merely by previewing an operation.
