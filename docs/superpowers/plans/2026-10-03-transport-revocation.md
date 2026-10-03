# Transport confidentiality and truthful revocation plan

> Use superpowers:executing-plans inline and one fresh integrated review.

**Goal:** close AP7 and AP8 from the October 1 product-truth review.
**Architecture:** shared bounded TLS connection IO, explicit startup configuration,
control-client endpoint validation, typed per-capability revocation outcomes.
**Spec:** [design](../specs/2026-10-03-transport-revocation-design.md).

## Global Constraints

Fail closed before side effects. Keep native error causes and redact public errors.
Preserve connection caps, socket identity, shutdown drain and private-file custody.
No weakened assertions, added debt allowance, merge or deployment. Existing branch
publication authorization applies. Root implements; Cargo builds are serialized.

### Task 1: Shared TLS server boundary

Files: chio-http-serve transport configuration, listener IO and tests; control-plane
private TLS loader. Interfaces: ServerTransportConfig -> PreparedServerTransport ->
TransportListener; MaxConnListener remains the outer owner of connection permits.

- [x] Add and run failing startup/connection/identity/timeout controls. Expected: RED.
- [x] Implement paired cert/key, plaintext validation, bounded certificate/private
  key loading, explicit rustls provider and timed asynchronous handshake IO.
- [x] Verify actual trusted TLS, untrusted/wrong-name/plaintext refusal, key mismatch,
  malformed PEM, unsafe custody, timeout, concurrent honest client and permit reuse.
- [x] Run `cargo test -p chio-http-serve`. Expected: all pass.

### Task 2: Three production listeners and control client

Files: trust-control/MCP/API configs and serve paths; native CLI types/dispatch;
control client endpoint validation/factory; MCP implicit discovery URLs.
Interfaces: Task 1's prepared profile must be validated before other startup work;
MCP keeps CappedPeerAddr and TLS-aware discovery defaults.

- [x] Reproduce non-loopback plaintext startup and client endpoint/redirect gaps.
  Expected: tests fail against current behavior.
- [x] Add `--tls-cert`, `--tls-key`, `--allow-plaintext`; wire all three services,
  preserve shutdown and peer metadata, use HTTPS for implicit TLS resource URLs.
- [x] Refuse non-loopback HTTP control clients and all redirects, with redacted
  errors. Keep literal loopback HTTP and HTTPS honest controls.
- [x] Run production startup, TLS and control-client tests plus CLI parsing tests.
  Expected: all pass, denied startups perform no unrelated effects.

### Task 3: Truthful session revocation

Files: MCP admin session revocation and regression tests. Interfaces: one backend
per batch; typed local errors, safe per-capability write/readback outcomes.

- [x] Reproduce false-success response under remote failure and partial progress.
  Expected: RED through the request boundary.
- [x] Replace error swallowing; confirm every capability and return non-2xx plus
  partial progress when any write/readback fails or revocation remains false.
- [x] Test remote 500, local write failure, readback failure, false readback,
  already-revoked, partial progress and idempotent retry. Expected: all pass.

### Task 4: Integrated qualification and publication

Files: source inventories if contracts change; execution record, retained evidence,
review queue and plan checkboxes.

- [x] Run changed owner tests, strict all-target lint, formatting and contract gates.
  Retain terminal exits, logs and source/binary hashes. Expected: pass.
- [x] One independent integrated review; reproduce/fix Important or Critical
  findings, record all rulings and declined boundaries. Expected: resolved controls.
- [ ] Commit/push and verify remote SHA. Confirm each completed task; propose AP9
  receipt immutability/export/retention and remaining key/guard/release gates.

## Review Focus

- A stalled TLS peer cannot serialize acceptance or escape connection caps/drain.
- TLS identity load errors cannot downgrade or expose key contents; private custody
  cannot be replaced by a less restrictive file-read helper.
- All three production CLI/configuration paths enforce TLS before side effects.
- Sender identity still derives from authenticated proxy/socket context, never headers.
- Redirects, URL normalization and loopback spelling cannot leak a control credential.
- Batch revocation never reports complete when write/readback evidence is missing;
  partial retry and already-revoked results retain idempotency and typed causes.
