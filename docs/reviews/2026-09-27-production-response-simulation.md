# Explicit response execution and production simulation

The September 27 directive removes the unshipped response compatibility contract.
Plans and compact authorization bodies require an execution binding. Missing,
null and unknown bindings reject during decoding. Fresh admission, committed
admission recovery and dispatch recovery all require `Live`. There is no legacy
plan variant, decoder default, alias or retirement/inventory workflow.

This supersedes the compatibility and retirement work described in the
September 26 execution review and September 27 signed-readback checkpoint.
Their dated verification records remain historical evidence.

## Implemented boundary

- A separate immutable kernel simulation request requires `DryRun` and exact
  agreement between the full plan and compact authorization body. It reuses
  capability, finding, submission proof, authority attestation, policy and
  threshold approval verification. Its result cannot be serialized into a live
  admission permit. No approval reservation or budget hold is created.
- The evaluator reads an immutable snapshot and models all six effects, reverse
  rollback and each overlapping contribution's expiry. It uses the same pure
  containment, throttle, egress, capability suspension and issuance composition
  as the live path. It never owns an effect port or alert delivery capability.
- SQLite captures all effect targets in one read transaction. Causal graph
  observations carry their own exact versions and must match the approved scope.
  This does not claim an atomic snapshot across independent databases or acquire
  a live issuance fence. The model assumes a future fence could be acquired.
- Signed reports bind the deployment digest, full plan, kernel-derived authority
  facts, snapshot and predicted outcomes. The indexed receipt store atomically
  persists the receipt and logical report identity. Independent verification
  requires an expected signer and deployment digest and recomputes the model.
- The response-planning outbox has a distinct terminal `Simulated` state with
  report evidence and no live dispatch identity, preparation or completion
  outcome. Restart recovers the exact report, including the cut point after
  receipt commit and before outbox completion. Receipt errors cannot authorize
  an effect; an ambiguous append succeeds only after verified exact readback.
- The host explicitly selects its execution profile. Dry-run installs no live
  effect backend in the scheduler and rejects live coordinator entry points.
  The authority daemon checks policy selections and artifact requests against
  the configured mode. Deployment profile assembly validates the mode, digest
  and receipt signing identity together.
- The wire schema and generated Rust, TypeScript and Python plan bindings require
  the same closed execution binding. Six shared negative vectors cover missing
  and null bindings, missing and unknown modes, unsupported versions and extra
  fields. No decoder fallback is retained.
- Outbox initialization and integrity validation use one set of schema constants.
  A focused fresh-store failure exposed duplicate definitions; the duplicate
  initializer was removed instead of adding a migration or repair fallback.
- Shared issuance composition and the new integration tests live in ordinary
  modules. Existing source-size caps remain unchanged.
- The precision-preserving typed signed-JSON reader is named `parse_signed_json`.
  Its integer and duplicate-key protections remain required production behavior;
  no compatibility alias is exported.

Simulation evidence is advisory. It neither proves future external execution nor
constitutes an `Applied` receipt, an issuance fence or a live authorization.

## Verification

Local control-plane verification passed: 108 selected library tests cover the
response planner, production effects, real kernel approval adapter and committed
admission cold recovery; all three new external report/snapshot tests pass.

The real kernel composition covers automatic and governed authorization with a
throttle plan. Pure-model and signed-report tests cover all six effects, including
five stateful targets and alert prediction. This is not every possible combination
of effect kind and approval policy. Re-signed negative reports exercise structural
verification after a valid signature, including mode and model-result substitution.

The first fresh-store run failed on divergent duplicate outbox schemas. The
original failure is retained in `/tmp/chio-response-dry-run-control-schema-red.log`;
initialization now uses the same canonical constants as integrity validation.
The stronger tampering fixture initially failed at closed-metadata validation
because re-signing a nonempty receipt id adds a nonce. Clearing the fixture id
isolates the intended binding mutations; the verifier was not relaxed. Original
output is retained in `/tmp/chio-response-dry-run-control-tamper-fixture.log`.

All owning commands exited zero. Rust verification totals **175 passed, zero
failed, two ignored subprocess entry points**:

| Owning target | Passed | Log |
|---|---:|---|
| Control-plane selected response, effect and recovery library tests | 108 | `/tmp/chio-response-dry-run-control-final.log` |
| Control-plane `response_dry_run` integration target | 3 | Same control-plane log |
| Authority runtime library | 22 | `/tmp/chio-response-dry-run-authority.log` |
| Quarantine `response_dispatch` and `response_dry_run` | 11 + 4 | `/tmp/chio-response-dry-run-types-model-vectors.log` |
| Security-types `response` and `response_dispatch` | 16 + 4 | Same types/model/vector log |
| Core-types `security_generated_vectors` and `signed_json` | 5 + 2 | Same types/model/vector log |

The wire corpus passed 90 positive and 270 negative vectors. Generated Python
bindings passed exact roundtrip plus all six malformed execution-binding cases.
The pinned Rust, TypeScript and Python generators completed successfully; 155 of
the 158 changed generated Python files change only their shared schema digest.
The other three change the response model and its package exports.

Touched Rust formatting, diff checks, weak-negative-assertion, source-file-hygiene,
wire-schema inventory and domain-separation checks passed. No source-size cap or
assertion baseline was widened. Cargo used one owner, `--locked -j2`,
`CARGO_INCREMENTAL=0`, `CHIO_CHECKOUT_ROOT=/tmp/arc-security-launch` and the existing
`/home/connor/chio-lanes-target/lane-d` cache. The owning commands were:

```sh
cargo test --locked -j2 -p chio-control-plane --lib --test response_dry_run -- response_dry_run security::event_consumer:: security::adapters::effect_port:: security::active_response::
cargo test --locked -j2 -p chio-active-response-authority --lib
cargo test --locked -j2 -p chio-security-types -p chio-quarantine -p chio-core-types --test response --test response_dispatch --test response_dry_run --test signed_json --test security_generated_vectors
```

The broad workspace sweep stopped in the preceding batch was not rerun or
relabeled passed. This batch does not claim fresh workspace Clippy, M5 closure,
hosted qualification or operator rollout acceptance.
