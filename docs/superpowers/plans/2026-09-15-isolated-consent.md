# Isolated bilateral consent implementation plan

Execute inline under the user's standing authorization. No sub-agents. Base is
`ff0de59644d924b71da76091e582e07f0dea1032` in `arc-funded-integration`.

- [x] Add failing Rust tests for separate provider/buyer signatures, independently
  pinned intent, substituted body/input/keys, exact replay and partial custody.
  Implement `work_consent.rs` with bounded public Intent/Proposal and local
  original request retention. Factor public agreement body validation without
  weakening native request or bilateral signature checks.
- [x] Add failing tests for separate governance/status context construction and
  selected-key substitutions. Factor unsigned standing out of context bootstrap;
  implement context draft/attest commands with first artifact custody.
- [x] Add provider CLI boundaries in `provider_files.rs` for original proposal,
  execution, output publication, claim and signed-decision settlement. Keep all
  native request/capability custody inside the provider directory.
- [x] Add actual namespace tests and `isolated_roles.rs` launcher. Use fail-closed
  bwrap, explicit mounts, fresh inputs/outputs, isolated PID/network namespace and
  no peer state. Supply only pinned checker files to the verifier. Reject role
  path/symlink aliases and never mount the repository or host root.
- [x] Add `isolated_process.rs` and Python qualification for payout/refund, active
  filesystem/network probes, independently signed consent, negative mutations,
  offline committed consent/decision replay and original unique settlement.
- [x] Review all new trust/custody boundaries inline. Run standalone Rust tests,
  selected owned-chain/process regressions, Python witness/wire tests, strict
  Clippy, formatting and hygiene. Record exact source/binary/artifact hashes in
  new report 31 and manifest 32, update the frontier and commit locally. Verify
  clean integration state and unchanged original checkout after the commit.

## Implementation notes

Public intent/proposal and buyer acceptance now preserve the registered agreement
v2 while binding the complete public proposal with an additional buyer signature.
Provider capability/request custody and buyer first consent remain local. Missing
components deny replacement; exact completed consent replays without the key.
Governance draft/status attestation use separate invocations and retained artifacts.

The actual five-domain Linux namespace reproduction passes payout/refund with
private keys generated inside role namespaces, explicit public file transfers,
active peer-state/read-only-input/network probes and original native identities.
Execution uses normal native startup reconciliation; handoff commands retain their
narrow mode. Review and qualification are recorded in
[report 31](../../market/open-agent-work/execution/31-isolated-bilateral-consent.md)
and the associated manifest. The coordinator retains public artifacts only.
