# Issuer lifecycle, key custody and execution-bound approvals

**Status:** Proposed next batch after AP1/KG1/RL1. No checklist item below is
completed by this plan. Refresh the source and review findings before execution.

**Goal:** Close KG2/KG3 and AP2/AP3 from the
[compliance and product-truth review](../../reviews/2026-10-01-compliance-product-truth-review.md)
at their actual runtime consumers. Separate receipt signing, capability issuance
and approval authority, then enforce the lifetime and exact use of each grant.

## Constraints

- Preserve the pinned, signed replication chain and private-custody separation
  established by KG1. The current protocol represents additions only; retirement,
  revocation and recovery need an explicit versioned transition contract.
- Reuse the owned clock, canonical signing, durable transaction and replay
  primitives. Recheck authority and time under the transaction that consumes them.
- Add failing controls at production composition boundaries before repairs. Keep
  source migrations, local verification, hosted verification and operator actions
  separate. No account registration, deployment, release or trust-pin replacement
  is implicit in implementation.
- Serialize Cargo graphs, review the completed diff once, resolve concrete
  findings, and retain all failed and terminal evidence. Do not increase debt
  baselines, suppress lint, ignore tests or loosen timeouts to obtain a pass.

## KG2: enforce issuer lifecycle and separate receipt authority

Owners: `chio-kernel` authority/validation, `chio-store-sqlite` authority store,
`chio-keyring` state/store, and control-plane construction and replication.

- [ ] Reproduce admission by a retired or expired issuer and admission under the
  kernel receipt key when a distinct capability authority is configured.
- [ ] Specify active, verify-only, retired and revoked states, with precise
  issuance and verification deadlines. Define authenticated rotation, retirement,
  revocation and recovery transitions, including migration from KG1 checkpoints.
- [ ] Atomically publish lifecycle state and replay commitments; reject unsigned,
  stale, conflicting and unauthorized changes across incremental and full import.
- [ ] Apply `verify_until` and revocation at keyring and kernel verification time.
  Receipt signing must not implicitly grant capability or approval authority.
  Preserve deliberately configured local authority behavior with explicit tests.
- [ ] Exercise issue A, rotate B, retire/revoke A and deny through `build_kernel`;
  check exact deadline boundaries, clock faults, restart, retained historical
  receipts, rollback, competing updates and custody mismatch. Document recovery
  and bounded-chain recheckpointing without claiming automatic safe handover.

## KG3: protect local authority key material

Owner: `chio-store-sqlite` authority database creation/opening, using existing
file-identity and private-file helpers where their contracts fit.

- [ ] Reproduce default-umask exposure in an isolated subprocess.
- [ ] Establish private directory/database modes before writing a seed and
  validate existing stores. Include WAL/SHM sidecars, symlinks, file replacement,
  SQLite URI paths and platform-specific behavior in the design.
- [ ] Reject unsafe pre-existing custody rather than silently broadening access.
  Provide a bounded offline migration procedure for legitimate deployments.
- [ ] Verify creation under umask 022, unsafe permissions and parent paths,
  reopen/rotation/replication, and zero seed-bearing writes on refusal. Do not
  describe filesystem permissions as encryption or external key custody.

## AP2: bind approvals to the executed call

Owners: kernel governed validation, API-protect mediated/approval routes,
`chio-http-core` approval store and SDK approval contracts.

- [ ] Reproduce approval for arguments A being substituted or unbound, and the
  mismatch between SDK parameter hashing and kernel intent binding.
- [ ] Build `BoundToolInvocation` server-side from the admitted capability,
  route, arguments and request identity. Require that binding whenever approval
  is required, including non-HTTP kernel callers.
- [ ] Connect approval persistence and redemption to admission with single-use,
  expiry, tenant and current-policy checks. Preserve safe pending/recovery
  semantics across restart; distinguish denial from an advisory workflow.
- [ ] Exercise real submit/approve/evaluate paths: A succeeds once, B and an
  unbound intent deny, and wrong capability, route, request, tenant, policy,
  expired/revoked approval and concurrent redemption deny without tool dispatch.

## AP3: make approver identity and policy enforceable

Owners: the same approval consumers, policy loading and approval receipt types.

- [ ] Require an explicitly configured approver roster and authenticated signer
  identity. Do not substitute the sidecar key for an invalid requester or infer
  approval authority from membership in a capability issuer set.
- [ ] Preserve approver attribution and exact approved intent in signed evidence.
  Decide and implement the supported dual-approval contract, including distinct
  principals and current-policy revalidation, or reject it at policy load.
- [ ] Reject unsupported approval policy fields (`approve_when`, timeout behavior
  and currency thresholds) rather than accepting ineffective configuration.
  Update public examples and SDK behavior to the supported contract.
- [ ] Test an unlisted signer, duplicate approver, changed roster, signer retirement,
  invalid requester and unsupported policy fields through their actual consumers.

## Acceptance and handoff

- [ ] Run affected owner tests, production composition controls, warnings-denied
  lint and source gates. Do not substitute serialization tests for admission.
- [ ] Resolve one independent review and record commands, source hashes and
  terminal logs; commit/push authorized security work and verify the remote SHA.
- [ ] Reconcile KG2/KG3/AP2/AP3 individually with their roadmap owners and keep
  incomplete parts explicit. AC4 protected run/step writes, CA3 framework ingress,
  remaining TCB readers, guard integration, evidence/retention and full hosted
  release qualification remain subsequent queue items.
