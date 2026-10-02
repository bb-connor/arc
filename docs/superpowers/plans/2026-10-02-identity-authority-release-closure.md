# Identity, authority replication and release signer closure

**Status:** Implemented and locally qualified at source
`0fd0a9d66d60f03d30501ca727569a8069406e46`, from base
`6cf283c4b9e36485a98275ba6798052b01a5a9d0`. The
[execution record](../../reviews/2026-10-02-identity-authority-release-closure-execution.md)
owns the evidence, publication handoff and limits. Hosted and deployed acceptance
remain separate. The original plan was checked at `d7a33ba9341b78458cd639df352ad5618d31e38c`.

**Goal:** Close the three High findings AP1, KG1 and RL1 in the
[compliance and product-truth review](../../reviews/2026-10-01-compliance-product-truth-review.md),
with executable rejection controls at their actual consumers.

**Architecture:** Agent subject keys remain caller-owned public identities.
Issuer-set changes require an authenticated, signed transition from a previously
pinned authority, applied atomically with durable replay state. Release consumers
verify the actual workflow identity for the exact package tag.

## Constraints

- Preserve private subject-key ownership, authority custody, tenant checks,
  canonical signing and existing shared clock/fence semantics.
- Reject malformed, unsigned, stale, regressing, conflicting or unpinned authority
  before installing keys. A transport service token cannot mint issuer trust.
- Keep local acceptance, hosted acceptance, source publication, release publication
  and operator actions distinct. Do not register accounts or activate releases as
  an implicit part of fixing source and verification documentation.
- Use focused failing controls before fixes; serialize Cargo builds. No exemption,
  baseline increase, ignored test or timeout relaxation can stand in for a repair.
- Refresh the candidate and relevant review findings before implementation. This
  plan is not a claim about the present ownership of any GitHub account name.

## AP1: caller-owned sidecar subject identity

**Owners:** `crates/products/chio-api-protect/src/proxy/sidecar.rs`, production
router regressions, Python SDK capability-minting contract and sidecar authority
documentation.

- [x] Reproduce the existing public-label seed attack through both mint routes,
  including the `/v1/capabilities` scope alias.
- [x] Parse and validate the caller's public subject key at the mint boundary.
  Reject non-key labels before issuance or store mutation. Remove private-key
  derivation from subject/job labels and use one shared parser for both routes.
- [x] Retain deterministic request/capability identity only where it represents
  public request identity; never turn that digest into a subject signing seed.
- [x] Exercise real DPoP verification: the caller key succeeds; the old derived
  seed, another key and a stolen token without the caller key fail. Check missing
  and malformed subjects and the SDK's documented public-key representation.
- [x] Update API examples and affected fixtures to carry real public keys, then
  run affected router/SDK checks and warnings-denied Rust linting.

## KG1: signed issuer-set replication

**Owners:** `chio-store-sqlite/src/authority.rs` and its transaction tests;
`chio-control-plane/src/trust_control/cluster/{deltas,snapshots}.rs`; cluster view,
client, rendering and transport validation; shared authority wire types.
Crates live under `crates/platform/` unless their existing type owner is elsewhere.

At the base, both `sync_peer_authority` and `apply_cluster_snapshot` reached
`apply_snapshot`. The repair covers incremental pulls, full snapshot recovery
and every other production caller of that import API.

- [x] Reproduce unauthorized issuer insertion at the shared store and full
  snapshot boundary. Cover both network import paths and actual composed kernel
  denial in the repaired regressions. This evidence scope supersedes the planned
  pre-fix exploit at both network paths; see the execution record.
- [x] Specify a domain-separated canonical signed transition/snapshot contract:
  pinned signer, stream/cluster identity, exact predecessor and generation,
  issued/freshness bounds, complete issuer-set digest and allowed head transition.
  Reuse existing signing and trusted-time primitives. A signature from a key
  carried only inside the proposed snapshot is not a trust anchor.
- [x] Define bootstrap and migration explicitly. Configure initial trust out of
  band; reject unsigned network state. Preserve local signing custody when
  replicating verification state. Do not manufacture authority history for old
  unsigned rows or silently trust the first peer response.
- [x] Verify the authenticated chain before import, then atomically compare and
  persist the issuer set, head, generation and replay commitment. Distinguish an
  exact idempotent replay from a same-generation conflict; prevent stale history
  from adding even a non-head issuer. Recheck durable state under the write lock.
- [x] Refuse off-loopback plaintext peers and retain certificate/hostname
  verification. Loopback transport and a shared service token still do not bypass
  signature or pinned-identity checks.
- [x] Test honest replication and rotation continuity, unsigned/substituted state,
  unpinned signer, history insertion, equal-generation conflict, stale/future
  state, clock failure, replay, restart and concurrent competing imports. Verify
  rejected imports leave every authority table and in-memory trust cache intact.
- [x] Prove a capability from a refused issuer remains denied through the composed
  kernel, then run the affected authority/cluster integration and lint checks.

## RL1: exact release verification identity

**Owners:** `docs/install/{VERIFY,PUBLISHING}.md`, actual binary/PyPI/npm release
workflows, their verification scripts and executable documentation checks.

- [x] Refresh the real repository/workflow/tag identities and enumerate consumer
  verification commands. Preserve evidence for historical publication separately.
- [x] Replace stale owner examples and broad identity regexes with one explicit
  repository policy and exact workflow/tag certificate identities per artifact
  family. Escape or reject invalid inputs rather than interpolating an untrusted
  owner/tag into a permissive regular expression.
- [x] Execute the documented verification command path against an appropriate
  signed fixture. Reject the wrong repository owner, workflow, tag and OIDC issuer,
  missing signature/certificate, and changed artifact bytes. State whether a
  fixture establishes only local command behavior or hosted keyless identity.
- [x] Check all relevant documentation examples use that same policy, and record
  any remaining operator account-ownership or publication gate explicitly.

## Acceptance and handoff

- [x] Resolve one bounded independent review of the implemented boundaries.
- [x] Record exact source, commands and terminal logs; retain failed attempts.
- [x] Commit/push authorized security changes and verify the remote source SHA.
- [x] Reconcile AP1/KG1/RL1 individually with their review and roadmap owners.
  Do not mark KG2 retirement/custody, AP2 approval binding, AC4 protected run/step
  writes, CA3 framework ingress or the remaining release pipeline complete merely
  because these three findings are closed.
