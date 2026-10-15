# Signed stop-operator deployment configuration (KSPEC-08 S28)

Status: draft for owner review. No code has landed.

KSPEC-08 is `docs/superpowers/specs/2026-10-04-durable-stop-epoch-design.md` (cited below as `SPEC`). This note designs the S28 prerequisite. S28 is a signed deployment configuration carrying an operator roster, a quorum threshold `k` and a pinned time-attestation key. Boot verifies it, and stop and resume consume it. The two-person resume, quorum and break-glass rules (S19, S29) and the control-profile issuance carve-out (S13) all depend on it.

## What exists today

- Every stop record names `StopAuthorizer::SharedCredential { credential_id_hash }` (`SPEC:256-265`, S18 at `SPEC:589-600`). The surfaces are the hosted MCP admin token, the process-host control socket and token, the offline CLI, and the api-protect sidecar control token (`docs/security/emergency-stop-scope.md`, section "Operator reach"). No principal is known, and anyone holding a control credential can resume (`SPEC:1098`).
- No signed deployment configuration exists on main. Nothing in `docs/security` or `docs/architecture` specifies one. The closest pieces are:
  - `ActiveDefenseDeploymentConfig` (`crates/security/chio-active-response-authority/src/config.rs:131`, loaded at `:251` with `O_NOFOLLOW`). It is bound to a normalized `deployment_digest` but carries no signature.
  - The kernel signing backend gate at boot (`crates/kernel/chio-kernel/src/boot.rs:123`, `:183`; `docs/security/kernel-signing-authority.md`). It fixes the receipt signer after a self-quote and keeps receipt signers out of approver rosters.
  - `FrostRosterV1` (`crates/trust/chio-federation/src/frost/roster.rs:77-97`) with `VerifiedActiveFrostRoster` (`:520`). This is a signed, rotatable roster carrying `roster_digest`, `threshold`, participants, `predecessor_roster_digest`, a validity window and `roster_authority_signature`. It is the closest model.
  - Tool-call approval rosters: `ProtectApprovalConfig.approvers` (`crates/products/chio-api-protect/src/proxy/approval_authority.rs:18-38`), `ThresholdApprovalRequirement` (`crates/core/chio-core-types/src/capability/threshold_approval.rs:70-90`) and the `ApproverDirectory` trait (`crates/kernel/chio-kernel/src/threshold_approval.rs:72-80`). `SPEC:685` keeps stop quorum separate from `ThresholdApprovalCollector`, so these are reused for types and checks, not for the collector.
- No `PrincipalId` derived from a subject key exists. `chio-security-types::flow::PrincipalId` (`crates/security/chio-security-types/src/flow.rs:39`) is an information-flow label and is not reused.
- No signed time attestation exists. `docs/security/trusted-time.md:28` explicitly sets up no cross-host time authority. The persisted trusted-time floor is the only time evidence a stop record holds (`trusted_floor_at_commit`).

## The configuration

One signed document, `chio.stop-operator-config.v1`. The kernel scope and every tenant scope read the same document.

```rust
pub struct StopOperatorConfigV1 {
    pub schema: String,                      // "chio.stop-operator-config.v1"
    pub authority_id: DurableAuthorityId,    // the admission store it governs (store uuid)
    pub deployment_generation: u64,          // strictly increasing per authority
    pub predecessor_digest: Option<Sha256Digest>,
    pub rosters: Vec<StopRosterV1>,          // one per scope, kernel scope required
    pub stop_quorum_max: u16,                // default 8, hard maximum 64 (SPEC:681)
    pub resume_policy: ResumePolicyV1,       // OperatorPair default (SPEC:602-614, :1103)
    pub same_principal_cooldown_ms: Option<u64>, // >= 300_000 when set (SPEC:616-621)
    pub time_attestation_key: Option<PublicKey>, // required for break-glass (SPEC:622-626)
    pub config_authority_key: PublicKey,     // the key that signs this document
    pub signature: Signature,                // over the canonical body without `signature`
}

pub struct StopRosterV1 {
    pub scope: StopScope,                    // Kernel or Tenant { tenant_id }
    pub principals: Vec<RosterPrincipalV1>,  // strictly ascending by principal id
    pub quorum_k: u16,                       // 1..=stop_quorum_max
}

pub struct RosterPrincipalV1 {
    pub principal: PrincipalId,              // sha256(subject public key), lowercase hex (SPEC:681)
    pub subject_key: PublicKey,
    pub permissions: StopPermissions,        // stop, resume, restrict, relax
}
```

- `PrincipalId` is a new type in `chio-core-types`: `sha256(b"chio.stop-principal.v1\0" || subject_key_bytes)`, encoded as 64 lowercase hex characters. The domain separator keeps it distinct from capability and receipt digests.
- `roster_digest` (`SPEC:682`) is the canonical digest of one `StopRosterV1`, computed, not stored. `StopAuthorizer::Quorum` records it together with `deployment_generation`, which closes open follow-up R1174-4230630372 (`SPEC:1361`).
- Load-time rejections, all fail-closed:
  - an unknown schema or a bad signature;
  - an `authority_id` that is not this store;
  - a generation not above the installed one;
  - a `predecessor_digest` that is not the installed document's digest;
  - duplicate or unsorted principals, or a duplicate scope;
  - a missing kernel roster;
  - `quorum_k` of 0, above the principal count, or above `stop_quorum_max`;
  - `stop_quorum_max` above 64;
  - a cooldown below 300 s;
  - a principal key equal to the kernel receipt signer, following the receipt-signer exclusion in `kernel-signing-authority.md`.

## Trust root and loading

- The trust root is `config_authority_key`, pinned outside the document. It is a deployment input next to the kernel signing backend (a path, or a key in the existing boot configuration of each host), never read from the admission store. Rotating the root needs a document signed by the old root that names the new key, using the FROST roster's predecessor model.
- Each host loads the document at boot, before `StopControl::durable` binds and before startup reconciliation (S9). The hosts are the hosted MCP edge, the process host, api-protect, trust control and the offline CLI. It is read with `O_NOFOLLOW` and a size bound, like `ActiveDefenseDeploymentConfig`, and verified offline (signature only, no store reads, no live clock).
- The admission store records the installed document. A new table `admission_operation_stop_configs` (append-only, one row per generation, payload plus digest) is covered by the global commit chain like the stop chain. Boot refuses a file older than the installed generation. A newer file is installed in a writer transaction, and only while the kernel scope is running, because SPEC `:501` denies a new deployment generation while stopped. This needs one admission schema version. Under ST8 it lands in the single v1 schema rather than as a v39 migration.
- No document present means the shared-credential behavior of today. A document that is present but fails verification leaves every scope `not_ready` with reason `stop_config_unverified`. Stop still answers and resume refuses (S10).

## How stop and resume consume it

- **Stop (S18).** A route accepts either today's shared credential or a signed operator stop token. The token follows the direct-token profile: subject is a roster principal, there is no delegation chain, and it is bound to scope, `authority_id` and a fresh nonce. A principal with `stop` permission is recorded as `StopAuthorizer::Operator { principal }`. Expiry is checked against authority time when available and otherwise against the persisted trusted-time floor. Stop never fails for want of time.
- **Resume (S19).** The shared credential no longer resumes once a document is installed. Resume needs a `StopControlQuorumV1` artifact (`SPEC:646-667`) whose `roster_digest` matches the installed roster for the scope and whose approvals come from at least `quorum_k` distinct principals with `resume` permission. Under `OperatorPair`, the resuming principals must exclude the stopper set taken from the chain records (S19a, `SPEC:628-632`). `SamePrincipalAfter` and break-glass follow `SPEC:616-626`. Break-glass verifies the `SignedTimeAttestation` against `time_attestation_key`, with the five writer checks at `SPEC:671-678`.
- **Roster unavailable.** When the roster cannot be read, the scope stays stopped (`SPEC:627`).
- **Records.** Every record keeps its 4 KiB bound. `Quorum` records carry exactly `k` ascending principals (`SPEC:681`, S6 at `SPEC:334`).

## Not in scope

The tool-call `ThresholdApprovalCollector`, tenant onboarding UX, key ceremonies for the config root, and a cross-host time authority (only a pinned attestation key is required).

## PR breakdown

1. `PrincipalId`, `StopOperatorConfigV1`, `StopRosterV1` and the canonical encoding with offline verification and every load-time rejection, in `chio-kernel::stop` or a small `chio-stop-config` module. Unit tests and signed fixtures from a generator. No host wiring.
2. The store: `admission_operation_stop_configs`, install and readback in a writer transaction, global commit coverage, the generation and predecessor rules, and refusal while stopped. Folded into the ST8 v1 schema if ST8 has landed, otherwise one schema version.
3. Boot wiring in each host: a pinned trust root input, load before `StopControl::durable`, `not_ready` on a bad document, and status reporting the installed generation and roster digests.
4. Operator stop tokens on every route, the `StopAuthorizer::Operator` record, and offline CLI support.
5. Quorum resume (`StopControlQuorumV1`), `OperatorPair` exclusion from chain stoppers, and the removal of shared-credential resume once a document is installed. `StopAuthorizer::Quorum` carries `roster_digest` and generation.
6. `SamePrincipalAfter` cooldown and break-glass with `SignedTimeAttestation`, including nonce recording in the resume transaction.
7. The control-profile issuance carve-out (S13), if still wanted.

PRs 1 to 3 are infrastructure with no behavior change when no document is installed. PR 5 is where the "no two-person resume" claim limit can be lifted.

## Open decisions

- Where the trust root key lives on each host: a dedicated file, or a field in the host's existing boot configuration.
- Whether tenant rosters ship in PR 1 or wait for tenant scopes, which are themselves still unbuilt.
- Whether installing a newer document requires a quorum of the current roster in addition to the root signature.
