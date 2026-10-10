# Compatibility and persisted data

Status: bounded architecture decision recorded. Experimental-format removal
remains conditional on the support decision below; no migration was changed.

## Established starting facts

- The PR base is `de84fc306efbb4c8dd6de748d0ad2a8d695fd30e`.
- At that base, `ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION` is 34. The
  reviewed head declares 40. Version numbers below 35 therefore cannot be
  dismissed as recovery-PR inventions.
- The Store recovery and ControlPlane recovery directories and both new pure
  crates (`chio-recovery`, `chio-semantic-contracts`) are absent at the base.
- The legacy quota regression constructs an earlier representation with the
  current runtime's gated helper. Its documentation explicitly distinguishes
  that fixture from an actual old-executable upgrade proof.
- No released deployment requiring that particular quota representation has
  been established by this review. Absence from the PR base does not prove that
  no external pre-release user has retained such data.

## Admission format transitions

`admission_operation_store/schema.rs::expected_admission_operation_schema`
constructs these exact catalogs. `migrate_schema` verifies predecessor families
and installs the current catalog under an Immediate transaction before stamping
the current revision. The versions below are code acceptance, not evidence of a
published release or external deployment.

| Admission version | Role in the reviewed source | Origin and decision |
|---|---|---|
| 0 and predecessors through 34 | Existing per-store stamping and guarded native migrations, including participant and nonce-preflight history | Predate recovery PR; retain applicable migration/refusal behavior. Do not reset shared native history. |
| 35 | Recovery records/events | Introduced in this PR; support commitment needs an explicit decision. |
| 36 | Captured deployment history | Introduced in this PR; historical effect custody remains required even if this incoming format is retired. |
| 37 | Historical holds and original-presence indexes; predecessor guards exclude newer workflow/knowledge/product families | Introduced in this PR. |
| 38 | Durable command-alias index and retained alias custody | Introduced in this PR; exact replay semantics remain required. |
| 39 | Captured terminal custody and the first knowledge encoding catalog | Introduced in this PR. |
| 40 | Atom/chunk knowledge encoding, reference capacity and chunk accounting | Current format; contains substantial functionality, not just a version stamp. |

The four new predecessor-verification modules are
`schema/recovery_format_migration.rs`, `schema/command_alias_format.rs`,
`schema/captured_terminal_format.rs`, and `schema/knowledge_encoding_format.rs`.
They are different transition guards, not four parallel recovery runtimes.
For versions 35/36 they repeat exact schema verification at each family boundary.
That verification can be centralized once in the owning migration transaction
while preserving every family-specific future-custody exclusion.

## Process journal transitions

The baseline `ProcessRuntime` opens version 1. Current `store.rs::open` accepts
1 through 7 and fences downgrades. These numbers also encode enforcement state:
they cannot safely be collapsed as if they were layout-only versions.

| Process version | Current behavior |
|---|---|
| 1 | Existing ordinary Process journal; pre-recovery starting format. |
| 2 | First recovery reservation stamps this version; exact request/call charge is retained. Raw knowledge remains allowed. |
| 3/4 | Intermediate knowledge predecessors accepted at open, but current enforced knowledge requires promotion to 5. Raw knowledge refuses. |
| 5 | `enable_knowledge` promotes 1 through 4; mediated reads and durable raw-route refusal are enforced. |
| 6 | First permanent unused-recovery-reservation closure adds its retained prohibition. |
| 7 | First exact confined-delivery marker orders byte dispatch against Stop. |

Sources: `chio-process/src/store/recovery.rs:33`, `store/knowledge.rs:4`,
`store/unused_recovery_reservation.rs:8`, `store/confined_delivery.rs:19`, and
`store.sql`. Existing raw blobs receive `legacy_quarantined=1` and a distinct
generation on upgrade; removing that quarantine would grant new read authority
to old unlabeled bytes.

## Support decision to make before pruning

The normative operations spec requires byte-preserving supported upgrades,
refusal of incompatible older binaries, and quarantine when an old verifier is
unavailable. It does not identify an externally released 35/36/37/38/39 recovery
binary or promise unlimited support for every experimental revision.

Recommended policy: retain the pre-recovery baseline path and the chosen current
format. Require explicit justification for accepting each PR-local predecessor.
If those predecessors have no supported consumers, replace their upgrade paths
with explicit read-only refusal and preserve a separate archival migration tool
only if needed. This changes supported behavior and is conditional on that
decision. Do not silently reinterpret old data as current, renumber current
stores downward, or remove the current format's custody/retirement features.

## Grant compatibility is a real pre-existing boundary

The base already defines `chio:declassification-grant:v1` in
`chio-core-types/src/declassification.rs:12`. The new
`recovery/authority.rs:49` wraps the existing claims and mandatory recovery
binding in `chio.declassification-grant.v2`, signed under a distinct domain.
There is no old `RecoveryGrantV1` implementation at the base. The V2 suffix
does not establish two competing recovery engines. Keep the domain/version
distinction; never reinterpret old signed V1 bytes as recovery-bound authority.

Process also has a pre-existing public `PROCESS_ABI` contract covering journal,
worker and host documents (`chio-process/README.md:52`). Recovery journal
simplification must preserve that boundary or explicitly change the ABI.

The baseline Process package is `publish = false`, and no local tag points at
the PR base. Neither fact proves the absence of external Git installations.
No production database or external installation census was performed. Actual
deployment consumers of experimental formats remain unknown. The support
recommendation is therefore a concrete proposed policy, not an invented claim
that those consumers do not exist.

[Knowledge format decisions](knowledge.md) distinguish true predecessor
readers from current size-tier encodings. Historical captured-deployment custody
is separately required for same-version rotation and post-effect settlement;
it must survive any pruning of unsupported incoming database revisions.
