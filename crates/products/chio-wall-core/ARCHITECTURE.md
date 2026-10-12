# chio-wall-core architecture

## Responsibility and boundary

`chio-wall-core` owns the data contracts for Chio-Wall control-path packages.
The public surface is `control_path` plus root re-exports of its artifact types,
enums, schema constants, and `ChioWallContractError`. The crate implements no
listener, policy engine, kernel, signer, receipt store, or filesystem loader.
Consumers supply JSON acquisition, explicit validation, and enforcement.

`ChioWallBuyerMotion` has the `ControlRoomBarrierReview` variant and
`ChioWallControlSurface` has `ToolAccessDomainBoundary`. Information domains
are `Research` and `Execution`; guard decisions are `Allow` and `Deny`.
These closed enums constrain the representable vocabulary of the artifact.
They do not authenticate a caller or establish what a runtime actually did.

## Structure and artifact relationships

`src/lib.rs` forbids unsafe code, declares `control_path`, and re-exports the
contracts. `src/control_path.rs` contains all schemas, types, validators, shared
field helpers, and unit tests. `tests/integration_smoke.rs` exercises the exported
profile API with a valid boundary and an invalid same-domain profile.

| Artifact | Data it describes |
| --- | --- |
| `ChioWallControlProfile` | Workflow, domain boundary, retained-artifact policy, and intended use. |
| `ChioWallPolicySnapshot` | Policy identifier, source domain, and allowed tool names. |
| `ChioWallAuthorizationContext` | Request, workflow, actor label, requested domain, tool, and policy reference. |
| `ChioWallGuardOutcome` | Decision, guard and pipeline labels, matched policy, evaluated tool, and allowlist. |
| `ChioWallDeniedAccessRecord` | Denied request context and escalation/support owners. |
| `ChioWallBuyerReviewPackage` | Review package identity, owners, and file references. |
| `ChioWallControlPackage` | Package identity, same-system boundary, owners, and artifact inventory. |

`ChioWallArtifact` pairs an artifact-kind enum with a path string. Its seven
kinds include the six supporting JSON artifacts and `ChioEvidenceExport`.
The control package is the inventory owner, so its own file is outside that
seven-kind inventory. Schema constants cover each schema-bearing package type.

## Data and control flow

A caller constructs an artifact or deserializes it through Serde, then invokes
its `validate()` method. Public fields remain mutable, so a consumer must repeat
validation after edits that affect the contract. Successful Serde decoding alone
performs no semantic validation. Structs serialize fields in camelCase; enum
values use snake_case. The structs do not declare `deny_unknown_fields`, so
ordinary Serde decoding may accept additional fields.

Each validator checks its own artifact. Schema checks precede required field
checks. Package validation loops over inventory entries, validates their path
strings, rejects repeated kinds, then checks that every required kind appeared.
It does not open referenced files or compare the request identifiers across
separately validated artifacts. The CLI performs those package-level joins.

## Trust and invariants

Schema-bearing types require an exact schema string. Required scalar strings
must be nonempty after trimming, have no surrounding whitespace, and contain no
control characters. Tool lists must be nonempty and each entry must obey those
string rules. Both policy and outcome lists reject exact duplicate tool names.
Fields named `fail_closed` must be true in profiles, policy snapshots, outcomes,
review packages, and control packages.

Profiles require differing source/protected domains. Authorization contexts and
denied-access records require differing source/requested domains. A denied guard
outcome must evaluate a tool absent from its allowlist. An allowed outcome may
name a tool absent from that list; callers seeking allowlist enforcement must
run their actual guard instead of treating this validator as an evaluator.

Path fields receive the required-string checks only. `ChioWallArtifact::validate`
does not reject absolute paths or traversal components, enforce containment,
inspect symlinks, or require file existence. `ChioWallControlPackage::validate`
requires each artifact kind exactly once but does not verify its contents.
Consumer filesystem policy must resolve and constrain paths before use.

`ChioWallContractError` distinguishes invalid schema, missing list fields, empty
and padded scalar fields, other validation failures, and JSON errors converted
from `serde_json::Error`. Validators establish local consistency. No signing,
canonicalization, receipt verification, or operational fail-closed enforcement
is implemented in this crate.

## Dependencies and verification

Serde supplies JSON representations; `serde_json` supplies the error conversion;
`thiserror` supplies typed error display. There are no Cargo features or async
runtime requirements. Serialization and validation work entirely in memory.

`cargo test -p chio-wall-core` runs unit and integration tests. Unit cases cover
padded and control-bearing identifiers, duplicate and invalid allowlist entries,
same-domain boundaries, denial contradictions, false fail-closed settings,
missing artifact paths, duplicate artifact kinds, and incomplete inventories.
One test explicitly accepts an allowed outcome whose tool is absent from the
allowlist. The README example exercises public profile validation on both sides
of the domain inequality. Receipt authenticity and runtime enforcement require
separate application verification.
