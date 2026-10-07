# Verification and release evidence

Status: Proposed acceptance program. Confidence: high in the required evidence
distinctions. Runtime qualification for this integration remains open.
Dependencies: all normative specs and the [phase roadmap](16-roadmap-decisions.md).

## Evidence classes

| Class | What it can establish | What it cannot establish |
| --- | --- | --- |
| Source inspection | A pinned source expresses a contract | Actual runtime enforcement or available installer |
| Document/schema validation | Spec links, traceability and example structure agree | Any native operation worked |
| Component test | A particular component behavior under stated fixture | Full kernel/host/provider/desktop composition |
| Independent local integration | Real effect plus outside observer on exact machine | Another architecture, distro or provider |
| Clean-install qualification | Signed/pinned distribution installs and passes selected matrix | Every optional profile or future rolling update |
| Release publication | Named artifacts available with verified provenance | Runtime qualification unless its evidence is also present |

Every requirement in the numbered specs has a proposed acceptance case. The
generated [traceability](requirements.json) records these as
`proposed_acceptance_test`, with `evidence_status=proposed`. An artifact filename
in a spec is an expected output name, not a statement that the file exists or the
test passed. The checked-in [verifier](verify.py) validates this package only.
Do not substitute its green output for a runtime qualification artifact.

## Qualification matrix

| Lane | Required real environment | Mandatory positive and negative evidence |
| --- | --- | --- |
| P0 compatibility | Pinned Omarchy v4.0.4 plus separately tracked development tuple | Manifest/facade/lifecycle probing; unsupported ABI refusal; source/package provenance |
| P1 observe-v1 | Actual built-in Omarchy bar and installed backend | Status, stale/reconnect/lock behavior; no mutation methods admitted |
| P2 project-v1 | Actual non-root x86_64 host, exact Pi/native/provider tuple | One task and fixed checks; FS/network/FD/socket/credential denials; kill, timeout, crash, restart, original-effect reconciliation |
| P3 reviewed-publish-v1 | Qualified native approval facade and enrolled destination | Exact approve and deny; stale/substitution/replay; destination conflict; post-effect disconnect |
| P4 desktop-v1 | Actual pinned compositor with qualified desktop resource | Bounded metadata reads and workspace selection; unknown tool/raw command denial; compositor restart races |
| P5 repair-v1 | Enrolled scalar config resource with qualified exclusion/reload contract | Preview/apply/reload/readback; conflicting writers; interrupted apply; safe refusal of hooks/multifile |
| P6 delegated-v1 | Native registry and qualified child launcher, separately scoped hosts | Attenuation, aggregate budget, revocation, uncertain child and parent restart; no double-spend |
| P7 selected profiles | Fresh supported installation outside implementer's dev checkout | Install, upgrade, failed upgrade, rollback, uninstall, evidence export and independent operator walkthrough |

Architecture, kernel/ABI, Omarchy release, Quickshell, Qt, Hyprland, systemd,
native Chio bundle, bridge archive, Pi peer/dependency lock, provider route,
resource recipes, policy, controller and plugin are all part of the tuple.
Successful arm64 container checks never fill x86_64 desktop cells. A component
present on a branch does not close missing public distribution prerequisites.
Release v4.0.4 and the inspected development branch are different cells.

## Independent oracles and fault campaigns

For denied filesystem/network/tool actions, run observers outside the guest and
check the actual protected destination, native effect counter or listener. Include
a working positive control to prove the test fixture is reachable. An exception,
exit code, guest log or returned enforcement label alone is insufficient.

Enumerate deterministic crash cutpoints: before/after local reservation, native
reservation, resource dispatch, resource effect, native result retention, delivery,
ACK and controller projection. Retain original IDs, effect count, descendant
census, budget reservations and evidence readback for every cut. Combine selected
cutpoints with disk-full, revocation, suspend, upgrade and stale approval tests.
Use bounded randomized scheduling only in addition to these deterministic cases.

Schema tests must include cross-method substitution, unknown fields, changed
enums, invalid UUIDs, unsafe integers and typed-result mismatch. Raw wire tests
must separately reject duplicate keys, invalid UTF-8, oversized frames and depth.
JSON Schema cannot check freshness, canonical digest correctness, native evidence,
socket ownership or actual denial of side effects.

## Evidence bundle and admission rules

The proposed `release-evidence.schema.json` describes a release evidence index,
not a signed receipt format. Store immutable content-addressed test artifacts,
raw commands, exit status, machine tuple, tester identity, source/artifact hashes,
start/end times, measured outcomes, failed/skipped cases and verifier version.
The public bundle uses synthetic data and the qualified redaction profile.
Any signatures use native release/evidence tooling; this package invents no new
trust root. A trusted reviewer verifies artifact hashes and actual test contents.

Select exact profile IDs. A profile passes only when every mapped requirement
applicable to that profile has passing current-tuple evidence, prerequisites are
closed, no required case is skipped, and no unresolved critical/important review
finding affects it. Tests for an optional later profile can remain open only when
that profile is absent from the artifact and unavailable at runtime. A missing
case is unknown, not pass. Changing an enforcement component invalidates dependent
cells until rerun; changing copy alone need not rerun unrelated kernel probes.

Release qualification, downloadable publication and production/operator adoption
are reported separately. A source PR does not update any of them. Release notes
name supported profile, actual platform, remaining limits and evidence identity.
No “all agents,” “all Linux,” “secure desktop,” “exactly once” or full-governance
claim without corresponding bounded contract and evidence.

## Normative requirements

| ID | Requirement | Proposed acceptance |
| --- | --- | --- |
| OM-VER-001 | Evidence MUST preserve source/component/runtime/release distinctions and report skipped cases. | AT-VER-001 |
| OM-VER-002 | Runtime denial claims MUST have independent outside-effect oracles and positive controls. | AT-VER-002 |
| OM-VER-003 | Qualification MUST exercise deterministic dispatch/delivery/recovery crash cutpoints. | AT-VER-003 |
| OM-VER-004 | Every release profile MUST map to complete current-tuple requirement evidence. | AT-VER-004 |
| OM-VER-005 | Clean-install lifecycle and independent operator acceptance MUST precede profile publication claims. | AT-VER-005 |
| OM-VER-006 | The document validator MUST fail broken traceability, malformed examples and incompatible response shapes. | AT-VER-006 |

## Proposed acceptance

### AT-VER-001: False-green index
Trigger: label a source review or skipped runtime case as qualified.
Expected: evidence gate refuses promotion. Oracle: required evidence-class matrix
and independent review. Artifact: `evidence-class-refusals.json`.

### AT-VER-002: Unreachable negative fixture
Trigger: disconnect the target listener before a network-denial test.
Expected: missing positive control invalidates test rather than passing denial.
Oracle: external target availability. Artifact: `oracle-positive-controls.json`.

### AT-VER-003: Full crash inventory
Trigger: execute each named deterministic cutpoint on actual effect path.
Expected: all cutpoints recorded and original IDs/effect count consistent.
Oracle: outside ledger and native retained state. Artifact: `release-crash-matrix.json`.

### AT-VER-004: Tuple and profile substitution
Trigger: reuse evidence on different kernel/provider, omit one required test and
enable an unqualified profile. Expected: every promotion refused. Oracle: pinned
requirements and artifact digest comparison. Artifact: `release-profile-gates.json`.

### AT-VER-005: Fresh operator installation
Trigger: independent operator installs pinned artifacts on clean supported image,
performs one task, restarts, upgrades and uninstalls. Expected: documented result
with preserved evidence; no hidden developer paths. Oracle: image/package inventory
and operator recording. Artifact: `clean-install-acceptance.json`.

### AT-VER-006: Package validation mutants
Trigger: remove an acceptance heading, duplicate a requirement, break a local link,
and change valid fixtures into forbidden shapes in a temporary copy.
Expected: validator exits nonzero for every mutant. Oracle: independent mutation
harness checking exit status. Artifact: `document-validation.json`.
