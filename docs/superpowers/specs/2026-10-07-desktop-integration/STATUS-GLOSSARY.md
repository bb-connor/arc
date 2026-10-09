# Status glossary

Every status and disclaimer in the native host program is defined here once.

## Case status

Used in the `Status` column of [CASES](CASES.md).

| Term | Meaning |
| --- | --- |
| specified | Written in a design; no implementation exists. |
| owner-gated | Depends on a named owner change that has not landed: a row of NORTH-STAR-FLOWS section 9 or a tracked owner issue. |
| implemented | Code exists on a branch; not installed or qualified. |
| installed | Built artifact installed on a named host tuple. |
| qualified | Passed its CASES rows on real hosts with independent oracles. |
| released | Qualified tuple published from public sources. |

## Capability status

Used in the `Status` column of [CAPABILITIES](CAPABILITIES.md).

| Term | Meaning |
| --- | --- |
| shipped | On `main` (alias T) with tests; not qualified as a native host profile. |
| main (experimental) | Arrives on `main` with #1160 (alias F); experimental, and the credential broker is Linux-only. |
| W planned | Designed in #1173; no code. `WorkHandleV1`, `WorkViewV1`, `WorkClient` and `WorkTransport` are design-only. |
| R unqualified | Implemented in #1179; not qualified. |
| library-only | A crate exists with no native host serving path in this program. |

## ADR-0011 fields

`boundary_class` applies per operation:

- `prevent`: Chio decides before the effect.
- `detect_only`: Chio records after or outside the effect path.
- `advisory_only`: guidance, discovery or ranking; never grants scope.
- `cannot_see`: outside Chio's mediation.

`planning_status`: `ready_after_adr` (planning proceeds under accepted ADRs,
here ADR-0038), `blocked_by_adr` (semantics unresolved), `deferred` (postponed;
in this program, macOS HOST-M2 and other work scheduled after the success test
in unified roadmap section 11) and `hard_skip` (out of scope).

## Standing limits

Cite this section instead of restating these limits:

- Hook-mode host activity is `detect_only`; a hook failure does not block the
  host.
- Isolation is credited to the host backend through its #1174 S7 evidence kind;
  Chio grants, the host denies.
- A receipt can be missing after dispatch (#1174 KDEF-D1). A missing receipt is
  not evidence that no effect occurred.
- Historical evidence never qualifies a new version tuple.
- Documentation review, local tests, hosted CI, installed qualification and
  public release are separate statuses.
- Two keys held by one administrator do not prove two organizations.
