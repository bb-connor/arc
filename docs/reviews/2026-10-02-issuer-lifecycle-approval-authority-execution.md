# Issuer lifecycle and execution-bound approval batch

Source base: `a617c0b02f182afac6acab2df89a2cd9270e4923`, isolated checkout
`/tmp/arc-security-launch`, branch `packet/3-retention-accounting`.

Source implementation commit: `11485c4ef6747768454a42781f4faaf7bb0b7bb4`. The documentation commit
that contains this record carries the final handoff.

Status: **KG2, KG3, AP2 and AP3 are implemented and locally accepted** within the
explicit platform and operational limits below. Independent source review accepted
the four corrected findings. This is not hosted, release or deployed acceptance.

The [implementation plan](../superpowers/plans/2026-10-02-issuer-lifecycle-approval-authority.md)
and [design](../superpowers/specs/2026-10-02-issuer-lifecycle-approval-authority-design.md)
own the approved scope. Historical review findings and totals remain snapshots of
their reviewed revisions.

## Implemented boundaries

| Finding | Runtime change | Acceptance boundary |
| --- | --- | --- |
| KG2 | Signed v2 rotation, retire, revoke and independently authorized recovery; bounded verification windows, persistent time floor and separate receipt identity | SQLite issuance and both peer import paths, real `build_kernel` dispatch, remote fresh-admission refresh, keyring live projection and issuer CLI |
| KG3 | Private directory, database and sidecars before seed writes; ownership, links, URI and retained descriptor identity checked | Linux creation/open, live operations, restart, unsafe custody refusal and isolated umask-022 subprocess |
| AP2 | Server-built approval binds full capability, route, canonical arguments, request, tenant and policy; persisted signed decision consumed through durable operation authority | API-protect and MCP submit/decide/execute, concurrent redemption, restart and zero-dispatch substitution controls |
| AP3 | Explicit approver roster and attributed external signatures; current authority rechecked; ineffective ordinary policy fields reject at load | Kernel, API-protect, MCP, policy loader, Python SDK, Hermes and operator helper |

Public history is not a live issuer set. Rotation uses an inclusive whole-second
issuance cutoff and exclusive verification deadline. A compromised old key can
backdate within the permitted issuance interval; revoke it or use the independent
recovery root. Recovery keys cannot become ordinary capability issuers, even in a
correctly signed malicious transition. Imports never copy private seeds.

Legacy v1 commitments remain byte-compatible, but their live verification window
is bounded. Version 2 cannot be downgraded after acceptance. Schema 3 prevents an
older authority binary from ignoring lifecycle state. Operator instructions and
limits are in [issuer lifecycle](../security/issuer-lifecycle.md) and
[SQLite custody](../security/authority-sqlite-custody.md).

Ordinary approvals retain the actual arguments for approver inspection and the
independently signed decision. Legacy records without the original binding and
token are audit-only. Terminal decisions are immutable. Capability or ancestor
revocation and removal of the signer from the current roster withdraw authority;
there is no separate per-token revocation endpoint. Unsupported dual-approval,
currency-threshold and ordinary timeout policy configuration rejects at loading.

Session threshold proposals retain the exact server-bound intent and original
wire-operation digest. An approved retry uses that retained intent unchanged.
Its signed scope commits both the kernel-owned session ID and optional
authenticated tenant, including when two sessions share a tenant and principal.
Fresh presentation in another session and raw entry without owned session context
deny. Retained continuation Debug output omits the original arguments. Calls
below the cumulative threshold do not require an otherwise unused approver
resolver; actual proposal and token admission still require explicit policy.

## Evidence and failed attempts

The retained local archive is
`/home/connor/chio-security-evidence/2026-10-02-lifecycle-approval-authority`.
Each runner record contains the exact command, terminal exit code, elapsed time
and SHA-256 of the complete log. The [qualification manifest](artifacts/2026-10-02-issuer-lifecycle-approval-authority/qualification.json)
binds terminal records, binary hashes and changed source hashes to the source
commit. Earlier failures and cancellation remain separate records. The
[independent review](artifacts/2026-10-02-issuer-lifecycle-approval-authority/independent-review.md)
records all four findings and their accepted source corrections.

| Final executed scope | Passed | Limits |
| --- | ---: | --- |
| Full kernel unit suite | 1,504 | No failed or ignored tests |
| Full API-protect and MCP-remote unit suites | 352 | 234 API and 118 MCP |
| Full policy unit suite and three affected integration suites | 222 | 194 unit, 8 human-in-loop, 12 compile, 8 extension |
| SQLite authority/approval selection and lifecycle/custody integration suites | 66 | 41 selected unit, 14 lifecycle, 11 custody |
| Keyring unit and state suites | 19 | 8 unit and 11 state |
| CLI consumers and control-plane authority/native credential selections | 73 | 16 CLI, 46 authority, 11 native credentials |
| Python SDK, Hermes and operator helper | 511 | 216 SDK, 271 Hermes, 24 operator; 4 live Hermes cases skipped |

The Rust total is **2,236 passed, zero failed and zero ignored** across those
final selected runs. Warnings-denied, all-target Clippy passed for the nine
affected packages; workspace formatting and all scoped source gates passed.
Hygiene allowances, timeouts and ignored-test counts were not expanded. The clock
gate reports 426 observations and 38 native compositions with no additions;
the trust gate reports 473 constructors, 85 tenant tables and 170 explicit SQL
principal contracts. These are census counts, not a proof of complete coverage.

The final build initially produced 1,503 kernel passes with one fixture failure,
37 selected SQLite passes with four failures, and 45 selected control-plane
passes with one fixture failure. The last repair changed four test files only:
explicit policy identity, valid maximum-generation history, error provenance,
earlier clock-regression refusal, a deterministic shared clock, and a valid
current-key status fixture. The affected suites were rebuilt and rerun to the
terminal results above. Unchanged consumer binaries remain bounded evidence for
their unchanged production and test paths; the manifest records that reuse.

An earlier broad affected-owner campaign was cancelled after observed failures:
API 234 passed, CLI 721 passed/3 failed, and control-plane native cases were
partially executed. Its remaining targets were not executed and are not passes.
Full workspace and full control-plane qualification were not completed by this
batch. The SDK wide Ruff attempt also retains 10 pre-existing client/testing
findings reproduced at the base; the changed new contract/model/tests and Hermes
surfaces pass. No suppression or lint baseline was added.

Original controls reproduced implicit receipt-key issuance/approval authority,
unbound approvals, ineffective policy configuration, indefinite old issuer trust,
clock-error trust fallback and unsafe file custody. Further behavioral controls
reproduced remote stale-cache trust, rejection of a legitimate same-generation
expiry shrink, and promotion of the independent recovery root into issuer custody.

Early integration attempts also encountered compilation failures (include-relative
module paths, migrated fixture fields and a borrowed-path argument) and fixture
failures (private directory modes, current-thread async host, reusing terminal
request lineage, and missing durable admission composition). Compilation failures
are not behavioral RED evidence. Rejected replay is asserted by signed denial and
zero execution, rather than assuming every protocol uses HTTP 409.

The decoder inventory gained three reviewed checked constructors and one typed
approval-context conversion, with reviewed MCP record and redemption owners.
Nine wire identifiers (including three legacy KG1 tags) are now acknowledged in
the wire lock. The new security tags have actual signed-shape test pins; the
unpinned-schema debt remains 168. Raw-input debt, lint allowances, ignored tests
and timeouts were not increased. The inventory remains a bounded lexical census;
CA3 framework ingress remains separate work.

## Explicit limits and next work

Linux filesystem custody is the implemented platform contract. Other operating
systems refuse before creating seed-bearing files until equivalent ACL and SQLite
descriptor semantics are qualified. Seeds remain plaintext. This is not HSM,
external custody or whole-database rollback protection.

Automatic checkpoint replacement, custody transfer, deployed migration, actual
recovery-root provisioning and production approver/source activation are separate
operator actions. The bounded chain requires an explicit new-stream plan before
its 1,024-transition limit. Enterprise witnessed lifecycle orchestration and
complete receipt-signing custody remain separate from this SQLite issuer batch.

The old Docker qualification harness cannot exercise the new approval contract:
it lacks a provisioned, activated approval source, external signer and current
manifest/cage setup. Those workflow selections now report `unavailable`, refuse
before runtime construction and exit nonzero. Native Rust consumer evidence does
not turn them into Docker or process-crash acceptance. Optional live Hermes tests
also remain skipped when no live sidecar is configured.

The next substantial batch is AC4 plus CA3: require current lease/fencing authority
for protected run and step writes in their committing transaction, and inventory
framework extractors and shared decoder consumers before migrating the exposed
signed/authoritative ingress. Add stale-owner and concurrent takeover controls,
duplicate/original-byte ingress controls, and exercise actual production consumers.
Remaining TCB reader semantics, guard integration, evidence retention, review
findings and hosted/release acceptance remain on their existing roadmap owners.
