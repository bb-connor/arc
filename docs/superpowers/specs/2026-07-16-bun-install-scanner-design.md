# Chio Install Scanner for Bun: Policy-Checked, Receipted Dependency Ingestion

- Status: Draft for review (2026-07-16). Proposal only. Part of the substrate-receipts program (see Related); this is the cheapest surface in it.
- Scope: a new npm package `@chio/bun-security-scanner` (TypeScript, likely homed with the host plugins on `@chio/bridge` infrastructure), plus a vendor policy block in `arc`/`hush`.
- Related: `docs/superpowers/specs/2026-07-15-bun-runtime-enforcement-design.md` (same session signer, same receipt chain), `docs/superpowers/specs/2026-07-15-policy-expansion-design.md` (placement litmus, warn semantics 1.2), `spec/PROTOCOL.md`.

## 1. Context and problem statement

Agents add dependencies. A coding agent that decides it needs a package runs `bun add`, and whatever that package (or its transitive graph) contains enters the workspace and, on next execution, the session. Dependency ingestion is an agent action with real blast radius, and today Chio has no surface at it: supply-chain discipline exists inside the arc repo (cargo-vet, cargo-deny) but there is no product that governs what an agent installs.

Bun 1.3 shipped a first-class choke point for exactly this: the Security Scanner API. A `bunfig.toml` entry names a scanner package, and Bun invokes it during `bun install`, `bun add`, and other package operations, before dependencies are written to disk. The scanner returns advisories at two levels with blocking semantics: `fatal` aborts the install unconditionally; `warn` prompts in interactive terminals and exits immediately in CI. Socket and an OSV.dev scanner already ship as providers. No other mainstream JS package manager has a blocking, pre-write scanner API, and Bun is Anthropic-owned and under the ecosystem's attention post-Rust-port, so this surface is both unique and timely.

The fit with HushSpec is unusually clean: Bun's `warn` (permitted pending confirmation, deny where no confirmation channel exists, which is what CI is) is hush section 6's warn semantics almost verbatim, and the TTY prompt is the confirmation channel the policy expansion program's item 1.2 requires.

## 2. Goals

- Install decisions evaluated from a Hush document, not from a threat feed alone: registry allowlists, package/version constraints, lifecycle-script gating, license constraints, minimum-package-age rules.
- A signed receipt per install operation: packages requested, per-package decisions, rule ids, policy hash, and lockfile digest before and after, chained through the session signer when a governed session is active and buffered locally otherwise.
- Composition with existing intelligence scanners (OSV, Socket) rather than competition with them.
- Fail-closed behavior for the scanner's own faults.

## 3. Non-goals

- Vulnerability intelligence. Chio does not maintain a CVE or malware feed; that is what OSV/Socket delegation is for.
- Post-install auditing of `node_modules` state, lockfile diffing outside install operations, or runtime behavior of installed code (the runtime enforcement design covers execution).
- npm and pip equivalents. Neither has a comparable blocking API; they are future work with different shapes and are out of scope here.
- Attesting that what runs later matches what was scanned (see 7, claim discipline).

## 4. Architecture

The package implements Bun's scanner contract (`version: "1"`, an async `scan` over the proposed package set) with three internal stages:

1. **Policy evaluation.** Load the workspace/org Hush document (same resolution order as the runtime enforcement design), evaluate each proposed package against the install policy block, and map decisions: hush deny -> `fatal`, hush warn -> `warn`, allow -> no advisory. Policy load failure or an internal error returns a single `fatal` advisory naming the fault: the scanner fails closed on itself.
2. **Delegation (optional).** Bun's `bunfig.toml` accepts exactly one scanner, so composition must happen inside ours: the policy block may name upstream scanner packages, which are invoked in-process and their advisories merged (upstream `fatal` stays fatal; upstream `warn` may be escalated by policy). Without delegation configured, the scanner is policy-only.
3. **Receipt emission.** One receipt per install operation, canonical-JSON encoded, carrying the operation summary, decisions, policy hash, and lockfile digests. When the session signer from the runtime enforcement design is running, receipts chain there; otherwise they append to a local JSONL buffer with the same canonical bytes (the chio-hermes pattern: local log is a convenience, the signer store is canonical).

## 5. Policy surface

HushSpec has no dependency block today. Per the placement litmus, this starts vendor-scoped and is a promotion candidate once the shape settles (dependency ingestion is runtime-agnostic; pip/cargo would want the same block):

```yaml
extensions:
  vendor:
    chio:
      install:
        registries: ["https://registry.npmjs.org"]
        deny_packages: ["left-pad@*"]
        pin_overrides_required: true
        min_package_age_days: 7
        lifecycle_scripts: deny        # gates trustedDependencies changes
        licenses: { deny: ["AGPL-3.0"] }
        delegate: ["@bun-security-scanner/osv"]
```

`min_package_age_days` is the freshness heuristic against registry-poisoning attacks (most malicious versions are caught within days of publication). `lifecycle_scripts: deny` matters because Bun does not run postinstall scripts except for `trustedDependencies`; the policy gates edits to that list, which is otherwise a quiet escalation path.

## 6. Failure modes

- Scanner internal error, unloadable policy, unreachable delegate: `fatal` advisory, install aborts. The scanner never silently passes on its own failure.
- Bun's behavior when a scanner package itself crashes or is missing is not specified in Bun's documentation. This must be established empirically before any enforcement claim, and if Bun fails open on scanner crash, that fact goes in the claim scoping (a determined agent could corrupt the scanner package itself; mitigation is the receipt gap this leaves plus filesystem protection of the scanner install, which the runtime design's fs rules can express).
- No `bunfig.toml` entry means no scanner runs at all. Fleet configuration (is the scanner configured everywhere?) is attested by the session-binding receipt from the runtime design, which records plugin/scanner configuration at session start.

## 7. Claim discipline

A verified install receipt proves: at install time T, this package set was evaluated against policy hash P with these decisions, and the lockfile moved from digest A to digest B. It does not prove that `node_modules` still matches B later, that packages fetched outside `bun install` (direct tarball downloads by a tool, git checkouts) were evaluated, or anything about runtime behavior. Coverage of git and tarball dependencies inside `bun install` itself is unverified against the API and is an open item below.

## 8. Rollout

1. Package builds and passes against the oven-sh scanner template's conformance expectations; policy-only mode first, delegation second.
2. Advisory soak: run with all decisions mapped to `warn` in TTY (never in CI) to validate policy fit, receipts flowing.
3. Enforcement claims only after the scanner-crash behavior (6) is established and documented.

## 9. Risks and open questions

- **Publishing is blocked on the npm scope.** The `@chio` npm scope is currently empty and the bare `chio` name is squatted (2026-07 distribution audit). Claiming the scope is a prerequisite to shipping and predates this design.
- **Single-scanner slot.** Delegation makes Chio the org's one configured scanner; a bug in ours blocks all installs. Fail-closed is correct but the operational cost is real; needs a documented break-glass (remove the bunfig entry, which is itself visible in the session-binding receipt).
- **API stability.** The Scanner API is new in 1.3; the `version: "1"` field exists precisely because Bun expects to revise it.
- **Coverage of non-registry dependencies** (git, tarball, workspace links) by the scan callback is undocumented; test and scope claims accordingly.
- **Spec pressure.** The install block must ride the vendor namespace until promotion; it must not become new arc-only drift while spec re-convergence is in flight.

## 10. Deliverables

`@chio/bun-security-scanner` package (policy evaluation, delegation, receipts, fail-closed faults); vendor policy block schema + validation in `chio-policy`; scanner-crash behavior report against current Bun; conformance run against the scanner template; publish gated on the npm scope; claim-scoped README per section 7.

## 11. References

- Bun Security Scanner API: https://bun.com/docs/pm/security-scanner-api
- Scanner template: https://github.com/oven-sh/security-scanner-template
- Socket's Bun scanner: https://socket.dev/blog/socket-integrates-with-bun-1-3-security-scanner-api
- OSV provider: https://www.npmjs.com/package/@bun-security-scanner/osv
