# Native host qualification and activation owner

Status: proposed owner extension, specified and not implemented. See
[STATUS-GLOSSARY](STATUS-GLOSSARY.md). Shared plan packet 2a delivers it, and no
native profile activates or promotes without it. Platform candidates may be
assembled earlier; they stay unqualified and cannot activate a protected
capability because packaging succeeded.

## Owner

Extend `crates/tooling/chio-release-evidence`. At PROGRAM-MAP T its
`chio-release-qualification-manifest` binary records source, lock and artifact
hashes in a self-signed internal manifest; `validate_signed_manifest` checks
the embedded signature and candidate identity, not a trusted issuer, case
outcomes or profile readiness. Its `--verify` success cannot authorize
activation.

Proposed additions are `src/lib.rs`, `src/native_host.rs` and
`tests/native_host_qualification.rs`, keeping the current binary and v1
manifest semantics. The owner defines a separate versioned native-profile
contract with a strict bounded decoder and reuses existing canonical and
signature primitives, with no platform-specific signer. Native activation
owners consume its typed result through adapters in `integrations/linux/` and
`integrations/macos/`.

Packet 2a has a shared verifier gate and separate Linux and macOS wiring gates.
The shared gate closes on the implemented library, CLI and owner tests; each
platform gate also needs its own activation call sites and installed tests. O7
depends on the shared and Linux gates, M10 on the shared and macOS gates.
Neither platform waits for the other. Release eligibility never replaces current capability,
credential or resource admission.

## Inputs and decision

The verifier consumes three separately authenticated inputs:

1. The candidate and installation inventory: artifact digests, source and lock
   identity, platform, OS and backend, ABI, principal and deployment mode,
   policy and active installation generation.
2. The approved requirement catalog and release policy, obtained independently
   of the candidate's results. It maps each capability and profile to its
   owner, cases, stimuli, positive controls and observations, and names the
   permitted exclusions.
3. Evidence bound to that tuple and catalog, with provenance, authorized issuer,
   evidence dimensions, observed results, command and log digests and validity.

It returns a non-forgeable typed accepted result bound to the tuple, capability
set, catalog digest and validity, or an explicit refusal. A caller-supplied
`ready` flag, copied exit code, valid self-signature or candidate-supplied trust
root cannot supply acceptance. The installed capability inventory must match
the approved policy. Removing profiles or cases, downgrading the
catalog, omitting a consumer or substituting an empty collection never yields
vacuous success. Failed, skipped, unknown, stale, revoked, mismatched or missing
outcomes are rejected; decoding is strict, canonical and bounded before
semantic use, on the same bytes the signature covers (Q18). FIRST-CLASS-
INTEGRATIONS' promotion rules decide partial versus aggregate claims.

## Qualification candidates and activation

A qualification-only mode lets installed tests generate evidence before
promotion: an exact signed candidate, a named enrolled test principal, finite
capability and expiry, isolated fixture resources, bounded cleanup and an
explicit case run, all under an independently approved test policy and existing
native admission and confinement. Ordinary consumers and production resources
cannot reach it, and no flag, environment variable, self-signature or partial
manifest selects it. Replaying test authorization as release approval, changing
principal, resource or candidate, escaping scope or restarting after expiry
refuse, observed through independent production sentinels. Normal activation
needs the complete production result.

## Enforcement and lifecycle

Consume acceptance at profile enablement, service start, update activation,
backend or policy replacement, principal change and any operation that could
expose an unqualified capability. Bind it to the installed and active
executable, policy and owner closure through the installation generation fence;
verifying staged bytes cannot approve different active bytes. Caches follow the
owner's tuple, policy, generation and validity rules; expiry, revocation or
uncertain clock fence the affected profile (Q31). A narrower qualified profile
may stay available if its own closure still passes.

## Required acceptance

Use the real library, CLI and activation call sites with a useful signed
installed positive control, then:

- remove each required case, sub-stimulus, control and observation in turn;
- substitute bytes, source, principal, architecture, backend, policy, catalog,
  case owner, log digest, ABI or active generation;
- use an untrusted or revoked issuer, a candidate-supplied root, expired
  evidence, a rolled-back clock and unavailable freshness;
- exercise canonical, duplicate, depth, count and byte limits with authorized
  signers, each with a valid positive;
- change the installed inventory, drop the catalog, try empty-ready, unapproved
  exclusions and version rollback;
- race enablement, update and removal, change bytes after validation, restart
  mid-transition and replay an old result in a new incarnation.

Observe route availability, protected-byte canaries and dispatch counters
directly; UI text is not an oracle. Keep `cargo test --locked -p
chio-release-evidence` passing alongside the new suites.
