# Native host qualification and activation owner

Status: proposed owner extension, not implemented. This contract closes the
previous unassigned dependency on a shared evidence verifier. It is required
before a native profile can activate or promote, and is delivered by shared
plan packet 2a. Platform candidate assembly may precede installed acceptance;
those candidates remain explicitly unqualified and cannot activate a protected
capability merely because packaging succeeded.

## Concrete implementation owner

Extend the existing `crates/tooling/chio-release-evidence` owner. At PROGRAM-MAP
T, `src/main.rs` implements the `chio-release-qualification-manifest` binary;
`ReleaseQualificationManifest` records source/lock identity and artifact hashes.
Its declared scope is self-signed internal qualification. `validate_signed_manifest`
checks the embedded signature and candidate identity, not an independently
trusted qualification issuer, complete Q-case outcomes or native profile readiness.
Existing `--verify` success therefore cannot authorize installation activation.

Proposed additions in that crate are `src/lib.rs`, `src/native_host.rs` and
`tests/native_host_qualification.rs`; preserve the current binary and v1 artifact
manifest semantics. The owner defines a separate versioned native-profile
contract and strict bounded decoder, reusing canonical/signature primitives.
Do not reinterpret existing signed v1 bytes or invent a platform-specific signer.
The release owner supplies the trusted issuer policy, versioned case catalog,
verification library and command; native installation/activation owners consume
its typed result. The command/API names become executable instructions only
after implementation and owner approval.

Platform wiring belongs to the existing native lifecycle/activation owners
selected in O0/M0 and adapters in `integrations/linux/` and `integrations/macos/`.
Those packets must record concrete owner entrypoints before coding. Packet 2a
has a shared verifier implementation gate and separate Linux and macOS wiring
gates. The shared gate closes on the implemented library/CLI and owner tests;
each platform's gate additionally requires its own actual activation call sites
and installed tests. O7 depends on the shared plus Linux gates; M10 depends on
the shared plus macOS gates. Neither platform waits for the other platform's
wiring or results. Full packet completion records all gates separately; an
unbound verifier CLI cannot close any platform's activation gate.
This is release eligibility enforcement, not a replacement for current native
capability, credential or resource admission.

## Verification inputs and decision

The verifier consumes three separately authenticated inputs:

1. The actual candidate and installation inventory: artifact bytes/digests,
   source/lock identity, platform/architecture, OS/backend, owner/client ABI,
   principal/deployment mode, policy and active installation generations.
2. The approved requirement catalog and release policy, obtained independently
   of the candidate's result declarations. It maps every selected capability
   and profile to required owner, Q/C/platform cases, each stimulus, positive
   control and independent observation. It names permitted exclusions for
   genuinely absent surfaces and the release channel/assurance scope.
3. Evidence bound to that exact tuple and catalog, with required provenance,
   authorized issuer/reviewer, source/native/hosted/installed dimensions,
   observed result, source commands/log digests and validity/freshness.

Verification returns a non-forgeable typed accepted result within the owning
process or an authenticated owner response across a qualified boundary, with
exact tuple, capability set, catalog/policy digest and validity context. Otherwise
it returns an explicit refusal/unavailable reason. A caller-provided `ready`
boolean, exit code copied into config, valid self-signature or arbitrary
candidate-supplied trust root cannot supply acceptance.

FIRST-CLASS-INTEGRATIONS' catalog scope distinguishes individual harness,
Herdr/harness tuple and aggregate completion claims. Test missing unrelated
records as an allowed partial promotion and missing own mandatory subcases as
a refusal; aggregate completion still requires its mixed/full-coverage records.

The mandatory catalog is not learned from the results being verified. Removing
all profiles/cases, downgrading policy/catalog version, omitting a consumer,
changing a capability's declared dependency or replacing missing evidence with
an empty collection must not produce vacuous success. The installed/advertised
capability inventory must match the selected independently approved policy.
Narrower profiles need their own legitimate policy and cannot expose excluded
routes, owners or claims. Approved source-review exclusions are authenticated,
scoped and checked, not arbitrary free text in an untrusted manifest.

Required evidence rejects failed, skipped, unknown, stale, revoked, mismatched
or missing outcomes. Parsing is strict/canonical and bounded before semantic
consumption; signature and semantic validation use the same accepted bytes.
Issuer authentication is rooted outside supplied evidence. Q18's correctly
signed malformed fixtures must reach the decoding/semantic gates instead of
being masked by signature refusal. Case counts alone are not sufficient.

## Qualification candidates versus release activation

Installed tests must be able to generate evidence before production promotion.
The native activation owner therefore implements two distinct admitted modes.
A qualification-only candidate runs under an independently approved test policy
and existing native authority: exact signed candidate, named enrolled test
principal, selected finite capability/expiry, isolated fixture resources, bounded
cleanup and an explicit case run. That test policy lists the predecessor gates
required before any such native effect; missing native admission or confinement
cannot be bypassed for convenience. Its test authorization is not a passing
result or production release endorsement.

The qualification mode is unavailable to ordinary consumers and production
resources. A flag, environment variable, local self-signature or incomplete
release manifest cannot select it. Installed evidence is captured under that
explicit scope, then independently assessed by the release policy/verifier.
Normal activation and promotion require the complete production eligibility
result. Test cross-mode attempts: replay test authorization as release approval,
change principal/resource/candidate, escape finite scope and restart after expiry.
Observe independent production-byte/effect sentinels and refuse every crossing.
This separation allows O7/M9 to run, while O7/M10 promotion remains fail closed.

## Native enforcement and lifecycle

Consume acceptance at profile enablement, service startup, update activation,
backend/policy replacement, principal change and any operation that could expose
an unqualified capability. Bind the verified candidate to the actual installed
and active executable/policy/owner closure; close substitution and race windows
through the owning installation transaction/generation fence. Verification of
staging bytes cannot approve different active bytes. No client cache or optional
controller may authorize this transition.

Cache only under the owner's bound tuple, policy, generation and validity rules.
Material changes invalidate it, and expiry/revocation or uncertain clock/freshness
fences the affected profile. Q31 applies to time-bounded release evidence as well
as task authority. Ordinary native admission still checks current grants and
resource custody independently; release eligibility never grants a tool call.
A narrower already qualified profile may remain available if its own complete
closure and current authority still pass. Recovery/status of retained work
follows its separate native owner rules and is not lost with UI eligibility.

## Required implementation acceptance

Use the actual new library/CLI and actual native activation call sites, not a
manifest linter alone. Require a useful signed installed positive control, then:

- Remove each required Q/C/platform case and each required sub-stimulus,
  positive control and independent observation individually. Failed/skipped/
  unknown placeholders cannot satisfy the missing record.
- Substitute candidate bytes, source, principal, architecture, backend, policy,
  catalog, case owner, log digest, runtime/client ABI or active generation.
- Use a valid signature from an untrusted or revoked issuer, a candidate-supplied
  root, expired evidence, a rolled-back clock and unavailable freshness.
- Exercise canonical/duplicate/depth/count/byte limits with authorized signers,
  and retain a valid-format positive control for each negative family.
- Change the installed capability inventory or drop its requirement catalog;
  reject empty-ready, unapproved exclusions and version/floor rollback.
- Race enablement/update/removal, change staged/active bytes after validation,
  restart mid-transition and replay an old accepted result in a new incarnation.
- Observe native route availability, protected-byte canaries and dispatch/effect
  counters directly: an affected capability cannot activate or promote, while
  the unchanged complete authorized control succeeds. UI text is no oracle.

Run existing `cargo test --locked -p chio-release-evidence` regressions and,
after adding the proposed test, the owner-approved native-profile suite and
platform installed activation suites. Record their actual commands, source
and bytes. Packet 2a delivers the shared verifier and the relevant platform's
executable gate before that platform's O7/M10 promotion relies on it;
final installed case results still come from O7/M9 and are consumed at promotion.
