# Inline review: bilateral consent and isolated roles

Reviewed inline without sub-agents. Scope includes public consent, original
private request retention, separate context signing, provider command entrypoints,
namespace mounts, checker dependencies and the complete owned-chain process flow.
The manifest binds the final source and executable; this is local qualification.

## Preserved authority

The buyer verifies a separately supplied intent before signing. Its outer signed
acceptance binds the entire public proposal, including input; the inner bilateral
agreement preserves the registered v2 commitment. Provider execution checks the
outer signature/digest, exact retained proposal and original private request,
then applies existing native signatures/request/waiver checks. A raw agreement
alone cannot invoke this new provider execution command. Legacy native paths keep
their original contracts. Full signed body validation was factored from signature
verification without removing either signature or any native request check.

The provider retains intent before capability issuance and the complete private
request before publication. The buyer retains intent before signing and first
consent before publication. Completed replay uses original times and signatures,
not regenerated authority. Invalid buyer keys and changed work terms do not
consume buyer consent custody. Exclusive files and synchronized directories
preserve partial state rather than repairing it with a new original identity.
Concurrent first attempts can fail while a record is being written; completed
exact retries recover the same artifact. Global non-equivocation and rollback
protection for these local files are not claimed.

## Corrections from tests and review

A missing provider intent marker with its proposal still present initially caused
a retry to recreate the marker and issue another capability before failing at
proposal retention. The failing custody regression demonstrated this. The provider
now denies before replacing the missing marker. The buyer similarly retains a
separate intent marker and denies a missing/incomplete consent response rather
than signing a replacement. The retained development red log records the original
provider failure; final Rust tests cover both roles' missing-component paths.

The first full namespace lifecycle correctly stopped at the native startup guard:
the new execution CLI used the deliberately restricted handoff open mode. Execution
now uses normal startup reconciliation. Public export/import and explicit
settlement retain their narrower open mode. The admission guard itself was not
weakened. Both complete isolated payout and refund then passed.

## Actual namespace boundary

The launcher mounts one role state, explicit public inputs and a new output
directory. It does not mount the repository or host root. Host network/PID/IPC
namespaces are not shared; capabilities are dropped and environment cleared.
Existing seeds are read-only mounts. Checker mounts derive from the actual pinned
source inventory, preventing a duplicated allowlist from drifting. Public file
transfer reads no seeds, native requests or journals. Shared mock-chain ownership
and administration remain explicit limits.

Five probes per scenario attempt peer-state/host-sentinel access, a read-only input
write and access to a live host-loopback listener. Missing bwrap/namespace support
fails execution. The actual provider/verifier sockets still work across these
namespaces, and only the receiver-selected socket is mounted. The verifier socket
retains its read-only method restriction.

The checkpoint operator retains its existing checkpoint/status pair within one
domain. Governance draft creation sees no status seed. Status attestation validates
the selected public context before publishing the final existing context. Drafts
alone cannot admit work, and no unsupported Finding assurance is added.

## Recovery and evidence boundaries

The process flow forces read-only publication failure after buyer/verifier custody
commits, removes the signer keys, and recovers the exact original artifacts. The
verifier also loses observer and checker access. Altered consent fails; payout and
refund preserve original native identities, unique chain events and one execution.
Python verifies the existing public execution witness, not the new consent wrapper
or financial backing. Existing native financial-resolution, earned-child and
execution-custody crash regressions are independently selected for qualification.

All new code is confined to the standalone example and documentation. No workspace
crate/dependency, native same-signer checkpoint rule or formal model changes are
introduced. No new unsafe code or production unwrap/expect calls are introduced.
Full workspace testing, public transport, separate administrators, public chain
finality, external revocation, external rollback anchors and real funds remain
outside this local slice.
