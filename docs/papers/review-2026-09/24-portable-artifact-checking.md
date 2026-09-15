# Portable artifact checking without receiver trust

2026-09-13. Continuing after [recoverable Git publication](23-recoverable-git-publication.md).
A consumer can now check the delivered source repair without access to the
publishing receiver's keys, store or repository. The experiment also produces
a validly signed publication claim when the claimed reference was never
created. Its verifier accepts the valid artifact while explicitly leaving
private publication history unverified. These are different propositions.

## The executed counterexamples

The receiver setup creates three repositories for each gate:

1. An honestly checked repair, published through the existing Git adapter.
2. The original buggy source, provisioned under a false checking assertion and
   published through that adapter.
3. The valid repair in a prepared commit, with no claimed publication slot and
   no `refs/heads/verified-repair` reference. A receiver deliberately registers
   a tool that returns a false publication result. The real kernel mediates
   the call and signs that returned result under the actual selected key.

All six original replies pass pinned-key signature verification, request hash
and parameter binding, target and decision checks, and result-content binding.
A different pinned key fails verification. The third repository's gate remains
`waiting`, and the claimed reference is absent before and after export.

The false-publication bundle is exported using another local reference. Its
header advertises the claimed publication name, while the pack carries the
valid prepared commit. Native Git can import it. A sender-chosen reference name
in a portable archive is not a witness to that name's private history.

This does not expose a signature forgery or a production authorization defect.
The kernel receipt correctly authenticates the result the tool returned. The
test intentionally supplies a dishonest receiver/tool setup. Treating the
authenticated result as proof of the external effect would add a trust
assumption that signature and content-hash verification do not discharge.

## A usable consumer check with a narrower assertion

The new [auditor](../../../examples/outcome-ledger-comparison/src/graph/repair_git_audit.rs)
receives a small manifest and a Git bundle, plus a baseline selected by its own
operator. The sender cannot replace the baseline or the locally installed
checker. No publisher signature is required.

The auditor checks the bundle digest and a bounded profile: Git bundle v3,
SHA-256 object format, one fixed advertised reference, no prerequisites or
filters, and at most 64 packed objects in one MiB. It imports into a new
repository using native Git, checks the pack and object graph, requires exactly
the two regular-file paths, and compares their bytes with the artifact digest.
It then runs the existing seven-case behavioral contract on those bytes.

Candidate Python cannot see the auditor's Git check repositories. The outer
auditor namespace has no receiver directory or network mounts. Across twenty
auditor runs, nine receiver-state paths per run fail to open, including real
key seeds, gate databases and repository configurations. Host-side positive
controls open all eighteen distinct targets. The packet mount rejects write
opens in all twenty runs. Nested candidate namespaces retain the earlier
restrictions on creating further user namespaces.

Successful output records `artifactPassed: true`, the commit and artifact
hashes, the local verifier executable's hash and seven checked cases. It always
reports `publicationHistoryVerified: false` and
`receiverExecutionVerified: false`. A separate receiver-claim sidecar is not
read by the artifact auditor. Its signature is authenticated separately in the
comparison, under the original selected key, to make the counterexample
explicit. Unsigned packets follow the same artifact-checking path.

Consumers can use the checked source itself. They cannot use this result as a
verified record of private dispatch, accounting, settlement or publication.
The result is produced by running a trusted local program; it is not a proof
that an untrusted remote verifier ran that program. The binary hash identifies
the local executable and does not prove its runtime environment or execution.

## What the run observed

[The comparison](evidence/24-portable-artifact-checking/artifact-audit-comparison.json)
has ten scenarios per gate. The outcome observations match in every pair.

| Packet | Artifact result | Publication history |
| --- | --- | --- |
| Honest publication and correct repair | Pass | Unverified |
| Buggy source with an authenticated receiver claim | Fail seven behavioral cases | Unverified |
| Valid source with an authenticated false publication claim | Pass | Unverified |
| Valid source without a receiver claim | Pass | Unverified |
| Sender changes the trusted base | Reject | Unverified |
| Declared target differs from the bundle | Reject | Unverified |
| Corrupted pack | Reject during native Git import | Unverified |
| Wrong advertised reference | Reject | Unverified |
| Excessive packed-object count | Reject before import | Unverified |
| Oversized bundle | Reject before import | Unverified |

The corruption cases recompute the sender's transport hash after mutation.
They therefore exercise structural validation and native pack checking, rather
than merely failing the outer digest comparison.

There are two initial receiver checks and eight independent auditor behavioral
checks, totaling seventy actual Git commit cases. Fourteen cases for the buggy
source produce 42 hook markers and fail; the other 56 produce none and pass.
Six auditor results accept valid artifacts, including both unsigned packets
and both false-publication packets. None claims verified receiver history.
The six original kernel replies are authenticated; four correspond to actual
publication and two to the deliberately false tool result. Reusing a reply in
mutated packet cases does not authenticate the mutated packet metadata.

## Boundaries and prior art

The consumer trusts its own checker, baseline, Git and Python implementations,
local executable and host kernel. The finite regression contract permits
test-specific implementations and does not establish arbitrary source safety.
This is local re-execution, without a succinct proof, zkVM or remote trusted
execution claim. The real repair was authored during earlier work; no live
LLM discovers it in this experiment.

The auditor and its descendants have per-process address-space, file-size,
CPU and descriptor limits. They are not aggregate quotas. A bounded pack header
does not by itself bound all decompression or parser costs. The test suite
does not qualify arbitrary hostile packs, aggregate denial of service or
production isolation. The new outer namespace allows its trusted auditor to
create the inner checker namespaces. All processes share one host, and no
independently administered deployment is qualified here.

Git documents bundles as an offline transport of objects and advertised refs.
Its format contains a sender-written header followed by a pack. Our inference,
also exercised by the false-publication case, is that this artifact alone
cannot establish the advertised reference's existence in a private repository.
[Git bundle](https://git-scm.com/docs/git-bundle),
[Git bundle format](https://git-scm.com/docs/gitformat-bundle).

Foundational proof-carrying code already separates an untrusted producer from
a locally trusted checker. Our behavioral replay is a finite executable test,
not a foundational proof of program safety. Moving checking to the consumer
does not establish novelty over that principle.
[Foundational Proof-Carrying Code](https://www.cs.princeton.edu/~appel/fpcc.html).

The trusted receiver is unnecessary for the delivered artifact's checked
property, but local verification remains necessary. The strongest objection
to calling this a breakthrough is that it composes established transport and
re-execution techniques, and works equally with the ordinary ledger. No
measured cost advantage, fair exchange or new distributed trust mechanism has
emerged. A result that changed that judgment would need a useful workload
with independently verified operational advantage under an equally capable
alternative, or a mechanism that removes a remaining necessary trust party.

## Reproduction and qualification

```sh
CARGO_TARGET_DIR=target cargo run --locked --offline \
  --manifest-path examples/outcome-ledger-comparison/Cargo.toml -- \
  --repair-artifact-audit examples/outcome-ledger-comparison/fixtures/git-hook-repair/base .

CARGO_TARGET_DIR=target cargo run --locked --offline \
  --manifest-path examples/outcome-ledger-comparison/Cargo.toml -- \
  --audit-repair-bundle examples/outcome-ledger-comparison/fixtures/git-hook-repair/base \
  RUN_DIRECTORY/chio/packets/unsigned_valid
```

An optional final argument selects a new output directory. Linux, bubblewrap,
Git 2.43.0 with SHA-256 support, Python 3.12 and `prlimit` were used. The
[README](../../../examples/outcome-ledger-comparison/README.md) lists the
runtime assumptions. Offline Cargo requires cached dependencies.

All seven integration tests passed in 87.73 seconds, including an additional
standalone consumer invocation and all previous recovery/append comparisons.
All-target Clippy, formatting and diff checks pass. The paper builds at
12 pages and 4,950 body words. Source boundaries and retained evidence hashes are in the
[manifest](evidence/24-portable-artifact-checking/manifest.json).

No production runtime, Python repair source, dependency manifest or lockfile
changed. The new experiment, tests and paper remain local and uncommitted on
`paper/roadmap-phase-0-1`, based on
`2b3b5af8cbfbc6f16ce6005de3f97cd149803b81`. There is no exact-commit CI, release
qualification or achieved-breakthrough claim.
