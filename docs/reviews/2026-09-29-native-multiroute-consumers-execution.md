# Native multi-route authority and consumer integration

Source base: `95f04d5d74`, branch `packet/3-retention-accounting`,
`/tmp/arc-security-launch`. This continues the
[native consumer plan](../superpowers/plans/2026-09-29-native-multiroute-consumers.md).
It does not establish hosted, release or M5 acceptance.

## Task outcomes

| Task | State | Delivered boundary |
| --- | --- | --- |
| 1. Multi-route broker authority | Complete | Bounded exact routes, common authority-generation commitment, original per-route custody, capture, recovery lookup and offline evidence selection. |
| 2. Host-owned Docker/provider adapters | Complete | Pinned TLS provider transport and a Rust Docker adapter with bounded parsing, exact resource identity and no effect retry. |
| 3. Consumer preparation and migration | Partial | Durable prepared requests, process protocol and SDK, mini-SWE model/execution callers, explicit operator route validation and interpreter closure implementation. Session/repository callers remain open. |
| 4. Native campaigns and CI | Partial | Native broker cases and budget contention/recovery pass. Mini-SWE baseline still fails as retained history grows; session/public-repository and packaged-consumer acceptance remain open. |

## Authority and effect boundaries

The installed route set contains one to sixteen distinct server/audience/socket
routes. Its common generation binds every member's verifier configuration and
authenticated peers. Selection uses the original server/tool and audience; a
sibling route cannot reuse the shared generation to read or execute another
route's custody. Actual native capture tests exercise both routes, substitutions
and unchanged quota ownership. Verified manifest merging rejects conflicting
entries before mutation.

The process host signs and durably retains each prepared request under its
process and operation key. Repeated preparation returns the original canonical
bytes only when the retained binding matches. The worker cannot choose provider
credentials, the provider model/options/tools policy, Docker daemon/container
selectors or another signer. The process protocol is v3 and the journal reader
and writer share version 2. Old journals and obsolete signed enforcement
evidence do not acquire current authority.

The provider transport pins its configured loopback HTTPS endpoint, sole TLS
root and peer certificate digest before sending credentials. The Docker adapter
pins the Unix socket identity and peer, API version, daemon identity, full
container identity, start time and security configuration. It checks that
identity before starting an exec and after its terminal result. The command,
workspace, resource limits, response body and stream decoder are bounded.
Timeouts, replacement or incomplete output never trigger an automatic retry or
certify success. A privileged Docker administrator can still disrupt execution;
the resulting uncertainty is preserved.

The mini-SWE SDK uses host preparation and authenticated broker dispatch for
execution and inference. Its response decoder is not advertised as a receipt
signature verifier. Action guards examine the prepared command inside its
canonical broker body, so an outer action field cannot disguise the command.

## Repairs from native qualification

Native runs exposed a missing aggregate budget, response limits checked too late
and noncanonical response-header order. These were repaired at their owning
boundaries. Header names are canonicalized and duplicates rejected before
durable signing; an incompatible response ceiling is refused before capture.

Retained-history validation now authenticates initialization once per traversal,
inside the current transaction. Each event still validates its canonical bytes,
index, digest, original operation, lease and authority. No cached result crosses
a transaction or mutation boundary. This reduces repeated work but does not
resolve the remaining long-history handoff deadline failure.

The explicit CPython packager retains a bounded standard-library archive,
isolated import-path file, selected native extensions and exact ELF libraries.
The archive and import-path bytes are runtime artifacts, not just ordinary read
grants. The extension directory receives enumeration access; files remain
individually retained. The cage compiler deduplicates repeated identical paths
before counting its 64 read resources, rejects a changed descriptor identity and
continues to reject distinct hardlink aliases. Canonical ELF interpreter paths
must match explicit runtime declarations. Provisioning, discovery, signed
manifests and operator ceilings carry the same selected closed syscall profile.
Native audit records identified CPython's `mremap` and UUID/platform `uname`
requirements. Discovery now honors the selected standard profile; that profile
permits the bounded `uname` metadata read. A regression checks profile selection
and continued denial of network creation. The helper maps the syscall explicitly
on both supported architectures.

The budget campaign's observer now waits for the runner table rather than
treating creation of its database file as schema readiness. Its explicit
Enforced configuration and 64 MiB artifact ceiling match the native fixture.

## Verification and limits

Focused terminal evidence is recorded with the
[artifacts](artifacts/2026-09-29-native-multiroute-consumers/README.md).
Failed, zero-test and diagnostic runs are retained separately and do not count
as passing qualification.

- Broker unit suite: 183 pass; six privileged native cases pass separately,
  serially. Docker parser/lifetime cases and real adapter probes pass.
- Control-plane multi-route capture: five pass. The strengthened original
  capture substitutions also pass against the final assertion bodies.
- SQLite native history: 95 distinct cases pass. A full local disk interrupted
  30 of them; only those 30 were retried after freeing reproducible build output.
- Prepared-request reopening, route identity, journal-version refusal, manifest
  merge and broker command extraction pass. Process state/blob reader: six pass.
- Python process SDK: 44 pass. Mini-SWE operator/provider tests: 25 pass.
  Conformance native launch configuration: five pass.
- Fresh native outcome composition and canonical ELF loader tests: three pass.
  The earlier empty selector is recorded as zero tests, not acceptance.
- Cage compiler: fifteen existing cases pass plus the new 64-resource,
  overlapping-path and hardlink case. The initial new case omitted its explicit
  forbidden-path policy; the corrected case passes. Release-mode test mutants
  were correctly refused; these compiler tests use the test profile.
- The final native CPython discovery probe passes with its selected stdlib and
  native extension imports, explicit runtime files and the standard profile.
  This qualifies startup/discovery for that bounded closure, not arbitrary
  application imports, SQLite mutation or the remaining consumer campaigns.
- Owning CLI/broker/cage Clippy, formatting, file hygiene, trust-boundary,
  negative-assertion and wire-schema checks pass. No source-size or assertion
  allowance was increased.

The current signed budget fixture comes from a real four-worker, two-effect
campaign. After the host was killed, recovery performed no additional effects.
The exported v3 report passes signature and original launch-policy verification.
Bob and Carol have terminal launch receipts; Alice and Dave have start evidence
only. The artifact does not invent exits or prove physical effects by itself.
Its provenance records the separate campaign observation, binary hash and dirty
source boundary. Historical signed fixtures remain negative evidence.

OCI confirms the qualification worker is `STOPPED`. Both retained volumes,
the build cache and original private campaign states remain available. The
artifact manifest records the completed local/native checks and their binary
identities; no private signing keys were exported.

Mini-SWE runs 1 through 12 did not qualify the baseline. Run 12 completed four
calls, then failed the fifth lifecycle handoff after durable capture. The original
operation remains uncertain and is not redispatched. Neither deadlines nor
signature/history checks were relaxed to make the campaign pass. Without a
passing baseline, crash/restart, unknown-effect, provider/operator/session/public
repository and packaged-consumer campaigns are not accepted.

## Next execution boundary

1. Remove repeated retained-history work across the hot admission/capture/output
   path using transaction-scoped verified context, preserving all mutation,
   corruption, rollback and original-custody checks. Qualify sustained multi-route
   execution under the existing deadlines, then the known and uncertain crash
   campaigns.
2. Finish host-owned repository authority and migrate operator/session/public
   repository launchers to the same prepared broker contract. Retain the complete
   source snapshot, scope and receipt proof chain.
3. Finish interpreter and packaged SDK/example/conformance qualification. Replace
   broad CI read grants with the bounded runtime closure and exact application
   resources; update all affected native campaign inputs without skipping gates.

The [remaining security queue](2026-09-28-remaining-security-work.md) also retains
the broader reader/error, arithmetic, clock, declaration, assurance, retention,
formal, supply-chain and delivery work. This batch closes none of those by
implication. No push, merge or publication is performed.
