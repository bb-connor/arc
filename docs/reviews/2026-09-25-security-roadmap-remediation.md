# Security review remediation

Scope: findings from the September 25 review of
`24b995af66dbd3661f74ccea0a5192ddcfd763b3`. This records source corrections and
bounded qualification, not security-launch or production-promotion approval.

## Corrected boundaries

| Finding | Correction |
| --- | --- |
| Privileged MCP discovery | Enforced discovery uses signed manifest admission, retained executable identities, the selected UID/GID and the real cage. The temporary manifest grants only the declared filesystem ceilings, with no network or environment access. Unconfined demo discovery refuses root. A single absolute I/O deadline covers blocked writes and inherited output pipes; process cleanup is owned before pipe extraction. |
| Cross-process cage authority | Every profile restricts `prlimit64` to PID zero and denies process-signaling syscalls. The helper rejects plans that remove these constraints. Harmless native probes cover self/peer resource-limit reads and peer signal zero. |
| Prepared broker credentials surviving disable/delete | Preparation retains the encrypted blob version. A shared backend mutation lock linearizes final version/status validation and durable dispatch commitment against provision, disable and delete. Already committed dispatches may finish; a successful mutation fences later commitments. The lock is released before provider I/O. |
| Relocation rollback resurrecting a retired source | Export retirement is included in the external rollback anchor and synchronized before export acknowledges success. Import seeds its new anchor from the imported transaction. Cleanup locks and removes only the relocating authority's artifacts, preserving unrelated authorities and the original source marker in a shared root. |
| Incomplete rotation reported as success | Normal completion, rotation retry and startup recovery share witness synchronization, independent auditor confirmation, exact Active receipt forwarding and a stable-head check. Seed installation and handoff cleanup wait for this result. Dropping an abandoned staged backend releases only its own pending lease. |
| Indexed receipts preventing retention | Schema v5 retains an immutable logical identity index while signed payloads move to the archive. Reads and retries authenticate and query the retained archive in one SQLite snapshot and recover the original receipt. A missing mapped payload fails closed. Migration preserves existing mappings and immutability guards. |
| Credential in response header names | Credential scanning covers original names, normalized names and values before release; discarded header material is zeroized. |
| Stable releases public before provenance | All binary releases stage as drafts. Stable publication depends on provenance and checksum staging, revalidates source gates, verifies downloaded hosted bytes, and checks unchanged asset identities before publication. Candidate operator acceptance remains required. |

## Follow-up defects corrected

- Broker dispatch revalidates live authority after potentially blocking capture
  and samples expiry again at final commitment.
- Authenticated caller-report replay respects emergency stop before releasing
  output.
- Non-native caller starts retain the original approval, DPoP, nonce,
  capability, declassification and runtime deadlines. Native and non-native
  calculations share the credential-deadline primitive; replay cannot extend
  the original window.
- Generic flow admission persists observed input taint before a destination or
  declassification decision can deny the call. This observation grants no
  release or declassification authority. An overflowing label join persists
  Top while admission still denies the overflow.
- The internal admission HTTP route authenticates headers before buffering or
  decoding a potentially large JSON body.
- npm and PyPI publishing now require exact-source main CI, security and release
  qualification, as well as matching package versions and tag namespaces.

## Compatibility and recovery

Receipt schema v5 is a forward migration. Older receipt-store binaries must
not be substituted after migration. Rollback anchors read the previous global
v1 format and write v2, which retains permanent export retirement. Restoring
only an old database cannot remove that retirement.

Private non-native caller context v6 adds a frozen exclusive start deadline.
Older contexts remain decodable for inspection and existing recovery checks;
they cannot acquire new start authority by inferring missing credential
horizons. Native context v5 continues to require its original native custody.

## Remaining roadmap gates

The protected publisher App secret exists; its metadata was verified on
September 26 UTC. This is not evidence that the trusted definition/source/image,
independent verifier, signed capture, or App-bound required-check transition has
completed. The independently published `chio-enterprise-evidence` binary still
needs established source/build/artifact provenance before the protected capture
chain can be accepted.

The genuine `aws-lc-rs 1.18.1` registry audit and independent fork-delta review
remain assurance work. No exemption or unsupported certification was added.

The documented full signed response dry-run profile, including rollback
simulation, is not established by the existing test-only plan publication.
`SecretBrokerDeploymentBinding.stage` describes the broker projection; it is
not a response-executor enforcement switch. The shipped dark, component-scoped
contract does not authorize an automatic-response deployment. A composed
production dry-run profile and its operational acceptance remain separate work;
no fake Applied receipt or external containment effect is used as a substitute.

Current-source hosted qualification, host installation acceptance, operator
publication and the observed pilot window remain independent gates. Historical
M7/M8/M9 results retain their original source identities.

## Validation

Completed focused checks:

- Broker library: 158 passed, including prepared credential mutation,
  post-capture expiry and header-name containment.
- Keyring: 10 router tests and 3 independent-service tests passed, including
  receipt-forwarding failure and loss/restoration of an auditor after activation.
- SQLite: 8 relocation tests, 7 rollback/identity tests and 66 retention/migration
  tests passed. The retention run includes the authenticated archive snapshot
  regression.
- Kernel: 29 caller/deadline tests passed, including original DPoP and shorter
  signed approval deadlines.
- Control plane: 6 selected tests passed, including emergency-stop replay,
  denied-input attestation and authentication before request-body consumption.
- Final flow/receipt integration: all 12 native evidence tests, both production
  flow-denial tests, 46 default-feature flow library tests and 34 security-kernel
  adapter tests passed after the snapshot and overflow corrections.
- CLI discovery: the bounded-I/O unit test and both live discovery integration
  tests passed. The live CLI integration uses the unconfined demo profile;
  privileged enforced discovery is not claimed as an executed CLI scenario.
- Release gates: 14 source-gate, 15 draft-asset and 13 provenance tests passed.
  The security-CI structural check and cage source inventory check passed.
  Actionlint passed with its existing unknown `macos-15-intel` label diagnostic
  excluded; runner selection was not changed.
- The existing cage gate fixture and hostile inventory checks passed after
  updating the mandatory inventory to 72 tests and 27 native probes.
- Native x86_64 Linux: 6 selected enforcement tests passed using the corrected
  cage library and freshly built static PIE helper. These cover self/peer
  resource limits and peer signals in minimal/standard profiles, identity,
  filesystem read/write denial, process creation and environment isolation.
  The isolated VM used Linux 6.8 and a GNU static PIE build. This does not replace
  the designated musl image or signed trusted-capture qualification.
- Workspace formatting and strict all-target Clippy for the nine changed crates
  passed. Clippy completed in 4m 50s with `-D warnings`.

These are focused remediation results. The complete workspace test suite,
hosted final-source acceptance and full adversarial campaigns were not rerun
as part of this correction pass. The original failures and later successful
checks remain distinct evidence.
