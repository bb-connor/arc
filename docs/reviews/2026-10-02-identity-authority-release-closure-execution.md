# Identity, authority replication and release verification execution

AP1, KG1 and RL1 source repairs are implemented and locally qualified at
`0fd0a9d66d60f03d30501ca727569a8069406e46`, from base
`6cf283c4b9e36485a98275ba6798052b01a5a9d0` on
`packet/3-retention-accounting`. This completes the implementation batch in
[the approved plan](../superpowers/plans/2026-10-02-identity-authority-release-closure.md).
Source publication, hosted qualification, release publication and operator
migration have separate acceptance boundaries.

## Completed tasks

| Finding | Implemented behavior | Local acceptance |
| --- | --- | --- |
| AP1 | Both capability mint routes preserve caller-owned strong Ed25519 public keys. A shared parser rejects missing, malformed, weak and unsupported key material before issuance. Public job/subject labels no longer derive private keys. Python supplies the optional control bearer only on mint requests; Kubernetes supplies the workload public-key annotation. | Real router controls cover all three request shapes and actual DPoP verification. The caller succeeds; the old derived seed, unrelated signer, forged caller-key proof and stolen bearer without proof fail. All 229 API-protect tests, 211 Python SDK tests and Go controller packages pass. |
| KG1 | An operator pins an immutable public checkpoint. Prior-head signed transitions and a fresh final-head signed envelope bind the stream, anchor, exact predecessor, generation and complete issuer history. The receiver verifies the chain and commits authority/replay/clock state atomically. Both cluster import paths use this owner. Private seeds stay local; followers cannot issue or rotate without current-head custody. | Controls cover actual HTTP pulls, full snapshots, unchanged trust after rejection, composed kernel denial, honest rotation, replay/conflicts, clock faults, restart, concurrent imports and rollback. The selected control-plane/store suites and SQLite integration pass. A built production CLI performs initialization, pinning and refusal controls. |
| RL1 | Release consumers require the literal `bb-connor/arc` workflow identity for the exact artifact-family tag and the GitHub OIDC issuer. Producer workflow checks and all installation examples use that policy. | Nine real-cosign local fixture tests reject wrong owner, repository, workflow, tag, issuer, trust root, missing/corrupt signature material and changed bytes. Thirteen provenance tests, sixteen macOS portability tests, both package matrices and current actionlint pass. |

Deterministic capability IDs continue to represent public request identity. They
are not signing seeds. Canonical string grants retain their existing bearer
semantics; sender proof is required by the structured `dpop_required` contract.
The Kubernetes controller checks the public-key annotation's shape before
finalizer/mint mutation, while the sidecar performs authoritative cryptographic
validation. Existing label-based subjects need revocation and reminting. The
gated Hermes live-sidecar fixture was migrated and syntax checked but not launched.

KG1 uses a versioned canonical contract with bounded keys, transitions and wire
bytes, a five-minute maximum envelope lifetime and no future-issued allowance.
Plain HTTP peers require literal loopback addresses. HTTPS retains certificate
and hostname validation, and peer redirects are disabled. A service bearer does
not establish issuer trust. See the
[replication design](../superpowers/specs/2026-10-02-authority-replication-design.md)
and [provisioning contract](../security/kernel-signing-authority.md#signed-cluster-authority-replication-kg1).

Legacy complete local authority history can become an explicitly provisioned
checkpoint. Missing or empty legacy history fails opening instead of silently
creating trust from the private seed. Operators must upgrade peers and provision
matching anchors; unsigned network snapshots have no compatibility fallback.
Schema setup may add schema objects before detecting incomplete legacy history,
but it does not invent issuer rows or replace the seed.

## Regression and review evidence

AP1's original production-router controls reproduced changed caller identity,
accepted labels and acceptance of the publicly derived signing key. KG1's
pre-repair RED controls reproduced unsigned issuer insertion through the shared
SQLite import and full snapshot path, plus off-loopback plaintext acceptance.
The original plan requested a pre-repair exploit through both network paths and
kernel admission. That full pre-repair sequence was not executed. The repaired
controls exercise both actual network import paths and composed kernel denial;
the execution checklist records this narrower baseline evidence explicitly.

The [bounded independent review](https://github.com/bb-connor/arc/blob/ecb44791501c2aba671de2a967d2506f039ab42e/docs/reviews/artifacts/2026-10-02-identity-authority-release-closure/independent-review.md)
found no Critical issue and two Important issues: the generic public-key parser
accepted syntactically valid off-curve keys, and incomplete legacy authority
history could appear to open successfully with an empty trust set. Both failed
executable controls before repair. The sidecar now restricts subjects to strong
Ed25519, and the authority opener rejects a head absent from persisted history.
The reviewer confirmed both source resolutions. Final owner tests and lint
provide the executor's post-repair acceptance; the reviewer did not run Cargo.

Qualification also exposed a market fixture that signed verifier evidence before
the allocation's durable acceptance time. The fixture now waits for the actual
next valid clock boundary and rebuilds the signed report and admission evidence.
All 55 cases that failed in the initial broad control-plane attempt pass in the
final focused run. Production time ordering and timeout bounds were preserved.
A separate control now checks the exact private token-byte mismatch and the
stable public error projection, plus zero dispatch/payment effects. These later
test-only repairs were root-reviewed, not a second independent review.

Kernel, broker and new replication rejection assertions now check explicit
causes. The negative-assertion baseline shrank from 1,256 assertions at 1,174
sites to 1,254 at 1,172, without extending its expiry. Fixture helpers were split
into modules to preserve existing source-size limits. The decoder inventory adds
the two actual checked signed-input constructors; no raw-reader baseline or debt
allowance was added.

## Terminal qualification

The [qualification artifact](https://github.com/bb-connor/arc/blob/ecb44791501c2aba671de2a967d2506f039ab42e/docs/reviews/artifacts/2026-10-02-identity-authority-release-closure/qualification.json)
records commands, exact committed file hashes, terminal exit codes and raw log
hashes. Raw evidence, including failed and intermediate attempts, remains at
`/home/connor/chio-security-evidence/2026-10-02-identity-authority-release-closure/`.

| Boundary | Accepted result |
| --- | --- |
| API-protect full owner test binary | 229 passed, 0 failed, 0 ignored |
| Control-plane authority, transport and affected market fixtures | 124 passed, 0 failed, 0 ignored |
| SQLite replication and transaction controls | 18 passed, 0 failed, 0 ignored |
| SQLite integration smoke suite | 5 passed, 0 failed, 0 ignored |
| CLI provisioning unit controls | 2 passed, including a complete valid anchor with a duplicate key and the correct operator digest |
| Strengthened kernel and broker rejection controls | 1 passed in each owner |
| Production CLI build and subprocess smoke | Build passed; five invocations verified initialization, overwrite refusal, wrong-digest refusal before database creation, pinning and idempotent pinning; distinct private seeds were retained |
| Python SDK and Go controller | 211 Python tests passed; all Go packages passed |
| Release verifier and workflow controls | 9 local cosign, 13 provenance and 16 portability tests passed; PyPI/npm matrices and actionlint v1.7.12 passed |
| Rust lint | All targets in kernel, SQLite, control-plane, API-protect, broker and CLI passed with `-D warnings`; CLI passed again after the final test-only strengthening |
| Source gates | Workspace and explicit include-root formatting, file hygiene, clock inventory, decoder contracts, HTTP egress contracts and negative-assertion ratchet passed |

Cargo graphs were serialized on Linux aarch64 with four build jobs and
incremental compilation disabled. The 229-test API run executes the owner test
binary compiled by the final Cargo graph; it does not claim doc-test coverage.
The three API tests in the combined authority graph overlap that full owner run.
The final CLI-only rerun filtered out kernel and broker tests; their earlier
named controls provide their acceptance. No full workspace run is claimed.

The production CLI binary has SHA-256
`d25c1a7c533bb172e32a79d309decbebf1e848238517fc363fa4c7b903a99064`.
It was built before the final test-only duplicate-key strengthening. Production
code is unchanged since that build; this is local provisioning evidence, not a
release artifact qualification.

All prior failures remain terminal failures in the archive, including compile
wiring errors, a seconds/milliseconds test-clock mismatch, the market fixture
ordering failures, the stale public-error assertion, source hygiene/decoder
inventory checks and the older actionlint tool's unsupported runner label.
Passing retries have separate records. No ignored tests, new lint suppression,
dependency exemption, increased cap or timeout relaxation was used.

## Publication and remaining boundaries

The source commit and this evidence handoff are published together to
`packet/3-retention-accounting`; the final remote-head comparison is retained in
the external `publication.json` record. Unrelated `output/` files and older
experimental worktrees are preserved. This does not merge or release the branch.

RL1's fixture CA and signatures are local. Its test adapter provides local trust
and disables public SCT/Rekor checks only in the fixture. The production verifier
retains public Sigstore chain, SCT and Rekor verification and exposes no
repository override or skip flags. Hosted GitHub OIDC/Fulcio/Rekor acceptance,
account/registry configuration and signed publication remain unexecuted here.

KG1 establishes authenticated additions and rotation continuity. It does not
retire or revoke issuers, encrypt/private-mode the authority database, transfer
private custody, replace a live operator pin, authenticate cluster elections or
make unrelated databases in a full cluster snapshot transactional together.
Operator deployment and recovery remain explicit work. The security roadmap and
last-week review backlog are not complete.

## Next execution batch

The [next plan](../superpowers/plans/2026-10-02-issuer-lifecycle-approval-authority.md)
covers four related findings:

1. KG2: issuer retirement/revocation and verification deadlines, plus separation
   of receipt signing from capability issuance.
2. KG3: private directory/database/WAL custody, safe existing-file validation and
   a bounded offline migration path.
3. AP2: server-built exact invocation binding and durable single-use approval
   redemption at admission.
4. AP3: an explicit approver roster and signer attribution, with enforcement or
   rejection of unsupported approval policy fields.

AC4 protected run/step writes, CA3 framework ingress, remaining TCB readers,
guard integration, evidence/retention and hosted release qualification stay in
the subsequent queue.
