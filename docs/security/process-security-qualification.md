# Combined process and M4 qualification

Status on 2026-09-15: Task 5 of the
[integration plan](process-security-integration.md) is in progress. A draft
integration PR is a source/CI checkpoint, not completed qualification, a merge,
or M5 acceptance. The user requested execution without subagents; subsequent
review is direct primary-agent review, not independent reviewer evidence.

Published checkpoint: `f0ff43b819547b5cf1ebfd34ad18aae16412f115` on
`integration/process-security-m4`, in [draft PR #1160](https://github.com/bb-connor/arc/pull/1160).
Both reviewed parent histories and all
[109 inherited thread dispositions](process-security-review-dispositions.md)
are retained. Main remains `f5566d9a765c21cb36652a99c79de64968a656bf` at the
remote refresh. Original PR threads have not been represented as resolved.

## Current evidence

These are distinct local runs, not one exact-head acceptance certificate.

| Scope | Result and boundary |
| --- | --- |
| Patched full workspace Clippy | Passed with Rust 1.94.1, locked/offline dependencies and warnings denied. |
| Patched full workspace tests | Exited 101 in the proof-contract target: 138 passed, nine fixture-discovery failures. The repaired target now passes all 147 cases. The workspace invocation stopped at that failure; later targets and full workspace acceptance remain open. |
| Rust dependency policy | cargo-deny advisories, bans, licenses and sources pass after the rustls 0.23.45 repair. |
| Rust dependency audits | Locked cargo-vet fails with 26 missing safe-to-deploy audits. No new exemptions, certificates or trust authorities were added. |
| Python SDK and LangGraph | 206 SDK cases and 58 LangGraph cases pass, including installed wheels and two supported LangGraph profiles. Installed typing passes. All 22 Python lockfiles pass offline consistency checks. |
| TypeScript packages | Full publishable workspace build/test and six owning standalone package gates pass. Dashboard passes 103 tests; web3 example builds and passes six real Chromium tests. |
| JavaScript/Python advisory scan | The final expanded OSV scan passes with three pre-existing policy filters unchanged. This is not a zero-known-vulnerability claim for excluded findings. |
| Native Docker process recovery | Complete patched-snapshot qualification passes, including live owned-container host SIGKILL, restart, credential rotation, one-effect receipts, unresolved custody, shutdown and resource bounds. Container CPU/memory accounting remains explicitly unavailable. |
| Installed process starter | Complete patched-snapshot qualification passes with real external Python/Node consumers, mailbox exchange, independent receipt verification and installed package/sdist tests. |
| Installed AI SDK 6/7 | Complete patched-snapshot qualification passes, including recovery, journals, state pressure, cooperative swarms and supervision. No live model calls. The earlier mixed-binary run remains diagnostic only. |
| M4 SDK parity | Owning Python/Go/TypeScript parity gate passes. Native Rust consumer, M3 and composed gates remain distinct. |
| Fuzz and Docker locks | Full 30-target selector fixture passes. Fuzz locked metadata and generated Docker workspace lock consistency pass after regeneration. This is not a fuzz campaign or full fuzz compilation pass. |
| Security CI contract | Both the full checker and its full fixture suite remain blocked by the execution-image Cargo.lock digest ratchet. Isolated fixture results do not waive it. |

The TLS update addresses
[RUSTSEC-2026-0285](https://rustsec.org/advisories/RUSTSEC-2026-0285.html).
Required AWS-LC and webpki updates preserve existing feature selections. The
source Cargo.lock digest is
`47bf5b6fc16784c18104912b1d90ee1160c2e8e330baff34fde35478e66fdbce`.
The security execution-image ratchet still requires
`a4e631319b00c54f2cbc6457ad0149198a4a367db8dec060fcce376c98728b49`.
No image, controller, trusted-source or enterprise-workflow pin was changed.

## Patched executable and fixture-discovery closeout

All three installed qualifiers completed at clean source `f0ff43b819`, using
the same privately retained CLI, SHA256
`82ba58ec8a8d742b9d22504ff4f0fd604ee6e0361b7f33df7d591163870b92a5`.
This was a Rust 1.94.1 workspace-test build on Linux/aarch64, not an optimized
release or x86_64 confinement certificate. Report SHA256 identities:

- AI SDK: `4d47b452f93fb0616bc1411766a14f3087122ff2f3f8ba42f58e96570dea5352`.
- Docker: `a74d4c975237dc3ed8ba680483158b3f2f87ea54916c3692ffaaaee17c204b73`.
- Starter: `81496d691735292ddc111c4758c6839b38e585d12fc926a7f8aed2a161a32138`.

The workspace failure exposed missing test setup for an external Cargo target
directory. The hardened runtime resolver correctly refuses to infer checkout
authority from the current directory or embedded build paths. The proof-test
command helper now supplies its owned `CHIO_CHECKOUT_ROOT`. The original
recursive-swarm fixture case failed without that anchor and passed with it;
the complete repaired proof target passes 147 cases with no ignores. Production
resolution, installed fixture overrides, verifiers and trust policy are unchanged.

Hosted run `34977549611` passed the authenticated-worker job, but its larger
process-host job exceeded its 90-minute job limit during the research swarm
benchmark. It is not a passing complete workflow. The ordinary process job
also does not run the feature-gated real x86_64 cage-enforcement inventory.

## Remaining gates

Finish the patched workspace and explicit process-feature suites, complete
M1-M4 exact inventories and rollback/caller crash matrix, and check generated
proof coverage and all fuzz binaries. Preserve the completed installed results;
rerun affected profiles after executable or package changes. Keep commands, source,
compiler, features, executable hashes and terminal results together.

The five already-trusted audit feeds have no exact target records for the five
new TLS dependency versions at this refresh. An unlocked cargo-vet refresh also
requires an explicit ownership policy for the locally patched sigstore-verify
0.6.3. That policy was not guessed or changed to bypass source review. Existing
source-review preparation is not a completed package security audit.

Exact-head hosted qualification, protected merge, and required trusted-runner
authorization remain open. Linux/aarch64 process/container evidence is not
Linux x86_64 tool-confinement evidence. M5's governed, confined reference swarm
remains Task 7 after integration; existing process swarm demos do not replace it.
