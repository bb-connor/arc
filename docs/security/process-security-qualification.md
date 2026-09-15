# Combined process and M4 qualification

Status on 2026-09-15: Task 5 of the
[integration plan](process-security-integration.md) is in progress. A draft
integration PR is a source/CI checkpoint, not completed qualification, a merge,
or M5 acceptance. The user requested execution without subagents; subsequent
review is direct primary-agent review, not independent reviewer evidence.

Implementation checkpoint: `02e2142f28` on `integration/process-security-m4`.
Both reviewed parent histories and all
[109 inherited thread dispositions](process-security-review-dispositions.md)
are retained. Main remains `f5566d9a765c21cb36652a99c79de64968a656bf` at the
remote refresh. Original PR threads have not been represented as resolved.

## Current evidence

These are distinct local runs, not one exact-head acceptance certificate.

| Scope | Result and boundary |
| --- | --- |
| Patched full workspace Clippy | Passed with Rust 1.94.1, locked/offline dependencies and warnings denied. |
| Patched full workspace tests | Running. The earlier unpatched compilation was interrupted before test execution and is not a pass. |
| Rust dependency policy | cargo-deny advisories, bans, licenses and sources pass after the rustls 0.23.45 repair. |
| Rust dependency audits | Locked cargo-vet fails with 26 missing safe-to-deploy audits. No new exemptions, certificates or trust authorities were added. |
| Python SDK and LangGraph | 206 SDK cases and 58 LangGraph cases pass, including installed wheels and two supported LangGraph profiles. Installed typing passes. All 22 Python lockfiles pass offline consistency checks. |
| TypeScript packages | Full publishable workspace build/test and six owning standalone package gates pass. Dashboard passes 103 tests; web3 example builds and passes six real Chromium tests. |
| JavaScript/Python advisory scan | The final expanded OSV scan passes with three pre-existing policy filters unchanged. This is not a zero-known-vulnerability claim for excluded findings. |
| Native Docker process recovery | Full owning qualification passes, including live owned-container host SIGKILL, restart, credential rotation, one-effect receipts, unresolved custody, shutdown and resource bounds. Final patched-binary qualification remains separate. |
| Installed process starter | Passes with a retained CLI snapshot and real external Python/Node consumers. Snapshot SHA256 is `f5d3925958072f3bf0acb193a2e881eb62962c26818fe434c2dfb53e4227d815`. |
| Installed AI SDK 6/7 | First broad run is diagnostic only: Cargo replaced its mutable CLI path during execution. A new private snapshot implementation and two executable-integrity regressions pass; complete patched-snapshot qualification remains required. |
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

## Remaining gates

Finish the patched workspace and explicit process-feature suites, complete
M1-M4 exact inventories and rollback/caller crash matrix, rerun installed AI
SDK and affected container qualification with immutable binaries, and check
generated proof coverage and all fuzz binaries. Keep final commands, source,
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
