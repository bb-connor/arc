# SDK compatibility and portability continuity

`H-SDK-02` and `H-SDK-11` return from `needs_revalidation` to
`recorded_scoped_closed` for their original source-scoped obligations only.
Both have SPEC_PASS and independent QUALITY_PASS. Confidence is high within
those scopes. Their historical dispositions, source pins and execution epochs
remain unchanged; each `current_review` retains its previous status and reason.

For `H-SDK-02`, six CLI emitters retain both qualification keys as literal false.
Legacy corpus values remain accepted without rewriting modeled inputs, report
aliases remain equal, and the documented behavioral Make targets retain their
meaning. Thirteen of sixteen original direct pins match. The two naming files
match their already accepted successor pins; the workflow retains its four
compatibility invocations. The independent quality review used hash continuity
for the naming files and did not repeat their implementation review.

For `H-SDK-11`, the fixture contains 84 package identities: 83 exact workspace
name/version/source/checksum matches (79 registry and four local packages), plus
only its exact local root. All 175 dependency references resolve uniquely.
The current lock gate and fixture library checks cover the four changed paths
among 240 original source pins. Policy configuration, audits and import lock
retain their historical hashes; the earlier policy pass and prerequisite failure
remain historical. No current cargo-vet execution is credited.

Actual recorded commands, run from the repository root:

| Command | Recorded result |
| --- | --- |
| `python3 -B scripts/tests/legacy-machine-interfaces.test.py -v` | 6 passed in the spec review and 6 independently repeated in quality review |
| `python3 -B scripts/tests/check-source-names.test.py -v` | 70 passed in the spec review |
| `python3 -B scripts/check-portable-recovery-lock.py` | Exit 0 in independent quality review |
| `python3 -B scripts/tests/check-portable-recovery-lock.test.py -v` | 5 passed in independent quality review |
| `python3 scripts/check-recovery-boundaries.py --offline` | Exit 0; alloc graph 81 packages/165 edges, std graph 83 packages/174 edges |

The owning runner recorded these fixture-only library checks, each exiting zero
with `--offline --locked`. The unqualified `cargo` commands used current Rust
1.95.0; the explicit 1.93.0 and wasm checks are later supporting observations.
These checks confer no Rust unit-test count.

```sh
cargo check --offline --locked --manifest-path fixtures/recovery-portable-consumer/Cargo.toml --lib --no-default-features
cargo check --offline --locked --manifest-path fixtures/recovery-portable-consumer/Cargo.toml --lib --no-default-features --features std
cargo +1.93.0 check --offline --locked --manifest-path fixtures/recovery-portable-consumer/Cargo.toml --lib --no-default-features
cargo +1.93.0 check --offline --locked --manifest-path fixtures/recovery-portable-consumer/Cargo.toml --lib --no-default-features --features std
cargo check --offline --locked --manifest-path fixtures/recovery-portable-consumer/Cargo.toml --lib --no-default-features --target wasm32-unknown-unknown
```

Evidence is under
`target/recovery-pr/current-review-followup/runtime-integration-successor-20261009/`.
The frozen ten-file portable packet predates the graph and three optional
toolchain/target checks. It remains byte-identical; later evidence supplements
its historical limitations. The quality manifests bind 269 source files and 58
evidence files, including the later successful records and logs. Those counts
describe hash verification, not semantic review of every pinned file. Confidence
in the optional checks' owning-runner provenance is moderate; their hash joins
were independently verified.
The quality source manifest's register pin predates this accounting update and
matches the pre-update Git blob. The other 268 reviewed source files still match;
the frozen manifest remains unchanged.

| Essential evidence or source | SHA-256 |
| --- | --- |
| [Alias SPEC_PASS](../../../../../target/recovery-pr/current-review-followup/runtime-integration-successor-20261009/interface-alias-continuity/review.json) | `ec803825ee7a549b091a3e739025a69db9de3ba85c5d2fb7554e56f4a9cb1045` |
| [Alias source manifest](../../../../../target/recovery-pr/current-review-followup/runtime-integration-successor-20261009/interface-alias-continuity/source-manifest.json) | `3c768a25b7e6272ab2f232120e8bbaad8f9d98c4e7982aaf837f86d36dc4959a` |
| [Portable SPEC_PASS](../../../../../target/recovery-pr/current-review-followup/runtime-integration-successor-20261009/portable-lock-continuity/spec-review.json) | `929f8e94334113ab3f0d3eff0eda42c32b94b621714be74fea6cbb7110cac253` |
| [Frozen portable packet](../../../../../target/recovery-pr/current-review-followup/runtime-integration-successor-20261009/portable-lock-continuity/packet-manifest.json) | `4237c6fa966a9a212463028d191a459823f0e1ef475e27954aa09bd73c85c2e9` |
| [Independent QUALITY_PASS](../../../../../target/recovery-pr/current-review-followup/runtime-integration-successor-20261009/sdk-portability-and-alias-quality/quality-review.json) | `53c5e5116cb29599092a2a57859943a0b4fd07f9052c99ec1c502d82de5895ac` |
| [Quality source manifest](../../../../../target/recovery-pr/current-review-followup/runtime-integration-successor-20261009/sdk-portability-and-alias-quality/reviewed-source-manifest.json) | `878763b163c0cf8ea4d0597b9921d4b595baf8987071d6aff08045c81de48fdb` |
| [Quality evidence manifest](../../../../../target/recovery-pr/current-review-followup/runtime-integration-successor-20261009/sdk-portability-and-alias-quality/reviewed-evidence-manifest.json) | `0c3277fa320b805f52e306bfff1c661f230a62d721b4a6908ba9f004f97c6f5b` |
| Workspace `Cargo.lock` | `37962561aef886a241691c463b952e3e22fcf201ecafc8a336f8596e4f4a0e15` |
| `fixtures/recovery-portable-consumer/Cargo.lock` | `9eafe8500114439b623ce1d50f383d12f44ac233815d31c7acbe6fcf68595ed8` |
| `fixtures/recovery-portable-consumer/Cargo.toml` | `acaa878f38e821f218d092bec3f5a0d65f3d86726bdecefe05e015ebe9151998` |
| `scripts/check-portable-recovery-lock.py` | `58186d12fd0bbd690da957c822270eb5971681d401838690f8c49392014e4053` |
| `scripts/tests/legacy-machine-interfaces.test.py` | `e0b1a25296a380586314781d728a421cc3e47d7820d52dab6426aa13bb50c2e5` |

This restores two current scoped classifications, leaving 45 revalidation flags
(35 canonical and ten additional), 72 retained scoped closures, and 388 total
records. Historical totals remain 117 scoped closures and 231 unclosed findings.
`H-SDK-01` remains open; source-fixture cleanup and metadata work remain pending.
These results grant no whole-workspace MSRV/WASM, native-platform, provider,
hosted, runtime or release qualification.
