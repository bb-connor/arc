# Chio nono permission provenance repair

This unpublished fork retains nono 0.53.0 and changes one production expression
in filesystem-capability deduplication. The separately owned `nono-chio`
descriptor wrapper remains the confinement entrypoint.

- Upstream release: `c4b25b827330640cb95f85809d88d977191b42e7`,
  `always-further/nono`, directory `crates/nono`.
- Registry archive SHA-256:
  `ae7eb523cc2036e9ad6527411c3da5dc2172dc454cc3447a03b910420a39bfee`.
- License: Apache-2.0. Copyright Luke Hinds. The license text is retained from
  Chio's existing attributed wrapper.

The upstream contract gives User/Profile grants precedence over System/Group
grants. The original deduplicator selects that grant correctly but then merges
complementary read/write permissions across the provenance boundary. A user
read grant plus a system write grant therefore becomes user read/write.

The repair merges complementary permissions only within the same provenance
tier. Cross-tier collisions preserve the explicit grant unchanged. Tests cover
every permission pair, both provenance pairs, both input orders, file and
directory scope, three-entry deferred merges and same-tier union behavior.

Chio's current wrapper constructs an empty upstream capability set with network
blocked and probes the Landlock ABI. It does not call this deduplicator or
upstream pathname-based enforcement. This repair prevents retaining the known
defect in the selected package; it does not establish a failure in Chio's
descriptor enforcement path.

All upstream production and test files are retained. One upstream unit test
expected cross-tier widening from user Write plus group Read. Its expectation
now requires exact user Write, matching the documented provenance contract.
The original passing upstream suite and first repaired-suite failure are
retained as evidence; the unchanged upstream tests are not claimed to all pass
under the stronger semantics. The manifest disables
publication, provides an independent test workspace and selects Chio's existing
dependency repairs for that workspace. The standalone lockfile records those
qualification inputs. This selection does not certify the original registry
release or the unused upstream secret, supervisor, trust and rollback APIs.

```sh
cargo test --locked --no-default-features --manifest-path third_party/nono-upstream-chio/Cargo.toml
cargo clippy --locked --no-default-features --all-targets --manifest-path third_party/nono-upstream-chio/Cargo.toml -- -D warnings
```

## Standalone qualification dependency selection

The independent workspace explicitly patches `ignore` and `regress` to the
same repaired local packages selected by Chio's root workspace. Cargo does not
inherit a parent workspace's patches when this manifest is tested directly.
The standalone lockfile retains the unrelated regress 0.10.5 selection.

The capability and keystore unit-test bodies now live in child test modules.
This preserves their module names, attributes and test bodies while bringing
both production files below the repository's 2,000-line limit. The size gate
and its allowlist are unchanged.
