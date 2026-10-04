# Chio AWS-LC Rust source repairs

Source: aws-lc-rs 1.18.1 registry archive, SHA-256
`b281d307588d634de920874890732659e2e7672f72b5e10e81badc1a8a83621e`.
The archive is publicly available at
`https://static.crates.io/crates/aws-lc-rs/aws-lc-rs-1.18.1.crate`.
The published crate records upstream commit
`22e629d5c46276497a24ee3e575be4315940e7cb` in
`.cargo_vcs_info.json`.

This fork repairs DES and TDEA key validation in the optional `legacy-des`
feature. DES parity bits do not contribute to the effective key, but the
registry release passes arbitrary parity to native weak-key detection and
compares TDEA components byte for byte. That accepts parity variants of known
weak and semi-weak DES keys, and it accepts TDEA components that encode the
same effective key with different parity.

The repair normalizes every DES key to odd parity before calling
`DES_set_key`, rejects every nonzero native result, and compares TDEA
components after masking their parity bits. The regression target covers weak
and semi-weak parity variants and parity-distinct equal TDEA components. It
fails against the registry release and passes against this fork on native
Linux x86_64. Native library, DES regression and FIPS tests are recorded in the source audit report below.

The fork also initializes every integer field in native AES key schedules before
constructing Rust values. Native AES-128/192 setup leaves unused words untouched;
the registry wrapper unsafely assumed that all fields had been initialized. All
six cipher and key-wrap allocation sites now start zeroed. The private error
diagnostic uses a bounded safe C-string constructor. See the
[source audit](../../docs/security/audits/aws-lc-rs-1.18.1-fork.md) for the
reviewed boundaries, the Memcheck reproduction and remaining limitations.

The standalone library and build script enforce Clippy's unwrap/expect denies.
Fallible constructors propagate environment, native descriptor/length, parsing
and key-validation errors. The FIPS RSA predicate rejects a non-RSA key without
panicking. Existing upstream infallible compatibility methods and verified
invariants retain narrowly identified exceptions. The mandatory lint gate checks
their exact compiler spans and source hashes for default/legacy and FIPS library
builds; the fork is not claimed panic-free.

Five em dashes in upstream documentation and Rust documentation comments are
normalized to hyphens for the repository text convention. They do not affect
compiled behavior.

Eight upstream test-vector files also have CRLF endings, trailing whitespace
or trailing blank lines normalized for the repository diff check. The test
parser already ignores these differences; vector keys and values are unchanged.

The tracked [CHIO-PATCH.patch.json](CHIO-PATCH.patch.json) is the complete change to
files present in the registry archive, excluding this provenance document.
It is an ASCII JSON array of patch lines; decoding preserves the original UTF-8
bytes, including removed upstream text. It adds the DES regression target and
changes the crate manifest, DES key validation, AES initialization, the private
error diagnostic, standalone lint policy and fallible boundary repairs, and the
five text-convention occurrences. The 71 test fixtures
missing from the published archive are copied from the upstream commit above.
Their checked-in hashes are in
[CHIO-RESTORED-FIXTURES.sha256](CHIO-RESTORED-FIXTURES.sha256).
Eight fixtures were normalized with the exact transformation below. All
other fixture bytes match the upstream commit. These fixtures are test data,
not production source.

To independently reconstruct the fork, extract the verified registry archive,
decode `CHIO-PATCH.patch.json` and apply the result from the extracted crate root,
then copy the fixture
paths named in `CHIO-RESTORED-FIXTURES.sha256` from the upstream commit's
`aws-lc-rs/` directory. Normalize the following eight files with
`perl -0777 -pi -e 's/\r\n/\n/g; s/[ \t]+(?=\n)//g; s/\n+\z/\n/'`:

```text
src/test/test_1_tests.txt
tests/data/cavp_3des_cmac_tests.txt
tests/data/cavp_aes128_cmac_tests.txt
tests/data/cavp_aes192_cmac_tests.txt
tests/data/cavp_aes256_cmac_tests.txt
tests/data/digest_tests.txt
tests/data/rsa_pkcs1_sign_tests.txt
tests/data/rsa_pss_verify_tests.txt
```

Run `sha256sum -c CHIO-RESTORED-FIXTURES.sha256` from the reconstructed
crate root. Then compare every file with this checked-in directory, excluding
`CHIO-PATCH.md`, `CHIO-PATCH.patch.json`, and
`CHIO-RESTORED-FIXTURES.sha256`, which are review metadata. The regression
was observed to fail against the published crate and pass against this fork
with separate Cargo target directories; the commands below exercise the fork.

Cargo Vet records the published source review without certifying that known-
flawed archive as safe to deploy. Deployment qualification additionally requires
`bash scripts/check-supply-chain.sh`: an exact fork inventory, complete archive
reconstruction, actual Cargo source/feature resolution, the native/transitive
`safe-to-deploy` audits, and the DES/AES regressions. A patch file alone does not
certify the dependency.

Decode the tracked patch with:

```sh
python3 -c 'import json,sys; sys.stdout.write("".join(json.load(open(sys.argv[1]))))' \
  /path/to/CHIO-PATCH.patch.json | git apply -
```

```sh
cargo test --locked --manifest-path third_party/aws-lc-rs-chio/Cargo.toml
cargo test --locked --manifest-path third_party/aws-lc-rs-chio/Cargo.toml \
  --features legacy-des --test des_parity_regression
```
