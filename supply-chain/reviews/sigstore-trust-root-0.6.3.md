# sigstore-trust-root 0.6.3 source review and repair

Reviewed September 16, 2026 by the executing Codex agent. Confidence is high
for the reproduced date-parsing defect and the tested repair. This is direct
source review, not independent human certification.

Registry archive SHA-256:
`ee8762a4813252faffdf6f7e2040213078eb2482fbc351381134f3fc60c1be9c`.
The release identifies commit `f9821a44bbb711b09aff29162e8d925f1de5d485`
of prefix-dev/sigstore-rust, under `crates/sigstore-trust-root`.

## Scope

Reviewed both manifests, all five production modules and their tests, the two
integration tests, and the six embedded JSON documents. The package has no
unsafe code, build script or process execution. Default features are empty;
Chio's selected graph does not enable this package's optional TUF client.

The default path parses caller-provided JSON/files or embedded data and extracts
keys/certificates. The embedded production and staging roots and signing
configuration remain byte-for-byte unchanged. Their inventory, URLs, validity
windows and key fingerprints are retained with the evidence. They are static
release inputs, not evidence of current remote freshness. Some log identifiers
use protocol-specific encoding and need not equal a hash of the stored bytes.

The optional online TUF path delegates metadata and target verification to
`tough`, propagates errors and accepts explicit repository/cache configuration.
Its explicit offline mode reads unverified cache files, then may use embedded
data. Offline mode does not establish authenticity of a modified cache or
freshness. The embedded TUF roots are bootstrap versions, not current metadata.
This review and the offline unit tests do not certify a live TUF update.

## Reproduced defect and selected repair

In the registry release, three timestamp-authority helpers parse validity dates
with `.ok()`. A malformed start/end is therefore treated like an absent bound.
With a real embedded root and one modified validity string:

- `is_timestamp_within_tsa_validity` returns true;
- `tsa_certs_with_validity` returns certificates with the invalid bound absent;
- `tsa_validity_for_time` returns success instead of a parsing error.

The loader also accepts malformed and reversed validity periods. The retained
five-test reproducer reports four failures against original production source
and one pass for valid intervals. The loader assertion is additional hardening;
the three helper failures demonstrate the permissive parsing behavior.

`third_party/sigstore-trust-root-chio` uses one checked bound parser, propagates
errors in result-returning helpers and rejects invalid examined bounds in the
boolean helper. Loading rejects invalid dates and reversed intervals across
Fulcio, timestamp, Rekor and CT authorities. Open intervals and inclusive
endpoints retain their previous meaning. No cryptographic primitive, embedded
anchor, network endpoint or dependency version changes.

Chio's owned verifier already parsed validity dates strictly and joined the
window to the signing authority. This finding does not demonstrate a Chio
verification bypass. Two added verifier tests use a real bundle to confirm that
valid original evidence succeeds and malformed start/end dates fail for both
certificate chains and authenticated timestamps.

## Validation

- Original and repaired all-feature unit suites: 17 tests pass.
- Repaired regression target: all five tests pass.
- Five documentation compilation checks pass; one upstream example is ignored.
- Two upstream integration tests report success but return early because their
  external conformance fixture is absent. They are excluded from substantive
  coverage claims.
- Strict Clippy passes for all targets and features on both original and
  repaired source.
- Chio's owned verifier: all 44 library tests pass with selected crypto, Merkle
  and trust-root repairs, including the two new real-evidence date tests.
- Main/fuzz metadata selects the owned source. Their only lockfile change is
  removal of the original trust-root registry source and checksum.

The original package receives no cargo-vet certification. The selected repaired
source is maintained as owned code, matching the other reviewed dependency
repairs. This does not certify its dependencies or complete workspace gates.

## Remaining caller obligations

Loading does not authenticate a supplied trust root, establish supported media
types or reject duplicate log identifiers. Key-map getters can overwrite an
identifier; callers must supply authorized roots and bind the intended key.
Certificates and keys remain encoded data until their cryptographic use checks
them. Public struct mutation bypasses loader checks; helper checks remain local
to the periods they examine. The boolean helper describes any TSA's window,
including the documented no-TSA case, not a verified timestamp or its signer.
The range helper can represent only intervals with both endpoints.

Signing-configuration parsing validates its media type and typed date syntax;
endpoint getters filter validity and supported versions. Selector/count fields
are configuration data, not enforcement of a required signing quorum. Resource
limits for caller-supplied files/collections remain caller responsibilities.

Evidence is retained in the primary checkout under
`output/process-security-20260915/sigstore-root-audit-25ab21af2/`, including the
checksum-verified archive, original failure, selected tests, strict Clippy,
embedded inventory, source comparison and owned-verifier results.
