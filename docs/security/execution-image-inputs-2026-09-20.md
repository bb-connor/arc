# Execution image input qualification

September 20, 2026. Confidence is high for the local input checks below.
The image is built and locally validated. Registry publication, reviewed
workflow-definition rotation and capture authorization remain outstanding.

## Selected inputs

The runner Dockerfile and structural checker now agree on Cargo.lock SHA-256
`dde3e435b45deeebca46dbf9c76903aad86689a8f4ce2c2df2a11b83c999e3c8`.
This includes the selected dependency repairs through source
`013af8f1fdaf4b7a7a8a7f2f2b0b4e5a5ff321b3`. The subsequent Typify backend
audit commit `77c869129ad6edfb7f289a17c18f57d09dc36f36` leaves this lock intact.

The base remains Linux/amd64
`rust:1.94.1-alpine3.22@sha256:667605141d2be37e8a27b3e5368fa388fcd3065ed2dbc2fe64665bce7254fc67`.
Four direct APK pins changed because the previous versions were no longer
available from the configured Alpine repositories:

| Package | Previous | Selected |
| --- | --- | --- |
| jq | 1.8.1-r0 | 1.8.2-r0 |
| openssl-dev | 3.5.7-r0 | 3.5.8-r0 |
| python3 | 3.12.13-r0 | 3.12.14-r0 |
| util-linux | 2.41-r9 | 2.41.6-r1 |

The complete 225-package inventory is pinned in
`deploy/docker/security-evidence-apk.lock`, SHA-256
`86fad0ccb2b3f1cf2402c12ddade71d14b21e9995b3d113795259b899c0a57c0`.
The Dockerfile still compares the entire installed inventory and its digest.
`deploy/docker/security-evidence-apk-archives.json` records SHA-256 digests for
the 199 retained APK archives used to replay installation over the pinned base.
Packages already in the base account for the difference in counts. An offline
replay, with Docker networking disabled and `apk add --no-network`, produced
exactly the same inventory. No package check or structural requirement was
removed.

## Terminal validation

The latest local image ID is
`sha256:1c13c24c331e3aae2dbcc3706f84bc809955138d6c8ba755cb06970088f8033b`.
This is a local Docker image identifier, not a published registry manifest
digest and not an authorized execution-image pin.

The build used the immutable source archive for `013af8f1f` plus the four
reviewed Dockerfile, APK inventory, structural checker and checker-fixture
changes. The archive SHA-256 is
`1ee7959748c5c0ccf324f7bd80f2d006aeeb56e5041446447912514e1abecec9`.
Tracked regular-file modes were restored from the Git tree before checking
the input contract. These checks reached terminal success:

- Image build, including locked dependency fetch and pinned tool versions.
- Structural checker and its complete mutation-fixture suite.
- Linux/amd64 image identity, entrypoint and working directory.
- All 11 installed boundary files: exact source digests, root ownership and
  read-only or executable read-only modes.
- Exact Rust, Clippy, rustfmt and cargo-mutants versions and all 225 packages.
- Absence of `/opt/authorized-source` in the running image's filesystem.
- `cargo fetch --locked --offline`, with networking disabled and the source
  mounted read-only, using `/opt/chio-security/cargo-cache`.

The first offline-cache invocation stopped before execution because the
Docker VM could not see the host's `/tmp` directory. The successful invocation
uses a persistent shared directory reconstructed from the same archive and
the same four input files. Both results are retained.

The checker fixture now expects the existing specific nonce/FIPS diagnostic
when that required assertion is removed. It continues to require rejection
for every removed aggregate assertion; production rejection behavior is
unchanged.

## Evidence and remaining authority work

Retained evidence in the primary checkout's
`output/process-security-20260915/`:

- `security-image-inputs-013af8f1f/`: input digests, source archive, build log,
  image inspection, runtime checks, offline-cache results and qualification.
- `security-image-inputs-9dc12ff1c/apk-refresh/`: all APK bytes and hashes,
  offline replay script, logs and exact installed inventory.
- `resume-20260920/`: persistent reconstructed input tree and current-source
  structural mutation-fixture results.

The input lock and local checks do not certify M5, designate a runner or
authorize capture. A published immutable image digest and the reviewed
workflow-definition changes still need to be connected to the authorization
contract described in `docs/security/committed-linux-evidence.md`. The
definition update includes changes beyond token wiring, so it requires a
complete gate mapping before authority rotation.
