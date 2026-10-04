# Verifying Chio Release Artifacts

The release signer policy is **`bb-connor/arc`**, with the GitHub Actions OIDC
issuer **`https://token.actions.githubusercontent.com`**. This repository and
owner were confirmed through GitHub's repository API on 2026-10-02. A fork,
renamed repository or future organization transfer requires a reviewed policy
change. Consumers must not substitute an owner supplied by a download site.

The release workflows produce detached cosign signatures (`.sig`) and Fulcio
certificates (`.pem`). These instructions describe the signed pipeline. They do
not establish that any historical release ran through that pipeline, or that a
candidate is published or accepted. An older release without both sidecars fails
verification; do not install it by bypassing verification.

## Exact signer policy

Each artifact family uses one workflow and the **exact tag selected by the
consumer**, including prerelease and build metadata when present:

| Artifact family | Workflow | Permitted tag shape |
|---|---|---|
| Native archive or signed checksum index | `release-binaries.yml` | `v<semver>` |
| PyPI wheel or sdist | `release-pypi.yml` | `py/v<semver>` or `py/<slug>-v<semver>` |
| npm tarball | `release-npm.yml` | `ts/v<semver>` or `ts/<slug>-v<semver>` |

For example, the native tag `v0.1.1-rc.1` requires this literal certificate SAN:

```text
https://github.com/bb-connor/arc/.github/workflows/release-binaries.yml@refs/tags/v0.1.1-rc.1
```

A certificate for another tag, branch, owner, repository or workflow fails even
if its signature is otherwise valid. Selecting a fleet tag does not authorize a
package-specific tag, or the reverse. Registry trusted publisher settings are
separate operator configuration; they do not replace this consumer policy.

## Executable verification command

Use Python 3 and cosign **v2.4.1**, matching the workflows. Run from a trusted
checkout of the reviewed source. The script is part of the verifier's trust
boundary; do not fetch it from the artifact's untrusted download location.

[`scripts/verify-release-identity.py`](../../scripts/verify-release-identity.py)
validates tag syntax, chooses the workflow from the artifact family and invokes
`cosign verify-blob` with `--certificate-identity` and
`--certificate-oidc-issuer`. Identity is compared literally. The script has no
repository override and leaves public Fulcio chain, SCT and Rekor checks enabled.
See the [pinned cosign command reference](https://github.com/sigstore/cosign/blob/v2.4.1/doc/cosign_verify-blob.md)
and [Sigstore verification guidance](https://docs.sigstore.dev/cosign/verifying/verify/).

Set `CHIO_CHECKOUT` to the trusted checkout, `CHANNEL` to `binaries`, `pypi` or
`npm`, `TAG` to the exact tag, and `ARTIFACT` to the downloaded file. Place its
nonempty `.sig` and `.pem` siblings in the same directory, then run:

<!-- release-verification-command -->
```bash
python3 "${CHIO_CHECKOUT}/scripts/verify-release-identity.py" verify \
  --channel "$CHANNEL" --tag "$TAG" --artifact "$ARTIFACT"
```

A nonzero exit denies use of the artifact. Missing, empty or corrupt signing
material, a mismatched issuer or signer identity, and changed artifact bytes must
fail. Do not add flags that skip certificate or transparency verification.

To inspect the literal identity before verification:

```bash
python3 scripts/verify-release-identity.py identity \
  --channel binaries --tag v0.1.1-rc.1
```

## Download examples

The versions below illustrate naming; they do not assert these signed releases
exist. For unpublished drafts, downloading also requires maintainer access.
Select the actual intended release tag before fetching.

### Native archive

```bash
CHIO_CHECKOUT="$PWD"
CHANNEL=binaries
TAG=v0.1.1-rc.1
ARTIFACT=chio-0.1.1-rc.1-x86_64-unknown-linux-gnu.tar.gz

gh release download "$TAG" --repo bb-connor/arc \
  --pattern "$ARTIFACT" --pattern "${ARTIFACT}.sig" --pattern "${ARTIFACT}.pem"
python3 "${CHIO_CHECKOUT}/scripts/verify-release-identity.py" verify \
  --channel "$CHANNEL" --tag "$TAG" --artifact "$ARTIFACT"
```

Verify each target separately. A signed checksum index uses the same `binaries`
channel and exact tag. Checksums alone provide no signer authentication.

### PyPI wheel or sdist

```bash
CHIO_CHECKOUT="$PWD"
CHANNEL=pypi
TAG=py/chio-crewai-v0.2.0
ARTIFACT=chio_crewai-0.2.0-py3-none-any.whl

pip download --no-deps --dest . 'chio-crewai==0.2.0'
gh release download "$TAG" --repo bb-connor/arc \
  --pattern "${ARTIFACT}.sig" --pattern "${ARTIFACT}.pem"
python3 "${CHIO_CHECKOUT}/scripts/verify-release-identity.py" verify \
  --channel "$CHANNEL" --tag "$TAG" --artifact "$ARTIFACT"
```

Use the actual wheel filename. An sdist uses its `.tar.gz` filename and sidecars.
For a fleet release, set `TAG=py/v0.2.0` explicitly instead.

### npm tarball

```bash
CHIO_CHECKOUT="$PWD"
CHANNEL=npm
TAG=ts/express-v0.2.0
ARTIFACT=chio-protocol-express-0.2.0.tgz

gh release download "$TAG" --repo bb-connor/arc \
  --pattern "$ARTIFACT" --pattern "${ARTIFACT}.sig" --pattern "${ARTIFACT}.pem"
python3 "${CHIO_CHECKOUT}/scripts/verify-release-identity.py" verify \
  --channel "$CHANNEL" --tag "$TAG" --artifact "$ARTIFACT"
```

Use the actual `npm pack` filename. For a fleet release, set `TAG=ts/v0.2.0`
explicitly. To verify registry bytes, fetch the exact package version with
`npm pack @chio-protocol/express@0.2.0`, then run the same command on that tarball
with the release sidecars. A byte mismatch fails; investigate the cause rather
than accepting a different file. npm provenance is a separate registry check.

## Local executable documentation checks

```bash
python3 scripts/tests/release-identity.test.py
```

This test executes the marked command above through real cosign v2.4.1. It
creates local EC signatures and CA-issued certificates carrying the expected SAN
and OIDC issuer extension. The isolated test adapter supplies that local CA and
disables SCT/Rekor checks because the fixtures have no public log entries. Those
options exist only in the test adapter; the production verifier exposes no bypass.
The test covers all three artifact families, wrong owner/repository/workflow/tag,
a branch identity, wrong OIDC issuer, missing/empty/corrupt sidecars and altered
bytes. CI runs it in [`release-identity-check.yml`](../../.github/workflows/release-identity-check.yml).

**This proves local command behavior, not hosted keyless identity.** Hosted
acceptance still requires an actual artifact signed by the exact tagged workflow,
with production Fulcio, SCT and Rekor validation enabled. Account ownership,
registry trusted publisher registration, protected environments, signed release
publication and release acceptance remain operator gates.

## Rust callers and other artifact types

[`chio-attest-verify`](../../crates/trust/chio-attest-verify/README.md) has an
`ExpectedIdentity` API whose identity field accepts a regex. A Rust caller must
construct an anchored regex from the **escaped full literal identity** returned
by this policy (for example `format!("^{}$", regex::escape(&identity))`), and pin
the issuer above. Broad owner/version alternatives do not implement this policy.
These CLI fixture tests do not qualify that crate's verification behavior.

OCI image and SLSA provenance verification are described in
[PUBLISHING.md](PUBLISHING.md). Source qualification, provenance, per-platform
runtime acceptance and publication approval are additional release gates.
