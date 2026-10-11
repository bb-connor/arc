# Chio Binary Distribution

This page defines the release distribution contract for future tagged releases.
Publication and hosted acceptance must be checked for the exact intended tag;
this page does not establish them. Authenticate signed artifacts using the
canonical `bb-connor/arc` policy in [VERIFY.md](VERIFY.md) before execution.
Historical release publication is separate from acceptance of this pipeline.

## Supported Platforms

| OS      | Architecture         | Target triple                  | Archive           |
| ------- | -------------------- | ------------------------------ | ----------------- |
| Linux   | x86_64               | `x86_64-unknown-linux-gnu`     | `.tar.gz`         |
| Linux   | aarch64 (arm64)      | `aarch64-unknown-linux-gnu`    | `.tar.gz`         |
| macOS   | x86_64 (Intel)       | `x86_64-apple-darwin`          | `.tar.gz`         |
| macOS   | aarch64 (Apple)      | `aarch64-apple-darwin`         | `.tar.gz`         |
| Windows | x86_64               | `x86_64-pc-windows-msvc`       | `.zip`            |

Container images are expected for `linux/amd64` and `linux/arm64` after the
release workflow publishes them.

## Install via Homebrew After A Tagged Release

```bash
curl -fsSL -o /tmp/chio.rb https://github.com/bb-connor/arc/releases/latest/download/chio.rb
brew install --formula /tmp/chio.rb
chio --version
```

The release workflow renders the installable formula from
`packaging/homebrew/chio.rb.tmpl` and publishes it as the `chio.rb` release
asset when a release is cut. See [`docs/install/homebrew.md`](./homebrew.md) for
details.

## Install via Docker After A Tagged Release

```bash
# Pull the latest published image
docker pull ghcr.io/bb-connor/chio-sidecar:latest

# Pin to a specific version
docker pull ghcr.io/bb-connor/chio-sidecar:0.1.0

# Run the published image
docker run --rm ghcr.io/bb-connor/chio-sidecar:latest --help
```

The published image must satisfy this contract:

- is built from `deploy/docker/Dockerfile.sidecar` (Alpine base, non-root user `chio`, UID
  `10001`);
- defaults to `chio --help`; operators override the command with `run`,
  `mcp serve-http`, or another real subcommand at deploy time;
- uses `tini` as PID 1 for correct signal handling;
- stores sidecar state under `/var/lib/chio` (mount a volume to persist it).

## Install a verified native archive after an accepted tagged release

```bash
set -euo pipefail
VERSION=0.1.1-rc.1
TAG="v${VERSION}"
: "${SOURCE_SHA:?Set the independently accepted full source commit}"
TARGET=$(uname -m | sed 's/x86_64/x86_64/; s/arm64/aarch64/; s/aarch64/aarch64/')
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$OS" in
  linux)  TRIPLE="${TARGET}-unknown-linux-gnu" ;;
  darwin) TRIPLE="${TARGET}-apple-darwin" ;;
  *) echo "unsupported OS: $OS"; exit 1 ;;
esac

ARCHIVE="chio-${VERSION}-${TRIPLE}.tar.gz"
BASE="https://github.com/bb-connor/arc/releases/download/${TAG}"

curl -fsSL "${BASE}/${ARCHIVE}"        -o "${ARCHIVE}"
curl -fsSL "${BASE}/${ARCHIVE}.sha256" -o "${ARCHIVE}.sha256"
curl -fsSL "${BASE}/${ARCHIVE}.sig" -o "${ARCHIVE}.sig"
curl -fsSL "${BASE}/${ARCHIVE}.pem" -o "${ARCHIVE}.pem"
# Run from a trusted reviewed source checkout with cosign v2.4.1 installed.
python3 scripts/verify-release-identity.py verify \
  --channel binaries --tag "$TAG" --source-sha "$SOURCE_SHA" --artifact "$ARCHIVE"
shasum -a 256 -c "${ARCHIVE}.sha256"
tar xf "${ARCHIVE}"
sudo install -m 0755 "chio-${VERSION}-${TRIPLE}/chio" /usr/local/bin/chio
chio --version
```

The expected source SHA must come from independent accepted release qualification
or a reviewed, trusted checkout, as described in [VERIFY.md](VERIFY.md). The
illustrative tag above does not establish publication. Missing signatures
must stop installation. Homebrew formula and OCI verification have separate
contracts; see [homebrew.md](homebrew.md) and
[PUBLISHING.md](PUBLISHING.md#sidecar-image-signing).

## Signature and Checksum Verification

Every tagged release must publish:

- Per-archive `.sig` and `.pem` files for exact-tag signature verification.
- Per-archive `.sha256` files (one line each: `<hash>  <archive>`).
- A combined `SHA256SUMS` file covering every archive in the release.

Authenticate the archive with [VERIFY.md](VERIFY.md) first. The following
checksum checks detect byte mismatches but provide no signer authentication:

```bash
# Single archive
shasum -a 256 -c chio-0.1.0-aarch64-apple-darwin.tar.gz.sha256

# All archives at once
curl -fsSL https://github.com/bb-connor/arc/releases/download/v0.1.0/SHA256SUMS -o SHA256SUMS
shasum -a 256 -c SHA256SUMS
```

Container image provenance must be attested by the build workflow
(`.github/workflows/sidecar-image.yml`). Confirm the digest matches what the
workflow logs:

```bash
docker buildx imagetools inspect ghcr.io/bb-connor/chio-sidecar:0.1.0
```

## Troubleshooting

- **`brew install` fails with `SHA256 mismatch`**: the tap formula was
  published before the release workflow replaced the placeholder checksums.
  Re-run `brew update` and retry.
- **`docker run` exits immediately with code 64**: you overrode the image with
  `run`, `mcp serve-http`, or another subcommand that still needs policy and
  authority configuration. Mount config into `/etc/chio` and retry with the full
  command line.
- **Linux binary reports `GLIBC_2.XX not found`**: the published
  `linux-gnu` builds target a recent glibc. Use the Docker image instead,
  or build from source.

## Where Binaries Come From

| Asset                                          | Built by                                              |
| ---------------------------------------------- | ----------------------------------------------------- |
| GitHub Release archives + `SHA256SUMS`         | `.github/workflows/release-binaries.yml`              |
| `ghcr.io/bb-connor/chio-sidecar` container image | `.github/workflows/sidecar-image.yml`                 |
| Homebrew formula template                      | `packaging/homebrew/chio.rb.tmpl` rendered into release asset `chio.rb` |
