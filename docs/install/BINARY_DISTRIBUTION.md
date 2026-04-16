# ARC Binary Distribution

Pre-built `arc` sidecar binaries are published with every tagged release so
developers can run ARC without installing a Rust toolchain.

## Supported Platforms

| OS      | Architecture         | Target triple                  | Archive           |
| ------- | -------------------- | ------------------------------ | ----------------- |
| Linux   | x86_64               | `x86_64-unknown-linux-gnu`     | `.tar.gz`         |
| Linux   | aarch64 (arm64)      | `aarch64-unknown-linux-gnu`    | `.tar.gz`         |
| macOS   | x86_64 (Intel)       | `x86_64-apple-darwin`          | `.tar.gz`         |
| macOS   | aarch64 (Apple)      | `aarch64-apple-darwin`         | `.tar.gz`         |
| Windows | x86_64               | `x86_64-pc-windows-msvc`       | `.zip`            |

Container images are published for `linux/amd64` and `linux/arm64`.

## Install via Homebrew

```bash
brew tap backbay/arc https://github.com/backbay/arc
brew install backbay/arc/arc
arc --version
```

The formula lives at `Homebrew/arc.rb`. See
[`docs/install/homebrew.md`](./homebrew.md) for tap details.

## Install via Docker

```bash
# Pull the latest published image
docker pull ghcr.io/backbay/arc-sidecar:latest

# Pin to a specific version
docker pull ghcr.io/backbay/arc-sidecar:0.1.0

# Run the default sidecar entrypoint
docker run --rm -p 8939:8939 ghcr.io/backbay/arc-sidecar:latest
```

The image:

- is built from `Dockerfile.sidecar` (Alpine base, non-root user `arc`, UID
  `10001`);
- runs `arc run` as its default command;
- uses `tini` as PID 1 for correct signal handling;
- stores sidecar state under `/var/lib/arc` (mount a volume to persist it).

## Install via `curl | sh` (archive download)

```bash
VERSION=0.1.0
TARGET=$(uname -m | sed 's/x86_64/x86_64/; s/arm64/aarch64/; s/aarch64/aarch64/')
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$OS" in
  linux)  TRIPLE="${TARGET}-unknown-linux-gnu" ;;
  darwin) TRIPLE="${TARGET}-apple-darwin" ;;
  *) echo "unsupported OS: $OS"; exit 1 ;;
esac

ARCHIVE="arc-${VERSION}-${TRIPLE}.tar.gz"
BASE="https://github.com/backbay/arc/releases/download/v${VERSION}"

curl -fsSL "${BASE}/${ARCHIVE}"        -o "${ARCHIVE}"
curl -fsSL "${BASE}/${ARCHIVE}.sha256" -o "${ARCHIVE}.sha256"
shasum -a 256 -c "${ARCHIVE}.sha256"
tar xf "${ARCHIVE}"
sudo install -m 0755 "arc-${VERSION}-${TRIPLE}/arc" /usr/local/bin/arc
arc --version
```

## Signature and Checksum Verification

Every release publishes:

- Per-archive `.sha256` files (one line each: `<hash>  <archive>`).
- A combined `SHA256SUMS` file covering every archive in the release.

Verify a downloaded archive with:

```bash
# Single archive
shasum -a 256 -c arc-0.1.0-aarch64-apple-darwin.tar.gz.sha256

# All archives at once
curl -fsSL https://github.com/backbay/arc/releases/download/v0.1.0/SHA256SUMS -o SHA256SUMS
shasum -a 256 -c SHA256SUMS
```

Container image provenance is attested by the build workflow
(`.github/workflows/sidecar-image.yml`). Confirm the digest matches what the
workflow logged:

```bash
docker buildx imagetools inspect ghcr.io/backbay/arc-sidecar:0.1.0
```

## Troubleshooting

- **`brew install` fails with `SHA256 mismatch`**: the tap formula was
  published before the release workflow replaced the placeholder checksums.
  Re-run `brew update` and retry.
- **`docker run` exits immediately with code 64**: `arc run` requires
  configuration (a policy path and capability authority). Mount a config
  directory into `/etc/arc` and re-run.
- **Linux binary reports `GLIBC_2.XX not found`**: the published
  `linux-gnu` builds target a recent glibc. Use the Docker image instead,
  or build from source.

## Where binaries come from

| Asset                                          | Built by                                              |
| ---------------------------------------------- | ----------------------------------------------------- |
| GitHub Release archives + `SHA256SUMS`         | `.github/workflows/release-binaries.yml`              |
| `ghcr.io/backbay/arc-sidecar` container image  | `.github/workflows/sidecar-image.yml`                 |
| Homebrew formula (this repo)                   | `Homebrew/arc.rb` (synced to the `backbay/arc` tap)   |
