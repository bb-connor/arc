# Homebrew Formula For Chio

Use Homebrew only after the exact accepted tag includes a `chio.rb` release
asset. This page does not establish current formula publication or acceptance.
The formula is not covered by the detached archive signature checks; use
[VERIFY.md](VERIFY.md) to authenticate a native archive before installation.

## One-line Install After A Tagged Release

```bash
TAG=v0.1.1-rc.1
curl -fsSL -o /tmp/chio.rb "https://github.com/bb-connor/arc/releases/download/${TAG}/chio.rb"
brew install --formula /tmp/chio.rb
```

## About The Formula

The release-binaries workflow renders the installable formula from
[`packaging/homebrew/chio.rb.tmpl`](../../packaging/homebrew/chio.rb.tmpl) and
publishes the result as the `chio.rb` release asset alongside the platform
archives when a release is cut.

## Upgrading After A Tagged Release

```bash
TAG=v0.1.1-rc.1
curl -fsSL -o /tmp/chio.rb "https://github.com/bb-connor/arc/releases/download/${TAG}/chio.rb"
brew upgrade --formula /tmp/chio.rb
```

## Uninstalling

```bash
brew uninstall chio
```

## Verifying The Install

```bash
chio --version
which chio
```

For other install paths (Docker, curl), see
[`BINARY_DISTRIBUTION.md`](./BINARY_DISTRIBUTION.md).
