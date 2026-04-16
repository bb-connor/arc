# Homebrew Tap for ARC

## One-line install

```bash
brew tap backbay/arc https://github.com/backbay/arc && brew install backbay/arc/arc
```

## About the tap

The formula lives in this repository at [`Homebrew/arc.rb`](../../Homebrew/arc.rb).
The release-binaries workflow (`.github/workflows/release-binaries.yml`)
publishes archives and `sha256` files for each supported target, and the tap
repository mirrors the formula with concrete SHA-256 values substituted for
the `0000…` placeholders.

## Upgrading

```bash
brew update
brew upgrade backbay/arc/arc
```

## Uninstalling

```bash
brew uninstall backbay/arc/arc
brew untap backbay/arc
```

## Verifying the install

```bash
arc --version
which arc
```

For other install paths (Docker, curl), see
[`BINARY_DISTRIBUTION.md`](./BINARY_DISTRIBUTION.md).
