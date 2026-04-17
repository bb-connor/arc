# Homebrew Tap for ARC

## One-line install

```bash
curl -fsSL -o /tmp/arc.rb https://github.com/backbay/arc/releases/latest/download/arc.rb
brew install --formula /tmp/arc.rb
```

## About the tap

The release-binaries workflow renders the installable formula from
[`Homebrew/arc.rb.tmpl`](../../Homebrew/arc.rb.tmpl) and publishes the
result as the `arc.rb` release asset alongside the platform archives.

## Upgrading

```bash
curl -fsSL -o /tmp/arc.rb https://github.com/backbay/arc/releases/latest/download/arc.rb
brew upgrade --formula /tmp/arc.rb
```

## Uninstalling

```bash
brew uninstall arc
```

## Verifying the install

```bash
arc --version
which arc
```

For other install paths (Docker, curl), see
[`BINARY_DISTRIBUTION.md`](./BINARY_DISTRIBUTION.md).
