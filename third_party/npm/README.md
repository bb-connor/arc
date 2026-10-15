# npm path forks

Each directory holds one npm package that has a security repair upstream has
not released. The directory contains:

- `<name>-<version>.tgz`: the registry archive, byte for byte. Its SHA-512
  equals the `integrity` value the registry publishes.
- `CHIO-PATCH.patch`: the complete delta from that archive, applied with
  `patch -p1` inside its `package/` directory.
- `<name>-<version>-chio.N.tgz`: the patched archive. `sdks/typescript`
  installs it through a `file:` devDependency and a `$<name>` override, so
  every copy of the package in that workspace resolves to it.
  `package-lock.json` pins it by SHA-512 integrity.
- `CHIO-PATCH.md`: provenance, delta and tests.
- `CHIO-PATCH.test.cjs`: regression tests against the installed package.

A patched version is the next upstream patch version with a `-chio.N`
prerelease tag. It sorts above every affected release, so advisory scanners
match the fork only against advisories that also cover the next release.

## Rebuild

Packing is deterministic with npm 11.19.0. From the repository root:

```bash
pkg=node-forge base=node-forge-1.4.0   # or: pkg=braces base=braces-3.0.3
work="$(mktemp -d)"
tar -C "$work" -xzf "third_party/npm/$pkg/$base.tgz"
patch -d "$work/package" -p1 < "third_party/npm/$pkg/CHIO-PATCH.patch"
npm pack --ignore-scripts --pack-destination "$work" "$work/package"
sha256sum "$work"/*-chio.*.tgz "third_party/npm/$pkg"/*-chio.*.tgz
```

## Test

```bash
npm ci --ignore-scripts --no-audit --no-fund --prefix sdks/typescript
node --test third_party/npm/*/CHIO-PATCH.test.cjs
```

When upstream publishes a release with the repair, delete the directory,
remove the devDependency and override from `sdks/typescript/package.json`, and
regenerate `sdks/typescript/package-lock.json` in the same change.
