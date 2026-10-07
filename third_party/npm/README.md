# Private Node tooling repairs

These archives are integrity-locked Node packages used by the private TypeScript
workspace. They retain the original licenses and attribution. They are not
published SDK dependencies or upstream releases.

The patches are applied to checksum-verified npm registry archives. The source
inventory and security disposition live at
[`supply-chain/npm-tooling-forks.json`](../../supply-chain/npm-tooling-forks.json)
and [the repair record](../../docs/security/npm-peer-tooling-advisories-2026-10-04.md).
The checker reconstructs every file and checks live advisories against the
original package identities, so these local names cannot hide new upstream
vulnerabilities.

```sh
python3 scripts/tests/check-npm-tooling-forks.test.py
python3 scripts/check-npm-tooling-forks.py
npm ci --ignore-scripts --no-audit --no-fund --prefix sdks/typescript
node --test scripts/tests/npm-tooling-forks.test.cjs
```

Replace each private package with a supported upstream release once it includes
the repair and passes these controls. Regenerate all affected npm lockfiles and
remove its private archive, patch and source record in the same change.
