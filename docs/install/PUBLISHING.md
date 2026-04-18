# ARC SDK Publishing Runbook

Operator guide for publishing ARC's Python SDKs to PyPI and TypeScript
SDKs to npm. Both release lanes use OIDC Trusted Publishing, meaning
**no long-lived API tokens are stored in GitHub secrets**; all
authentication flows come from GitHub's OIDC identity combined with
pre-configured trust on the registry side.

- Python workflow: [`.github/workflows/release-pypi.yml`](../../.github/workflows/release-pypi.yml)
- TypeScript workflow: [`.github/workflows/release-npm.yml`](../../.github/workflows/release-npm.yml)
- Local smoke-test scripts:
  - [`sdks/python/scripts/package-check.sh`](../../sdks/python/scripts/package-check.sh)
  - [`sdks/typescript/scripts/package-check.sh`](../../sdks/typescript/scripts/package-check.sh)

---

## Tag format

Both workflows trigger on annotated git tags. The tag name encodes
what to publish.

| Tag pattern | Publishes |
|---|---|
| `py/v<MAJOR.MINOR.PATCH>` | Every Python package listed below. All packages must be at the same version. |
| `py/<slug>-v<MAJOR.MINOR.PATCH>` | Just that package (e.g. `py/arc-crewai-v1.2.0`). |
| `ts/v<MAJOR.MINOR.PATCH>` | Every TypeScript package. All packages must be at the same version. |
| `ts/<slug>-v<MAJOR.MINOR.PATCH>` | Just that package (e.g. `ts/express-v1.2.0` -> `@arc-protocol/express`). |

The per-package slug is the **directory name**, not the distribution
name. For example, `@arc-protocol/express` lives in
`sdks/typescript/packages/express`, so its slug is `express`.

**Meta-tag policy**: a `py/v*.*.*` or `ts/v*.*.*` tag publishes every
package, and the matrix CI validates that every package's declared
version matches the tag. If even one is out of step, the workflow
fails before any publish happens. For uneven version trains, use
per-package slug tags.

Tags must be pushed from `main` (or a protected release branch) after
all SDK changes for that version have merged.

### Creating a release tag

```bash
# Single package, single version bump
git tag -a py/arc-crewai-v1.2.0 -m "release arc-crewai 1.2.0"
git push origin py/arc-crewai-v1.2.0

# Full Python SDK fleet (after bumping every pyproject.toml)
git tag -a py/v0.2.0 -m "release Python SDKs 0.2.0"
git push origin py/v0.2.0
```

---

## Package inventory

### Python (PyPI)

Published under the listed distribution name:

| Slug | Distribution | Directory |
|---|---|---|
| `arc-sdk-python` | `arc-sdk-python` | `sdks/python/arc-sdk-python` |
| `arc-asgi` | `arc-asgi` | `sdks/python/arc-asgi` |
| `arc-django` | `arc-django` | `sdks/python/arc-django` |
| `arc-fastapi` | `arc-fastapi` | `sdks/python/arc-fastapi` |
| `arc-langchain` | `arc-langchain` | `sdks/python/arc-langchain` |
| `arc-crewai` | `arc-crewai` | `sdks/python/arc-crewai` |
| `arc-autogen` | `arc-autogen` | `sdks/python/arc-autogen` |
| `arc-llamaindex` | `arc-llamaindex` | `sdks/python/arc-llamaindex` |
| `arc-temporal` | `arc-temporal` | `sdks/python/arc-temporal` |
| `arc-prefect` | `arc-prefect` | `sdks/python/arc-prefect` |
| `arc-dagster` | `arc-dagster` | `sdks/python/arc-dagster` |
| `arc-airflow` | `arc-airflow` | `sdks/python/arc-airflow` |
| `arc-ray` | `arc-ray` | `sdks/python/arc-ray` |
| `arc-streaming` | `arc-streaming` | `sdks/python/arc-streaming` |
| `arc-iac` | `arc-iac` | `sdks/python/arc-iac` |
| `arc-observability` | `arc-observability` | `sdks/python/arc-observability` |
| `arc-langgraph` | `arc-langgraph` | `sdks/python/arc-langgraph` |
| `arc-code-agent` | `arc-code-agent` | `sdks/python/arc-code-agent` |
| `arc-lambda-python` | `arc-lambda-python` | `sdks/lambda/arc-lambda-python` |

### TypeScript (npm)

| Slug | Distribution | Directory |
|---|---|---|
| `node-http` | `@arc-protocol/node-http` | `sdks/typescript/packages/node-http` |
| `express` | `@arc-protocol/express` | `sdks/typescript/packages/express` |
| `fastify` | `@arc-protocol/fastify` | `sdks/typescript/packages/fastify` |
| `elysia` | `@arc-protocol/elysia` | `sdks/typescript/packages/elysia` |
| `ai-sdk` | `@arc-protocol/ai-sdk` | `sdks/typescript/packages/ai-sdk` |

`@arc-protocol/conformance` is marked `"private": true` and is
deliberately excluded from publishing.

---

## One-time setup (required before first publish)

### PyPI Trusted Publishing

For **each** Python package, a PyPI project maintainer must configure
a Trusted Publisher:

1. Log in to https://pypi.org as a maintainer of the project (or use
   https://pypi.org/manage/account/publishing/ to pre-register a
   pending publisher for a brand-new distribution).
2. Under **Publishing** -> **Add a new pending publisher**, set:
   - PyPI Project Name: e.g. `arc-crewai`
   - Owner: `backbay-industries`
   - Repository name: `arc`
   - Workflow name: `release-pypi.yml`
   - Environment name: `pypi`
3. Save.

The environment name (`pypi`) is hard-coded in `release-pypi.yml`. Do
not change it without also updating the Trusted Publisher
configuration for every project.

Reference: https://docs.pypi.org/trusted-publishers/

### npm OIDC / provenance

npm provenance requires the workflow to run with
`permissions.id-token: write` (already set in `release-npm.yml`) and
for the npm package to opt in to Trusted Publishing:

1. Log in to https://www.npmjs.com as an org admin of `@arc-protocol`.
2. For each package (`node-http`, `express`, `fastify`, `elysia`,
   `ai-sdk`), go to **Settings** -> **Trusted Publishers** -> **Add**
   and register:
   - GitHub org: `backbay-industries`
   - Repository: `arc`
   - Workflow path: `.github/workflows/release-npm.yml`
   - Environment name: `npm`
3. Confirm the org-level 2FA policy is set to "Publishing and
   settings modification" -- provenance publishes bypass interactive
   2FA but still honor the org policy.

After this is done, `npm publish --provenance` from the workflow will
mint an attestation signed by Sigstore and linked to the tag's source
commit. No `NPM_TOKEN` secret is needed; any existing token should be
revoked after the first successful provenance publish.

Reference: https://docs.npmjs.com/generating-provenance-statements

### GitHub environments

Both workflows use deployment environments (`pypi` and `npm`) so that
environment-level protection rules (e.g. required reviewers, branch
restrictions) can gate publishes. Configure under
**Settings** -> **Environments** in the repo:

- `pypi`: restrict to tags matching `py/*`.
- `npm`: restrict to tags matching `ts/*`.
- Optionally add required reviewers for production releases.

---

## Dry-run / test mode

Both workflows expose `workflow_dispatch` with a `dry_run` toggle
(default `true`). A dry run builds the sdist+wheel (Python) or runs
`build` + `lint` + `test` + `npm pack` (TypeScript) and uploads the
artifacts, but skips the `publish` job entirely.

Dry runs are the right way to validate CI after changing the
workflow or adding a new package. Trigger via **Actions** ->
**Release PyPI / Release npm** -> **Run workflow** -> pick branch,
optionally fill `package`, leave `dry_run` checked.

For local iteration, use the `package-check.sh` scripts instead:

```bash
./sdks/python/scripts/package-check.sh
./sdks/typescript/scripts/package-check.sh
```

---

## Release checklist

1. Land all SDK changes for the release on `main`.
2. Bump the version in the package's `pyproject.toml` (or
   `package.json`). For a full-fleet release, bump **every** package.
3. Run the local smoke check:
   - `./sdks/python/scripts/package-check.sh`
   - `./sdks/typescript/scripts/package-check.sh`
4. Open a release PR, get review, merge.
5. From `main`, create and push the release tag (see **Tag format**).
6. Watch the workflow in GitHub Actions. The `build` job should
   succeed for every matrix leg before `publish` starts.
7. Confirm the package is live:
   - `pip install <dist-name>==<version>`
   - `npm view @arc-protocol/<slug>@<version>`

---

## Rollback

### PyPI

PyPI **does not allow re-uploading the same version** after a
release. The correct rollback is to **yank** the broken version and
publish a new patch:

1. On https://pypi.org/manage/project/<dist-name>/releases/, click
   **Options** -> **Yank** on the bad version. Enter a reason
   (shown to users in resolver errors).
2. Fix the bug on `main`, bump the patch version, land the PR.
3. Cut a new tag (e.g. `py/arc-crewai-v1.2.1`) and let the workflow
   publish normally.

Yanked versions remain installable if explicitly pinned, but resolvers
will skip them for `>=` / `~=` specifiers.

### npm

npm allows `npm unpublish` only within 72 hours of first publish and
only if no other package depends on it. The recommended rollback is
to **deprecate**:

```bash
npm deprecate @arc-protocol/<slug>@<version> "Do not use: superseded by <next-version>. See CHANGELOG for details."
```

Then bump the patch version, tag, and let the workflow republish.

For severe security issues within the 72-hour window, unpublishing
is permitted:

```bash
npm unpublish @arc-protocol/<slug>@<version>
```

Coordinate with @arc-protocol org admins before unpublishing; the
name+version combo is burnt for 24 hours.

### Revoking a provenance attestation

Provenance attestations cannot be withdrawn once minted (they live
in the Sigstore transparency log). Deprecation plus a follow-up
release is the correct response.

---

## Troubleshooting

**`invalid-publisher: invalid audience in JWT`** during PyPI upload
  -> Trusted Publisher config on PyPI does not match the workflow.
  Verify the environment name, workflow filename, owner, and repo
  name match exactly.

**`403 Forbidden` from npm with provenance enabled**
  -> Org-level Trusted Publisher not configured, or the package's
  access level is `restricted`. Run `npm access ls-packages
  @arc-protocol` to verify.

**`build` job passes but `publish` does not start**
  -> The plan job set `dry_run=true`. For `workflow_dispatch`,
  uncheck the **Dry run** input. For tag pushes, `dry_run` is always
  `false`.

**Matrix leg fails with "Meta tag pins version X but package Y is at Z"**
  -> Some package's `pyproject.toml` or `package.json` was not bumped
  in step 2. Bump it, amend the release PR, delete the tag (`git tag
  -d <tag> && git push --delete origin <tag>`), and re-tag.
