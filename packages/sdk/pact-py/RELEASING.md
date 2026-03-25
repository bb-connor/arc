# Releasing `pact-py`

`pact-py` is the distribution name. The import package remains `pact`.

## Release Gate

Run both commands from the repo root:

```sh
./scripts/check-pact-py.sh
./scripts/check-pact-py-release.sh
```

The release qualification script verifies:

- the declared version in `pyproject.toml` matches `src/pact/version.py`
- wheel and sdist artifacts build cleanly
- package metadata passes `twine check`
- wheel and sdist both install into clean virtual environments
- the installed distribution reports version `pact-py == pact.__version__`
- the built artifacts include `pact/py.typed`
- the source distribution excludes stale cache artifacts and stale `src/pact.egg-info` metadata

## Expected Artifacts

- wheel: `pact_py-<version>-py3-none-any.whl`
- source distribution: `pact_py-<version>.tar.gz`

## Publication Notes

- `pact-py` is currently release-ready beta, not 1.0 stable.
- Public PyPI publication is a later roadmap milestone; until then, qualify and
  publish only through approved internal channels.
