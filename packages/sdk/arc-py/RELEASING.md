# Releasing `arc-py`

`arc-py` is the distribution name. The import package remains `arc`.

## Release Gate

Run both commands from the repo root:

```sh
./scripts/check-arc-py.sh
./scripts/check-arc-py-release.sh
```

The release qualification script verifies:

- the declared version in `pyproject.toml` matches `src/arc/version.py`
- wheel and sdist artifacts build cleanly
- package metadata passes `twine check`
- wheel and sdist both install into clean virtual environments
- the installed distribution reports version `arc-py == arc.__version__`
- the built artifacts include `arc/py.typed`
- the source distribution excludes stale cache artifacts and stale `src/arc.egg-info` metadata

## Expected Artifacts

- wheel: `arc_py-<version>-py3-none-any.whl`
- source distribution: `arc_py-<version>.tar.gz`

## Publication Notes

- `arc-py` is currently release-ready beta, not 1.0 stable.
- Public PyPI publication is a later roadmap milestone; until then, qualify and
  publish only through approved internal channels.
