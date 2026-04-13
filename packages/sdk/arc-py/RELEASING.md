# Releasing `arc-sdk`

`arc-sdk` is the distribution name. The import package remains `arc`.

## Release Gate

Run these commands from the repo root:

```sh
./scripts/check-arc-py.sh
./scripts/check-arc-py-release.sh
./scripts/check-sdk-publication-examples.sh
```

The release qualification scripts verify:

- the declared version in `pyproject.toml` matches `src/arc/version.py`
- wheel and sdist artifacts build cleanly
- package metadata passes `twine check`
- wheel and sdist both install into clean virtual environments
- the installed distribution reports version `arc-sdk == arc.__version__`
- the built artifacts include `arc/py.typed`
- the source distribution excludes stale cache artifacts and stale egg-info
  metadata
- clean installs expose `ArcClient`, `ArcSession`, and `ReceiptQueryClient`

## Expected Artifacts

- wheel: `arc_sdk-<version>-py3-none-any.whl`
- source distribution: `arc_sdk-<version>.tar.gz`

## Publication Notes

- `arc-sdk` is the stable `1.0.0` Python publication target for ARC's hosted
  MCP and receipt-query surface.
- The package stays pure Python and does not require a Rust toolchain.
- The API is intentionally narrow: remote MCP sessions, receipt queries,
  invariants, and auth helpers.
