# Releasing `arc-go`

`arc-go` is a Go module rooted at `packages/sdk/arc-go`.

## Release Gate

Run both commands from the repo root:

```sh
./scripts/check-arc-go.sh
./scripts/check-arc-go-release.sh
```

The release qualification script verifies:

- `CGO_ENABLED=0` test, vet, and build coverage for the module
- the conformance peer binary installs cleanly
- a separate consumer module can import the SDK and build against it
- version constants are present and exposed through the public module surface

## Tagging

Because this module lives in a repository subdirectory, release tags must use
the subdirectory-prefixed Go module format:

```sh
git tag packages/sdk/arc-go/v0.1.0
git push origin packages/sdk/arc-go/v0.1.0
```

## Publication Notes

- `arc-go` is currently release-ready beta, not 1.0 stable.
- External publication depends on pushing the correct module tag and allowing
  the Go module proxy/checksum database to observe it.
