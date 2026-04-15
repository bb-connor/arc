# Summary 290-01

Phase `290` refreshed the root quickstart and published the container images
needed for the 5-minute path.

## Delivered

- Updated [README.md](/Users/connor/Medica/backbay/standalone/arc/README.md)
  with:
  - a private-GHCR container quickstart using `docker pull`, `docker run`, and
    the first policy-enforced tool call
  - the existing source-build quickstart preserved as a second lane
  - a framework-examples section linking to Docker, Anthropic SDK, and
    LangChain examples
- Updated [examples/docker/README.md](/Users/connor/Medica/backbay/standalone/arc/examples/docker/README.md)
  and [compose.yaml](/Users/connor/Medica/backbay/standalone/arc/examples/docker/compose.yaml)
  so the published demo image is the default and local build remains available.
- Published verified images:
  - `ghcr.io/bb-connor/arc:main`
  - `ghcr.io/bb-connor/arc:17fd537`
  - `ghcr.io/bb-connor/arc-mcp-demo:main`
  - `ghcr.io/bb-connor/arc-mcp-demo:17fd537`

## Verification

- `docker pull ghcr.io/bb-connor/arc:main`
- `docker pull ghcr.io/bb-connor/arc-mcp-demo:main`
- `docker run --rm ghcr.io/bb-connor/arc:main --help`
- `docker compose -f examples/docker/compose.yaml up -d`
- `python3 examples/docker/smoke_client.py`

The README path is now backed by a published pullable image instead of a local
source build.
