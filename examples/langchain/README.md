# LangChain Tool Example

This example wraps a Chio-governed hosted-edge tool as a LangChain
`StructuredTool` while the hosted session itself is managed by `chio-sdk`.

## What it does

- initializes a hosted Chio session through `chio-sdk`
- lists tools from the hosted HTTP edge
- exposes the governed tool as a LangChain `StructuredTool`
- invokes the tool through LangChain while Chio policy enforcement remains in
  the execution path
- verifies the result `_meta.chioEvidence` with `chio.mcp.verify_mcp_result`
  against a pinned kernel key and returns only the output the signed receipt
  commits to
- confirms the verified receipt through the trust service query API

The edge is the Docker quickstart `chio-mcp-demo` service (profile
`enforced-native`), which provisions a signed cage launch policy and serves the
wrapped server through `chio mcp serve-http`. The example only connects to it.

## Install

From this directory:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ../../sdks/python/chio-py -e .
```

## Run

```bash
python run.py
```

The script defaults to the Docker quickstart endpoints:

- `CHIO_BASE_URL=http://127.0.0.1:8931`
- `CHIO_CONTROL_URL=http://127.0.0.1:8940`
- `CHIO_AUTH_TOKEN=demo-token`
- `CHIO_ADMIN_TOKEN=demo-admin-token`
- `CHIO_CONTROL_TOKEN=demo-control-token`

`CHIO_KERNEL_PUBLIC_KEY` has no default. Set it to the hex public key the
edge kernel signs receipts with, obtained from the operator. The script refuses
to run without it and never takes the key from an edge response.

The example prints a JSON summary containing the hosted session ID, active
capability ID, tool inventory, echoed payload, and receipt ID.

Optional environment variables:

- `CHIO_BASE_URL`: hosted edge base URL
- `CHIO_CONTROL_URL`: trust service base URL
- `CHIO_AUTH_TOKEN`: session bearer token the hosted edge accepts
- `CHIO_ADMIN_TOKEN`: admin bearer token for the edge's session trust route
- `CHIO_CONTROL_TOKEN`: control bearer token the trust service accepts for receipt queries
- `CHIO_SERVER_ID`: server ID the edge assigns to the wrapped server
  (default `wrapped-http-mock`)
- `CHIO_MESSAGE`: override the demo input message

See also:

- [docs/start-here/PROGRESSIVE_TUTORIAL.md](../../docs/start-here/PROGRESSIVE_TUTORIAL.md)
- [examples/docker/README.md](../docker/README.md)
