# LangChain Tool Example

This example wraps an ARC-governed hosted-edge tool as a LangChain
`StructuredTool` while the hosted session itself is managed by `arc-sdk`.

## What it does

- initializes a hosted ARC session through `arc-sdk`
- lists tools from the hosted HTTP edge
- exposes the governed tool as a LangChain `StructuredTool`
- invokes the tool through LangChain while ARC policy enforcement remains in
  the execution path
- resolves the resulting receipt through the trust service query API

## Install

From this directory:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ../../packages/sdk/arc-py -e .
```

## Run

```bash
python run.py
```

The script defaults to the phase `309` Docker quickstart endpoints:

- `ARC_BASE_URL=http://127.0.0.1:8931`
- `ARC_CONTROL_URL=http://127.0.0.1:8940`
- `ARC_AUTH_TOKEN=demo-token`

The example prints a JSON summary containing the hosted session ID, active
capability ID, tool inventory, echoed payload, and receipt ID.

Optional environment variables:

- `ARC_BASE_URL`: hosted edge base URL
- `ARC_CONTROL_URL`: trust service base URL
- `ARC_AUTH_TOKEN`: bearer token accepted by both services
- `ARC_MESSAGE`: override the demo input message

See also:

- [docs/PROGRESSIVE_TUTORIAL.md](/Users/connor/Medica/backbay/standalone/arc/docs/PROGRESSIVE_TUTORIAL.md)
- [examples/docker/README.md](/Users/connor/Medica/backbay/standalone/arc/examples/docker/README.md)
