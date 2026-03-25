# `pact-py`

Pure-Python SDK for the PACT trust and receipt-control plane.

Current scope:

- pure-Python invariant helpers backed by the shared bindings vectors
- low-level transport helpers for JSON-RPC over streamable HTTP
- beta `PactClient` and `PactSession` APIs
- no Rust toolchain requirement
- no native bridge requirement
- no stable high-level ergonomic client yet

Current release posture:

- release-ready beta with pure-Python transport and invariant coverage
- distribution metadata, typed-package markers, wheel/sdist qualification, and clean-install smoke checks are in place
- public PyPI publication remains a later 1.0 milestone; current qualification targets internal and design-partner release quality

Current invariant coverage:

- canonical JSON
- SHA-256 helpers
- Ed25519 signing and verification over UTF-8 and canonical JSON
- receipt verification
- capability verification
- signed manifest verification

Current transport coverage:

- JSON and `text/event-stream` response parsing
- bearer auth plus MCP session and protocol headers
- low-level session initialization and teardown
- low-level request and notification execution
- auth discovery helpers and hosted OAuth flow helpers
- nested callback routing helpers for sampling, elicitation, and roots
- direct reuse by the Python conformance peer for initialize/session, auth, low-level request execution, and nested callbacks

Current beta limitations:

- high-level ergonomic task and notification helpers are still evolving
- public PyPI publication and broad external compatibility validation are still being hardened
- the package should be treated as beta, not yet 1.0 stable

Distribution details:

- installable package name: `pact-py`
- import package: `pact`

Minimal beta example:

```py
from pact import PactClient

client = PactClient.with_static_bearer("http://127.0.0.1:8080", "token")
session = client.initialize()
tools = session.list_tools()

print(tools)
session.close()
```

Run the current checks with:

```sh
./scripts/check-pact-py.sh
```

Run the release-artifact qualification with:

```sh
./scripts/check-pact-py-release.sh
```

Release process details live in [RELEASING.md](./RELEASING.md).
