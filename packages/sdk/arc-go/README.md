# `arc-go`

Pure-Go SDK for the ARC trust and receipt-control plane.

Current scope:

- pure-Go invariant helpers backed by the shared bindings vectors
- remote HTTP transport helpers for JSON-RPC over streamable HTTP
- beta `Client` and `Session` APIs for initialize/session, tools/resources/prompts, notifications, tasks, and nested flows
- auth discovery helpers and hosted OAuth flow helpers
- nested callback routing helpers for sampling, elicitation, and roots
- task, subscription, completion, and log-level helpers on `Session`
- `CGO_ENABLED=0` support by default
- no CGO bridge requirement

Current release posture:

- release-ready beta with live conformance coverage through Waves 1-5
- module version plumbing, consumer-build smoke checks, and release qualification are in place
- aligned to the current `v2.3` production-candidate protocol and release docs
- broader external publication through Git tags and proxy propagation remains a later 1.0 milestone

Current live conformance coverage:

- Wave 1 MCP Core: initialize/session, tools/resources/prompts
- Wave 2 MCP Experimental: tasks, progress, and cancellation
- Wave 3 MCP Core: auth discovery, authorization-code initialize, and token-exchange initialize
- Wave 4 MCP Core: notifications and subscriptions
- Wave 5 MCP Core: nested sampling, elicitation, and roots callbacks

Current beta limitations:

- the package should be treated as beta, not yet 1.0 stable
- broad external publishing and compatibility validation still need hardening
- no CGO/native bridge is provided or required

Run the current checks with:

```sh
CGO_ENABLED=0 go test ./...
```

Run the current live Go conformance lanes with:

```sh
cargo test -p arc-conformance --test wave1_go_live --test wave2_go_live --test wave3_go_live --test wave4_go_live --test wave5_go_live -- --nocapture
```

Run the release qualification with:

```sh
./scripts/check-arc-go-release.sh
```

Release process details live in [RELEASING.md](./RELEASING.md).
