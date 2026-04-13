# ARC Conformance Fixtures

This directory holds the E8 Slice A interoperability and conformance assets.

Structure:

- `scenarios/`
  Versioned scenario descriptors used by the harness.
- `results/`
  Machine-readable result artifacts. Generated output should land here or in CI artifacts.
- `peers/`
  External peer fixtures and bootstrap assets for JavaScript and Python, plus the Go live lanes.
- `fixtures/`
  Shared policies, manifests, and transcripts used by scenarios.
- `reports/`
  Generated Markdown summaries derived from JSON result artifacts.

Rules:

- scenario descriptors are the source of truth for scenario identity and categorization
- reports are generated, not hand-edited
- peer assets should be minimal, explicit, and easy to reproduce in CI
- ARC-specific trust assertions should be reported separately from MCP-core compatibility

The first Wave 1 scenario set lives under `scenarios/wave1/`.

Generate a sample Markdown matrix from the checked-in sample result artifact with:

```bash
cargo run -p arc-conformance --bin arc-conformance-report -- \
  --scenarios-dir tests/conformance/scenarios \
  --results-dir tests/conformance/results \
  --output /tmp/arc-compatibility-matrix.md
```

Run the live Wave 1 remote HTTP harness with real JS and Python peers:

```bash
cargo run -p arc-conformance --bin arc-conformance-runner --
```

By default that command:

- boots `arc mcp serve-http` against `fixtures/wave1/mock_mcp_server.py`
- runs the JS and Python client peers against the remote edge
- writes JSON result artifacts under `tests/conformance/results/generated/wave1-live/`
- writes a generated report to `tests/conformance/reports/generated/wave1-live.md`

Wave 2 task scenarios live under `scenarios/wave2/`.
Wave 3 auth scenarios live under `scenarios/wave3/`.
Wave 4 notification scenarios live under `scenarios/wave4/`.
Wave 5 nested-flow scenarios live under `scenarios/wave5/`.
The native ARC conformance lane lives under `native/`.

Current live status:

- Wave 1 MCP Core remote HTTP matrix is green across the JS and Python peers
- Wave 1 MCP Core remote HTTP lane is also green for the Go peer
- Wave 2 task creation, `tasks/get`, and `tasks/result` are green across the JS and Python peers
- Wave 2 `tasks/cancel` is green across the JS and Python peers for the remote HTTP wrapped-tool path
- Wave 2 task creation, `tasks/get`, `tasks/result`, and `tasks/cancel` are also green for the Go peer
- Wave 3 remote HTTP auth/discovery is green across the JS and Python peers, including protected-resource metadata, authorization-server metadata, auth-code initialization, token-exchange initialization, and unauthenticated `WWW-Authenticate` challenges
- Wave 3 remote HTTP auth/discovery is also green for the Go peer, including protected-resource metadata, authorization-server metadata, auth-code initialization, token-exchange initialization, and unauthenticated `WWW-Authenticate` challenges
- Wave 4 remote HTTP notifications/subscriptions are green across the JS and Python peers, including `resources/subscribe`, forwarded `notifications/resources/updated`, and forwarded resource/tool/prompt `list_changed` notifications
- Wave 4 remote HTTP notifications/subscriptions are also green for the Go peer
- Wave 5 remote HTTP nested flows are green across the JS and Python peers, including `sampling/createMessage`, form-mode `elicitation/create`, URL-mode `elicitation/create` plus `notifications/elicitation/complete`, and `roots/list`
- Wave 5 remote HTTP nested flows are also green for the Go peer, including `sampling/createMessage`, form-mode `elicitation/create`, URL-mode `elicitation/create` plus `notifications/elicitation/complete`, and `roots/list`

Generate the Wave 3 auth matrix against the local OAuth-backed edge with:

```bash
cargo run -p arc-conformance --bin arc-conformance-runner -- \
  --auth-mode oauth-local \
  --scenarios-dir tests/conformance/scenarios/wave3 \
  --results-dir tests/conformance/results/generated/wave3-auth \
  --report-output tests/conformance/reports/generated/wave3-auth.md
```

Generate the Wave 4 notification matrix with:

```bash
cargo run -p arc-conformance --bin arc-conformance-runner -- \
  --scenarios-dir tests/conformance/scenarios/wave4 \
  --results-dir tests/conformance/results/generated/wave4-notifications \
  --report-output tests/conformance/reports/generated/wave4-notifications.md
```

Generate the Wave 5 nested-flow matrix with:

```bash
cargo run -p arc-conformance --bin arc-conformance-runner -- \
  --scenarios-dir tests/conformance/scenarios/wave5 \
  --results-dir tests/conformance/results/generated/wave5-nested-flows \
  --report-output tests/conformance/reports/generated/wave5-nested-flows.md
```

Run the Go live lanes with:

```bash
cargo run -p arc-conformance --bin arc-conformance-runner -- \
  --peer go \
  --scenarios-dir tests/conformance/scenarios/wave1 \
  --results-dir tests/conformance/results/generated/wave1-go-live \
  --report-output tests/conformance/reports/generated/wave1-go-live.md
```

```bash
cargo run -p arc-conformance --bin arc-conformance-runner -- \
  --peer go \
  --auth-mode oauth-local \
  --scenarios-dir tests/conformance/scenarios/wave3 \
  --results-dir tests/conformance/results/generated/wave3-go-live \
  --report-output tests/conformance/reports/generated/wave3-go-live.md
```

Run the dedicated native ARC lane with:

```bash
target/debug/arc-native-conformance-fixture --http-listen 127.0.0.1:9954
```

```bash
target/debug/arc-native-conformance-runner \
  --scenarios-dir tests/conformance/native/scenarios \
  --results-output tests/conformance/native/results/generated/arc-self.json \
  --report-output tests/conformance/native/reports/generated/arc-self.md \
  --stdio-command target/debug/arc-native-conformance-fixture \
  --http-base-url http://127.0.0.1:9954
```
