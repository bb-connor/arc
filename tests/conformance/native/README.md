# ARC Native Conformance

This directory contains the native ARC conformance lane introduced in phase
`314`.

Structure:

- `scenarios/`
  JSON scenario descriptors for the native suite.
- `results/generated/`
  Generated JSON result artifacts.
- `reports/generated/`
  Generated Markdown reports.

The native suite covers these categories:

- capability validation
- delegation attenuation
- receipt integrity
- revocation propagation
- DPoP verification
- governed transaction enforcement

## Driver Contracts

The native runner supports three driver modes.

### `artifact`

No external process is required. The runner validates deterministic ARC
fixtures such as signed capabilities, delegation chains, receipts, and DPoP
proofs.

### `stdio`

The target is an executable that speaks the native ARC framed transport on
stdin/stdout.

Contract:

1. The runner writes one length-prefixed canonical JSON `AgentMessage` frame to
   stdin.
2. The target writes zero or more length-prefixed canonical JSON
   `KernelMessage` frames to stdout.
3. The runner stops reading after the terminal `tool_call_response` or EOF.

This contract is language-neutral. A third-party implementation can satisfy it
with any executable that reads and writes the documented frame format.

### `http`

The target is an HTTP service that exposes one test-only endpoint:

- `POST /arc-conformance/v1/invoke`

Request body:

```json
{
  "scenarioId": "governed-transaction-enforcement",
  "request": { "...": "AgentMessage JSON" }
}
```

Response body:

```json
{
  "messages": [
    { "...": "KernelMessage JSON" }
  ]
}
```

The HTTP driver intentionally carries plain JSON rather than framed bytes so
non-Rust implementations can wire the harness up quickly.

## Running The Checked-In Suite

Build the fixture and runner:

```bash
cargo build -p arc-conformance --bin arc-native-conformance-runner --bin arc-native-conformance-fixture
```

Start the HTTP fixture in one terminal:

```bash
target/debug/arc-native-conformance-fixture --http-listen 127.0.0.1:9954
```

Run the native suite in another terminal:

```bash
target/debug/arc-native-conformance-runner \
  --scenarios-dir tests/conformance/native/scenarios \
  --results-output tests/conformance/native/results/generated/arc-self.json \
  --report-output tests/conformance/native/reports/generated/arc-self.md \
  --stdio-command target/debug/arc-native-conformance-fixture \
  --http-base-url http://127.0.0.1:9954
```

Third-party implementations can replace either target:

- use `--stdio-command` for a process that implements the native framed
  protocol
- use `--http-base-url` for an HTTP bridge that implements the JSON test
  contract
