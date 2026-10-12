# Lambda verdict-matrix driver architecture

## Responsibility and boundary

This deployment-shape driver exercises a remote evaluator through the
`POST /chio/evaluate` surface. Its public types are `Scenario`,
`ScenarioScript`, `VerdictTuple`, `ScenarioOutcome`, and `DriverReport`.
Its entrypoints cover scenario discovery/loading, request translation,
response projection, expected-tuple indexing, and a complete driver run.

The sidecar owns policy, guard, and capability evaluation.
The driver owns fixture translation and comparison.
The Lambda extension association comes from the matrix registry;
this binary does not invoke AWS Lambda or package an extension.

## Structure

`src/lib.rs` contains the scenario models, directory walker, HTTP client,
request builder, tuple extraction, report aggregation, and unit tests.
`src/main.rs` resolves the corpus, reads sidecar environment variables,
prints pretty JSON, and selects a process exit code.
There are no internal Chio dependencies or separate kernel modules.

## Data and control flow

`resolve_scenario_root` walks upward from the current directory until it
finds a Cargo manifest and the matrix directory. It returns the scenarios
child path. `load_scenarios` validates the root, walks JSON files recursively,
sorts paths, and deserializes each fixture. An empty tree yields an empty list.

`run_driver` trims the optional URL. An absent or empty URL creates only
unsupported outcomes. With a URL, it creates a blocking client and gates
capability/revocation categories before sending other cases sequentially.

`scenario_to_http_request` assigns a fixed timestamp, synthetic IDs,
an anonymous caller marked verified, and a tool path with percent-encoded
segments. Read/get tool suffixes and `metrics.query` select GET; other tools
select POST. The envelope itself always travels as a POST to the evaluator.
Invalid `input_json` becomes null arguments. Nonempty non-GET bodies receive
a synthetic all-zero hash. The capability header carries an unsigned ID
and scope list.

Successful HTTP responses pass through `tuple_from_evaluate_response`.
It reads the verdict tag and matrix receipt metadata, with a deny-reason
fallback and an empty scope list when metadata is absent.
Actual and expected tuples have sorted scope vectors before equality.
The report counts pass, fail, and unsupported outcomes separately.

## Trust and invariants

`load_scenarios` rejects symlinked roots and every encountered symlink,
and checks the scenario schema string. Reads have no byte ceiling;
traversal and later file opening are separate operations.
`Scenario.requires` and `script.operation` are stored but do not select behavior.

The HTTP client has a five-second timeout and targets the configured URL.
This test URL bypasses the production egress-contract abstraction through
explicit lint markers. Operators control its destination.
Transport failures, non-success statuses, JSON parse errors, and tuple
mismatches become failed outcomes. Capability and revocation scenarios
always remain unsupported because signed token construction is unavailable.

Response projection trusts the received JSON fields. It does not verify
receipt signatures, enforce a response schema, or validate scope members;
non-string scope array entries are filtered out.
`normalized` sorts scope vectors without removing duplicate entries.
A matching malformed response can only be assessed through its projected
values, so tuple equality has a bounded wire-comparison meaning.

## Dependencies

`serde` and `serde_json` deserialize fixtures and serialize reports.
`reqwest` supplies blocking JSON requests with rustls TLS support.
`url::form_urlencoded::byte_serialize` encodes tool path segments.
No Cargo features are declared by this package.

## Verification

Unit tests cover missing sidecar outcomes, unreachable loopback failures,
symlink refusal, unsupported signed-token categories, request fields,
path encoding, scope sorting, and response metadata/fallback projection.
These tests use local fixtures and a refused loopback port.
The conformance crate's `deployment_shape_smoke` target checks registry
labels, sidecar gates, and source/README presence.

Run `cargo test -p chio-verdict-matrix-driver-lambda --lib` from a repository
checkout so corpus discovery can find the shared scenarios.
A configured live sidecar changes the execution boundary; retained driver
reports describe its attempted cases. Hosted Lambda behavior requires a
separate invocation and environment qualification.
