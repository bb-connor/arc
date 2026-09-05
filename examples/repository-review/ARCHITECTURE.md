# Repository review application

The application uses the public CLI and worker protocol to run a review over
immutable Git objects. It does not embed the Rust kernel or introduce another
tool authorization path.

```mermaid
flowchart LR
    Git[Git commit objects] --> Snapshot[Private source snapshot]
    Snapshot --> MCP[MCP tool process]
    Changes[Code reader / LangGraph] --> Host[Chio process host]
    Tests[Test reader / LangGraph] --> Host
    Publisher[Publisher / LangGraph] --> Host
    Host --> MCP
    MCP --> Reports[SQLite publication history]
    Changes --> Join[Trusted coordinator joins completed results]
    Tests --> Join
    Join --> Publisher
```

## Ownership

- `snapshot.py` resolves commit references, reads regular Git blobs, records
  omissions and computes the bounded source snapshot identity.
- `tools.py` serves inventory, captured file reads and append-only publication
  through MCP. It cannot read arbitrary paths supplied by a model.
- `worker.py` constructs one persistent LangGraph per OS worker, retaining
  tool-call identities and original receipt text. The optional model factory
  supplies application planning. It has no publication tool in reader roles.
- `review.py` initializes the declared authority tree, owns host lifecycle,
  rotates worker credentials, launches concurrent readers, joins their
  completed results, launches the publisher and verifies receipt exports.
- `qualify.py` supplies the failure oracle and behavioral assertions. Its
  scripted model is separate from the application's inventory default.

## Durable identities

The source snapshot digest is the graph thread id. Each reader and publisher
has a distinct Chio process and SQLite graph checkpoint file. Namespace,
thread, assistant-message and tool-call ids determine each operation key.
Attempt ids select transport endpoints and credential files only. They never
enter operation identity or report content.

`run.json` pins the original host key, source digest, commit range, model
factory configuration and application source hash. Native host state pins
the issuance/runtime policies and MCP definitions. Reader graph completion
precedes the coordinator's handoff; publisher planning is checkpointed before
publication. Rebuilding export files cannot authorize a new tool effect.

## Trust and failure boundaries

The coordinator, source snapshot, model factory and MCP server are trusted
host code. Same-user worker processes are not sandboxed. The native kernel
owns scope enforcement, call limits, admission, original receipts and outcome
recovery. LangGraph owns planning checkpoints, and SQLite owns local report
history. File handoffs are not authenticated kernel IPC.

MCP tool errors, kernel denials and unknown outcomes stop the graph. A known
publication can replay after worker and host death. An uncertain publication
cannot be automatically redispatched. The offline verifier establishes
receipt signature integrity against an independently pinned key; it does not
assert model correctness, log inclusion or complete causal provenance.
