# chio-http-session

Maintains per-session invocation history for Chio guards. `SessionJournal`
combines a bounded entry ring, a hash commitment, cumulative byte totals,
tool counts, and consecutive-tool streak state.

## Usage

Create a journal and record a caller-supplied invocation summary. The
example needs no persistence or network service.

```rust
use chio_http_session::{RecordParams, SessionJournal};

let journal = SessionJournal::with_caps("session-demo".into(), 8, 4);
let sequence = journal.record(RecordParams {
    tool_name: "read".into(), server_id: "catalog".into(),
    agent_id: "agent-demo".into(), bytes_read: 128, bytes_written: 0,
    delegation_depth: 0, allowed: true,
})?;
assert_eq!(sequence, 0);
let snapshot = journal.snapshot()?;
assert_eq!(snapshot.data_flow.total_bytes_read, 128);
assert_eq!(snapshot.tool_counts.get("read"), Some(&1));
journal.verify_integrity()?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Guarantees

`record` validates tool, server, and agent fields before locking and
appending. `snapshot` captures guard-facing state under one mutex.
`verify_integrity` recomputes retained entry hashes and links.

`with_caps` bounds retained entries and distinct tool-count keys. Cumulative
totals and streak length survive entry eviction; once the tool-count map is
full, new tool names are omitted from that map. `from_memory_budget` applies
configured kernel caps.

## Status

Implemented process-local journal. Callers retain and share the journal
across requests, bind it to an authenticated session, and decide when to
drop it. Hashes commit supplied records; they carry no signer identity or
independent tool-execution proof.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol](../../../spec/PROTOCOL.md#3-components-and-trust-boundaries)
- [chio-http-core](../chio-http-core/README.md)
- [License](../../../LICENSE)
