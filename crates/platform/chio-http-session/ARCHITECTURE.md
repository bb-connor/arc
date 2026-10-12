# chio-http-session architecture

## Responsibility and boundary

`SessionJournal` owns a mutex-protected invocation journal identified by a
caller-supplied session string. `RecordParams` carries tool/server/agent
identity, bytes read and written, delegation depth, and allowed status. It
records supplied measurements; a guard or adapter must measure them and
authenticate the session.

`CumulativeDataFlow`, `JournalEntry`, and `SessionJournalSnapshot` expose
cloned views. A snapshot combines counts, retained tool sequence, cumulative
data flow, current streak, entry count, and the exported head hash.
Retaining one shared journal gives related requests a common history.

## Structure

All implementation and unit tests live in `src/lib.rs`. `JournalInner`
contains bounded rings for entries and tool names, a distinct-key-bounded
count map, cumulative scalar counters, a sequence counter, and an
evicted-prefix commitment. Public methods acquire the mutex through
`lock_inner`; poisoned locks produce `SessionJournalError::LockPoisoned`.

## Data and control flow

`record` validates identity fields, acquires the lock, obtains Unix seconds
from `SystemTime`, computes the entry hash, updates totals and streak state,
and appends to the rings. Sequence and byte counters use saturating
arithmetic. The distinct-key map keeps existing tools counting when full,
while omitting previously unseen names.

On entry eviction, the discarded hash is folded into an accumulated prefix
hash. The exported head combines that prefix with the retained tail. The
retained-entry length therefore differs from the cumulative invocation count
after eviction.

## Trust and invariants

Tool/server/agent values must be nonempty, unpadded, and free of control
characters. Entry hashes use little-endian numeric fields and
length-prefixed strings, including the prior hash; this representation is
separate from RFC 8785 JSON.

`verify_integrity` checks retained links and hashes. After eviction, it
accepts the first retained entry link into the discarded prefix, whose
bodies are unavailable. Independent auditing of that prefix requires
separately retained evidence. There is no signature, durable backend, expiry
policy, or restoration API here. The record clock falls back to zero if
reading Unix time fails.

## Dependencies

`chio-bounded` supplies capacity-limited rings and gauges.
`chio-kernel::MemoryBudgetConfig` single-sources default and configured
entry/tool-map caps. `sha2` and `hex` build commitments. `serde` serializes
exported records and snapshots; `thiserror` describes field, lock, and chain
failures.

## Verification

Unit tests cover record sequencing, invalid identities, cumulative
statistics, entry-ring eviction, surviving counts and streaks, distinct-tool
caps, and hash/link consistency. Run `cargo test -p chio-http-session`. The
README records one summary and checks a coherent snapshot and retained chain
under default crate features. No database or kernel dispatch is involved.
