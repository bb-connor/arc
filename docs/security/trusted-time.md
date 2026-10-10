# Trusted time and authority windows

The shared port is `chio_security_types::clock::Clock`. A reading contains
`UnixMillis` for signed epoch evidence and `MonotonicInstant` for local elapsed
time. They cannot be compared or subtracted across domains. A monotonic instant
belongs to its clock origin; it is never serialized as an epoch or transferred
between hosts. Wire formats keep their existing explicit seconds or milliseconds
fields, with checked conversions at the reader.

`Clock::read` is fallible. Native clocks share a process-wide origin and fence;
sampling and publishing the fence occur under the same lock. Browser clocks
validate both JavaScript readings and keep a fence in the browser context.
Unavailable time, a poisoned fence, either clock moving backward, and numeric
overflow refuse the operation. There is no epoch-zero fallback in these adapters.
Injected clocks must honor the same contract; `ClockFence` supports deterministic
adapters. `FixedClock` is for fixed evaluation instants and fixtures, not advancing
production deadlines.

API-protect opts into `AdvancingSystemClock` and `AdvancingClockFence`. These
project an epoch floor from a wall/monotonic anchor and return the greater of
that floor and the current wall sample. Backward or stalled wall time cannot
freeze expiry; elapsed fractions are retained across reads. Forward wall steps
advance the anchor immediately. Unavailable samples, monotonic regression,
poisoned state and overflow still refuse the operation. The service shares this
clock with its HTTP authority, mediation kernel, replay stores, durable admission,
local budget store and reaper. Existing strict `SystemClock` consumers retain
their refusal behavior. This process-local projection does not replace durable
rollback fences or establish a cross-host time authority.

MCP background ticks preserve the session and pending work when authority time
fails. They dispatch nothing until a valid observation succeeds, and skip time
reads entirely when no background work is queued. Requests requiring time still
return the typed clock rejection. Recovery does not refresh queued task expiry.

Skew applies to a remote signed timestamp at a verification boundary. It never
permits a local clock to regress or extends an already accepted expiry. The
verifier's pinned policy supplies its maximum skew; `validate_future_skew`
checks addition without saturation. Protocol freshness windows similarly reject
overflow and recheck freshness under the replay-reservation lock before mutation.
Changing the allowed skew requires changing that authority's policy, not the clock.

`AuthorityDeadline` captures an epoch expiry and one monotonic cap. Every retry
uses the smaller remaining interval and the original cap. A stalled wall clock
cannot extend the request; a forward wall step can end it sooner. Reads and
writes check the same deadline, including partial frames. A clock failure before
an IPC write sends no bytes.

| Consumer | Epoch domain | Local deadline domain | Failure behavior |
| --- | --- | --- | --- |
| Portable capability verification | Token seconds, converted explicitly | None | Deny evaluation |
| Keyring checkpoint and artifact time | Milliseconds | Existing service I/O deadlines | Return typed clock error |
| Response execution and durable security state | Milliseconds | Authority IPC uses a fixed monotonic cap | Refuse fresh work or reservation |
| Broker administration, capture and watermark issuance | Explicit seconds or milliseconds | Existing transport deadlines | Refuse issuance or dispatch |
| External guard cache, limiter and breaker | Clock health only | Monotonic nanoseconds | Miss, deny acquisition, or remain open |
| Financial lifecycle and Finding admission | Seconds | None | Reject freshness evaluation |
| FROST coordination | Milliseconds | None | Refuse control operation |

The original portable, keyring and external-guard clock traits are removed.
Other migrated adapters re-export this same trait. Durable Finding status time
also checks its authenticated database floor before returning a native reading.

Kernel aggregate issuance and its validators, finding-pool decisions, governed
active-response execution, child receipts and security-release acknowledgments
share the kernel's fenced authority clock. Release acknowledgments resample it
after callbacks. SQLite receipt writers, checkpoints, retention, finding payloads
and operator payment stores accept explicit clocks. Joint revocation uses the
admission store's durable time floor, including after restart. Relocation checks
time again after verifier callbacks and before replacing lock artifacts.

Process-host composition passes its clock to durable admission, policy-backed
issuance, keyring issuance and storage, native broker routes, source import,
swarm orchestration, reputation scoring and its storage owners, and evidence export.
Remote issuance probes this clock before sending the mutating RPC, then samples
it again when validating the response. Native convenience constructors delegate
to explicit-clock variants. Supplying a service clock must never select a fresh
native adapter inside that owner.

The repository-wide migration remains incomplete. The clock gate derives scope
from complete crates in the trust-boundary and TCB-library catalogs. Its October 2
base-source scan found 471 observations, including 317 omitted by the old scanner.
The immutable `clock-scope-evidence-2026-10-02.json` retains their provenance at
`491f585e9013dcb6335589c82d00ac219efbf0a6`. These are measurements of pre-existing
source, not newly introduced bypasses or completed migrations.

`scripts/security-clock-inventory.json` separates legacy debt, newly covered
pre-existing debt and exact native composition functions. Counts include fixtures
and cannot be reported as counts of production defects. Debt cannot exceed the
pinned source evidence; `--ratchet` only removes debt. New native compositions
require separate reviewed source contracts in `security_clock_compositions.py`.
The two native receipt-writer test constructors remain explicit fixture compositions.
No entire crate or source file is exempted as a composition boundary. The scanner
recognizes aliases, function references, epoch elapsed calls, native adapters and
time-returning traits and SQL clock functions in Rust string literals, including
escaped quoted SQLite time arguments. This lexical gate is a review tripwire,
not semantic proof that every time-dependent decision uses the intended owner.

Receipt identifier scopes have no time authority. Kernel admission, capability
issuance and SQLite commits read their explicitly supplied clock even while a
receipt identifier scope is active. Runtime harnesses pass the same fixed epoch
to both kernel construction and `SqliteAuthorityStore::open_serving_with_clock`.
Test fixtures inject a clock from `chio-test-support`; changing that fixture
clock cannot change an owner constructed with the production clock.

Finding challenge ingress samples filing time immediately before coordinator
submission, after collecting the untrusted body and waiting for a blocking
worker. An earlier availability probe cannot serve as the filing timestamp.

An MCP clock failure before background evaluation leaves the work queued. Once
kernel evaluation has started, errors become retained terminal task results;
the edge does not automatically retry them because effects or authority
consumption may already have occurred. After recovery, the client can collect
that result and submit fresh authorized work on the same session.

Public capability-response validators now take an explicit `UnixMillis` reading as
the final argument. Embedding services must supply their fenced authority time.
Checkpoint owners use `CheckpointSigningContext` and the `_at` builder variants;
the original checkpoint builder names remain native convenience APIs.
