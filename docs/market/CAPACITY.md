# Cognition Market Capacity Model

Every ceiling the market enforces is here, with what it bounds, what a
caller sees when it binds, and what to change when it binds too early. A
ceiling absent from this page is a bug in this page.

The market fails closed at every one of them. Reaching a ceiling refuses
work; it never degrades a guarantee.

## Per-tenant admission

| Ceiling | Value | Set by |
| --- | --- | --- |
| Live proof nonces | caller-supplied, `1..=10_000_000` | operator, per admission call |
| Retained request admissions | 64 per live-proof slot | `RETAINED_BINDINGS_PER_NONCE_SLOT` |
| Expiry sweep cadence | 3600s, or on capacity pressure | `DPOP_SWEEP_INTERVAL_SECS` |

A tenant's live-proof capacity is the operator's sizing decision and is
passed on every admission. It bounds unexpired DPoP proofs, not requests:
a proof lives for its own short TTL, so this is a burst bound rather than a
rate.

Retained request admissions are what lets an interrupted mutation be
retried without spending a second invocation. They outlive the proofs that
recorded them, so they carry their own ceiling at 64 per proof slot. The
factor is headroom for the ratio between a capability's lifetime and a
proof's: a capability outliving its proofs by roughly ten to one leaves
room to spare. A tenant that reaches it is refused with a capacity error
rather than having a recorded admission evicted, because evicting one
would break the retry it exists to serve.

**When it binds too early:** raise the tenant's live-proof capacity, which
raises the binding ceiling proportionally. If admissions are refused while
the sweep shows most bindings expired, shorten the capability TTL rather
than raising the ceiling.

## Per-tenant spend

| Ceiling | Value | Set by |
| --- | --- | --- |
| Monthly spend units | per tenant, `1..=2^53-1` | `HostedTenantLimits` |
| Concurrent jobs | per tenant, `1..=1024` | `HostedTenantLimits` |
| Queued jobs | per tenant | `HostedTenantLimits` |

The monthly ceiling is enforced inside the same statement that inserts a
reservation, by a trigger the runtime role cannot bypass: the runtime holds
no write privilege on the accumulator, and a charged reservation's units
are immutable once written. An accumulator that underflows denies rather
than clamping, because nothing re-derives it at runtime.

**When it binds too early:** raise `max_monthly_spend_units` for the
tenant. Do not repair the accumulator by hand; it is derived state and a
manual write is the thing the privilege model exists to prevent.

## Hosted edge

| Ceiling | Value | Set by |
| --- | --- | --- |
| In-flight requests per replica | 1024 | `MAX_CONCURRENT_REQUESTS` |
| Request body | 4 MiB | `MAX_HTTP_BODY_BYTES` |
| Readiness answer lifetime | 1s | `READINESS_ANSWER_LIFETIME` |

A request that cannot take a permit is shed with a retryable error
carrying the caller's request id, so the trusted proxy retries against
another replica rather than queueing here. Liveness and readiness answer
outside that limiter, and readiness additionally answers from an answer at
most a second old with one backend check in flight at a time, so probe
traffic cannot become a database round trip per request.

**When it binds too early:** add replicas before raising the in-flight
ceiling. The ceiling exists so one replica sheds rather than exhausting the
connection pool it shares with every other request.

## Single-operator profile

| Ceiling | Value | Set by |
| --- | --- | --- |
| Concurrent discovery reads | 8 | `MAX_READ_COMPANIONS` |
| Concurrent writers | 1 | the serving-owner lease |

Discovery reads lease a read-only companion connection from a bounded
pool, so they neither queue behind a write transaction nor behind each
other. A ninth concurrent reader waits for a lease to return rather than
opening a connection past the bound.

One writer is not a tuning parameter. The serving owner holds the lease
that makes this process the authority, and the rollback anchor is what
proves the database has not moved underneath it.

**When it binds too early:** the single-operator profile is sized for one
operator. A deployment that needs more concurrent writers wants the hosted
PostgreSQL profile, not a larger bound here.

## Changing a ceiling

Ceilings that belong to a tenant are configuration and move per tenant.
Ceilings that are constants are deliberate: each one bounds a resource
shared by every caller, and raising one moves the failure from a refused
request to an exhausted pool, a full disk, or an unbounded queue. Change
one only with the measurement that shows the resource it protects has room.
