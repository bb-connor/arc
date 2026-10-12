# Security alert delivery

This contract applies to the `ProductionActiveDefenseHost` library. It does not
claim that a shipped binary has installed the host, configured a production
SIEM backend, or passed native deployment qualification.

## Durable admission and delivery

An escalation effect or scheduler page first records an alert in the SQLite
outbox. That admission is durable, but it is not confirmation from an operator's
SIEM. The response worker delivers at most 16 due rows per pass, on its configured
tick cadence. Missed cadences are skipped and delivery passes do not overlap.

Each configured backend must confirm a row before the row becomes delivered.
Confirmations persist separately, so a retry skips backends that have already
confirmed. Delivery is at least once: cancellation or a lost acknowledgement can
cause a resend with the same deduplication key. Backend implementations must
honor that key and must avoid blocking in their asynchronous dispatch future.

The worker awaits backend calls alongside response ticks. Synchronous delivery
queries and writes use its runtime's managed blocking pool. Started storage
operations retain delivery custody until they finish, including after an await
is cancelled. Runtime teardown drains those operations before releasing the
worker's thread ownership. No delivery task is detached from that lifetime.

The row limit bounds dispatch count, not SQLite scan cost or backend duration.
Integrity checks remain enabled. Synchronous public readiness and admission
operations can wait on their storage; this is not a blanket latency guarantee
for every host API or an unavailable underlying filesystem.

## Health and readiness

`ResponseWorkerHealth::security_alert_delivery` reports completed passes,
delivered rows, failed attempts, pending and parked rows from the last completed
pass, and its last storage, clock, integrity or panic error. A failed pass keeps
the error until a later successful pass clears it. A panic uses a fixed health
message rather than its payload. The release profile uses unwinding, which is
required for this isolation; process aborts are not recoverable panics.

A backend outage retries under the existing outbox backoff. Host readiness
reports an exhausted-alert error when a row has used its attempt budget, or a
delivery error after an internal delivery failure. These failures do not stop
independent containment expiry or response recovery. Worker readiness and host
delivery readiness are separate observations.

Parked rows remain parked after restart, including when configuration raises
the maximum attempt count. Their durable count is checked by host readiness.
Restarting the service does not clear that condition.

## Operator response

1. Preserve the outbox and inspect the delivery health, backend configuration,
   and provider-side result for the affected deduplication key. Treat alert
   payloads as security evidence and keep them within the incident's access
   controls.
2. Repair backend connectivity or credentials through the deployment's existing
   operational process. Pending rows retry automatically. Check both backend
   confirmation and a successful delivery pass before declaring recovery.
3. Route an exhausted critical alert through the incident-response process and
   retain the parked row. This release has no supported requeue or discard API.
   Readiness stays closed for that row; a reviewed recovery mechanism is still
   needed to clear it. Do not delete or rewrite evidence to manufacture readiness.

The absence of a supported parked-row recovery API is an explicit operational
limit. Local tests of delivery and recovery do not establish production SIEM
acceptance or authorize rollout.
