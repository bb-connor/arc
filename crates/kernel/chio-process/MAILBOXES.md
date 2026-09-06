# Durable process mailboxes

The optional `mailboxes` feature provides bounded local channels as native
Chio tools. The CLI process host enables it. Python, JavaScript and Rust
workers use ordinary kernel invocations, with the same capability checks,
guards, call budgets, signed receipts and durable admission as other tools.
There is no additional worker protocol method or tool dispatcher.

## Endpoint authority

Each configured channel exposes three concrete tools on server `chio-ipc`:

| Tool for channel `reviews` | Required arguments | Effect |
| --- | --- | --- |
| `send_reviews` | `message_key`, `payload` | Append one canonical JSON payload or return its existing sequence |
| `receive_reviews` | `after_sequence`, `limit` | Read up to 16 pending messages without consuming them |
| `ack_reviews` | `through_sequence` | Release pending payloads through a sequence, retaining key/hash tombstones |

Each endpoint has a separate `ToolGrant`. A producer can receive only the
send grant; a consumer can receive read and acknowledgement grants. Parents
need `delegate` to attenuate these rights to children. Possessing a send grant
authorizes writing to that channel. Payload fields cannot transfer authority
or establish a sender identity. Any authorized holder, including a parent
with broader scope, can send. The ordinary invocation receipt records the
capability used for that call.

A host that opens the server with `attest_senders` records the kernel-selected
sending process on every message. The kernel resolves the invoking capability
and subject to exactly one live process; a send from a capability bound to no
process, or to more than one, is rejected. A message key then belongs to the
process that committed it: replaying the key with the same payload from that
process returns the original sequence, while another process reusing it is a
conflict. Received messages carry the attested process id in `sender`. The
CLI host attests senders. Servers opened without a registry, and messages
stored before attestation, report `sender: null`; consumers must treat a null
sender as unattested. Attestation names the process identity the kernel
admitted, not the application code that ran inside it.

Messages and tool outputs are untrusted data and traverse native guards.
Output guards can redact message content. Applications needing exact signed
receipt evidence must retain the original `receipt_json` separately, rather
than transporting integrity metadata through sanitizable message content.

## Calls and recovery

With a privately provisioned worker client:

```python
sent = producer.invoke("handoff-1", "chio-ipc", "send_reviews", {
    "message_key": "review-1", "payload": {"text": "Review ready"},
})
received = consumer.invoke("poll-1", "chio-ipc", "receive_reviews", {
    "after_sequence": "0", "limit": 1,
})
# Persist application progress before acknowledging the consumed messages.
acknowledged = consumer.invoke("ack-1", "chio-ipc", "ack_reviews", {
    "through_sequence": "1",
})
```

Check the invocation verdict, terminal state and output status before acting
on a response. Native mailbox output is a JSON value, without an MCP content
envelope. Sequences are canonical decimal strings, starting at `"1"`; the
initial cursor is `"0"`. Unknown fields and malformed cursors are rejected.

A successful send returns `{"status":"sent","sequence":"1"}`. The message
key is channel-wide, 1-256 bytes without control characters. Its canonical
payload hash and attested sender are frozen. Repeating it with the same
payload from the same sender returns the same sequence, including `status:
"acknowledged"` after acknowledgement. A changed payload or a different sender
conflicts. Producer deduplication keys are not returned by receive.

A receive returns `status: "received"`, a `messages` array containing
`sequence`, `payload` and `sender`, and `next_sequence`. Retrying the same logical
operation recovers its original snapshot, including an empty result. After
a completed empty poll, use a new logical operation key to observe later
sends. Persist that poll identity before dispatch. A cursor below the channel's
acknowledgement watermark returns `cursor_expired`; a cursor beyond its history
is invalid. This is a non-consuming read, without blocking waits or leases.

Acknowledgement is monotonic and returns `status: "acknowledged"` with
`through_sequence`. An acknowledgement grant can discard unread messages,
and affects all consumers of that channel. It is not a per-consumer delivery
guarantee. Earlier receive operations can still replay their recorded output
after acknowledgement; releasing queue capacity is not secure erasure.

Full queues return `{"status":"full"}` without reserving a message key.
After capacity is available, a new logical send operation may try the same
message key. Replaying the completed full operation still returns full.
Exhausted lifetime quotas return `{"status":"exhausted"}`; existing message
keys remain deduplicated. Neither response is a transport failure.

The mailbox transaction and kernel outcome journal are separate commits. A
crash after a mailbox effect but before its durable kernel outcome remains
uncertain and blocks automatic redispatch. Message-key deduplication does not
authorize bypassing this boundary. Cancellation blocks process admissions
and output delivery; it does not retract messages already committed.

## Configuration and persistence

Add `"mailboxes": [{"id": "reviews"}]` to a new
[`chio.process.host.v1` configuration](../../products/chio-cli/PROCESS_HOST.md),
grant the `chio-ipc` routes in policy, and select concrete routes for each
child. A mailbox-only host may omit `servers`. When mailboxes are configured,
`chio-ipc` is reserved and cannot also name an MCP server.

There may be 1-32 channels. IDs contain 1-32 ASCII letters, digits, underscores
or hyphens. Omit `limits` for defaults, or provide all four fields:

```json
{
  "id": "reviews",
  "limits": {
    "max_pending_messages": 32,
    "max_pending_bytes": 1048576,
    "max_message_bytes": 65536,
    "max_messages": 256
  }
}
```

Pending count is 1-256, payloads are at most 64 KiB of canonical UTF-8 JSON,
and pending bytes are at most 8 MiB, at least the per-message limit. Lifetime
messages include acknowledged tombstones, are at least the pending count,
and are at most 100,000. Keys and sequences are never recycled. These limits
bound live payloads and retained identities; they do not bound receipt-journal
growth, SQLite file allocation or application checkpoint history.

The private `mailboxes.db` uses WAL, synchronous FULL and immediate write
transactions for sends and acknowledgements. Independent connections serialize
capacity checks and insertion. Reads use a consistent transaction snapshot.
The database binds its version, sorted channel configuration, qualified kernel
authority UUID and public key; incompatible opens fail. Quotas and channels
cannot change in an existing host. Preserve and restore the full consistent
host state, including kernel journals and receipts. Independent database
rollback protection and distributed migration are not provided.

## Verification

`cargo test -p chio-process --features worker-server,mailboxes` covers endpoint
isolation through the real kernel, acknowledgement and original-receipt replay,
empty-poll identity, byte and count backpressure, concurrent database writers,
key conflicts, sender attestation and key ownership across restart, unattested
sends on attesting servers, lifetime quotas, cancellation and
configuration/authority drift.
The [repository review application](../../../examples/repository-review/README.md)
exercises reader handoffs, publisher consumption and acknowledgement through
the public CLI, with worker and host crashes. Its framework owns graph joins
and worker lifecycle. These mailboxes do not supply a scheduler or OS isolation.
