# Operator approvals for hosted MCP

This requires the candidate kernel containing `BoundToolInvocation` and the hosted
operator approval routes. The original public CLI 0.1.0 does not provide this
contract. Keep the operator credential outside the agent environment. Configure
durable kernel admission, session and authority databases, and an explicit admin
token distinct from the session admission token. Configure `--approval-config`
with the tenant, explicit approver public-key roster and an already activated
durable replay-source binding. Source provisioning, import and activation are
separate offline operator actions. An absent configuration disables this approval
flow; neither a capability issuer nor the kernel receipt signer is an implicit
approver.

The adjacent `approval-policy.yaml` combines one finite wildcard grant with
confirmation required for all four supported tools. That form retains one
shared invocation budget. To require confirmation only for selected tools,
use exact explicit tool grants; their invocation budgets are separate. A
confirmation pattern narrower than an explicit wildcard grant is rejected
because a single grant cannot encode that distinction safely.

The operator records a proposed call before its first dispatch. A pending record
does not perform the tool action. Approval signs permission to submit that exact
call; it also does not perform the action. The agent then uses the normal kernel
`tools/call` path, which rechecks capability, scope, expiry, revocation, policy,
budgets, approval and durable admission. A denied decision is terminal. Retrying a
denied operation under its original request ID cannot convert it to approved work.

Create a private proposal JSON using the already initialized host session and its
capability ID:

```json
{
  "session_id": "operator-prepared-session",
  "capability_id": "session-capability",
  "request_id": "unique-logical-operation",
  "tool_name": "write_file",
  "arguments": {"path": "/workspace/change.txt", "content": "reviewed content"},
  "purpose": "Write the reviewed change",
  "ttl_seconds": 300
}
```

Use `operator_approval.py submit --operator-file <private-operator.json>
--proposal-file <proposal.json> --output <new-pending.json>`. The helper prints the
approval ID and stores the complete response in a new mode-0600 file. Use `show`
with `--approval-id` and a new `--output` path. For `approve` or `deny`, also
provide `--decision-token-file <private-signed-token.json>`. The file must contain
a `GovernedApprovalToken` signed by an operator key in the configured roster. Its
token ID is `<record.id>-decision`; copy the exact record subject, request ID and
the result of `record.intent.binding_hash()`. Set its `decision` to `approved` or
`denied`, and choose an issuance time at or after record creation and an expiry no
later than the record deadline. The helper checks the action, record ID, bounded
shape and lifetime before network access; the server verifies the signature and
current authority. The helper does not create or hold an approver private key.

The helper never prints the admin bearer. `operator.json` contains `adminToken`
and local `port`; optional `--base-url` supports another HTTPS or loopback HTTP
origin.

The corresponding routes are:

- `POST /admin/approvals` with the proposal above.
- `GET /admin/approvals/{id}` to recover a pending or decided record.
- `POST /admin/approvals/{id}/decision` with `{"token": <signed GovernedApprovalToken>}`.

All routes require `Authorization: Bearer <operator-token>`. Duplicate submission
for a session/request returns 409. Repeating the exact signed decision returns the
same artifact while it is current; replacing a terminal token returns 409. A pending record cannot be
approved after its deadline. The deadline is capped by the capability expiry and
never exceeds 3,600 seconds.

The decided response includes `toolCallParams` with the exact arguments and
`_meta.chioRequestId`, `_meta.chioGovernedIntent`, and `_meta.chioApprovalToken`.
Submit those unchanged through the host's supported Chio execution tool. The
typed intent binds the exact capability ID and SHA-256 of canonical arguments;
the shared approval context also binds the complete signed capability, configured
tenant, request ID and exact installed kernel policy hash. The signed token binds
the caller subject, request ID and complete intent. Changing arguments, capability,
caller, request, tenant or policy invalidates admission.

A roster signature alone does not authorize execution. Every ordinary signed-token
`tools/call` must match the current retained Approved decision and its exact token
at the shared MCP session ingress. Pending, Denied, missing or expired records
refuse before dispatch, including direct native session calls. Conflicting ordinary
metadata aliases also refuse. Independent threshold collection protocols retain
their separate policy-owned admission requirements.

Approval records and decisions survive restart in the session database and carry
an integrity signature under the durable kernel identity; the decision itself
retains the operator's distinct signature. Keep that database and
the durable admission identity together during recovery. The approval endpoint
does not report execution outcome: inspect the normal signed execution receipt
and durable admission record. An approved token is not evidence that a resource
effect happened. When an outcome is unknown after dispatch, retain its request ID
and use kernel recovery; never mint a new request to silently redispatch it.

The historical `shared_kernel.py` approval, approved-budget and approved-unknown
workflows currently report `unavailable` before constructing a runtime. The
driver must be migrated to accept an externally provisioned activated replay
binding, an external signer, a publisher-signed manifest and current native cage
launch authorization. It does not create keys, activate a source or submit
unsigned decisions. Selecting only those cases records unavailable evidence
without invoking Docker or the candidate. Native Rust MCP tests cover the current
consumer contract; Docker approval acceptance remains outstanding. Historical
runs that submitted unsigned decisions do not qualify this contract. Every host
must separately demonstrate approved execution, denial and missing approval.

The private operator commands share the redirect-refusing, proxy-independent
transport described in [OPERATOR-CAPABILITIES.md](OPERATOR-CAPABILITIES.md).
Use the trusted final HTTPS or loopback origin directly. Preserve the private
output and reconcile ambiguous mutation outcomes before another decision; the
helper does not retry automatically.
