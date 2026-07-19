# Progressive Chio Tutorial

This tutorial takes the shortest honest path from "what is Chio?" to "I made a
governed call and I understand how delegation continues from here."

It uses the signed Docker demo stack so the same local deployment can back the
tutorial, the SDK examples, and the receipt viewer.

## 1. Chio Concepts

Chio sits between an agent client and the tools it wants to call.

- Policies define what can be issued.
- Capabilities bind those permissions to a subject and a TTL.
- The hosted edge mediates tool calls and issues receipts.
- The trust service stores receipts, revocations, lineage, and query APIs.
- Delegation narrows or continues authority rather than minting unbounded new
  power.

For the local demo, the trust service and hosted edge are separate processes:

- `chio trust serve` owns receipt, revocation, and authority state
- `chio mcp serve-http` exposes an MCP endpoint and asks the trust service to
  issue and record governed capabilities

## 2. Start The Demo Stack

From the repo root:

```bash
export CHIO_AUTH_TOKEN="$(openssl rand -hex 32)"
export CHIO_ADMIN_TOKEN="$(openssl rand -hex 32)"
export CHIO_SERVICE_TOKEN="$(openssl rand -hex 32)"
export CHIO_DASHBOARD_READ_TOKEN="$(openssl rand -hex 32)"
test "${CHIO_AUTH_TOKEN}" != "${CHIO_ADMIN_TOKEN}"
test "${CHIO_AUTH_TOKEN}" != "${CHIO_SERVICE_TOKEN}"
test "${CHIO_ADMIN_TOKEN}" != "${CHIO_SERVICE_TOKEN}"
test "${CHIO_DASHBOARD_READ_TOKEN}" != "${CHIO_AUTH_TOKEN}"
test "${CHIO_DASHBOARD_READ_TOKEN}" != "${CHIO_ADMIN_TOKEN}"
test "${CHIO_DASHBOARD_READ_TOKEN}" != "${CHIO_SERVICE_TOKEN}"
docker compose -f examples/docker/compose.yaml up -d --build --wait --wait-timeout 180
```

That publishes two loopback-only endpoints used throughout the rest of this
tutorial:

- hosted edge: `http://127.0.0.1:8931`
- trust service and receipt viewer: `https://127.0.0.1:8940`

The stack has no default credentials. `CHIO_AUTH_TOKEN` authenticates ordinary
hosted-edge calls, `CHIO_ADMIN_TOKEN` authenticates edge administration,
`CHIO_SERVICE_TOKEN` authenticates the trust-control service, and
`CHIO_DASHBOARD_READ_TOKEN` is exchanged once for a short-lived dashboard
cookie. Keep all four pairwise-distinct values in the current shell until
teardown and do not commit them to an environment file.

The stack provisions a private demo CA in a one-shot container. Its signing key
is never mounted into the TLS proxy, hosted edge, or trust service. The smoke
client copies only the public CA certificate and uses it as an exclusive trust
root. The trust service remains on a dedicated internal HTTP network; the
hosted edge is not attached to that network and reaches it only through the
final HTTPS proxy.

## 3. Write A Policy

Chio policies describe what the hosted edge may issue when a session starts.
The demo policy is intentionally small:

```yaml
kernel:
  max_capability_ttl: 3600
  delegation_depth_limit: 5

capabilities:
  default:
    tools:
      - server: "*"
        tool: "*"
        operations: [invoke]
        ttl: 300
```

This means:

- session capabilities may last up to five minutes
- the hosted edge may issue tool-call authority
- the tool permissions are rooted in the trust service rather than trusted
  implicitly at the client

You can save this as `tutorial-policy.yaml` or reuse
[examples/docker/policy.yaml](../../examples/docker/policy.yaml).

## 4. Inspect The Signed Tool Boundary

The upstream demo tool is a tiny MCP server that exposes `echo_text`:
[examples/docker/mock_mcp_server.py](../../examples/docker/mock_mcp_server.py).

Before either service starts, `chio-security-init` reviews
`examples/docker/tools.json` and transactionally creates:

- a strict signed `chio.manifest.v2`
- an independently signed native launch policy
- exact verifier public keys
- a canonical full target argv
- a signed generation-zero enterprise migration ledger

The hosted edge validates those inputs, the exact current trust-control
authority, the executable path, and the full argv before it starts the upstream
tool. The demo ledger is deliberately at `Disabled`: it authorizes the signed
legacy launch, but it does not claim cage containment. Production containment
requires `Enforced` or `LegacyRemoved` plus successful designated Linux cage
evidence.

The initializer destroys the manifest, policy, and migration signing seeds
after exporting the runtime material. Public artifacts are mounted read-only.
The edge keeps its runtime secrets in a root-owned private volume, while a fixed
digest-verifying launcher erases the child environment and drops the demo tool
to UID/GID 10002. That privilege split protects demo credentials, but it does
not turn the `Disabled` migration stage into cage containment.

## 5. Execute A Governed Call

The fastest end-to-end check is the host-side smoke client:

```bash
CHIO_EDGE_TOKEN="${CHIO_AUTH_TOKEN}" \
CHIO_ADMIN_TOKEN="${CHIO_ADMIN_TOKEN}" \
CHIO_DASHBOARD_READ_TOKEN="${CHIO_DASHBOARD_READ_TOKEN}" \
  python3 examples/docker/smoke_client.py
```

The output includes:

- `sessionId`
- `capabilityId`
- the tool inventory returned by the hosted edge
- the governed tool result
- `receiptId`

That single run proves the whole chain:

1. session initialization
2. capability issuance
3. governed tool execution
4. receipt persistence

## 6. Read A Receipt

The smoke client already resolves the receipt, but it helps to see the raw
query shape as well:

```bash
docker compose -f examples/docker/compose.yaml cp \
  chio-trust-tls:/var/lib/chio-tls-public/demo-ca.pem \
  ./demo-ca.pem
curl \
  --cacert ./demo-ca.pem \
  -H "Authorization: Bearer ${CHIO_SERVICE_TOKEN}" \
  "https://127.0.0.1:8940/v1/receipts/query?capabilityId=<capability-id>&limit=10"
rm ./demo-ca.pem
```

Browser access requires importing the private demo CA into a dedicated browser
trust store. Open the trust-service origin and exchange
`CHIO_DASHBOARD_READ_TOKEN` through the login form. The resulting host-only
cookie is short-lived and inaccessible to JavaScript. Do not place any
credential in a URL or browser storage.

If you need the capability attached to a hosted session, query the hosted edge:

```bash
curl \
  -H "Authorization: Bearer ${CHIO_ADMIN_TOKEN}" \
  "http://127.0.0.1:8931/admin/sessions/<session-id>/trust"
```

That response is what the framework examples use before querying the trust
service for receipts.

## 7. Delegate A Capability

The concrete public delegation lane in the current CLI is the federated
continuation workflow. The local hosted-session demo above gives you the mental
model; the child-capability continuation happens with a signed delegation
policy plus a federated issue step that binds the new local authority to an
upstream capability ID.

The relevant commands are:

```bash
chio trust federated-delegation-policy-create \
  --output delegation-policy.json \
  --signing-seed-file authority-seed.txt \
  --issuer local-org \
  --partner remote-org \
  --verifier https://trust.example.com \
  --capability-policy examples/policies/federated-parent.yaml \
  --parent-capability-id cap-upstream \
  --expires-at 1900000000

chio \
  --control-url https://trust.example.com \
  --control-token <service-token> \
  trust federated-issue \
  --presentation-response response.json \
  --challenge challenge.json \
  --capability-policy examples/policies/federated-child.yaml \
  --delegation-policy delegation-policy.json \
  --upstream-capability-id cap-upstream
```

What this does:

- the delegation policy narrows and signs what may continue downstream
- `--upstream-capability-id` binds the child issuance to a real parent
- the trust service records a delegation anchor so lineage and receipts can
  explain where the child authority came from

For a fuller walkthrough of the federated inputs, see
[docs/AGENT_PASSPORT_GUIDE.md](../reference/AGENT_PASSPORT_GUIDE.md).

## 8. Run The Framework Examples

With the demo stack still running, the framework examples all target the same
defaults:

- [examples/anthropic-sdk/README.md](../../examples/anthropic-sdk/README.md)
- [examples/langchain/README.md](../../examples/langchain/README.md)
- [examples/openai-compatible/README.md](../../examples/openai-compatible/README.md)

They all:

- initialize a hosted Chio session
- list tools through the official Chio SDK
- perform a governed `echo_text` call
- resolve the resulting receipt through the trust service

That is the stable baseline for integrating Chio into higher-level agent
frameworks.
