# Trust-Control Access Configuration

`chio trust serve --access-config <PATH>` reads one TOML document that names
every bearer credential the service accepts, the scopes each credential holds,
the tenant each credential may act for, the internal listener, and, on
clustered nodes, the node identity and pinned peers. A request without a
matching credential, scope, and tenant authority is refused.

Clients send a bearer secret with `--control-token`, `CHIO_CONTROL_TOKEN`, or
`chio mcp serve-http --remote-authority-workload-token`. That secret is the
secret of one credential in this file.

## File format

```toml
deployment = "prod-eu"
internal_listen = "10.0.0.5:8941"

[[credentials]]
id = "control-client"
kind = "deployment"
secret_sha256 = "<64 lowercase hex: SHA-256 of the bearer secret>"
scopes = ["receipts:read", "reports:read"]
deployment = "prod-eu"
tenant_authority = "deployment"

# Clustered nodes only.
[cluster]
node_id = "https://trust-a.example:8940"
node_key_file = "/etc/chio/trust-node.seed"

[[cluster.peers]]
node_id = "https://trust-b.example:8940"
internal_url = "https://trust-b.example:8941"
public_key = "<hex Ed25519 public key of the peer>"
scopes = ["cluster:replicate", "cluster-openings:replicate"]
```

| Key | Meaning |
|---|---|
| `deployment` | Name of this deployment. Every credential must carry the same value. |
| `internal_listen` | Socket address of the internal listener. Must differ from `--listen`. |
| `credentials[].id` | Unique credential id. Appears in `chio trust config check` and names the credential in emergency stop records. |
| `credentials[].kind` | `caller` (operator or service client) or `deployment` (kernel host or control-plane service). |
| `credentials[].secret_sha256` | Lowercase hex SHA-256 of the bearer secret. The file never holds the secret. |
| `credentials[].scopes` | Caller scopes granted to the credential. |
| `credentials[].deployment` | Must equal the top-level `deployment`. |
| `credentials[].tenant_authority` | `"deployment"` or `{ tenant = "<tenant id>" }`. |
| `cluster.node_id` | This node's identity. Must equal `--advertise-url`. |
| `cluster.node_key_file` | Private Ed25519 seed file of this node. |
| `cluster.peers[]` | One entry per other node: its `node_id`, `internal_url`, hex Ed25519 `public_key`, and peer scopes. |

## Scopes

Caller scopes (38):

```text
admin:emergency            admission-authority:write  attestation:write
authority:admin            authority:read             budgets:read
budgets:write              capabilities:issue         certifications:read
certifications:write       credit:read                credit:write
evidence:read              evidence:write             federation:read
federation:write           findings:read              findings:write
fiscal:read                fiscal:write               lineage:read
lineage:write              metrics:read               passport:read
passport:write             receipt-openings:erase     receipt-openings:read
receipts:admin             receipts:append            receipts:read
registry:write             reports:read               reputation:read
reputation:write           revocations:read           revocations:write
scim:write                 settlement:write
```

Peer scopes, valid only on `[[cluster.peers]]`: `cluster:replicate` and
`cluster-openings:replicate`.

## Routes, kinds, and tenant authority

Every route has one entry in the route table: the listener that serves it, the
credential kind it accepts, the scope it requires, and its tenant rule. A route
absent from the table returns `404`.

- Deployment-kind routes refuse `caller` credentials. These are receipt append,
  budgets, capability issuance, settlement reconciliation, authority status
  read, and admission authority.
- Deployment-only routes refuse credentials with a tenant authority.
- A credential with `tenant_authority = { tenant = "t" }` acts only for tenant
  `t`, and only on the tenant-scoped routes: receipt query, receipt tools,
  agent receipts, evidence export, and the fiscal marketplace credit limit.
  Receipt children is tenant-scoped in the table, and its handler refuses
  tenant credentials until child receipts carry tenant attribution.
- A credential with `tenant_authority = "deployment"` acts for every tenant of
  the deployment.

## Internal listener

`internal_listen` binds a second listener. It serves every `/v1/internal/*`
route and nothing else. The public `--listen` listener never serves
`/v1/internal/*`. Keep the internal address on a network reachable only by
other trust-control nodes and operators. TLS settings apply to both listeners.

## Cluster peer authentication

Clustered nodes authenticate to each other with Ed25519 signatures. Each request carries a signature by the sender's node key over:

- the scheme `chio.cluster.peer-request.v1`
- the deployment
- the recipient node id and the sender node id
- the HTTP method, path, and query
- the SHA-256 of the raw request body
- a single-use 32-byte nonce
- `issued_at`, accepted within 60 seconds
- the sender's term

The receiver refuses a reused nonce, an altered body, a request addressed to
another node, a stale `issued_at`, and a key that is not pinned in its
`[[cluster.peers]]`.

Followers forward writes to the leader with the caller's own bearer secret, so
the leader applies the caller's credential, scopes, and tenant authority.
Forwarded authority mutations also carry `x-chio-forwarded-authority-term`.

## Startup refusals

`chio trust serve` refuses to start when the access configuration:

- names a removed key. A document containing `service_token`,
  `tenant_read_tokens`, or `authority_workload_token` refuses with:

  ```text
  trust-control configuration key "<key>" is removed; declare [[credentials]] entries with scopes and tenant authority instead
  ```

- grants an unknown scope, or a peer scope on a credential;
- repeats a credential id;
- gives two credentials the same `secret_sha256`;
- holds a credential whose `deployment` differs from the top-level value;
- declares `[[cluster.peers]]` without a `[cluster]` identity;
- sets `internal_listen` equal to `--listen`.

The service does not convert other configuration formats. Each deployment
writes its access configuration once.

## Writing the configuration

Create one credential per caller role:

| Caller role | Credential |
|---|---|
| Administrative control client | `kind = "deployment"`, every caller scope (`--all-caller-scopes`), `tenant_authority = "deployment"` |
| MCP edge authority workload | `kind = "deployment"`, `authority:read` and `capabilities:issue` |
| Tenant reader for tenant `t` | `kind = "caller"`, `receipts:read`, `reports:read`, and `evidence:read`, `tenant_authority = { tenant = "t" }` |
| Clustered node | `[cluster]` with its own `node_key_file`, plus one `[[cluster.peers]]` per other node |

Tenant readers need `evidence:read` to export evidence.

`chio trust config credential` prints one validated `[[credentials]]` entry and
computes the digest from a secret file (one trailing newline is removed) or an
environment variable:

```bash
chio trust config credential --id <ID> --kind caller|deployment \
  --deployment <D> (--secret-file <PATH> | --secret-env <NAME>) \
  (--scope <S> ... | --all-caller-scopes) [--tenant <T>]
```

Worked example for a single-node deployment named `prod-eu`:

```bash
{
  printf 'deployment = "prod-eu"\ninternal_listen = "127.0.0.1:8941"\n\n'
  chio trust config credential --id control-client --kind deployment \
    --deployment prod-eu --secret-env CHIO_CONTROL_TOKEN --all-caller-scopes
  echo
  chio trust config credential --id authority-workload --kind deployment \
    --deployment prod-eu --secret-env CHIO_REMOTE_AUTHORITY_WORKLOAD_TOKEN \
    --scope authority:read --scope capabilities:issue
  echo
  chio trust config credential --id tenant-a-reader --kind caller \
    --deployment prod-eu --secret-file /run/secrets/tenant-a-reader \
    --scope receipts:read --scope reports:read --scope evidence:read \
    --tenant tenant-a
} > /etc/chio/trust-access.toml
chmod 600 /etc/chio/trust-access.toml

chio trust config check --access-config /etc/chio/trust-access.toml
chio trust serve --listen 127.0.0.1:8940 \
  --access-config /etc/chio/trust-access.toml \
  --receipt-db /var/lib/chio/receipts.sqlite3
```

The control client then authenticates with
`--control-token "$CHIO_CONTROL_TOKEN"`, the MCP edge with
`--remote-authority-workload-token`, and the tenant reader with the contents of
`/run/secrets/tenant-a-reader` as its bearer.

## Checking a configuration

`chio trust config check --access-config <PATH>` applies the same validation as
startup and prints each credential's id, kind, scopes, and tenant authority,
followed by the pinned peers. It never prints secrets. Run it before every restart that changes the file.
