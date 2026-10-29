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

Caller scopes (39):

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
root-exchange:sign         scim:write                 settlement:write
```

A credential naming `root-exchange:sign` loads, but no route accepts it until
the root-exchange signing route exists.

Peer scopes, valid only on `[[cluster.peers]]`: `cluster:replicate` and
`cluster-openings:replicate`. A peer that holds `cluster:replicate` must also
hold `cluster-openings:replicate`: replication starts from the full cluster
snapshot, which carries receipt openings, so a peer without that scope could
never finish its first sync. Loading refuses such a peer with
`PeerSnapshotScopeMissing`.

## Role presets

`chio trust config credential --role <ROLE>` writes a credential with its
role's kind and exactly these scopes. Each preset holds only the scopes of the
routes that role calls.

| Role | Kind | Scopes |
|---|---|---|
| `kernel-host` | `deployment` | `admission-authority:write`, `authority:read`, `budgets:read`, `budgets:write`, `capabilities:issue`, `lineage:write`, `receipt-openings:read`, `receipts:append`, `receipts:read`, `reports:read`, `revocations:read`, `revocations:write` |
| `operator` | `caller` | `admin:emergency`, `authority:admin`, `certifications:read`, `certifications:write`, `credit:read`, `credit:write`, `evidence:read`, `evidence:write`, `federation:read`, `federation:write`, `findings:read`, `findings:write`, `fiscal:read`, `fiscal:write`, `lineage:read`, `metrics:read`, `passport:read`, `passport:write`, `receipts:admin`, `receipts:read`, `registry:write`, `reports:read`, `reputation:read`, `reputation:write`, `revocations:read`, `revocations:write`, `scim:write` |
| `authority-workload` | `deployment` | `authority:read`, `capabilities:issue` |
| `tenant-reader` | `caller` | `evidence:read`, `receipts:read`, `reports:read` (requires `--tenant`) |

- A kernel host (`chio mcp serve-http`, `chio mcp serve`, `chio run`,
  `chio check`, `chio api protect` with `--control-url`) appends receipts,
  reads parent receipts and credit bonds, records capability lineage, keeps
  budgets and revocations, issues capabilities through the remote authority
  and reaches the admission authority on the internal listener. It is the
  only role that holds `receipt-openings:read`.
- An operator holds no `receipt-openings:*`, `budgets:*`,
  `admission-authority:write`, `receipts:append` or `capabilities:issue`
  scope. Its `caller` kind keeps it off every deployment-kind route.
- No preset holds `receipt-openings:erase`, `attestation:write`,
  `settlement:write` or `root-exchange:sign`. A process that needs one gets a
  credential written with `--kind` and explicit `--scope`s.

## Routes, kinds, and tenant authority

Every route has one entry in the route table: the listener that serves it, the
credential kind it accepts, the scope it requires, and its tenant rule. A
request whose method and route have no table row is refused with `404`. The
public listener answers `404` for every `/v1/` path it does not serve before
the dashboard fallback, which serves only the dashboard's static files.

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
other trust-control nodes, the kernel hosts that reach the admission authority
through `--control-internal-url` (`CHIO_CONTROL_INTERNAL_URL`), and operators.
TLS settings apply to both listeners.

## Cluster peer authentication

Clustered nodes authenticate to each other with Ed25519 signatures. Each request carries a signature by the sender's node key over:

- the scheme `chio.cluster.peer-signature.v1`
- the deployment
- the recipient node id and the sender node id
- the HTTP method, path, and query
- the SHA-256 of the raw request body
- a single-use 32-byte nonce
- `issued_at`, accepted from 60 seconds behind to 5 seconds ahead of the receiver clock. A peer clock may lead the receiver clock by at most 5 seconds; a peer leading by more is refused as stale.
- the sender's term

The receiver checks the deployment and recipient against its own configuration.
It refuses a reused nonce, an altered body, a request signed for another node
or another deployment, a stale `issued_at`, and a key that is not pinned in its
`[[cluster.peers]]`. It remembers each nonce until its `issued_at` leaves the
window, holds at most 65,536 of them, and refuses every new peer request with
503 while that store is full.

Each receiver also keeps, in its `--cluster-peer-replay-db` database, one row
per peer: the highest `issued_at` it has accepted from that peer. The row is
raised before the request is admitted, and a store that cannot be read or
raised refuses the request with 503
(`cluster peer replay high-water store is unavailable`). A restarted receiver
loads every row and refuses each request issued at or before its peer's row,
so no request an earlier process accepted is admitted again. Replay closure
across a restart does not depend on the receiver clock: it holds even when the
receiver clock steps backward across the restart.

A peer without a row (one that has not been accepted since the database was
created) is refused for every request issued at or before the receiver's
start time plus 5 seconds. A missing or reset database therefore never admits
more than that clock-based bound. Inside one process, requests from one peer
with distinct nonces in the same second are all admitted.

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
- pins a peer whose `internal_url` is a link-local or cloud metadata address
  literal (`169.254.0.0/16`, `fe80::/10`, `100.100.100.200`, `fd00:ec2::/32`),
  refused with `trust-control egress refused by the HttpEgressContract`. Its
  source is `HttpEgressError::LinkLocalDenied` (`link-local egress target
  denied: {host}`) for a link-local literal and
  `HttpEgressError::ReservedAddressDenied` (`cloud metadata egress target
  denied: {host}`) for a metadata literal outside link-local;
- sets `internal_listen` equal to `--listen`.

The service does not convert other configuration formats. Each deployment
writes its access configuration once.

## Writing the configuration

Create one credential per caller, each from the narrowest role preset that
covers what it calls:

| Caller | Credential |
|---|---|
| Kernel host (MCP edge, `chio mcp serve`, `chio run`, `chio api protect`) | `--role kernel-host` |
| MCP edge authority workload | `--role authority-workload` |
| Operator and dashboard | `--role operator` |
| Tenant reader for tenant `t` | `--role tenant-reader --tenant t` |
| Clustered node | `[cluster]` with its own `node_key_file`, plus one `[[cluster.peers]]` per other node |

Each kernel host, operator and workload gets its own secret; two credentials
never share one.

`chio trust config credential` prints one validated `[[credentials]]` entry and
computes the digest from a secret file (one trailing newline is removed) or an
environment variable:

```bash
chio trust config credential --id <ID> --deployment <D> \
  (--secret-file <PATH> | --secret-env <NAME>) \
  (--role <ROLE> [--scope <S> ...] | --kind caller|deployment --scope <S> ...) \
  [--tenant <T>]
```

With `--role`, each `--scope` adds a scope beyond the preset and a scope the
preset already holds refuses. Without a role, `--kind` and the `--scope`s
describe the whole credential.

Worked example for a single-node deployment named `prod-eu`:

```bash
{
  printf 'deployment = "prod-eu"\ninternal_listen = "127.0.0.1:8941"\n\n'
  chio trust config credential --id edge-control --role kernel-host \
    --deployment prod-eu --secret-env CHIO_CONTROL_TOKEN
  echo
  chio trust config credential --id authority-workload --role authority-workload \
    --deployment prod-eu --secret-env CHIO_REMOTE_AUTHORITY_WORKLOAD_TOKEN
  echo
  chio trust config credential --id operator --role operator \
    --deployment prod-eu --secret-file /run/secrets/operator
  echo
  chio trust config credential --id tenant-a-reader --role tenant-reader \
    --deployment prod-eu --secret-file /run/secrets/tenant-a-reader \
    --tenant tenant-a
} > /etc/chio/trust-access.toml
chmod 600 /etc/chio/trust-access.toml

chio trust config check --access-config /etc/chio/trust-access.toml
chio trust serve --listen 127.0.0.1:8940 \
  --access-config /etc/chio/trust-access.toml \
  --receipt-db /var/lib/chio/receipts.sqlite3
```

The MCP edge then authenticates with `--control-token "$CHIO_CONTROL_TOKEN"`
and `--remote-authority-workload-token`, operators pass the contents of
`/run/secrets/operator` to `chio trust` commands with `--control-token`, and
the tenant reader presents the contents of `/run/secrets/tenant-a-reader` as
its bearer.

## Private network peers and control planes

Every trust-control client, including the clients a node uses to reach its
pinned peers and the cluster leader, dials under an `HttpEgressContract` that
admits exactly its endpoints, follows no redirects, and refuses private,
loopback, link-local, unique-local and cloud metadata addresses. Loopback is
admitted only when every endpoint in the list is a loopback literal; a list that
names a loopback literal beside any other endpoint is refused at construction.
Link-local and metadata addresses are refused at construction and at connect.
A refusal aborts the request; only a transport failure moves the client to its
next endpoint.

A peer or control plane on a private network (for example inside a VPC) is
reached only through an operator allowance. Declare it in the file named by the
global `--egress-allowance-file` flag. Every command loads the file before it
runs, and every trust-control, cluster peer and adapter client it builds dials
under the loaded set. `chio finding` venue posts and `chio passport` document
fetches use raw HTTP clients outside the egress contract and ignore the file:

```toml
[[allow]]
host = "trust-b.vpc.internal"
port = 8941
cidr = "10.20.0.0/24"
```

Each entry pins one `host:port` to a CIDR. Every address that host resolves to,
public ones included, must lie inside the CIDR. The CIDR must be at least a /16
(IPv4) or /48 (IPv6), lie inside 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16,
100.64.0.0/10 or fc00::/7, and never touch link-local or a metadata range. A
host with an allowance is reached over `https` only. The file must be a regular
file of at most 64 KiB; unknown fields and invalid entries are refused at
startup. Without the flag no private address is
reachable. There is no flag that admits private or loopback peers wholesale.

`GET /v1/egress-allowances` returns `{"egressAllowanceDigest": ...}`, the
SHA-256 digest of the loaded allowance set, so operators can confirm which
allowances a node runs under. The route requires a caller credential with
`metrics:read`; `/health` does not report the digest.

## Checking a configuration

`chio trust config check --access-config <PATH>` applies the same validation as
startup and prints each credential's id, kind, scopes, and tenant authority,
followed by the pinned peers and the digest of the `--egress-allowance-file`
allowances (`egressAllowanceDigest`). It never prints secrets. Run it before every restart that changes the file.
