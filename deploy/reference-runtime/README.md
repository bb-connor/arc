# Chio reference runtime: supervision package

systemd units, service accounts and directory declarations for running the
Chio security runtime on one Linux host: the trust-control service, the
remote MCP edge that wraps one MCP server under a signed native-launch
policy, and the key-log witness and audit daemons of the keyring
composition.

Every unit is `Type=notify` and starts through `chio security supervise`,
which delivers secrets from the manager's credentials directory, reports
readiness only once the service answers, forwards stop signals so the
service drains, and ends with the service's own exit status. Secrets never
enter an environment file or an argument list; the environment file of the
edge carries only public pins and the wrapped command.

## Layout

| Path | Purpose |
|------|---------|
| `systemd/chio-trust-control.service` | trust-control on `127.0.0.1:8940`, readiness on `/health` |
| `systemd/chio-mcp-edge.service` | remote MCP edge on `127.0.0.1:8931`, preflight with `--require-enforcement`, readiness on `/admin/health` |
| `systemd/chio-keylog-witness@.service` | key-log witness instance (`a`, `b`, `c`) |
| `systemd/chio-keylog-audit@.service` | key-log audit monitor instance (`a`, `b`) |
| `sysusers.d/chio.conf` | the `chio-trust`, `chio-edge` and `chio-keylog` accounts |
| `tmpfiles.d/chio.conf` | `/etc/chio` and the credential, launch and keylog directories |
| `env/chio-mcp-edge.env.example` | public pins and the wrapped command for the edge |
| `keylog/witness-a.json.example`, `keylog/audit-a.json.example` | service configs for one witness and one monitor |

The structural gate `cargo test -p chio-cli --test reference_runtime_units`
checks every unit against the built `chio` binary: each command and flag the
units use exists, credentials are declared and consumed on both sides,
environment references are declared in the template, accounts exist in
`sysusers.d`, dependencies name units in this package, the hardening
baseline is present, and the keylog example configs agree with the units.

## Install

1. Build and install the binaries.

   ```bash
   cargo build --release -p chio-cli -p chio-keyring
   install -m 0755 target/release/chio /usr/local/bin/chio
   install -m 0755 target/release/chio-keylog-witness /usr/local/bin/chio-keylog-witness
   install -m 0755 target/release/chio-keylog-audit /usr/local/bin/chio-keylog-audit
   ```

2. Create the accounts and directories, then install the units.

   ```bash
   install -m 0644 deploy/reference-runtime/sysusers.d/chio.conf /etc/sysusers.d/chio.conf
   install -m 0644 deploy/reference-runtime/tmpfiles.d/chio.conf /etc/tmpfiles.d/chio.conf
   systemd-sysusers chio.conf
   systemd-tmpfiles --create chio.conf
   install -m 0644 deploy/reference-runtime/systemd/*.service /etc/systemd/system/
   systemctl daemon-reload
   ```

3. Create the credentials as root under `/etc/chio/credentials` (mode 0600).
   The manager reads them and exposes each one to its service alone. Every
   bearer must be distinct: the edge refuses a launch whose roles share a
   value, and the preflight reports that before the launch.

   ```bash
   umask 077
   for name in trust-service-token trust-authority-workload-token edge-session-token edge-admin-token; do
     openssl rand -base64 33 | tr -d '\n' > /etc/chio/credentials/$name
   done
   ```

   The edge presents the trust service token as its control token and the
   trust authority workload token as its workload token, so those two
   credentials are copies:

   ```bash
   cp /etc/chio/credentials/trust-service-token /etc/chio/credentials/edge-control-token
   cp /etc/chio/credentials/trust-authority-workload-token /etc/chio/credentials/edge-workload-token
   ```

   Write the resume keyring with the helper from `scripts/lib/provision-mcp-launch.sh`:

   ```bash
   . scripts/lib/provision-mcp-launch.sh
   chio_write_resume_hmac_keyring /etc/chio/credentials/edge-resume-hmac-keyring.json
   ```

   A credential is delivered exactly as written except that one trailing
   newline is removed; any other padding or control character fails the
   launch.

4. Start trust-control and pin its authority key.

   ```bash
   systemctl enable --now chio-trust-control.service
   curl -s -H "Authorization: Bearer $(cat /etc/chio/credentials/trust-service-token)" \
     http://127.0.0.1:8940/v1/authority | jq -r .publicKey
   ```

   The key is stable across restarts because the unit runs with
   `--authority-db`. Put it in `CHIO_CONTROL_AUTHORITY_PUBLIC_KEY` of the edge
   environment file; the edge refuses any other current authority key.

5. Provision the edge's launch material as root, then expose the public
   artifacts to the edge account. The provisioner binds the wrapped
   executable's digest, its arguments and its working directory; the
   environment file must carry exactly the same command.

   ```bash
   chio security provision-native-mcp-demo \
     --output-dir /etc/chio/mcp-edge/provision \
     --discover-tools \
     --target /usr/local/libexec/chio/mcp-upstream \
     --working-directory /var/lib/chio-mcp-edge \
     --execution-uid "$(id -u chio-edge)" --execution-gid "$(id -g chio-edge)" \
     --server-id chio-mcp-edge --server-name "Chio MCP edge" --server-version 1
   install -m 0640 -g chio-edge \
     /etc/chio/mcp-edge/provision/security/{signed-manifest.json,cage-launch-policy.json,enterprise-migration.sqlite3,cage-migration-genesis.json,reviewed-tools.json,target-command} \
     /etc/chio/mcp-edge/launch/
   install -m 0640 -g chio-edge /etc/chio/mcp-edge/provision/security/*-public-key \
     /etc/chio/mcp-edge/provision/security/cage-policy-signer /etc/chio/mcp-edge/launch/
   install -m 0640 -g chio-edge deploy/reference-runtime/env/chio-mcp-edge.env.example \
     /etc/chio/mcp-edge/chio-mcp-edge.env
   install -m 0640 -g chio-edge your-policy.yaml /etc/chio/mcp-edge/policy.yaml
   ```

   The signer seeds stay in the root-only provisioning directory. Fill the
   environment file from `launch/manifest-public-key`, `launch/cage-policy-signer`
   and the authority key above. The provisioner writes migration stage
   Disabled, which authorizes without confining; the edge unit's preflight
   runs with `--require-enforcement` and refuses that material, so an
   enforcing provisioning stage is required before the unit starts. Run the
   preflight by hand to see every finding:

   ```bash
   systemd-run --wait --pipe --collect -p LoadCredential=session-token:/etc/chio/credentials/edge-session-token \
     -p LoadCredential=admin-token:/etc/chio/credentials/edge-admin-token \
     -p LoadCredential=control-token:/etc/chio/credentials/edge-control-token \
     -p LoadCredential=workload-token:/etc/chio/credentials/edge-workload-token \
     -p EnvironmentFile=/etc/chio/mcp-edge/chio-mcp-edge.env -p User=chio-edge \
     /usr/local/bin/chio security supervise --exec \
       --credential-env CHIO_AUTH_TOKEN=session-token --credential-env CHIO_ADMIN_TOKEN=admin-token \
       --credential-env CHIO_CONTROL_TOKEN=control-token --credential-env CHIO_REMOTE_AUTHORITY_WORKLOAD_TOKEN=workload-token \
       -- /usr/local/bin/chio --session-db /var/lib/chio-mcp-edge/sessions.sqlite3 security preflight --require-enforcement \
       --signed-manifest /etc/chio/mcp-edge/launch/signed-manifest.json --manifest-public-key "$CHIO_MANIFEST_PUBLIC_KEY" \
       --cage-policy /etc/chio/mcp-edge/launch/cage-launch-policy.json --cage-policy-signer "$CHIO_CAGE_POLICY_SIGNER" \
       --server-id chio-mcp-edge -- /usr/local/libexec/chio/mcp-upstream
   ```

6. Start the edge.

   ```bash
   systemctl enable --now chio-mcp-edge.service
   systemctl status chio-mcp-edge.service
   ```

   The unit is active only after `/admin/health` answers the admin bearer.
   A failed preflight leaves the unit failed with the preflight report in
   the journal.

7. Key-log services, when the keyring composition is in use. Author the
   key-log policy per `crates/security/chio-keyring/README.md` and install it
   as `/etc/chio/keylog/policy.json`. Each instance needs a 32-byte seed
   credential and a config:

   ```bash
   for instance in a b c; do
     head -c 32 /dev/urandom > /etc/chio/credentials/keylog-witness-$instance.seed
     sed "s/witness-a/witness-$instance/g; s/witness@a/witness@$instance/g; s/\"witness_id\": \"a\"/\"witness_id\": \"$instance\"/" \
       deploy/reference-runtime/keylog/witness-a.json.example > /etc/chio/keylog/witness-$instance.json
   done
   for instance in a b; do
     head -c 32 /dev/urandom > /etc/chio/credentials/keylog-audit-$instance.seed
     sed "s/audit-a/audit-$instance/g; s/audit@a/audit@$instance/g; s/\"monitor_id\": \"a\"/\"monitor_id\": \"$instance\"/" \
       deploy/reference-runtime/keylog/audit-a.json.example > /etc/chio/keylog/audit-$instance.json
   done
   chgrp chio-keylog /etc/chio/keylog/*.json && chmod 0640 /etc/chio/keylog/*.json
   systemctl enable --now chio-keylog-witness@{a,b,c}.service chio-keylog-audit@{a,b}.service
   ```

   The config's `seed_file_path` is the fixed credentials path the manager
   mounts for that unit (`/run/credentials/<unit>/seed`), and its
   `socket_path` lives in the unit's runtime directory, which the manager
   removes on stop so a restart never meets a stale socket.

## Operations

- Rotation: replace the credential file under `/etc/chio/credentials`, then
  `systemctl restart` the unit; the manager re-reads credentials at every
  start. The edge and trust-control must move together for the control and
  workload tokens.
- Stop: `systemctl stop` sends SIGTERM to the supervisor, which forwards it
  and grants `--stop-grace` (30 s) for the bounded drain before SIGKILL;
  `TimeoutStopSec` is 35 s so the manager escalates only after that. Keep
  any platform grace period at least as high.
- Memory: `MemoryHigh` and `MemoryMax` are starting points for one wrapped
  MCP server; size them to the tool set and set `LimitNOFILE` from the same
  bounded-memory guidance as the rest of the deployment.
- Readiness: `systemctl status` shows the supervisor's status line, from
  "starting, waiting for GET ..." to "ready".

## Not supervised here

- `chio-secret-brokerd` and `chio-active-response-authorityd`. The broker
  performs a production capability handshake with its admission authority
  at startup, and the tree carries no production host for that authority;
  the response authority's only client is not wired into any binary. Both
  daemons also pin their own and their peer's process id inside a canonical
  deployment config whose digest is baked into a read-only store, so their
  launcher must fork both children, learn the ids, write the configs and
  build the store before either continues. That launcher lands with the
  authority host.
- The relay units under `docs/release/chio-pheromone-relay/systemd/`, which
  are unchanged.
