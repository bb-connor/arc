# HTTP listener transport

`chio trust serve`, `chio mcp serve-http`, `chio api protect` and the `chio start`
sidecar alias accept the same listener flags:

- `--tls-cert <chain.pem>` and `--tls-key <key.pem>` enable rustls server TLS.
  Both are required together. Provide a certificate trusted by the connecting
  clients and matching their hostname. The key is one unencrypted PKCS8, PKCS1
  or SEC1 PEM block; extra records and trailing text are refused.
- `--allow-plaintext` explicitly permits a non-loopback plaintext listener on
  a protected proxy network. It cannot be combined with TLS files.
- Without either choice, only numeric loopback binds are accepted. API-protect
  bind addresses now use numeric socket addresses, matching the other services.

For example, with existing operator-managed certificate and key files:

```sh
chmod 600 /run/chio/tls/key.pem
chio trust serve --listen 0.0.0.0:8940 \
  --tls-cert /run/chio/tls/chain.pem --tls-key /run/chio/tls/key.pem
```

Set `CHIO_TRUST_SERVICE_TOKEN` separately in the service's credential environment.
Normal service-specific policy, manifest, store and authority configuration still
applies. The private key must be an existing regular owner-only file, singly
linked and opened without following symlinks on Unix. It is bounded at 64 KiB;
the public chain is bounded at 2 MiB and 16 certificates. Invalid input fails
before store opening or upstream launch. Restart the service to load a renewed
identity. Clients verify certificate validity, name and trust.

The profile uses the explicit AWS-LC provider, rustls safe protocol versions and
HTTP/1.1 ALPN. Handshakes have a five-second deadline and count against the same
connection cap as established requests. A stalled handshake does not hold up
other accepts. Socket peer addresses remain available to rate limiting and the
[authenticated proxy identity boundary](../superpowers/specs/2026-10-02-inbound-authority-design.md).
Server TLS authenticates the server; this profile does not authenticate client
certificates or promote caller-supplied certificate headers into identity.

Trust-control clients accept HTTPS or literal loopback HTTP only. Names such as
`localhost` do not qualify for the HTTP exception; use `127.0.0.1` or `[::1]`.
Clients canonicalize endpoints, refuse URL credentials/query/fragment, and never
follow HTTP redirects. Use a certificate already trusted by the client's TLS
configuration. Remote MCP's implicit resource base uses HTTPS when TLS is enabled;
set `--public-base-url` when advertising an external proxy address.

## Session revocation response

`POST /admin/sessions/{session_id}/trust` returns `200` and `revoked: true` only
when every capability's write succeeds and a readback confirms that exact
capability is revoked. An already-revoked capability is successful with no
increment to `newlyRevokedCount`.

A partial operation returns `503`, `revoked: false`, the successful new-write
count, and per-capability `revoked` state plus `failure` (`write_failed`,
`readback_failed` or `not_confirmed`). Unknown readback state is `null`. Retry the
same operation after repairing the backend; completed writes are idempotent.
Initialization failures also return non-2xx. Native local causes are retained for
trusted middleware; backend details are absent from the wire response. Success
confirms this backend's state and does not claim cluster convergence or cancel
work already executing.

See the [execution record](../reviews/2026-10-03-transport-revocation-execution.md)
for local qualification and the remaining hosted, platform and release gates.
