# Authenticated funded-work verifier transport

Execute the next portable boundary around the existing durable verifier. A provider
sends a canonical signed envelope over TLS 1.3 to one locally selected HTTPS
origin and pinned socket address. Its signature covers the complete original
public verifier request, enrollment digest and origin. Enrollment commits both
role keys and original agreement/policy. The receiver loads its enrollment from
existing custody and selects its own read-only observer socket and checker.
Requests cannot select observation sources or supply observation transcripts.

Reuse the existing rustls/tiny_http listener. Accept one bounded JSON POST route;
reject unsupported framing, encodings, hosts and unauthenticated bodies before
observation/checking. Serialize decisions with the existing SQLite custody path.
Hold an OS service lock before creating/replacing the private HTTP backend socket.
Return the existing signed decision after commit; retries authenticate again and
reuse original custody without requiring the signing seed, observer or checker.

The Rust client uses operator-provided CA certificates, HTTPS hostname and an
explicit connect address. It performs no DNS lookup, redirects, proxy discovery,
system-root fallback or endpoint selection from received messages. Verify the
returned decision against the original public enrollment and request before
exclusive output publication. Provider import retains its independent fresh
observation and original native authority checks before financial successors.

This is an experimental verifier RPC, not new general agent messaging or a claim
of A2A profile compatibility. Existing canonical agreement/decision formats stay
unchanged. Qualification composes remote verification with the original local
chain payout/refund and retains the separate namespace lifecycle regression.
Remote service qualification uses separate local processes on one trusted host;
separate hosts, independent observer administration, public RPC/finality, egress
policy integration and hostile multi-tenant availability remain explicit gates.
