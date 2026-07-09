# Design: `crates/security/` enterprise hardening pack

- Status: DRAFT (awaiting review)
- Date: 2026-07-09
- Scope: three new crates under `crates/security/` (`chio-keyring`, `chio-secret-broker`, `chio-cage`), plus a `RequiredPermissions` read path in `chio-manifest`.
- Related normative docs: `spec/PROTOCOL.md`, `spec/SECURITY.md`, `docs/security/threat-coverage.md`.
- Sibling arcs: `2026-07-09-security-folder-design.md` (active defense), `2026-07-09-protocol-primitives-design.md` (protocol primitives). All three land in `crates/security/`.

## 1. Summary

The active-defense arc gives Chio detection and response. This arc closes the operational-trust gaps a security-conscious buyer asks about first, and each maps to a confirmed absence in the codebase inventory:

- `chio-keyring` (no key rotation today): authority-key lifecycle with rotation, overlap windows, and an append-only, Merkle-committed key-transparency log so verifiers can pin the set of keys that ever signed.
- `chio-secret-broker` (no secrets management beyond passkeys today): ephemeral, capability-bound credential leases so long-lived secrets never sit in agent-reachable memory.
- `chio-cage` (WASM sandboxing exists, but no OS-level isolation): compile signed `chio-manifest` permission declarations into operating-system sandbox profiles (seccomp-BPF plus Landlock on Linux), enforced at tool-server launch.

These are less novel than the active-defense arc, and deliberately so: they move procurement checklists and reduce blast radius rather than advance the state of the art. `chio-cage` also provides the mechanism behind the `tool_server_escape` threat row.

## 2. Goals and non-goals

Goals:

- Rotate authority keys without downtime and without trusting the rotating party: publish every key to an append-only transparency log with a signed Merkle root.
- Keep long-lived secrets out of the agent and tool-server address space by issuing short-TTL leases bound to a capability and revocable.
- Enforce filesystem, network, and syscall confinement on tool servers from the signed manifest, fail-closed when no profile is derivable.
- Keep the TCB posture consistent with the rest of Chio: key management and sandbox enforcement are authority- and kernel-adjacent; the broker is best-effort and never able to forge access.

Non-goals:

- No hardware security module driver (the passkey and FIPS backends in `chio-custody-hw` already cover hardware-backed signing). `chio-keyring` orchestrates rotation over those backends; it does not replace them.
- No external KMS or Vault integration in v1. The broker ships a lease abstraction with a local reference backend and a trait seam for external backends later.
- No Windows or macOS syscall sandbox in v1. `chio-cage` ships a portable `Sandbox` trait, a Linux reference implementation, and a fail-closed default that denies launch where no profile can be built.

## 3. Background: what already exists

- Signing backends: `crates/trust/chio-custody-hw` issues capabilities over multiple backends (Ed25519, FIPS P-256/P-384, PQ hybrid) with a per-subject rate limiter and a revocation cascade.
- Merkle-committed epochs: `crates/trust/chio-revocation-oracle` maintains a sparse Merkle tree with signed epoch roots and freshness checks. `chio-keyring`'s transparency log reuses this pattern.
- Secret detection: `SecretLeakGuard` and `crates/guards/chio-data-guards` classify AWS keys, JWTs, Stripe/OpenAI keys, and high-entropy strings. The broker uses this at the lease boundary.
- Manifest permissions: `chio-manifest` `RequiredPermissions` already declares `read_paths`, `write_paths`, `network_hosts`, and `environment_variables`. `chio-cage` compiles these into a sandbox profile.
- WASM confinement: `crates/guards/chio-wasm-guards` runs guards under wasmtime with fuel metering. `chio-cage` extends confinement to native tool-server processes, which WASM fuel does not cover.

## 4. `chio-keyring` (key lifecycle and transparency)

Modules: `epoch` (a key epoch: key id, algorithm, public key, activation and retirement times), `rotation` (advance to a new active key while keeping the previous key valid through an overlap window), `transparency` (append-only log of key epochs with a signed Merkle root, built on the `chio-revocation-oracle` sparse-Merkle pattern), `verify` (a verifier pins a transparency-log root and rejects any signing key not proven present in the log).

Core invariants:

- Every key that ever signs is in the transparency log before it is used. A signature from a key absent from the pinned log is rejected (fail-closed).
- Rotation never invalidates in-flight capabilities signed by the previous key until its overlap window closes, so rotation is downtime-free.
- The log is append-only: a signed epoch root commits to all prior roots, so a removed or back-dated key is detectable.

TCB posture: authority-adjacent. Key management is an authority function; the transparency log is publicly verifiable, so trust is minimized to "the log root you pinned."

Threat relevance: adds key rotation (a confirmed gap) and gives algorithm agility, which is defense in depth for `pq_signature_downgrade` (rotate toward PQ without a flag day).

## 5. `chio-secret-broker` (ephemeral credential leases)

Modules: `lease` (a short-TTL credential bound to a capability id and a subject), `broker` (mint, renew, and revoke leases; enforce per-subject rate limits reusing the `chio-custody-hw` limiter pattern), `backend` (a `SecretBackend` trait with a local reference implementation; external KMS or Vault backends are a later, feature-gated addition), `boundary` (run `SecretLeakGuard` over any value crossing the lease boundary so a raw long-lived secret can never be handed back by mistake).

Core invariants:

- A lease carries a TTL and a capability binding. When the capability is revoked or the TTL expires, the lease is dead. No lease outlives its capability.
- Long-lived secrets live only in the backend, never in the agent or tool-server address space. The agent receives a lease, not the underlying secret, whenever the backend supports indirection.
- Every mint, renew, and revoke is a signed receipt with a TTL, so credential issuance is auditable.

TCB posture: not in the TCB. A compromised broker can fail to mint a lease (fail-closed: the tool server does not get the credential) but cannot forge access, because the capability still gates the tool call independently.

Threat relevance: shrinks the blast radius of a compromised tool server (leases expire; long-lived secrets are not resident) and strengthens the response to `pii_phi_exposure` and secret exfiltration by keeping raw secrets out of reach.

## 6. `chio-cage` (OS sandbox profiles from the manifest)

Modules: `profile` (a `SandboxProfile`: allowed read roots, write roots, network destinations, and a syscall allowlist), `compile` (derive a `SandboxProfile` from a signed manifest's `RequiredPermissions`), `linux` (a reference `Sandbox` implementation using seccomp-BPF for syscall filtering and Landlock for filesystem rules), `sandbox` (the portable `Sandbox` trait plus a fail-closed default that denies launch when no profile can be built).

Core invariants:

- The sandbox profile is derived only from the signed manifest, so confinement is exactly as trusted as the manifest signature.
- Fail-closed: a tool server whose manifest yields no derivable profile does not launch. An unknown syscall defaults to deny.
- Confinement is enforced by the operating system at launch, not by cooperation from the tool-server code, so a tool-server escape must defeat the kernel sandbox, not just Chio.

TCB posture: enforcement is kernel-adjacent (it runs at tool-server launch). Because the profile comes from the signed manifest, the trust root is the manifest signer.

Threat relevance: provides the mechanism behind `tool_server_escape` (a Pending row). Note the framing: it does not close the row; closure needs the conformance test plus caught-mutant evidence per `docs/security/threat-coverage.md`.

## 7. Threat-model mapping

Mechanisms that make rows closable, not closures.

| Threat row | Current state | Mechanism this arc adds |
|------------|---------------|--------------------------|
| `tool_server_escape` | Pending | `chio-cage` OS-level syscall and filesystem confinement |
| `pq_signature_downgrade` | Pending | `chio-keyring` algorithm-agile rotation (defense in depth) |
| `pii_phi_exposure` | Pending, zero corpus | `chio-secret-broker` keeps raw secrets out of the tool-server address space |

## 8. Testing and evidence

- Adversarial corpus: new classes in `chio-adversarial-suite` (`key_log_omission` for a signing key absent from the transparency log, `lease_after_revocation` for a lease used past capability revocation, `sandbox_escape_attempt` for a syscall outside the allowlist), wired into `chio-arena`.
- Conformance: transparency-log append-only property, lease TTL and revocation binding, and manifest-to-profile compilation.
- Release gates: `check-keyring-log-append-only` (a new root commits to prior roots), `check-cage-fail-closed` (no profile implies no launch), `check-broker-lease-ttl` (every lease has a TTL and a capability binding).
- Platform note: `chio-cage`'s Linux backend tests require a Linux host with Landlock; they skip gracefully elsewhere, mirroring how the WASM guard tests gate on the wasm target.

## 9. Risks and open questions

- Landlock and seccomp availability varies by kernel version. Mitigation: `chio-cage` probes for support at startup and, absent it, fails closed rather than launching unconfined.
- Broker indirection depends on backend support. A backend that can only return a raw secret weakens the "never resident" guarantee. Mitigation: the boundary guard still runs, and the lease TTL still bounds exposure.
- Transparency-log growth. Mitigation: reuse the revocation-oracle epoch compaction pattern.

## 10. Crate manifest summary

| Crate | Folder | Depends on (new) | In TCB |
|-------|--------|------------------|--------|
| `chio-keyring` | `crates/security` | `chio-core-types`, `chio-revocation-oracle` pattern | Authority-adjacent |
| `chio-secret-broker` | `crates/security` | `chio-core-types`, `chio-data-guards` | No (best-effort, attested) |
| `chio-cage` | `crates/security` | `chio-manifest`, OS sandbox crates (Linux) | Kernel-adjacent (launch-time) |
