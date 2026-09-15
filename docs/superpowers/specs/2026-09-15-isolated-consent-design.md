# Bilateral consent and enforced role isolation

Extend the qualified public-authority/verifier handoff in the existing isolated
worktree. Keep the registered signed agreement v2 unchanged. The provider publishes
a signed proposal containing its public policy, exact agreement body and W0 input.
The buyer compares it against a separately supplied intent (policy digest, request
ID, input digest and exact work terms), verifies provider authority, then adds its own agreement signature and a signed acceptance of the complete
public proposal, including the disclosed input. Native execution uses the provider's original locally retained
request and requires the exact jointly signed body. No private capability crosses
the public artifact boundary.

Retain the provider intent before issuing its request; preserve partial proposal
state without issuing a replacement capability. Retain the first complete buyer
consent before publication. Exact completed retries return original artifacts;
changed requests, changed keys, missing/partial state and malformed public bytes
fail closed. Stored buyer responses replay at their original assessment time
without the buyer key. Each role has one consent slot in this bounded profile.

Split governance profile signing from status standing. Governance signs a public
context draft using its own seed and the selected status public key. The status
operator authenticates the selected governance/profile and adds its own standing.
The resulting existing context is validated against all six selected public pins.
The checkpoint operator retains the existing checkpoint/status pair of keys.

Run the full payout and rejected-output refund in Linux bubblewrap namespaces.
Five custody domains hold six distinct keys: buyer, provider, verifier, governance,
and checkpoint/status operator. Each process sees its own state, explicit read-only
input artifacts, a fresh output directory, runtime libraries and an isolated
process/network namespace. Only selected provider/verifier calls receive their
respective observer socket. Only the verifier receives pinned checker sources and
Python dependencies. No repository-wide or host-root mount and no unsandboxed
fallback. Initialization itself runs inside the role namespace.

The coordinator transfers public files and controls the owned mock chain. It never
loads role seeds, private native requests or role journals. Native request creation,
execution, submission and settlement move behind provider CLI commands. Existing
checkpoint and verifier CLI commands remain the actual handoff implementation.
Active probes must fail to read peer state/host sentinels, mutate read-only inputs
or reach the host network. First-response recovery, canonical ingress, altered
consent and original allocation/operation/hold identity remain regression gates.

This proves same-host process/filesystem/network isolation under one trusted host
administrator, not independent companies or protection from that administrator.
The chain adapter still owns mock transaction signing. No real funds, network
hosting, public finality, external revocation or rollback-aware multi-allocation
custody are introduced. Reuse the original worktree and preserve all earlier
evidence. Execute, review and qualify inline without sub-agents.
