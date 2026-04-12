# Risk Register

This register tracks the known non-blocking risks that remain after the local
post-`v2.41` production-candidate closeout.

| Risk | Current posture | Mitigation |
| --- | --- | --- |
| Hosted workflow results are not observable from every local environment | local launch evidence is complete, but external publication stays on hold until hosted CI is green | require hosted `CI` and `Release Qualification` success before tagging |
| Cluster replication remains deterministic leader/follower rather than consensus-based | acceptable for supported deployment scope, not for stronger distributed-trust claims | keep consensus work out of release claims and future milestone separately |
| Enterprise federation does not yet provide automatic SCIM lifecycle management | acceptable for current provider-admin and observability scope | keep provider-admin records explicit and fail closed when incomplete |
| Portable trust does not synthesize cross-issuer reputation | intentional design choice, not a regression | document per-credential evaluation semantics and avoid broader claims |
| A2A still lacks custom auth beyond the shipped matrix | known boundary for partner integrations | keep unsupported schemes explicit and fail closed during discovery/invocation |
| Full theorem-prover coverage is incomplete | acceptable for the current production candidate because the evidence boundary is explicit | keep protocol, partner, and release claims tied to executable tests and qualification artifacts |
