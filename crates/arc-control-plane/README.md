# arc-control-plane

`arc-control-plane` packages ARC's trust-control service, client helpers, and
shared runtime wiring for clustered authority, receipt, revocation, and budget
state.

Use this crate when you need the trust-control layer behind `arc trust serve`
or you are wiring a distributed ARC deployment instead of a single local
sidecar.
