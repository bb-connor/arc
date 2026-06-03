# chio-federation Architecture

`chio-federation` owns Chio's cross-operator federation contracts for trust activation, quorum reporting, open admission, reputation clearing, treaty admission, bilateral invocation review, and gossip. The crate models how remote visibility and shared evidence can move between operators while runtime trust still remains local, explicit, and fail-closed.

The root module defines the activation, quorum, admission, reputation, and qualification data contracts plus their validators. Specialized modules own bilateral DSSE envelopes, treaty ladder intersections, revocation gossip, pheromone gossip, handshake-based trust establishment, metrics, and the default-off selective-disclosure projection.

The security constraint is cross-operator boundary discipline. Federation artifacts must not create ambient runtime admission, stale trust activation, unbounded delegation, eclipse-prone quorum, or noncanonical live-money collateral before downstream kernels consume them.

Planned improvement: require exact uppercase 3-letter currency codes for federated bond collateral so admission policies cannot canonicalize lowercase money identifiers after review.
