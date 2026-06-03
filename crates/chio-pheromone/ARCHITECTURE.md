# chio-pheromone Architecture

`chio-pheromone` owns Chio's local pheromone signal contracts: signed deposits, concentration queries, scarcity policies, observation-cost commitments, runtime verifier trust roots, workflow context bindings, and in-memory substrate behavior. Runtime receipt handling and relay transport live in `chio-pheromone-runtime` and `chio-pheromone-relay`.

The crate validates static deposit material, passport identity binding, signature provenance, treaty scope, replay windows, scarcity admission, observation-cost Merkle inclusion, verifier-root trust, and concentration decay. It also exposes deterministic hashes for scarcity policy and window identifiers.

The security constraint is receiver-owned admission accounting. A deposit must consume exactly the scarcity buckets implied by unique accepted treaties, with no replay, kernel-key signing, untrusted verifier root, stale policy, or malformed cost evidence admitted into the local substrate.

Planned improvement: reject duplicate treaty scope entries on deposits and scarcity policies so a single signed signal cannot double-count the same treaty bucket.
