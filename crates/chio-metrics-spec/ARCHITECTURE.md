# chio-metrics-spec Architecture

`chio-metrics-spec` is the workspace authority for Prometheus metric family names and descriptor metadata. Emitters in other crates import names from this crate instead of creating local string literals, which keeps dashboards, alerts, and conformance tests tied to one taxonomy.

The crate has no runtime dependencies. It exposes descriptor constants, lookup helpers, Prometheus name predicates, a deterministic snapshot renderer, and descriptor validation. The snapshot file is the review surface for taxonomy changes; the validator is the semantic gate for data that Prometheus clients cannot safely repair later.

Histogram buckets stay as strings because downstream exporters use textual bucket boundaries. Validation still parses them as finite numbers and requires strict ascending order so an updated snapshot cannot bless duplicate, nonsensical, or unsorted SLO buckets.
