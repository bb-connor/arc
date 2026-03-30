# Summary 96-02

Aligned lifecycle discovery metadata with the runtime contract by requiring an
explicit TTL whenever ARC advertises a public lifecycle resolve URL.

Remote lifecycle resolution no longer backfills incomplete remote responses
from the presented passport artifact, so stale, malformed, or contradictory
public lifecycle metadata now fails closed instead of silently looking valid.
