---
status: passed
---

# Phase 217 Verification

## Outcome

Phase `217` removed ARC-side product packaging entrypoints so generic ARC
crates no longer own Mercury- or ARC-Wall-specific `product-surface` flows.

## Evidence

- [lib.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-control-plane/src/lib.rs)
- [main.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-cli/src/main.rs)

## Validation

- `rg -n --glob '!crates/arc-mercury/**' --glob '!crates/arc-mercury-core/**' --glob '!crates/arc-wall/**' --glob '!crates/arc-wall-core/**' '\bMERCURY\b|\bMercury\b|\bmercury\b|ARC-Wall|arc-wall|arc_wall' crates`

## Requirement Closure

`MAP-01` is now satisfied locally: ARC generic crates no longer expose
Mercury- or ARC-Wall-specific `product-surface` entrypoints.

## Next Step

Phase `218` can now remove the remaining Mercury-specific naming from ARC's
generic receipt query and trust-control surfaces.
