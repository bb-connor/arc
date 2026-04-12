# Summary 101-03

Documented the common appraisal artifact boundary and its conservative
migration rules in the public protocol and trust-profile surfaces.

Updated:

- `spec/PROTOCOL.md` to describe the nested artifact contract and the bridge
  inventory boundary honestly
- `docs/standards/ARC_PORTABLE_TRUST_PROFILE.md` to state that the inventory
  is a mapping aid, not proof of full cross-verifier equivalence
- phase-101 regression coverage to ensure exported appraisal reports surface
  the nested artifact correctly

This gives operators and future adapter authors one explicit migration target
without overstating verifier-result interoperability.
