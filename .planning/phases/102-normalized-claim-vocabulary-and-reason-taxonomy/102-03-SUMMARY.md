# Summary 102-03

Mapped the currently shipped verifier families into the new claim and reason
model and documented the boundary honestly.

Updated:

- the appraisal inventory so each shipped bridge now declares normalized claim
  codes and default reason codes in addition to legacy assertion keys
- signed appraisal export coverage so the nested artifact proves structured
  claim and reason projection
- `spec/PROTOCOL.md` and
  `docs/standards/ARC_PORTABLE_TRUST_PROFILE.md` to document the portable
  vocabulary and conservative migration rules

This makes the Azure, AWS Nitro, and Google mappings explicit without
overstating cross-vendor semantic equivalence.
