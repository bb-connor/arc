# D2 signer-rotation rule

D2 signer-rotation rule: sign with the current key and bind the original identity, uniformly across finalization, release and waiver (today #1160 quarantines, #1179 re-signs and #1173 refuses). Freezes the CT-SETTLE rotation rule. Open sub-question from #1179 to settle within CT-SETTLE: whether a finalization under a rotated signer may deliver output or only withhold it.

Decided by Connor on 2026-10-09: he accepted the #1196 roadmap recommendation as written.
