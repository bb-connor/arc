# Whole-batch review resolutions

Base `da4086017f`, reviewer `/root/remaining_cli_final_review`. One read-only review; no delegated implementation or second review.

1. Aggregate failed-read bypass: oversized/erroring reads now exhaust the shared budget; subsequent candidates reject before opening another source. Regression asserts the typed initial bound failure and the later exhausted-budget failure.
2. Private operator-profile lifetime: direct private canonical decoding replaces ordinary Value/canonical intermediates. Partial deserialization owns wiping secret fields; completed operator, buyer and seller profiles wipe seed/token/payload fields on drop. Private initialization serialization uses the zeroizing canonical serializer. A partial-seed failure control checks the wipe path. Final implementer review also moved initialization replay comparisons into private wiping custody; private replay rejects exposed files without changing permissions, while public replay preserves its public mode and exact bytes. Two direct owner tests exercise these replay contracts.
3. Publish acknowledgement identity: signed original finding bytes are locally validated before POST; response finding ID and artifact digest must both match before success. The production binding helper has independent mismatch controls and the HTTP success fixture now uses the actual digest.
4. Binary size contract: the 16 MiB document limit is for JSON. Opaque supply-chain artifacts use an explicit 512 MiB limit; larger artifacts fail closed.

The reviewer declined to infer runtime host enforcement, cryptographic implementation correctness or test/build qualification from static review. These remain separate owner/platform acceptance boundaries. This batch preserves existing enforced launch, signature and trust gates and reports its actual local qualification separately. No minor findings were deferred.

Implementation preceded batched tests under the user's standing action-first instruction. No claim of per-fix red/green testing is made. Initial failed build and test logs are retained.
