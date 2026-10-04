# Independent review and dispositions

Reviewer: transport_revocation_final_review (GPT-6 Astra, high), read-only, one review of tracked and untracked changes against aaa413406d63cc109f6aeda14de4e517a6d574a6.

Original verdict: **With fixes. Two Important findings; no Critical findings. Do not mark AP7 complete until resolved.** No Minor findings.

1. Important: the rustls-pki-types PEM iterator copies the private key base64 into an ordinary Vec and does not wipe it. Early returns for duplicate keys or empty certificates also drop DER without wiping, before the AWS-LC zeroizing provider is reached. Fix requires bounded zeroizing scratch and wiping ownership of every decoded key, plus a retained ownership audit covering success and error paths.
2. Important: raw PEM errors retain malformed input lines or arbitrary labels. Derived Debug and source-chain formatting disclose private input, including decimal byte arrays. Fix requires redacted typed diagnostics and direct/production regressions for malformed headers and unterminated private labels.

The reviewer found capped handshake IO, socket identity, startup enforcement, redirect refusal, and AP8 identity-bound write/readback and partial retry handling sound in the reviewed source.

## Root dispositions

Both findings accepted as Important. A regression reproduced private marker bytes in Debug/source diagnostics (`review-private-pem-red`). The parser now uses borrowed framing, fixed zeroizing base64/DER buffers and immediate Zeroizing key ownership; rejects additional blocks before DER decoding; validates certificates before private decoding; transfers guarded DER directly to the explicit AWS-LC zeroizing provider. Error types retain only redacted syntax categories. See `private-key-ownership.md`. Direct regression and shared suite passed (`review-private-pem-green`); final shared HTTP tests passed 19 and focused control-plane tests, including the production wrapper, passed 27 (`fixture-qualified-http`, `fixture-qualified-control`). Terminal suite/lint results are recorded in commands.json. No second reviewer approval is claimed. No findings were deferred as Minor.

## Declined boundaries and root rulings

- Hosted CI, merge/release readiness, deployment and native-platform custody: remain outside this local Linux qualification. Cost of treating it as sufficient would be an unqualified release or platform claim.
- FIPS, direct mTLS, certificate automation and deployed proxy correctness: deliberately unavailable/unclaimed. Operators still configure certificates and the AP6 trusted proxy correctly; server TLS authenticates the server only.
- Preexisting detached-task drain behavior and AP4-AP6 beyond changed integration: remain governed by earlier records. The new shared TLS drain control checks in-flight response completion; it does not certify every preexisting background task.
- Cluster-wide revocation convergence and already-running operation cancellation: AP8 confirms the selected backend only. A true result does not claim either wider guarantee.
- Terminal tests/lint and the subsequently added drain test: root owns those executable checks and retains their actual terminal statuses below. The review itself ran no Cargo commands.
