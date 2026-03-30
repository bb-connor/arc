# Summary 95-01

Defined one bounded hosted request-time authorization contract that carries
ARC-governed `authorization_details` and `arc_transaction_context` without
making hosted OAuth artifacts authoritative over governed receipt truth.

The hosted edge now validates the same governed detail vocabulary used by the
authorization-context report, preserves the request-time fields into issued
access tokens, and keeps approval tokens and receipts as separate audit
artifacts rather than alternate bearer credentials.
