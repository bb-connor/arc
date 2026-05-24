# chio-siem

`chio-siem` is the SIEM exporter pipeline for Chio's receipt audit log. It
provides the abstractions for forwarding receipt events to external SIEM
systems such as Splunk or Elasticsearch. It depends on `chio-core` (for
`ChioReceipt` and `FinancialReceiptMetadata`) and reads the kernel receipt
database directly via rusqlite; it deliberately does not depend on
`chio-kernel`, keeping the kernel TCB free of HTTP-client surface.

Use this crate to stream signed receipt events into your audit and detection
tooling.
