# arc-core

`arc-core` defines the core Rust protocol surface for ARC: capabilities,
receipts, canonical JSON, signing helpers, Merkle utilities, and the shared
typed artifacts consumed by higher runtime layers.

Use `arc-core` when you need ARC protocol types or verification helpers without
embedding the full governed runtime. If you need request evaluation and receipt
signing, start with `arc-kernel`.
