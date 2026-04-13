# TypeScript SDK Example

This example assumes a running ARC hosted edge plus trust service.

Required environment variables:

- `ARC_BASE_URL`: ARC hosted edge base URL, for example `http://127.0.0.1:8931`
- `ARC_CONTROL_URL`: ARC trust-service base URL, for example `http://127.0.0.1:8940`
- `ARC_AUTH_TOKEN`: bearer token accepted by both services

Run it with:

```bash
ARC_BASE_URL=http://127.0.0.1:8931 \
ARC_CONTROL_URL=http://127.0.0.1:8940 \
ARC_AUTH_TOKEN=demo-token \
node --experimental-strip-types packages/sdk/arc-ts/examples/governed_hello.ts
```

The script initializes a session, discovers the default capability issued for
that session, invokes `echo_text`, and then reads the resulting receipt through
`ReceiptQueryClient`.
