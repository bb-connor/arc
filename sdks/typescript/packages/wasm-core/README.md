# @chio-protocol/wasm-core

Shared, dependency-free helpers used by the Chio runtime SDKs
(`@chio-protocol/workers`, `@chio-protocol/edge`, `@chio-protocol/deno`, and
`@chio-protocol/browser`).

The package ships ESM JavaScript and TypeScript declarations so it can be consumed
directly by Node.js and bundled for Cloudflare Workers, Vercel Edge, Deno, and the
browser.

## API

### `receiptHexToJson(hex: string): string`

Decodes a hex-encoded receipt envelope to its canonical JSON text. Accepts an
optional `0x` prefix, and rejects odd-length input, any non hexadecimal
characters and invalid UTF-8 so malformed receipts fail fast before they reach
the wasm `verify_receipt` boundary.
