# Summary 288-01

Phase `288` added a bounded Anthropic SDK integration example at
[examples/anthropic-sdk](/Users/connor/Medica/backbay/standalone/arc/examples/anthropic-sdk/README.md).

## Delivered

- [package.json](/Users/connor/Medica/backbay/standalone/arc/examples/anthropic-sdk/package.json)
  pins the Anthropic SDK dependency.
- [run.mjs](/Users/connor/Medica/backbay/standalone/arc/examples/anthropic-sdk/run.mjs)
  starts `arc mcp serve`, initializes ARC over stdio, translates ARC tools into
  Anthropic tool definitions, and supports both:
  - `--dry-run` offline verification
  - live Claude tool use when `ANTHROPIC_API_KEY` is present
- [README.md](/Users/connor/Medica/backbay/standalone/arc/examples/anthropic-sdk/README.md)
  documents setup, dry-run verification, and live usage.

## Verification

- `cd examples/anthropic-sdk && npm install --no-package-lock`
- `node run.mjs --dry-run`

The dry-run successfully initialized ARC, listed the governed tool inventory,
and invoked `echo_text` through the ARC MCP edge.
