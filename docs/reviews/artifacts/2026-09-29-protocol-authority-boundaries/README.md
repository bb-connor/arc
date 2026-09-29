# Protocol authority boundary evidence

Local aarch64 Linux evidence for the batch based on `1d4f3b4ad3`.
[logs.json](logs.json) records SHA256 and byte length of the uncompressed logs.
Logs are gzip-compressed without a variable timestamp; `gzip -cd FILE.log.gz`
reads the original output.

The terminal `suite-terminal-v3` command is:

```sh
CARGO_INCREMENTAL=0 cargo test \
  -p chio-mcp-edge -p chio-mcp-adapter -p chio-a2a-adapter \
  -p chio-openai-adapter -p chio-provider-adapter-core -p chio-tool-call-fabric \
  -p chio-anthropic-tools-adapter -p chio-bedrock-converse-adapter \
  -p chio-cohere-tools-adapter -p chio-gemini-tools-adapter \
  -p chio-groq-tools-adapter -p chio-mistral-tools-adapter \
  -p chio-ollama-tools-adapter \
  --features chio-openai-adapter/provider-adapter --no-fail-fast
```

Exit 0: 883 tests passed, zero failed/ignored across 58 targets. Earlier failed
campaigns are evidence, not passes. `boundary-red` captures the unsafe short-token
cache behavior; `decoders-red` captures duplicate-authority acceptance by both
MCP readers and duplicate OpenAI argument acceptance. Intermediate runs include
compilation repairs, old error-string assertions and a stream count cap that
was too small for the existing positive per-tool limit. The final cap preserves
that positive case. The consumer `suite-terminal` failed six old taxonomy/limit
assertions; `suite-terminal-v2` failed one newly documented taxonomy assertion;
both are fixed in the terminal campaign.

Gate commands:

```sh
python3 scripts/check-trust-boundaries.py
python3 scripts/check-security-clocks.py
python3 scripts/tests/check-security-clocks.test.py
python3 scripts/check-negative-assertions.py
python3 scripts/check-rust-file-hygiene.py
```

The first four passed. The hygiene gate failed only two base-identical files:
`active_response.rs` at 2,003/2,002 lines and SQLite `budget_store/tests.rs` at
2,482/2,479. Changed owners satisfy their existing caps. No allowance was raised.
`error-codegen` records generation from `spec/errors/registry.yaml` using the
repository code generator. The initial `clippy` log records two test assertions
using `expect_err` in modules that only permit `unwrap`; they were corrected.

`clippy-terminal` uses the same 13-package selection and OpenAI feature with
`cargo clippy --lib --tests -- -D warnings`: exit 0. `format-terminal` records
`rustfmt --edition 2021 --config skip_children=true --check` on all 66 changed
Rust files: exit 0.

## Review repair qualification

Implementation candidate `53858afa39` was reviewed once. Repair commit
`68fb96f436` contains the production fixes and six regression cases.

| Log | Command scope | Terminal result |
| --- | --- | --- |
| `review-red` | Same 13 packages/features, `cargo test --lib --no-fail-fast review_regression` | Exit 101, all six regressions failed for the intended reasons |
| `review-expiry-red` | Same selection, `cargo test --lib review_regression_final_token_observation` | Exit 101, expired short-lived token accepted before repair |
| `review-suite` | Same full test command as above | Exit 0, 889 passed, zero failed/ignored, 58 targets |
| `review-clippy` | Same selection, `cargo clippy --lib --tests -- -D warnings` | Exit 0 |
| `review-format` | Rustfmt check on all 67 changed Rust files | Exit 0 |
| `review-trust-gate` | Trust-boundary script | Exit 0, 364 constructors, 85 tables, 170 SQL contracts |
| `review-negative-gate` | Negative-assertion script | Exit 0, baseline unchanged at 1260 |
| `review-hygiene` | Rust file hygiene script | Exit 1, same two base-identical failures outside changed owners |
| `openai-default-check` | `CARGO_INCREMENTAL=0 cargo check -p chio-openai-adapter --no-default-features --lib` | Exit 0; OpenAI sources unchanged by the repair |

[qualification.json](qualification.json) pins the reviewed and repaired commits,
reader owners, test totals and known gate failures. The
[review report](final-review.md) and [execution ledger](execution-ledger.md)
record findings, dispositions and their costs.

No whole-workspace, hosted, release, x86_64 native-enforcement or M5 evidence is
claimed. No second review was dispatched. All review findings are addressed;
the source/behavior evidence above is local qualification.
