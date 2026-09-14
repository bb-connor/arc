# Funded W0 work experiment

This joins a real Rust-produced authentication-declaration review, a Python
check of retained bytes, signed work artifacts and the experimental claim
escrow on a private chain. It implements the artifact-only subset of the
[F1 design](../../docs/market/open-agent-work/execution/02-contract-draft.md).
Read [PROFILE.md](PROFILE.md) for exact encodings and trust boundaries.

Four executable cases cover correct work/payment, wrong work/rejection/refund,
unavailable custody/timeout, and a 60-unit child claim paid after the unsubmitted
100-unit parent refunds. The child uses the intermediary's own funds. No native
parent process is killed. The native admission/recovery integration remains
gated on the qualified Security M4 candidate.

## Reproduce

Use Python with the existing hash-locked
[buyer dependencies](../federated-work/python_buyer/requirements.txt). Use the
locked `contracts/` Node dependencies. Build the standalone Rust example from
the repository root; root workspace tests do not select it.

```sh
CARGO_TARGET_DIR=target cargo build --locked --manifest-path examples/federated-work/Cargo.toml
python -B -m unittest discover -s examples/funded-work -v
CHIO_W0_PYTHON=/absolute/path/to/python node --test contracts/scripts/work-claim-w0.test.mjs
```

`CHIO_W0_BINARY` can select an explicitly built standalone Rust binary. The
Python interpreter must have the locked dependencies. The test runner fails if
the checker binary is unavailable; it does not silently skip the integration.

For an inspectable standalone child run, create a new state directory of mode
0700 and choose a new output path. Keep this directory if its custody matters.
All five Ed25519 fixture keys are generated there in a mode-0600 file. Only
public artifacts and signatures appear in the report.

```sh
state_dir=$(mktemp -d /tmp/chio-funded-w0.XXXXXX)
CHIO_W0_PYTHON=/absolute/path/to/python node contracts/scripts/work-claim-w0.mjs \
  child "$state_dir" --output "$state_dir/public-result.json"
```

Available cases: `accepted`, `rejected`, `missing-custody`, `child`. No live RPC
or external keys are accepted. Ganache owns an in-process development chain
with mock ERC20 tokens. On this Linux/aarch64 Node environment its native
accelerators are unavailable; the supported JavaScript fallback runs the tests.

The standalone Rust `check-openapi FILE` command exposes the existing bounded
checker. It reads at most 64 KiB plus one sentinel byte and denies oversized
input. It does not execute a kernel tool call or create a native receipt.

The report retains joint agreements, exact input/output, provider submission,
custody receipt, decision, EIP-712 signature, observations, transaction receipts
and token/escrow events. It also reports actual checker timing and gas receipts.
Functional mock-token amounts do not establish profit or cheap verification.

No independent company operations, native Finding assurance, remote custody,
public-chain finality, challenge court, long-duration availability or economic
advantage is established by this experiment. Those remain program gates.
