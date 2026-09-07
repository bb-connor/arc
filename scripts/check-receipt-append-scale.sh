#!/usr/bin/env bash
set -euo pipefail

export CHIO_RECEIPT_SCALE_HISTORY=1000000
export CARGO_INCREMENTAL=0

cargo test -p chio-store-sqlite --release append_scale_proof -- --nocapture
