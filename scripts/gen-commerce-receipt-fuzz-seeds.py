#!/usr/bin/env python3
"""Write the commerce_receipt_verify fuzz seed corpus from the offline PSP fixture.

Each seed is `[slot, mode, receipt_bytes...]` as decoded by
`chio_commerce_order::fuzz::verify_commerce_receipt`. Mode bit 0 asks the
harness to re-sign the receipt with the fixture kernel key, so seeds never
carry signatures of their own. Output is byte-for-byte deterministic; run with
`--check` to fail when the committed corpus drifts from the fixture.
"""

import argparse
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURE = REPO_ROOT / "fixtures/proof-room/commerce-payments/offline-psp-valid/authority-receipts"
CORPUS = REPO_ROOT / "fuzz/corpus/commerce_receipt_verify"

INTENT_SLOT = 0
MANDATE_SLOT = 3
DISPATCH_SLOT = 7
RAW = 0
RESIGN = 1

INTENT = "receipt-intent-commerce-001.json"
MANDATE = "receipt-mandate-commerce-001.json"
DISPATCH = "receipt-settlement-dispatch-commerce-001.json"


def receipt(name: str) -> bytes:
    return (FIXTURE / name).read_bytes()


def replace_once(data: bytes, old: bytes, new: bytes) -> bytes:
    if data.count(old) != 1:
        raise SystemExit(f"expected exactly one {old!r} in fixture receipt")
    return data.replace(old, new)


def zero_parameter_hash(data: bytes) -> bytes:
    marker = b'"parameter_hash":"'
    start = data.index(marker) + len(marker)
    end = data.index(b'"', start)
    if end - start != 64:
        raise SystemExit("fixture parameter_hash is not 64 hex characters")
    return data[:start] + b"0" * 64 + data[end:]


def seeds() -> dict[str, bytes]:
    dispatch = receipt(DISPATCH)
    intent = receipt(INTENT)
    mandate = receipt(MANDATE)
    return {
        "valid-dispatch.bin": bytes([DISPATCH_SLOT, RAW]) + dispatch,
        "valid-intent-resigned.bin": bytes([INTENT_SLOT, RESIGN]) + intent,
        "wrong-action-hash-dispatch.bin": bytes([DISPATCH_SLOT, RESIGN])
        + zero_parameter_hash(dispatch),
        "wrong-action-hash-unsigned.bin": bytes([INTENT_SLOT, RAW]) + zero_parameter_hash(intent),
        "tampered-parameters-mandate.bin": bytes([MANDATE_SLOT, RESIGN])
        + replace_once(mandate, b'"transition":"bind_mandate"', b'"transition":"reserve_budget"'),
        "non-canonical-number.bin": bytes([DISPATCH_SLOT, RESIGN])
        + replace_once(dispatch, b'"parameters":{', b'"parameters":{"amount":1e400,'),
        "truncated.bin": bytes([DISPATCH_SLOT, RAW]) + dispatch[: len(dispatch) // 2],
        "duplicate-key.bin": bytes([DISPATCH_SLOT, RESIGN])
        + replace_once(
            dispatch, b'"parameters":{', b'"parameters":{"order_id":"order-commerce-001",'
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail on corpus drift")
    args = parser.parse_args()
    expected = seeds()
    if args.check:
        actual = {path.name: path.read_bytes() for path in CORPUS.glob("*.bin")}
        if actual != expected:
            drift = sorted(set(actual) ^ set(expected) | {
                name for name in set(actual) & set(expected) if actual[name] != expected[name]
            })
            print(f"commerce_receipt_verify corpus drift: {', '.join(drift)}", file=sys.stderr)
            return 1
        return 0
    CORPUS.mkdir(parents=True, exist_ok=True)
    for name, data in expected.items():
        (CORPUS / name).write_bytes(data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
