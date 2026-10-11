"""Signed artifact parsing rejects ambiguity before submitting any decision."""

import pytest

from chio_hermes.approval_inputs import parse_signed_token


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        ('{"signature":"a","signature":"b"}', "duplicate field"),
        ('{"signature":"a","expires_at":1.0}', "non-integer number"),
        ('{"signature":"a","issued_at":NaN}', "non-integer number"),
        ('{"decision":"approved"}', "externally signed decision"),
        (" " * 65_537, "exceeds 64 KiB"),
    ],
)
def test_signed_decision_rejects_ambiguous_or_unsigned_input(raw: str, reason: str) -> None:
    with pytest.raises(ValueError, match=reason):
        parse_signed_token(raw)
