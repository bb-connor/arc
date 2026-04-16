"""Kafka receipt envelope serialization for ARC streaming.

This module converts an :class:`arc_sdk.models.ArcReceipt` (or the
HTTP-flavoured :class:`arc_sdk.models.HttpReceipt`) into the Kafka
wire representation the ARC receipt topic expects:

* ``key`` -- UTF-8 encoded ``request_id`` so Kafka's log compaction
  and partition assignment can key receipts to the originating
  event.
* ``value`` -- canonical JSON bytes (sorted keys, no whitespace,
  ensure_ascii) so Merkle chain hashing stays deterministic across
  producers.
* ``headers`` -- a small set of string headers so downstream
  consumers can filter / route without parsing the value.

The envelope schema version is ``arc-streaming/v1``. It is additive;
bumps only happen on breaking wire changes.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from typing import Any

from arc_sdk.models import ArcReceipt

from arc_streaming.errors import ArcStreamingConfigError

#: Envelope schema version. Bump on any breaking change to the wire
#: layout so receipt consumers can route old payloads.
ENVELOPE_VERSION = "arc-streaming/v1"

#: Kafka header carrying the receipt id on produced events. Downstream
#: consumers use this to correlate produced events with their ARC
#: authorization receipt.
RECEIPT_HEADER = "X-Arc-Receipt"

#: Kafka header carrying the ARC verdict ("allow" / "deny") so simple
#: routers can decide without deserialising the value.
VERDICT_HEADER = "X-Arc-Verdict"


def canonical_json(obj: Any) -> bytes:
    """Produce canonical JSON bytes (sorted keys, no whitespace).

    Matches the canonicalisation used by :mod:`arc_sdk.client` and the
    Rust kernel so content hashes remain byte-compatible across
    languages.
    """
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


@dataclass(frozen=True)
class ReceiptEnvelope:
    """Kafka-friendly envelope around an ARC receipt.

    Attributes
    ----------
    key:
        Bytes for the Kafka record key (``request_id``).
    value:
        Canonical JSON bytes of the envelope payload.
    headers:
        Sequence of ``(name, bytes)`` tuples ready to pass to the
        confluent-kafka ``Producer.produce(headers=...)`` kwarg.
    request_id:
        Convenience accessor for tests / logging.
    receipt_id:
        Convenience accessor for tests / logging.
    """

    key: bytes
    value: bytes
    headers: list[tuple[str, bytes]]
    request_id: str
    receipt_id: str


def build_envelope(
    *,
    request_id: str,
    receipt: ArcReceipt,
    source_topic: str | None = None,
    source_partition: int | None = None,
    source_offset: int | None = None,
    extra_metadata: dict[str, Any] | None = None,
) -> ReceiptEnvelope:
    """Serialise ``receipt`` into a Kafka-friendly envelope.

    Parameters
    ----------
    request_id:
        The ARC ``request_id`` the receipt is associated with. Becomes
        the Kafka record key (bytes-encoded). Must be non-empty.
    receipt:
        The :class:`ArcReceipt` to envelope.
    source_topic:
        Optional originating topic. Included in the envelope for audit
        queries.
    source_partition:
        Optional originating partition.
    source_offset:
        Optional originating offset.
    extra_metadata:
        Optional caller-supplied metadata merged into the envelope's
        ``metadata`` field. Values must be JSON-serialisable.

    Raises
    ------
    ArcStreamingConfigError:
        If ``request_id`` is empty.
    """
    if not request_id:
        raise ArcStreamingConfigError(
            "build_envelope requires a non-empty request_id"
        )

    verdict = "allow" if receipt.is_allowed else "deny"
    metadata = dict(extra_metadata or {})

    payload: dict[str, Any] = {
        "version": ENVELOPE_VERSION,
        "request_id": request_id,
        "verdict": verdict,
        "receipt": receipt.model_dump(exclude_none=True),
    }
    if source_topic is not None:
        payload["source_topic"] = source_topic
    if source_partition is not None:
        payload["source_partition"] = int(source_partition)
    if source_offset is not None:
        payload["source_offset"] = int(source_offset)
    if metadata:
        payload["metadata"] = metadata

    value = canonical_json(payload)
    headers: list[tuple[str, bytes]] = [
        (RECEIPT_HEADER, receipt.id.encode("utf-8")),
        (VERDICT_HEADER, verdict.encode("utf-8")),
    ]
    return ReceiptEnvelope(
        key=request_id.encode("utf-8"),
        value=value,
        headers=headers,
        request_id=request_id,
        receipt_id=receipt.id,
    )


def new_request_id() -> str:
    """Generate a fresh request id for an inbound event.

    Kafka messages do not carry an ARC request id natively. The
    middleware synthesises one per consumed record so the resulting
    receipt can be keyed consistently into the receipt topic.
    """
    return f"arc-evt-{uuid.uuid4().hex}"


__all__ = [
    "ENVELOPE_VERSION",
    "RECEIPT_HEADER",
    "VERDICT_HEADER",
    "ReceiptEnvelope",
    "build_envelope",
    "canonical_json",
    "new_request_id",
]
