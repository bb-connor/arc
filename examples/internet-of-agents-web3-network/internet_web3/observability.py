"""Operations timeline, trace, and SIEM event artifacts."""
from __future__ import annotations

from .artifacts import ArtifactStore, Json, now_epoch
from .identity import digest


BOUNDARY_EVENTS = [
    ("trust-control", "capability issuance and lineage"),
    ("market-api-sidecar", "RFQ, payment requirements, payment proof, fulfillment"),
    ("provider-review-mcp", "provider review attestation"),
    ("subcontractor-review-mcp", "specialist subcontractor review"),
    ("settlement-api-sidecar", "settlement packet assembly"),
    ("web3-evidence-mcp", "read-only validation evidence"),
    ("budget", "budget authorization and reconciliation"),
    ("approval", "signed human approval fixture"),
    ("rail-selection", "cross-rail policy routing"),
]


def _trace_id(order_id: str) -> str:
    return digest({"trace": order_id})[:32]


def _span_id(order_id: str, boundary: str) -> str:
    return digest({"span": order_id, "boundary": boundary})[:16]


def write_observability_artifacts(
    *,
    store: ArtifactStore,
    order_id: str,
    receipts: Json,
    summary_refs: dict[str, str],
) -> Json:
    trace_id = _trace_id(order_id)
    siem_events = []
    trace_map = {
        "schema": "chio.example.ioa-web3.trace-map.v1",
        "trace_id": trace_id,
        "spans": [],
    }
    timeline = {
        "schema": "chio.example.ioa-web3.operations-timeline.v1",
        "order_id": order_id,
        "status": "correlated",
        "events": [],
    }
    for index, (boundary, description) in enumerate(BOUNDARY_EVENTS, start=1):
        receipt_count = receipts.get("boundaries", {}).get(boundary, 1)
        receipt_id = f"rcpt-{boundary}-{order_id}"
        span = {
            "trace_id": trace_id,
            "span_id": _span_id(order_id, boundary),
            "boundary": boundary,
            "receipt_id": receipt_id,
            "receipt_count": receipt_count,
            "description": description,
        }
        trace_map["spans"].append(span)
        siem_events.append({
            "schema": "chio.siem.event.v1",
            "event_id": f"siem-{index}-{boundary}",
            "trace_id": trace_id,
            "span_id": span["span_id"],
            "boundary": boundary,
            "receipt_id": receipt_id,
            "severity": "info",
            "message": description,
            "observed_at": now_epoch(),
        })
        timeline["events"].append({
            "at": now_epoch(),
            "boundary": boundary,
            "description": description,
            "trace_id": trace_id,
            "span_id": span["span_id"],
            "receipt_id": receipt_id,
            "artifact": summary_refs.get(boundary),
        })
    status = {
        "schema": "chio.example.ioa-web3.observability-status.v1",
        "status": "correlated",
        "trace_id": trace_id,
        "siem_event_count": len(siem_events),
        "span_count": len(trace_map["spans"]),
        "all_events_have_receipts": all(event.get("receipt_id") for event in siem_events),
    }
    store.write_json("operations/trace-map.json", trace_map)
    store.write_json("operations/siem-events.json", {
        "schema": "chio.example.ioa-web3.siem-events.v1",
        "events": siem_events,
    })
    store.write_json("operations/operations-timeline.json", timeline)
    store.write_json("operations/observability-status.json", status)
    return status

