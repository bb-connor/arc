from __future__ import annotations

import json

from django.http import HttpRequest, JsonResponse


def _receipt_id(request: HttpRequest) -> str | None:
    receipt = getattr(request, "arc_receipt", None)
    if isinstance(receipt, dict):
        return receipt.get("id")
    return None


def healthz(_request: HttpRequest) -> JsonResponse:
    return JsonResponse({"status": "ok"})


def hello(request: HttpRequest) -> JsonResponse:
    return JsonResponse(
        {
            "message": "hello from django",
            "receipt_id": _receipt_id(request),
        }
    )


def echo(request: HttpRequest) -> JsonResponse:
    try:
        payload = json.loads(request.body.decode("utf-8") or "{}")
    except json.JSONDecodeError as exc:
        return JsonResponse({"error": str(exc)}, status=400)

    return JsonResponse(
        {
            "message": payload.get("message"),
            "count": payload.get("count", 1),
            "receipt_id": _receipt_id(request),
            "body_cached": bool(request.body),
        }
    )
