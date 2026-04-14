"""Minimal URL configuration for arc-django tests."""

from django.http import HttpResponse, JsonResponse
from django.urls import path


def health_view(request):
    return JsonResponse({"status": "ok"})


def protected_view(request):
    receipt = getattr(request, "arc_receipt", None)
    return JsonResponse({"status": "ok", "has_receipt": receipt is not None})


urlpatterns = [
    path("health", health_view),
    path("protected", protected_view),
]
