from __future__ import annotations

from django.urls import path

from hello_app import views

urlpatterns = [
    path("healthz", views.healthz),
    path("hello", views.hello),
    path("echo", views.echo),
]

