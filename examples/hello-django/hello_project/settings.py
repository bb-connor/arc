from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = "hello-django-secret-key"
DEBUG = True
ALLOWED_HOSTS = ["*"]

ROOT_URLCONF = "hello_project.urls"
INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "hello_app",
]

MIDDLEWARE = [
    "chio_django.ChioDjangoMiddleware",
]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

USE_TZ = True
TIME_ZONE = "UTC"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

CHIO_SIDECAR_URL = os.environ.get("CHIO_SIDECAR_URL", "http://127.0.0.1:9090")
CHIO_FAIL_OPEN = False
CHIO_EXCLUDE_PATHS = ["/healthz"]
CHIO_EXCLUDE_METHODS = ["OPTIONS"]
CHIO_RECEIPT_HEADER = "X-Chio-Receipt"

