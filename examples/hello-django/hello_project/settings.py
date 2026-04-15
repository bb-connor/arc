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
    "arc_django.ArcDjangoMiddleware",
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

ARC_SIDECAR_URL = os.environ.get("ARC_SIDECAR_URL", "http://127.0.0.1:9090")
ARC_FAIL_OPEN = False
ARC_EXCLUDE_PATHS = ["/healthz"]
ARC_EXCLUDE_METHODS = ["OPTIONS"]
ARC_RECEIPT_HEADER = "X-Arc-Receipt"

