"""Minimal Django settings for arc-django tests."""

SECRET_KEY = "arc-django-test-key"
DEBUG = True
INSTALLED_APPS = [
    "django.contrib.contenttypes",
]
MIDDLEWARE = []
ROOT_URLCONF = "tests.urls"
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# ARC settings for tests
ARC_SIDECAR_URL = "http://127.0.0.1:4100"
ARC_FAIL_OPEN = False
ARC_EXCLUDE_PATHS = ["/health"]
ARC_EXCLUDE_METHODS = ["OPTIONS"]
