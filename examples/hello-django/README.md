# hello-django

Minimal Django example using [`sdks/python/chio-django`](../../sdks/python/chio-django/).

## What It Demonstrates

- `GET /hello` is allowed and exposes the Chio receipt id through the view
- `POST /echo` is denied without a capability token
- `POST /echo` succeeds with a trust-issued capability token
- Django request bodies remain readable after Chio middleware hashing
- the smoke flow captures app, sidecar, and trust artifacts in one bundle

## Files

```text
README.md
manage.py
pyproject.toml
hello_project/
hello_app/
openapi.yaml
policy.yaml
run.sh
smoke.sh
```

## Run

Start the app only:

```bash
./run.sh
```

Run the full end-to-end smoke flow:

```bash
./smoke.sh
```
