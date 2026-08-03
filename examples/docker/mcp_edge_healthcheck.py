#!/usr/bin/env python3

import http.client
import json
import os
import re
import urllib.error
import urllib.request


HEALTH_URL = "http://127.0.0.1:8931/admin/health"
REQUEST_TIMEOUT_SECONDS = 3
MAX_HEALTH_BODY_BYTES = 64 * 1024
BEARER_TOKEN = re.compile(r"[\x21-\x7e]{16,4096}")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, _request, _file_pointer, _code, _message, _headers, _url
    ):
        return None


def require_admin_token() -> str:
    token = os.environ.get("CHIO_ADMIN_TOKEN", "")
    if BEARER_TOKEN.fullmatch(token) is None:
        raise SystemExit("CHIO_ADMIN_TOKEN must be an explicit bearer token")
    return token


def read_bounded(response) -> bytes:
    payload = response.read(MAX_HEALTH_BODY_BYTES + 1)
    if len(payload) > MAX_HEALTH_BODY_BYTES:
        raise SystemExit("edge health response exceeds 64 KiB")
    return payload


def probe_health(opener, admin_token: str) -> dict:
    request = urllib.request.Request(
        HEALTH_URL,
        method="GET",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    try:
        with opener.open(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            if response.geturl() != HEALTH_URL:
                raise SystemExit("edge health response target changed")
            if response.status != 200:
                raise SystemExit(f"unexpected edge health status: {response.status}")
            raw = read_bounded(response)
    except urllib.error.HTTPError as exc:
        status = exc.code
        exc.close()
        raise SystemExit(f"edge health request failed with status {status}") from exc
    except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
        raise SystemExit("edge health request failed") from exc

    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit("edge health response is not valid UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise SystemExit("edge health response must be a JSON object")
    server = payload.get("server")
    auth = payload.get("auth")
    control = payload.get("controlPlane")
    if (
        payload.get("ok") is not True
        or not isinstance(server, dict)
        or server.get("serverId") != "docker-demo"
        or not isinstance(auth, dict)
        or auth.get("adminTokenConfigured") is not True
        or not isinstance(control, dict)
        or control.get("proxied") is not True
        or control.get("controlTokenConfigured") is not True
    ):
        raise SystemExit("edge health response does not match the Docker demo contract")
    return payload


def main() -> None:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    probe_health(opener, require_admin_token())


if __name__ == "__main__":
    main()
