"""Explicit, credential-free identity for an operator-selected chat endpoint."""

import hashlib
import ipaddress
import json
import math
import re
from urllib.parse import urlsplit

SCHEMA = "chio.mini-swe.provider.v1"


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate configuration field")
        result[key] = value
    return result


def reject_constant(_):
    raise ValueError("Nonfinite JSON")


def read_json(path, maximum=65536):
    with open(path, "rb") as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError("Configuration exceeds its byte limit")
    return json.loads(data, object_pairs_hook=unique_object, parse_constant=reject_constant)


def validate(value):
    fields = {
        "schema",
        "endpoint",
        "model",
        "credential_env",
        "max_output_tokens",
        "timeout_seconds",
        "input_usd_per_million",
        "output_usd_per_million",
    }
    if (
        not isinstance(value, dict)
        or not fields <= set(value)
        or set(value) - fields - {"temperature", "allow_loopback_http"}
        or value.get("schema") != SCHEMA
    ):
        raise ValueError("Invalid provider configuration fields")
    endpoint = value["endpoint"]
    if (
        not isinstance(endpoint, str)
        or len(endpoint) > 2048
        or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in endpoint)
    ):
        raise ValueError("Invalid provider endpoint")
    parsed = urlsplit(endpoint)
    if (
        not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.port == 0
    ):
        raise ValueError("Provider endpoint cannot include credentials, query or fragment")
    allow_http = value.get("allow_loopback_http", False)
    if type(allow_http) is not bool:
        raise ValueError("allow_loopback_http must be a boolean")
    if parsed.scheme != "https":
        try:
            loopback = ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            loopback = False
        if not (allow_http and parsed.scheme == "http" and loopback):
            raise ValueError("HTTPS is required except explicitly selected loopback HTTP")
    if (
        not isinstance(value["model"], str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}", value["model"]) is None
        or not isinstance(value["credential_env"], str)
        or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", value["credential_env"]) is None
    ):
        raise ValueError("A model name and credential environment variable name are required")
    for key, lower, upper in [("max_output_tokens", 1, 32768), ("timeout_seconds", 1, 300)]:
        if type(value[key]) is not int or not lower <= value[key] <= upper:
            raise ValueError("Provider token and timeout settings must be bounded integers")
    for key in ("input_usd_per_million", "output_usd_per_million"):
        if type(value[key]) not in (int, float) or not 0 <= value[key] <= 10000:
            raise ValueError("Explicit finite token prices are required")
    if "temperature" in value and (
        type(value["temperature"]) not in (int, float) or not 0 <= value["temperature"] <= 2
    ):
        raise ValueError("Invalid temperature")
    result = dict(value, endpoint=endpoint.rstrip("/"), allow_loopback_http=allow_http)
    for key in ("input_usd_per_million", "output_usd_per_million", "temperature"):
        if key in result:
            result[key] = float(result[key])
            if not math.isfinite(result[key]):
                raise ValueError("Nonfinite provider configuration")
    return result


def identity(config):
    value = validate(config)
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return "mini-provider:" + hashlib.sha256(encoded).hexdigest()
