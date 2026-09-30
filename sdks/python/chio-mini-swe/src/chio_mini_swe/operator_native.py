"""Check the worker's two routes before creating durable operator state."""

from urllib.parse import urlsplit

from chio_mini_swe.provider_config import identity, validate


def validate_routes(host, model_route, execution_route, provider):
    """Reject unavailable preparation and mismatched model policy early.

    Native host validation still authenticates the complete route, keys and
    launch policy. These checks prevent preparing an unusable worker or billing
    one provider policy while the host sends another.
    """
    broker = host.get("native_broker")
    routes = broker.get("routes") if isinstance(broker, dict) else None
    if not isinstance(routes, list) or not 1 <= len(routes) <= 16:
        raise ValueError("Mini-SWE requires explicit native broker preparation routes")
    indexed = {}
    for route in routes:
        quota = route.get("quota") if isinstance(route, dict) else None
        preparation = route.get("preparation") if isinstance(route, dict) else None
        if not isinstance(quota, dict) or not isinstance(preparation, dict):
            raise ValueError("Every mini-SWE route requires host-owned preparation")
        key = (quota.get("server_id"), quota.get("tool_name"))
        if not all(isinstance(part, str) and part for part in key) or key in indexed:
            raise ValueError("Native broker tool routes must be unique")
        indexed[key] = preparation
    selected = []
    for route in (model_route, execution_route):
        preparation = indexed.get((route["server_id"], route["tool_name"]))
        if preparation is None:
            raise ValueError("The worker's model and execution routes need preparation")
        selected.append(preparation)
    provider = validate(provider)
    endpoint = urlsplit(provider["endpoint"])
    from minisweagent.models.utils.actions_toolcall import BASH_TOOL

    expected_payload = {
        "kind": "mini_swe_chat",
        "model_id": identity(provider),
        "model": provider["model"],
        "tools": [BASH_TOOL],
        "max_completion_tokens": provider["max_output_tokens"],
        "temperature": provider.get("temperature"),
    }
    expected_destination = {
        "scheme": "https",
        "normalizedHost": endpoint.hostname,
        "explicitPort": endpoint.port or 443,
        "method": "POST",
        "exactPathAndQuery": endpoint.path.rstrip("/") + "/chat/completions",
    }
    model, execution = selected
    if (
        endpoint.scheme != "https"
        or model.get("payload") != expected_payload
        or model.get("destination") != expected_destination
        or model.get("timeout_ms") != provider["timeout_seconds"] * 1000
        or execution.get("payload") != {"kind": "json"}
    ):
        raise ValueError("Host preparation differs from the selected provider or execution policy")
    limits = host.get("limits")
    maximum = limits.get("max_calls") if isinstance(limits, dict) else None
    if type(maximum) is not int or not 1 <= maximum <= 1024:
        raise ValueError("Native mini-SWE requires an explicit aggregate invocation limit")
    return maximum
