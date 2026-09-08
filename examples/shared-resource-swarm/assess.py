"""Mechanical acceptance checks for the synthetic release-readiness fixture."""


def assess(snapshot):
    value = snapshot["documents"]["release-board"]["value"]
    entries = value.get("assessments", {})
    expected = {
        "api": ("blocked", "api-2"),
        "search": ("ready", "search-2"),
        "worker": ("blocked", "worker-2"),
    }
    failures = []
    if not isinstance(entries, dict):
        return {"accepted": False, "failures": ["assessments is not an object"]}
    if set(entries) != set(expected):
        failures.append("missing or unexpected service assessment")
    for service, (decision, required) in expected.items():
        entry = entries.get(service)
        if not isinstance(entry, dict):
            failures.append(f"{service}: missing assessment")
            continue
        if entry.get("decision") != decision:
            failures.append(f"{service}: incorrect decision")
        evidence = entry.get("evidence_ids")
        allowed = {service + "-1", service + "-2"}
        if (
            not isinstance(evidence, list)
            or not all(isinstance(e, str) for e in evidence)
            or required not in evidence
            or not set(evidence) <= allowed
        ):
            failures.append(f"{service}: missing decisive or invented evidence")
        if not isinstance(entry.get("reason"), str) or not entry["reason"].strip():
            failures.append(f"{service}: missing reason")
    return {"accepted": not failures, "failures": failures}
