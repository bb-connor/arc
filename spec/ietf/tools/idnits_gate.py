#!/usr/bin/env python3
"""Accept only a completed idnits 3.1.0 report with no errors or warnings.

With --allow-stale-date, a DOC_DATE_IN_PAST warning alone does not fail the
gate. idnits measures that warning against today's date, so it says when the
check ran, not whether the source changed. Submission checks omit the option.
"""
import json
import sys
from pathlib import Path

SEVERITIES = {
    "ValidationError": "error",
    "ValidationWarning": "warning",
    "ValidationComment": "comment",
}
STALE_DATE = "DOC_DATE_IN_PAST"


def validate(report, allow_stale_date=False):
    if not isinstance(report, dict):
        raise ValueError("report must be an object")
    nits = report.get("nits")
    counts = report.get("nitsBySeverity")
    file = report.get("file")
    if not isinstance(nits, list) or not isinstance(counts, dict):
        raise ValueError("missing completed validation report")
    if report.get("result") != ("fail" if nits else "pass"):
        raise ValueError("result disagrees with reported nits")
    if not isinstance(file, dict) or not isinstance(file.get("path"), str) or not file["path"]:
        raise ValueError("missing validated document path")
    if type(file.get("size")) is not int or file["size"] < 5:
        raise ValueError("invalid validated document size")
    observed = dict.fromkeys(SEVERITIES.values(), 0)
    for severity in observed:
        if type(counts.get(severity)) is not int or counts[severity] < 0:
            raise ValueError("invalid severity counts")
    for nit in nits:
        if not isinstance(nit, dict) or nit.get("severity") not in SEVERITIES:
            raise ValueError("unknown nit severity")
        if not isinstance(nit.get("code"), str) or not isinstance(nit.get("desc"), str):
            raise ValueError("invalid nit detail")
        observed[SEVERITIES[nit["severity"]]] += 1
    if any(observed[key] != counts[key] for key in observed):
        raise ValueError("severity counts disagree with nit details")
    failures = [nit for nit in nits if nit["severity"] != "ValidationComment"
                and not (allow_stale_date and nit["severity"] == "ValidationWarning"
                         and nit["code"] == STALE_DATE)]
    if failures:
        details = [f"{nit['severity']}: {nit['code']}: {nit['desc']}" for nit in failures]
        raise ValueError("errors or warnings reported: " + "; ".join(details))
    return observed


if __name__ == "__main__":
    try:
        args = sys.argv[1:]
        allow_stale_date = args[:1] == ["--allow-stale-date"]
        if allow_stale_date:
            args = args[1:]
        if len(args) != 1 or args[0].startswith("-"):
            raise ValueError("expected [--allow-stale-date] and one report path")
        counts = validate(json.loads(Path(args[0]).read_text()), allow_stale_date)
    except (OSError, ValueError, TypeError) as error:
        print(f"idnits: {error}", file=sys.stderr)
        sys.exit(1)
    print(f"idnits: {counts}")
