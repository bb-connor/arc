#!/usr/bin/env python3
"""Inspect or revoke one explicit capability using a private MCP admin credential."""

import argparse
import json
import sys
import urllib.parse
from pathlib import Path

from operator_http import OperatorError, identifier, origin, private_operator, request_json

BUDGET_LIMIT = 200  # Current MCP admin maximum; report possible truncation.
REVOCATION_REASONS = (
    "operator_request",
    "credential_compromise",
    "principal_offboarded",
    "tenant_offboarded",
    "policy_withdrawn",
    "incident_response",
)


def checked_bool(value):
    if type(value) is not bool:
        raise OperatorError("invalid_scoped_response")
    return value


def checked_uint(value):
    if type(value) is not int or not 0 <= value <= 2**64 - 1:
        raise OperatorError("invalid_scoped_response")
    return value


def checked_entry_id(value):
    if type(value) is not str or not value:
        raise OperatorError("invalid_scoped_response")
    return value


def revoke_result(capability_id, response):
    """The stored revocation entry for exactly this capability."""
    entry = response.get("entry")
    if not isinstance(entry, dict):
        raise OperatorError("revocation_not_confirmed")
    if entry.get("target_kind") != "capability_id" or entry.get("target_value") != capability_id:
        raise OperatorError("response_capability_mismatch")
    return {
        "capabilityId": capability_id,
        "revoked": True,
        "newlyRevoked": checked_bool(response.get("newly_revoked")),
        "entryId": checked_entry_id(entry.get("entry_id")),
    }


def status_result(capability_id, response):
    """A revoked capability names the entry that revoked it; a live one names none."""
    if response.get("capability_id") != capability_id:
        raise OperatorError("response_capability_mismatch")
    revoked = checked_bool(response.get("revoked"))
    result = {"capabilityId": capability_id, "revoked": revoked}
    if revoked:
        result["entryId"] = checked_entry_id(response.get("entry_id"))
    elif response.get("entry_id") is not None:
        raise OperatorError("invalid_scoped_response")
    return result


def budget_result(capability_id, response):
    if response.get("capabilityId") != capability_id:
        raise OperatorError("response_capability_mismatch")
    if response.get("configured") is not True:
        raise OperatorError("backend_not_configured")
    rows = response.get("usages")
    if (
        not isinstance(rows, list)
        or checked_uint(response.get("count")) != len(rows)
        or len(rows) > BUDGET_LIMIT
        or any(
            not isinstance(row, dict) or row.get("capabilityId") != capability_id for row in rows
        )
    ):
        raise OperatorError("invalid_scoped_response")
    usages = []
    for row in rows:
        usage = {
            key: checked_uint(row.get(key)) for key in ("grantIndex", "invocationCount", "updatedAt")
        }
        for key in ("totalExposureCharged", "totalRealizedSpend", "seq"):
            if key in row and row[key] is not None:
                usage[key] = checked_uint(row[key])
        usages.append(usage)
    if len({row["grantIndex"] for row in usages}) != len(usages):
        raise OperatorError("invalid_scoped_response")
    return {
        "capabilityId": capability_id,
        "usages": usages,
        "count": len(usages),
        "mayBeTruncated": len(usages) == BUDGET_LIMIT,
    }


def scoped_result(action, capability_id, response):
    if action == "revoke":
        return revoke_result(capability_id, response)
    if action == "status":
        return status_result(capability_id, response)
    return budget_result(capability_id, response)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["revoke", "status", "budget"])
    parser.add_argument("--operator-file", type=Path, required=True)
    parser.add_argument("--capability-id", required=True)
    parser.add_argument(
        "--reason",
        choices=REVOCATION_REASONS,
        default="operator_request",
        help="Recorded reason for revoke",
    )
    parser.add_argument("--base-url", help="Explicit trusted HTTPS or loopback HTTP origin")
    parser.add_argument("--timeout", type=float, default=30)
    args = parser.parse_args()
    attempted = False
    try:
        operator = private_operator(args.operator_file)
        base = origin(args.base_url, operator)
        capability_id = identifier(args.capability_id, operator)
        route = "/admin/budgets" if args.action == "budget" else "/admin/revocations"
        data = None
        if args.action == "revoke":
            data = {
                "target": {"kind": "capability_id", "capability_id": capability_id},
                "reason": args.reason,
            }
        elif args.action == "status":
            route += "?" + urllib.parse.urlencode({"capability_id": capability_id})
        else:
            route += "?" + urllib.parse.urlencode(
                {"capability_id": capability_id, "limit": BUDGET_LIMIT}
            )
        attempted = True
        response = request_json(base, route, operator, data, args.timeout)
        result = scoped_result(args.action, capability_id, response)
    except OperatorError as error:
        record = {"action": args.action, **error.record(), "retry": "never-automatic"}
        if args.action == "revoke":
            record["outcome"] = "unknown" if attempted else "not_sent"
        print(json.dumps(record), file=sys.stderr)
        return 1
    print(json.dumps({"action": args.action, "ok": True, "result": result}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
