"""Python implementation of the agreed declaration checker and work verifier."""
import base64
import hashlib

import protocol as p

METHODS = frozenset(("get", "put", "post", "delete", "options", "head", "patch", "trace"))


def observations(source):
    p.require(type(source) is str and len(source.encode("utf-8")) <= 64 * 1024, "review input exceeds profile")
    document = p.load_json(source)
    p.require(type(document) is dict and document.get("openapi") == "3.1.0", "unsupported OpenAPI version")
    paths = document.get("paths")
    p.require(type(paths) is dict and 1 <= len(paths) <= 256 and "webhooks" not in document, "unsupported paths or webhooks")
    components = document.get("components", {})
    schemes = components.get("securitySchemes", {}) if type(components) is dict else {}
    p.require(type(schemes) is dict, "security schemes must be an object")
    for name, scheme in schemes.items():
        p.require(name and type(scheme) is dict and "$ref" not in scheme, "unsupported security scheme")
        http = scheme.get("type") == "http" and type(scheme.get("scheme")) is str and bool(scheme["scheme"])
        api_key = scheme.get("type") == "apiKey" and scheme.get("in") in ("header", "query", "cookie")
        api_key = api_key and type(scheme.get("name")) is str and bool(scheme["name"])
        p.require(http or api_key, "only inline HTTP and API-key schemes are supported")

    def required(value):
        p.require(type(value) is list, "security requirements must be an array")
        anonymous = not value
        for alternative in value:
            p.require(type(alternative) is dict, "security alternative must be an object")
            anonymous |= not alternative
            for name, roles in alternative.items():
                p.require(name in schemes and type(roles) is list and all(type(role) is str for role in roles),
                          "unknown scheme or malformed roles")
        return not anonymous

    inherited = required(document["security"]) if "security" in document else False
    result = []
    for path, item in paths.items():
        p.require(path.startswith("/") and len(path.encode("utf-8")) <= 256 and type(item) is dict
                  and "$ref" not in item, "unsupported path item")
        for method in METHODS & item.keys():
            operation = item[method]
            p.require(type(operation) is dict and "callbacks" not in operation and "$ref" not in operation,
                      "unsupported operation")
            auth = required(operation["security"]) if "security" in operation else inherited
            result.append({"path": path, "method": method, "authenticationRequired": auth})
    p.require(1 <= len(result) <= 512, "operation count exceeds profile")
    return sorted(result, key=lambda row: (row["path"], row["method"]))


def request(value, peers):
    p.fields(value, ("acceptance", "input"))
    agreement = p.acceptance(value["acceptance"], peers)
    p.require(type(value["input"]) is str and len(value["input"].encode("utf-8")) <= 64 * 1024, "input disclosure exceeds profile")
    p.require(hashlib.sha256(value["input"].encode("utf-8")).hexdigest() == agreement["inputSha256"], "input digest differs from agreement")
    return agreement


def report_body(work):
    a = work["acceptance"]["quote"]["agreement"]
    return {"schema": "chio.example.openapi-auth-review.v1", "agreementSha256": p.digest(a),
            "acceptedBidSha256": p.digest(work["acceptance"]["accepted"]), "inputSha256": a["inputSha256"],
            "checker": a["checker"], "operations": observations(work["input"])}


def verify_report(work, report):
    body = p.envelope(report, work["acceptance"]["quote"]["agreement"]["provider"])
    p.require(p.same(body, report_body(work)), "report does not reproduce the agreed check")


def reveal(report):
    return {"media_type": "application/json", "payload_b64": base64.b64encode(p.canonical(report)).decode("ascii")}


def decode_reveal(value):
    p.fields(value, ("media_type", "payload_b64"))
    p.require(value["media_type"] == "application/json", "unsupported report media type")
    try:
        return p.load_json(base64.b64decode(value["payload_b64"], validate=True))
    except (ValueError, TypeError) as error:
        raise p.ProtocolError("malformed report envelope") from error


def terminal(work, delivery, peers):
    a = request(work, peers)
    accepted = work["acceptance"]
    rejected = "schema" in delivery
    p.fields(delivery, ("schema", "agreementSha256", "acceptedBidSha256", "receipt", "checkpoint", "inclusion")
             if rejected else ("finding", "report", "receipt", "checkpoint", "inclusion"))
    receipt = p.receipt(delivery["receipt"], peers["provider"], "review", work)
    p.require(receipt["capability_id"] == accepted["ask"]["body"]["tokenOffer"]["id"], "receipt changes capability")
    p.integer(receipt["timestamp"], accepted["accepted"]["body"]["acceptedAt"])
    p.inclusion(receipt, delivery["checkpoint"], delivery["inclusion"], peers["provider"])
    finance = receipt.get("metadata", {}).get("financial", {})
    expected = {"cost_charged": 0 if rejected else 100, "currency": "TST", "settlement_status": "settled",
                "budget_remaining": 100 if rejected else 0, "budget_total": 100, "grant_index": 0}
    p.require(p.same({key: finance.get(key) for key in expected}, expected), "financial receipt differs from agreement")
    for field in ("cost_charged", "budget_remaining", "budget_total", "grant_index"):
        p.integer(finance[field], expected[field], expected[field])
    p.require(type(finance.get("payment_reference")) is str and finance["payment_reference"], "missing settlement reference")
    admission = receipt["metadata"].get("admission_operation", {})
    p.require(admission.get("schema") == "chio.admission-receipt.v1"
              and admission.get("projected_state") == ("denied_after_delivery" if rejected else "completed")
              and admission.get("projected_dispatch_state") == "terminal"
              and type(admission.get("retained_dispatch_commit")) is dict, "missing executed terminal evidence")
    if rejected:
        p.require(delivery["schema"] == "chio.example.checked-review-rejection.v1"
                  and delivery["agreementSha256"] == p.digest(a)
                  and delivery["acceptedBidSha256"] == p.digest(accepted["accepted"]), "rejection changes agreement")
        p.require(p.same(receipt["decision"], {"verdict": "deny", "guard": "checked_output", "reason": p.REJECTION_REASON})
                  and receipt["content_hash"] == hashlib.sha256(p.REJECTION_CONTENT).hexdigest(), "unsupported rejection")
    else:
        p.require(receipt["decision"] == {"verdict": "allow"} and receipt["timestamp"] < a["deadline"], "work was not allowed in time")
        verify_report(work, delivery["report"])
        p.require(receipt["content_hash"] == p.digest(reveal(delivery["report"])), "receipt does not bind the report")
        finding = delivery["finding"]
        expected = {"schema": "chio.finding.v1", "finding_id": finding.get("finding_id"),
                    "descriptor": {"topic": "security:openapi:authentication-declarations", "context_sha256": p.digest(a),
                                   "outcome_class": "positive_result"},
                    "guarantee_class": "deterministic_replay", "payload_sha256": receipt["content_hash"],
                    "payload_media_type": "application/json", "evidence_receipt_ids": [receipt["id"]],
                    "evidence_checkpoint_ref": p.digest(delivery["checkpoint"]), "evidence_cost": p.PRICE,
                    "evidence_class": "observed", "replay_recipe_sha256": p.digest({"checker": a["checker"], "inputSha256": a["inputSha256"]}),
                    "bond_ref": "unbacked:" + p.digest(a), "status_feed_ref": "local-job:" + a["jobId"],
                    "issuer": peers["provider"], "issued_at": receipt["timestamp"], "expires_at": a["deadline"],
                    "signature": finding.get("signature")}
        p.require(p.same(finding, expected), "finding changes the evidence profile")
        p.integer(finding["issued_at"], 1)
        p.integer(finding["expires_at"], 1)
        p.amount(finding["evidence_cost"])
        body = {**finding, "signature": ""}
        p.require(finding["finding_id"] == p.digest({**body, "finding_id": ""}), "finding id is not content-addressed")
        p.verify_signature(body, finding["signature"], peers["provider"])
    return rejected, receipt["id"]
