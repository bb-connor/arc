"""Independent checks for one permitted specialist and its exact disclosure."""
import protocol as p

PROFILE = "chio.example.security-review-agreement.v4"


def validate_policy(parent):
    policy = p.fields(parent["subcontract"], ("specialist", "delegate", "paths", "inputSha256", "priceCeiling"))
    p.hex_bytes(policy["specialist"])
    p.hex_bytes(policy["delegate"])
    p.hex_bytes(policy["inputSha256"])
    p.require(len({parent["buyer"], parent["provider"], policy["specialist"], policy["delegate"]}) == 4, "subcontract authority and agent keys must be distinct")
    paths = policy["paths"]
    p.require(type(paths) is list and 1 <= len(paths) <= 16 and
              all(type(path) is str and path.startswith("/") and len(path.encode()) <= 256 for path in paths),
              "unsupported disclosure paths")
    p.require(paths == sorted(set(paths)), "disclosure paths must be sorted and unique")
    p.integer(policy["priceCeiling"], 100, 100)
    p.require(policy["priceCeiling"] <= parent["priceCeiling"], "subcontract exceeds parent ceiling")
    return policy


def project(source, paths):
    import review
    review.observations(source)
    document = p.load_json(source)
    selected, references = {}, set()
    for path in paths:
        p.require(path in document["paths"], "approved disclosure path is absent")
        operations = {}
        for method in review.METHODS & document["paths"][path].keys():
            operation = document["paths"][path][method]
            security = operation.get("security", document.get("security", []))
            for alternative in security:
                references.update(alternative)
            operations[method] = {"security": security}
        p.require(operations, "approved path has no supported operations")
        selected[path] = operations
    schemes = {}
    for name in references:
        original = document["components"]["securitySchemes"][name]
        fields = ("type", "scheme") if original["type"] == "http" else ("type", "name", "in")
        schemes[name] = {key: original[key] for key in fields}
    result = p.canonical({"openapi": "3.1.0", "paths": selected, "components": {"securitySchemes": schemes}}).decode()
    review.observations(result)
    return result


def disclosure(work):
    parent = work["acceptance"]["quote"]["agreement"]
    policy = validate_policy(parent)
    result = project(work["input"], policy["paths"])
    import hashlib
    p.require(hashlib.sha256(result.encode()).hexdigest() == policy["inputSha256"], "subcontract disclosure differs from approved bytes")
    return result


def child_agreement(parent):
    policy = validate_policy(parent)
    p.require(parent["profile"] == PROFILE and parent["subcontracting"] is True, "parent does not permit a subcontract")
    return {"profile": p.PROFILE, "jobId": "child-" + p.digest(parent), "inputSha256": policy["inputSha256"],
            "buyer": policy["delegate"], "provider": policy["specialist"], "priceCeiling": policy["priceCeiling"],
            "deadline": parent["deadline"], "checker": parent["checker"], "subcontracting": False, "creditProfile": p.CREDIT}


def verify_child(work, value):
    import review
    p.fields(value, ("request", "delivery"))
    expected = child_agreement(work["acceptance"]["quote"]["agreement"])
    p.require(p.same(value["request"]["acceptance"]["quote"]["agreement"], expected)
              and value["request"]["input"] == disclosure(work), "specialist evidence changes approved work or disclosure")
    quote = value["request"]["acceptance"]["quote"]
    p.require("subcontractPermit" in quote, "specialist evidence omitted procurement permit")
    permit = verify_permit(quote["subcontractPermit"], expected, work["acceptance"]["quote"]["agreement"]["provider"])
    p.require(p.same(permit, permit_terms(work)), "specialist permit changes the parent work request")
    rejected, _ = review.terminal(value["request"], value["delivery"], {name: expected[name] for name in ("buyer", "provider")})
    p.require(not rejected, "specialist did not deliver an accepted result")


def permit_terms(parent):
    child = child_agreement(parent["acceptance"]["quote"]["agreement"])
    return {"schema": "chio.example.subcontract-permit.v1",
            "parentAgreementSha256": p.digest(parent["acceptance"]["quote"]["agreement"]), "parentRequestSha256": p.digest(parent),
            "childAgreementSha256": p.digest(child), "delegate": child["buyer"], "specialist": child["provider"],
            "priceCeiling": child["priceCeiling"], "currency": "TST", "expiresAt": child["deadline"]}


def verify_permit(value, child, promisor):
    body = p.envelope(value, promisor)
    p.fields(body, ("schema", "parentAgreementSha256", "parentRequestSha256", "childAgreementSha256", "delegate",
                    "specialist", "priceCeiling", "currency", "expiresAt"))
    for name in ("parentAgreementSha256", "parentRequestSha256", "childAgreementSha256"):
        p.hex_bytes(body[name])
    p.require(body["schema"] == "chio.example.subcontract-permit.v1" and body["childAgreementSha256"] == p.digest(child)
              and child["profile"] == p.PROFILE and child["subcontracting"] is False and "subcontract" not in child
              and child["jobId"] == "child-" + body["parentAgreementSha256"]
              and child["buyer"] == body["delegate"] and child["provider"] == body["specialist"]
              and len({body["delegate"], body["specialist"], promisor}) == 3
              and body["priceCeiling"] == child["priceCeiling"] == 100 and body["currency"] == "TST"
              and body["expiresAt"] == child["deadline"], "permit does not authorize this child procurement")
    p.integer(body["priceCeiling"], 100, 100)
    p.integer(body["expiresAt"], 1)
    return body
