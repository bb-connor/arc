"""Sign adversarial nested report fixtures with the owned parent receiver key."""
import copy
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import client
import protocol as p
import review


def vectors(state, file):
    public = client.read(file)
    work, report = public["request"], public["delivery"]["report"]
    key = client.key(state)
    p.require(key.public_key().public_bytes_raw().hex() == report["signerKey"], "fixture receiver key mismatch")
    review.verify_report(work, report)
    cases = []
    for label in ("missing-child", "null-child", "extra-child-field", "expanded-child-input", "replayed-child-job",
                  "child-issuer-substitution", "invalid-child-report", "invalid-child-receipt", "missing-permit",
                  "resigned-permit-parent-request", "resigned-permit-price", "different-permit-promisor"):
        body = copy.deepcopy(report["body"])
        child = body["subcontract"]
        quote = child["request"]["acceptance"]["quote"]
        if label == "missing-child":
            del body["subcontract"]
        elif label == "null-child":
            body["subcontract"] = None
        elif label == "extra-child-field":
            child["anotherSpecialist"] = {}
        elif label == "expanded-child-input":
            child["request"]["input"] += " "
        elif label == "replayed-child-job":
            quote["agreement"]["jobId"] = "another-parent-job"
        elif label == "child-issuer-substitution":
            child["request"]["acceptance"]["ask"]["body"]["tokenOffer"]["issuer"] = report["signerKey"]
        elif label == "invalid-child-report":
            child["delivery"]["report"]["signature"] = "00" * 64
        elif label == "invalid-child-receipt":
            child["delivery"]["receipt"]["signature"] = "00" * 64
        elif label == "missing-permit":
            del quote["subcontractPermit"]
        else:
            permit = quote["subcontractPermit"]["body"]
            if label == "resigned-permit-parent-request":
                permit["parentRequestSha256"] = "a" * 64
            elif label == "resigned-permit-price":
                permit["priceCeiling"] = 200
            signer = Ed25519PrivateKey.generate() if label == "different-permit-promisor" else key
            quote["subcontractPermit"] = p.sign(permit, signer)
        signed = p.sign(body, key)
        p.envelope(signed, report["signerKey"])
        cases.append({"case": label, "report": signed})
    return {"request": work, "valid": report, "cases": cases}


if __name__ == "__main__":
    sys.stdout.buffer.write(p.canonical(vectors(*sys.argv[1:])) + b"\n")
