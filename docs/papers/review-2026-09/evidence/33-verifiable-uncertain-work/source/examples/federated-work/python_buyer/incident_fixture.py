"""Test utility: sign malformed public incident vectors with an owned fixture key."""
import base64
import copy
import sys

import client
import incident
import protocol as p


def vectors(state, file):
    valid = client.read(file)
    key = client.key(state)
    peers = {k: valid["request"]["acceptance"]["quote"]["agreement"][k] for k in ("buyer", "provider")}
    p.require(key.public_key().public_bytes_raw().hex() == peers["provider"], "fixture key mismatch")
    names = ("incident-request-binding", "incident-dispatch-fence", "replay-incident-id", "record-representation",
             "paid-capability-hash", "invented-finding", "completed-state", "boolean-epoch", "different-signer", "changed-input")
    cases = []
    for index, name in enumerate(names):
        public = copy.deepcopy(valid)
        body = public["incident"]["projection"]["body"]
        if index in (0, 1, 3):
            projection = incident.encoded(body["projection_json"])
            record = copy.deepcopy(projection["incident"])
            if index == 0:
                record["binding"]["request_binding_hash"] = "a" * 64
            elif index == 1:
                record["binding"]["retained_dispatch_commit"]["store_fence"]["owner_epoch"] += 1
            else:
                record["record_digest"] = "b" * 64
            if index != 3:
                projection["incident"] = record
            commitment = {"kind": "incident", "record_id": record["record_id"], "record_digest": p.digest(record)}
            manifest = {"schema": "chio.admission-projection-manifest.v1", "projection_body_digest": p.digest(projection),
                        "records": [commitment]}
            body["projection_json"] = base64.b64encode(p.canonical(projection)).decode()
            body["manifest_json"] = base64.b64encode(p.canonical(manifest)).decode()
            body["records"] = [{**commitment, "canonical_json": base64.b64encode(p.canonical(record)).decode()}]
            body["terminal_operation"]["terminal_replay"]["incident"]["projection_digest"] = p.digest(manifest)
        elif index == 2:
            body["terminal_operation"]["terminal_replay"]["incident"]["incident_id"] = "another-incident"
        elif index == 4:
            for field in ("source_operation", "terminal_operation"):
                body[field]["binding"]["authorization_capability_hash"] = "a" * 64
        elif index == 5:
            public["incident"]["finding"] = {}
        elif index == 6:
            body["terminal_operation"]["state"] = "completed"
        elif index == 7:
            body["context"]["coordinator_lease_epoch"] = True
        elif index == 8:
            body["signer_key"] = peers["buyer"]
        else:
            public["request"]["input"] += " "
        preimage = incident.NATIVE.encode() + b"\0" + p.canonical(body)
        signature = key.sign(preimage)
        key.public_key().verify(signature, preimage)
        public["incident"]["projection"]["signature"] = signature.hex()
        cases.append({"case": name, "public": public})
    return {"peers": peers, "valid": valid, "cases": cases}


if __name__ == "__main__":
    sys.stdout.buffer.write(p.canonical(vectors(*sys.argv[1:])) + b"\n")
