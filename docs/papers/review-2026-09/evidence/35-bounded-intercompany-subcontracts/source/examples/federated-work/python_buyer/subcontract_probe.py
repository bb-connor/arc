"""Malicious fixture client: bypass the cooperative buyer's permit checks."""
import copy
import secrets
import sys
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import client
import protocol as p


def spending(state):
    identity = client.key(state)
    config = client.read(state + "/enrollment.json")["body"]
    child = client.read(state + "/child.json")
    original = child["request"]["acceptance"]["quote"]
    peers = {name: config[name] for name in ("buyer", "provider")}
    transport = client.Transport(config["origin"], config)
    cases = []
    # This program possesses the delegated agent key and public enrollment only.
    # It constructs fresh signed bids itself, without client.negotiate preflight.
    for label in ("second-job-without-permit", "original-job-without-permit", "second-job-with-permit",
                  "different-input", "higher-price", "longer-deadline", "onward-subcontract",
                  "agent-forged-permit", "different-promisor", "permit-parent-substitution"):
        quote = copy.deepcopy(original)
        a = quote["agreement"]
        if label.startswith("second-job"):
            a["jobId"] = "unapproved-second-specialist-job"
        if label.endswith("without-permit"):
            del quote["subcontractPermit"]
        elif label == "different-input":
            a["inputSha256"] = "a" * 64
        elif label == "higher-price":
            a["priceCeiling"] = 200
        elif label == "longer-deadline":
            a["deadline"] += 10
        elif label == "onward-subcontract":
            a["subcontracting"] = True
        elif label == "agent-forged-permit":
            quote["subcontractPermit"] = p.sign(quote["subcontractPermit"]["body"], identity)
        elif label == "different-promisor":
            quote["subcontractPermit"] = p.sign(quote["subcontractPermit"]["body"], Ed25519PrivateKey.generate())
        elif label == "permit-parent-substitution":
            quote["subcontractPermit"]["body"]["parentRequestSha256"] = "b" * 64
        quote["bid"] = p.sign(p.bid_body(a, int(time.time())), identity)
        response = transport.invoke("quote", quote, config["session"], peers, identity)
        p.require(response["task"]["status"]["state"] == "TASK_STATE_FAILED", "receiver admitted " + label)
        cases.append({"case": label, "response": response})
    # A valid repeat can return only the already-consumed original capability.
    replay = transport.invoke("quote", original, config["session"], peers, identity)
    p.require(p.same(client.payload(replay), child["request"]["acceptance"]["ask"]), "quote replay minted another capability")
    token = child["request"]["acceptance"]["ask"]["body"]["tokenOffer"]
    for label, work in (("duplicate-child-work", child["request"]),
                        ("expanded-child-input", {**child["request"], "input": child["request"]["input"] + " "})):
        response = transport.invoke("review", work, token, peers, identity)
        p.require(response["task"]["status"]["state"] == "TASK_STATE_FAILED", "receiver admitted " + label)
        cases.append({"case": label, "response": response})
    # A permit promisor is not a capability issuer. This public fixture token
    # has a valid B-kernel signature; the adversarial process has no B-kernel key.
    cap = client.read(state + "/foreign-cap.json")
    work = child["request"]
    rid = secrets.token_hex(16)
    proof = {"schema": "chio.dpop_proof.v1", "capability_id": cap["id"], "tool_server": p.SERVER,
             "tool_name": "review", "action_hash": p.digest(work), "nonce": secrets.token_hex(32),
             "issued_at": int(time.time()), "agent_key": peers["buyer"]}
    headers = {"Content-Type": "application/json", "A2A-Version": "1.0", "Authorization": "Bearer " + p.canonical(cap).decode(),
               "Chio-Sender-Proof": p.canonical(p.sign(proof, identity, envelope=False)).decode()}
    params = {"message": {"messageId": rid, "role": "ROLE_USER", "parts": [{"data": work}]},
              "configuration": {"returnImmediately": False, "acceptedOutputModes": ["application/json"]},
              "metadata": {"chio": {"targetSkillId": "review"}}}
    wire = transport.http("POST", "/rpc", p.canonical({"jsonrpc": "2.0", "id": rid, "method": "SendMessage", "params": params}), headers)
    response = wire["result"]
    receipt = p.receipt(response["task"]["metadata"]["chio"]["receipt"], peers["provider"], "review", work)
    p.require(response["task"]["status"]["state"] == "TASK_STATE_FAILED" and receipt["decision"] != {"verdict": "allow"},
              "procurement promisor became capability issuer")
    cases.append({"case": "permit-promisor-is-not-an-issuer", "response": response})
    return cases


def disclosures(state, configured):
    identity, peers = client.context(state)
    config = client.configured_connection(state)
    transport = client.Transport(config["origin"], config)
    original = client.read(state + "/agreement.json")
    cases = []
    labels = ("no-subcontract-permission", "different-specialist", "different-delegate") if configured else ("no-locally-activated-specialist",)
    for label in labels:
        a = copy.deepcopy(original)
        if label == "no-subcontract-permission":
            a["subcontracting"] = False
        elif label.startswith("different-"):
            field = "specialist" if label == "different-specialist" else "delegate"
            a["subcontract"][field] = Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
        quote = {"agreement": a, "bid": p.sign(p.bid_body(a, int(time.time())), identity)}
        response = transport.invoke("quote", quote, config["session"], peers, identity)
        p.require(response["task"]["status"]["state"] == "TASK_STATE_FAILED", "receiver admitted " + label)
        cases.append({"case": label, "response": response})
    return cases


if __name__ == "__main__":
    result = spending(sys.argv[2]) if sys.argv[1] == "spending" else disclosures(sys.argv[2], sys.argv[3] == "true")
    sys.stdout.buffer.write(p.canonical(result) + b"\n")
