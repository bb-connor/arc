"""Owned-fixture negative vectors. No private key is included in output."""
import copy
import sys

import client
import protocol as p


def vectors(state, public):
    identity = client.key(state)
    valid = public["release"]
    peers = {name: valid["request"]["acceptance"]["quote"]["agreement"][name] for name in ("provider", "buyer")}
    changes = [
        ("receipt-schema", lambda v: v["receipt"]["body"].update(schema="chio.example.checked-delivery.v1")),
        ("pending-is-not-completed", lambda v: v["receipt"]["body"]["record"].update(transactionId=None, completedAtUnixMs=None, completedFence=None)),
        ("empty-rail-confirmation", lambda v: v["receipt"]["body"]["record"].update(transactionId="")),
        ("accepted-before-offer", lambda v: v["receipt"]["body"]["record"].update(acceptedAtUnixMs=v["consent"]["proposal"]["body"]["issuedAtUnixMs"] - 1)),
        ("accepted-after-expiry", lambda v: v["receipt"]["body"]["record"].update(acceptedAtUnixMs=v["consent"]["proposal"]["body"]["expiresAtUnixMs"])),
        ("different-receiver-policy", lambda v: v["receipt"]["body"]["record"]["policy"].update(rail="unselected-rail")),
        ("rewritten-unknown-outcome", lambda v: v["receipt"]["body"]["record"]["operation"].update(state="completed")),
        ("boolean-fence-epoch", lambda v: v["receipt"]["body"]["record"]["completedFence"].update(owner_epoch=True)),
        ("different-store-fence", lambda v: v["receipt"]["body"]["record"]["completedFence"].update(store_uuid="unselected-store")),
        ("different-work-input", lambda v: v["request"].update(input=v["request"]["input"] + " ")),
    ]
    def copied_role(v):
        v["consent"]["counterpartySignature"] = v["consent"]["proposal"]["receiverSignature"]
        v["receipt"]["body"]["record"]["request"] = copy.deepcopy(v["consent"])
    changes.append(("copied-receiver-signature", copied_role))
    cases = []
    for name, change in changes:
        value = copy.deepcopy(valid)
        change(value)
        value["receipt"]["signature"] = identity.sign(p.canonical(value["receipt"]["body"])).hex()
        p.envelope(value["receipt"], peers["provider"])
        cases.append({"case": name, "public": value})
    return {"peers": peers, "valid": valid, "cases": cases}


if __name__ == "__main__":
    sys.stdout.buffer.write(p.canonical(vectors(sys.argv[1], client.read(sys.argv[2]))) + b"\n")
