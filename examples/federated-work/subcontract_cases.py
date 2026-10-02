"""Receiver attacks and real subprocess crash recovery for a three-party job."""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess

from smoke import write
from subcontract_smoke import setup


def receiver_counts(case):
    with sqlite3.connect(case.root / "provider/work.sqlite") as db:
        reviews = db.execute("SELECT COUNT(*) FROM review_runs").fetchone()[0]
        jobs = db.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]
    with sqlite3.connect(case.root / "provider/payments.sqlite") as db:
        payments = dict(db.execute("SELECT state,COUNT(*) FROM chio_finding_operator_payments GROUP BY state"))
    return {"reviews": reviews, "jobs": jobs, "payments": payments}


def probe(case, role, mode, *args):
    command = case.python_command(role, "probe", "/state/key.seed")
    command[command.index("/client/client.py"):] = ["/client/subcontract_probe.py", mode, "/state", *args]
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def spending_denials(parent, specialist, state, child, root):
    import copy
    import client
    import protocol as p
    attacker = parent.root / "attacker"
    attacker.mkdir(mode=0o700)
    # Only the delegated key is present in this adversarial participant's mount.
    for name in ("key.seed", "enrollment.json"):
        shutil.copyfile(state / name, attacker / name)
        (attacker / name).chmod(0o600)
    write(attacker / "child.json", child)
    cap = copy.deepcopy(child["request"]["acceptance"]["ask"]["body"]["tokenOffer"])
    cap.update(issuer=parent.keys["provider"], id="foreign-promisor-capability")
    preimage = {k: v for k, v in cap.items() if k != "signature"}
    cap["signature"] = client.key(parent.root / "provider").sign(p.canonical(preimage)).hex()
    p.verify_signature(preimage, cap["signature"], parent.keys["provider"])
    write(attacker / "foreign-cap.json", cap)
    before = receiver_counts(specialist)
    denials = probe(parent, "attacker", "spending")
    assert receiver_counts(specialist) == before == {"reviews": 1, "jobs": 1, "payments": {"captured": 1}}
    with sqlite3.connect(specialist.root / "provider/authority.sqlite") as db:
        token = child["request"]["acceptance"]["ask"]["body"]["tokenOffer"]
        assert db.execute("SELECT invocation_count,total_cost_exposed,total_cost_realized_spend FROM capability_grant_budgets WHERE capability_id=?", (token["id"],)).fetchone() == (1, 0, 100)
    write(root / "spending-denials.json", denials)
    return denials


def verify(parent, root, public, mode="verify-work"):
    directory = parent.root / "verifier"
    directory.mkdir(mode=0o700, exist_ok=True)
    write(directory / "peers.json", parent.keys)
    write(directory / "public.json", public)
    python = parent.call("verifier", mode, "/state/peers.json", "/state/public.json")
    rust = parent.call("rust-verifier", mode, "/state/peers.json", "/state/public.json")
    assert python == rust
    write(root / (mode + ".json"), {"python": python, "rust": rust})


def historical_unknown(case, public):
    with sqlite3.connect(case.root / "provider/authority.sqlite") as db:
        operation = db.execute("SELECT operation_json FROM admission_operations WHERE operation_id=?", (public["operationId"],)).fetchone()
        journal = db.execute("SELECT * FROM payment_journal WHERE operation_id=?", (public["operationId"],)).fetchone()
        assert operation is not None and journal is not None
        assert json.loads(operation[0])["state"] == "outcome_unknown_after_dispatch"
        return operation, journal


def failure(binary, root, parent_fault, child_fault):
    parent, specialist, _, _ = setup(binary, root, child_fault)
    try:
        parent.start(parent_fault)
        initial = parent.invoke("buyer", "work", "/state", parent.url)
        if parent_fault == "after-subcontract":
            assert initial.returncode != 0
            assert parent.process.wait(timeout=10) in (-9, 137)
            parent.start()
        else:
            assert initial.returncode == 0, initial.stderr
        if child_fault != "none":
            assert specialist.process.wait(timeout=10) in (-9, 137)
            specialist.start()
        with ThreadPoolExecutor(max_workers=4) as executor:
            outputs = list(executor.map(lambda _: parent.call("buyer", "work", "/state", parent.url), range(4)))
        public = outputs[0]
        assert all(value == public for value in outputs)
        write(root / "public.json", public)
        state = next((parent.root / "provider/subcontracts").iterdir())
        child_id = state.name
        if parent_fault == "after-subcontract":
            assert public["incidentVerified"] and public["workExecuted"] is None
            assert (public["available"], public["reserved"], public["spent"]) == (900, 100, 0)
            verify(parent, root, public, "verify-incident")
            historical = historical_unknown(parent, public)
            released = parent.call("buyer", "resolve", "/state", parent.url)
            assert released["incident"] == public["incident"]
            assert (released["available"], released["reserved"], released["spent"]) == (1000, 0, 0)
            assert released["paymentResolution"] == "released_by_agreement"
            verify(parent, root, released["release"], "verify-release")
            write(root / "released.json", released)
            assert historical_unknown(parent, released) == historical
        else:
            assert public["buyerVerified"] and public["reviewRejected"]
            assert (public["available"], public["reserved"], public["spent"]) == (1000, 0, 0)
            verify(parent, root, public)
        with ThreadPoolExecutor(max_workers=4) as executor:
            children = list(executor.map(lambda _: parent.call("provider", "subcontract-recover", "/state", child_id), range(4)))
        child = children[0]
        assert all(value == child for value in children)
        write(root / "child-recovered.json", child)
        if child_fault in ("before-review", "after-review"):
            assert child["incidentVerified"] and child["workExecuted"] is None
            assert (child["available"], child["reserved"], child["spent"]) == (900, 100, 0)
            historical = historical_unknown(specialist, child)
            child_release = parent.call("provider", "subcontract-recover", "/state", child_id, "--release-unknown")
            assert child_release["incident"] == child["incident"]
            assert (child_release["available"], child_release["reserved"], child_release["spent"]) == (1000, 0, 0)
            write(root / "child-released.json", child_release)
            assert historical_unknown(specialist, child_release) == historical
        else:
            assert child["buyerVerified"] and not child["reviewRejected"] and child["spent"] == 100
        parent_counts, child_counts = receiver_counts(parent), receiver_counts(specialist)
        assert parent_counts == {"reviews": 0 if parent_fault == "after-subcontract" else 1, "jobs": 1, "payments": {"released": 1}}, parent_counts
        assert child_counts == {"reviews": 0 if child_fault == "before-review" else 1, "jobs": 1,
                               "payments": {"released" if child_fault in ("before-review", "after-review") else "captured": 1}}, child_counts
        parent.stop()
        specialist.stop()
        final = parent.call("buyer", "work", "/state", parent.url)
        assert final == (released if parent_fault == "after-subcontract" else public)
        result = {"scenario": root.name, "parent": parent_counts, "child": child_counts,
                  "buyerSpent": 0, "delegateSpent": child["spent"], "parentReplayed": False,
                  "concurrentParentRecoveries": 4, "concurrentChildRecoveries": 4}
        write(root / "invariants.json", result)
        return result
    finally:
        parent.stop()
        specialist.stop()


def hostile_worker(binary, root):
    parent, specialist, _, _ = setup(binary, root)
    try:
        source = Path(__file__).with_name("python_buyer")
        code = root / "worker-code"
        shutil.copytree(source, code, ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copyfile(source / "client.py", code / "original_client.py")
        shutil.copyfile(source / "subcontract_hostile_worker.py", code / "client.py")
        parent.worker_code = code
        key_before = (parent.root / "provider/key.seed").read_bytes()
        parent.start()
        public = parent.call("buyer", "work", "/state", parent.url)
        assert public["buyerVerified"] and not public["reviewRejected"], public
        assert (parent.root / "provider/key.seed").read_bytes() == key_before
        state = next((parent.root / "provider/subcontracts").iterdir())
        isolation = json.loads((state / "worker-isolation.json").read_text())
        assert not isolation["parentKeyReadable"] and not isolation["directTcpConnected"]
        assert not (state / "worker-isolation.json").is_symlink()
        attack = json.loads((state / "sandbox-attack.json").read_text())
        assert attack["task"]["status"]["state"] == "TASK_STATE_FAILED"
        assert receiver_counts(specialist) == {"reviews": 1, "jobs": 1, "payments": {"captured": 1}}
        verify(parent, root, public)
        write(root / "public.json", public)
        write(root / "sandbox-attack.json", attack)
        write(root / "isolation.json", isolation)
        return {"scenario": root.name, "extraProcurementDenied": True, "parentKeyReadable": False,
                "parentKeyOverwritten": False, "legitimateSpecialistJobs": 1}
    finally:
        parent.stop()
        specialist.stop()


def disclosure_denials(binary, root, configured):
    parent, specialist, _, _ = setup(binary, root)
    try:
        if not configured:
            (parent.root / "provider/subcontract.json").unlink()
        parent.start()
        denials = probe(parent, "buyer", "disclosures", str(configured).lower())
        assert receiver_counts(parent) == {"reviews": 0, "jobs": 0, "payments": {}}
        if configured:
            # Negotiate valid signed terms containing the wrong disclosure hash.
            # Send the actual work straight to the kernel, bypassing Python's
            # independent work validator. No specialist receives this input.
            parent.agreement["subcontract"]["inputSha256"] = "a" * 64
            write(parent.root / "buyer/agreement.json", parent.agreement)
            snapshot = parent.call("buyer", "buyer", "/state", parent.url)
            work = {"acceptance": snapshot["jobs"][0]["acceptance"], "input": (parent.root / "buyer/input.json").read_text()}
            write(parent.root / "buyer/changed-disclosure.json", work)
            denied = parent.call("buyer", "review-request", "/state", parent.url, "/state/changed-disclosure.json", "signed")
            assert denied["task"]["status"]["state"] == "TASK_STATE_FAILED"
            denials.append({"case": "changed-projection-digest", "response": denied})
            assert receiver_counts(parent) == {"reviews": 0, "jobs": 1, "payments": {}}
        assert receiver_counts(specialist) == {"reviews": 0, "jobs": 0, "payments": {}}
        assert not (parent.root / "provider/subcontracts").exists()
        write(root / "denials.json", denials)
        return {"scenario": root.name, "denials": len(denials), "specialistCalls": 0, "childStateCreated": False}
    finally:
        parent.stop()
        specialist.stop()
