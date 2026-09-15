#!/usr/bin/env python3
"""A separately implemented buyer for the bounded checked-review profile."""
from __future__ import annotations

from contextlib import contextmanager
import http.client
import os
from pathlib import Path
import re
import secrets
import signal
import sqlite3
import sys
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import protocol as p
import review


def read(path):
    with Path(path).open("rb") as stream:
        return p.load_json(stream.read(p.MAX_JSON + 1))


def key(state):
    with (Path(state) / "key.seed").open("r") as stream:
        return Ed25519PrivateKey.from_private_bytes(p.hex_bytes(stream.read(65).strip()))


def init(state):
    state = Path(state)
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    p.require(state.stat().st_mode & 0o077 == 0, "buyer state must be private")
    identity = Ed25519PrivateKey.generate()
    fd = os.open(state / "key.seed", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(identity.private_bytes_raw().hex().encode("ascii"))
        stream.flush()
        os.fsync(stream.fileno())
    # Persist the new directory entry, as well as the seed contents.
    fd = os.open(state, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return {"publicKey": identity.public_key().public_bytes_raw().hex()}


def connect(state):
    db = sqlite3.connect(Path(state) / "buyer.sqlite", timeout=5, isolation_level=None)
    db.row_factory = sqlite3.Row
    db.executescript("""
        PRAGMA journal_mode=WAL;
        PRAGMA synchronous=FULL;
        PRAGMA foreign_keys=ON;
        CREATE TABLE IF NOT EXISTS account(id INTEGER PRIMARY KEY CHECK(id=1),
            available INTEGER NOT NULL CHECK(available>=0));
        INSERT OR IGNORE INTO account VALUES(1,1000);
        CREATE TABLE IF NOT EXISTS jobs(job TEXT PRIMARY KEY, quote BLOB NOT NULL,
            acceptance BLOB, state TEXT NOT NULL CHECK(state IN ('quoted','prepared','attempted','accepted')),
            ack BLOB, request BLOB, attempted INTEGER NOT NULL DEFAULT 0 CHECK(attempted IN (0,1)), delivery BLOB);
        CREATE TABLE IF NOT EXISTS reservations(job TEXT PRIMARY KEY REFERENCES jobs(job),
            amount INTEGER NOT NULL CHECK(amount=100));
        CREATE TABLE IF NOT EXISTS terminals(job TEXT PRIMARY KEY REFERENCES reservations(job),
            receipt_id TEXT NOT NULL UNIQUE, rejected INTEGER NOT NULL CHECK(rejected IN (0,1)));
        CREATE TABLE IF NOT EXISTS expenses(job TEXT PRIMARY KEY REFERENCES terminals(job),
            amount INTEGER NOT NULL CHECK(amount=100), receipt_id TEXT NOT NULL UNIQUE);
        CREATE TABLE IF NOT EXISTS released_reservations(job TEXT PRIMARY KEY REFERENCES terminals(job),
            receipt_id TEXT NOT NULL UNIQUE);
    """)
    return db


@contextmanager
def transaction(db):
    db.execute("BEGIN IMMEDIATE")
    try:
        yield
        db.execute("COMMIT")
    except BaseException:
        db.execute("ROLLBACK")
        raise


def account(db):
    # One read transaction gives a coherent account even during concurrent recovery.
    with transaction(db):
        return {"available": db.execute("SELECT available FROM account").fetchone()[0],
                "spent": db.execute("SELECT COALESCE(SUM(amount),0) FROM expenses").fetchone()[0],
                "reserved": db.execute("SELECT COALESCE(SUM(r.amount),0) FROM reservations r LEFT JOIN terminals t ON r.job=t.job WHERE t.job IS NULL").fetchone()[0]}


def snapshot(state):
    db = connect(state)
    try:
        result = account(db)
        result["jobs"] = [{"job": row["job"], "state": row["state"],
                           "acceptance": p.load_json(row["acceptance"]) if row["acceptance"] else None}
                          for row in db.execute("SELECT * FROM jobs ORDER BY job")]
        result["reservationCount"] = db.execute("SELECT COUNT(*) FROM reservations").fetchone()[0]
        completed = db.execute("SELECT COUNT(*) FROM terminals").fetchone()[0]
        attempted = db.execute("SELECT COUNT(*) FROM jobs WHERE attempted=1").fetchone()[0]
        result.update(workExecuted=True if completed else (None if attempted else False), settled=bool(completed))
        return result
    finally:
        db.close()


class Transport:
    """Direct loopback HTTP, no redirects, proxy environment, or credential forwarding."""
    def __init__(self, url):
        match = re.fullmatch(r"http://127\.0\.0\.1:([1-9][0-9]{0,4})", url)
        p.require(match is not None, "this experimental transport requires literal loopback HTTP")
        self.port = int(match[1])
        p.integer(self.port, 1, 65535)
        card = self.http("GET", "/.well-known/agent-card.json")
        interfaces = card.get("supportedInterfaces", [])
        p.require(type(interfaces) is list and any(type(i) is dict and i.get("url") == url + "/rpc"
                  and i.get("protocolBinding") == "JSONRPC" and i.get("protocolVersion") == "1.0"
                  for i in interfaces), "provider does not advertise the pinned A2A interface")
        self.skills = {}
        for skill in card.get("skills", []):
            if skill.get("id") in ("quote", "accept", "status", "review", "delivery"):
                p.require(skill["id"] not in self.skills, "ambiguous advertised skill")
                self.skills[skill["id"]] = skill["id"]

    def http(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.request(method, path, body, headers or {})
            response = connection.getresponse()
            p.require(response.status == 200, "HTTP response was not successful; redirects are forbidden")
            return p.load_json(response.read(p.MAX_JSON + 1))
        finally:
            connection.close()

    def invoke(self, tool, args, cap, peers, identity=None):
        p.require(tool in self.skills, "provider does not advertise the requested skill")
        p.require(cap["issuer"] == peers["provider"] and cap["subject"] == peers["buyer"], "credential changes configured peers")
        p.verify_signature({k: v for k, v in cap.items() if k != "signature"}, cap["signature"], peers["provider"])
        now = int(time.time())
        p.integer(now, cap["issued_at"], cap["expires_at"] - 1)
        request_id = secrets.token_hex(16)
        params = {"message": {"messageId": request_id, "role": "ROLE_USER", "parts": [{"data": args}]},
                  "configuration": {"returnImmediately": False, "acceptedOutputModes": ["application/json"]},
                  "metadata": {"chio": {"targetSkillId": self.skills[tool]}}}
        headers = {"Content-Type": "application/json", "A2A-Version": "1.0",
                   "Authorization": "Bearer " + p.canonical(cap).decode("ascii")}
        if identity is not None:
            proof = {"schema": "chio.dpop_proof.v1", "capability_id": cap["id"], "tool_server": p.SERVER,
                     "tool_name": tool, "action_hash": p.digest(args), "nonce": secrets.token_hex(32),
                     "issued_at": now, "agent_key": peers["buyer"]}
            headers["Chio-Sender-Proof"] = p.canonical(p.sign(proof, identity, envelope=False)).decode("ascii")
        wire = self.http("POST", "/rpc", p.canonical({"jsonrpc": "2.0", "id": request_id,
                                                      "method": "SendMessage", "params": params}), headers)
        p.fields(wire, ("jsonrpc", "id", "result"))
        p.require(wire["jsonrpc"] == "2.0" and wire["id"] == request_id, "JSON-RPC reply is not correlated")
        output = wire["result"]
        receipt = p.receipt(output["task"]["metadata"]["chio"]["receipt"], peers["provider"], tool, args)
        p.require(receipt["capability_id"] == cap["id"], "reply used a different capability")
        state = output["task"]["status"]["state"]
        allowed = receipt["decision"] == {"verdict": "allow"}
        p.require(state in ("TASK_STATE_COMPLETED", "TASK_STATE_FAILED") and allowed == (state == "TASK_STATE_COMPLETED"),
                  "task state differs from the signed decision")
        if allowed:
            p.require(receipt["content_hash"] == p.digest(payload(output)), "A2A result does not match the receipt")
        return output


def payload(output):
    p.require(output["task"]["status"]["state"] == "TASK_STATE_COMPLETED", "provider has no completed result for this request")
    artifacts = output["task"]["artifacts"]
    p.require(type(artifacts) is list and len(artifacts) == 1 and len(artifacts[0]["parts"]) == 1,
              "ambiguous A2A result payload")
    return artifacts[0]["parts"][0]["data"]


def context(state):
    identity, peers = key(state), read(Path(state) / "peers.json")
    p.fields(peers, ("buyer", "provider"))
    p.require(identity.public_key().public_bytes_raw().hex() == peers["buyer"], "buyer identity differs from configured peer")
    return identity, peers


def request(state, url, tool, args, signed=False):
    identity, peers = context(state)
    cap = args["acceptance"]["ask"]["body"]["tokenOffer"] if tool == "review" else read(Path(state) / "session.json")
    return Transport(url).invoke(tool, args, cap, peers, identity if signed else None)


def crash():
    os.kill(os.getpid(), signal.SIGKILL)
    raise p.ProtocolError("crash injection did not terminate the buyer")


def negotiate(state, url, before_send=False):
    identity, peers = context(state)
    a = p.agreement(read(Path(state) / "agreement.json"), peers)
    job = a["jobId"]
    db = connect(state)
    try:
        with transaction(db):
            row = db.execute("SELECT quote FROM jobs WHERE job=?", (job,)).fetchone()
            if row:
                quote = p.load_json(row[0])
                p.require(p.same(quote["agreement"], a), "local job already binds different terms")
            else:
                quote = {"agreement": a, "bid": p.sign(p.bid_body(a, int(time.time())), identity)}
                db.execute("INSERT INTO jobs(job,quote,state) VALUES(?,?,'quoted')", (job, p.canonical(quote)))
        p.verify_quote(quote, peers)
        row = db.execute("SELECT acceptance FROM jobs WHERE job=?", (job,)).fetchone()
        if row[0] is None:
            ask = payload(request(state, url, "quote", quote))
            offer = p.verify_ask(quote, ask, peers)
            now = p.integer(int(time.time()), offer["issuedAt"], offer["expiresAt"] - 1)
            reservation = p.sign(p.reservation_body(a, ask), identity)
            acceptance = {"quote": quote, "ask": ask, "reservation": reservation,
                          "accepted": p.sign(p.accepted_body(ask, reservation, now), identity)}
            p.acceptance(acceptance, peers)
            with transaction(db):
                row = db.execute("SELECT acceptance FROM jobs WHERE job=?", (job,)).fetchone()
                if row[0] is None:
                    changed = db.execute("UPDATE account SET available=available-100 WHERE id=1 AND available>=100")
                    p.require(changed.rowcount == 1, "insufficient local credits")
                    db.execute("INSERT INTO reservations VALUES(?,100)", (job,))
                    db.execute("UPDATE jobs SET acceptance=?,state='prepared' WHERE job=?", (p.canonical(acceptance), job))
        with transaction(db):
            row = db.execute("SELECT acceptance,state,ack FROM jobs WHERE job=?", (job,)).fetchone()
            acceptance = p.load_json(row["acceptance"])
            p.acceptance(acceptance, peers)
            method = "accept" if row["state"] == "prepared" else "status"
            if method == "accept":
                db.execute("UPDATE jobs SET state='attempted' WHERE job=?", (job,))
        # A retained acknowledgement permits offline local replay. An uncertain
        # send only permits status retrieval, even when that status says absent.
        if row["ack"] is None:
            if before_send and method == "accept":
                crash()
            ack = payload(request(state, url, method, acceptance))
            p.acknowledgement(ack, acceptance, peers)
            with transaction(db):
                current = db.execute("SELECT ack FROM jobs WHERE job=?", (job,)).fetchone()[0]
                p.require(current is None or p.same(p.load_json(current), ack), "conflicting provider acknowledgements")
                db.execute("UPDATE jobs SET state='accepted',ack=? WHERE job=?", (p.canonical(ack), job))
        else:
            p.acknowledgement(p.load_json(row["ack"]), acceptance, peers)
        return acceptance
    finally:
        db.close()


def commit_terminal(db, job, work, delivery, peers):
    rejected, receipt_id = review.terminal(work, delivery, peers)
    p.require(work["acceptance"]["quote"]["agreement"]["jobId"] == job, "terminal changes local job id")
    with transaction(db):
        row = db.execute("SELECT request,delivery,attempted FROM jobs WHERE job=?", (job,)).fetchone()
        p.require(row is not None and row["attempted"] == 1 and p.same(p.load_json(row["request"]), work),
                  "terminal has no matching local work attempt")
        if row["delivery"] is not None:
            p.require(p.same(p.load_json(row["delivery"]), delivery), "terminal conflicts with retained job outcome")
            return rejected
        # One unique receipt across both terminal choices prevents cross-job reuse.
        db.execute("INSERT INTO terminals VALUES(?,?,?)", (job, receipt_id, int(rejected)))
        if rejected:
            db.execute("INSERT INTO released_reservations VALUES(?,?)", (job, receipt_id))
            db.execute("UPDATE account SET available=available+100 WHERE id=1")
        else:
            db.execute("INSERT INTO expenses VALUES(?,100,?)", (job, receipt_id))
        db.execute("UPDATE jobs SET delivery=? WHERE job=?", (p.canonical(delivery), job))
    return rejected


def work(state, url, fault=""):
    accepted = negotiate(state, url)
    peers = read(Path(state) / "peers.json")
    with (Path(state) / "input.json").open("rb") as stream:
        source = stream.read(64 * 1024 + 1).decode("utf-8")
    work = {"acceptance": accepted, "input": source}
    a = review.request(work, peers)
    review.report_body(work)
    job = a["jobId"]
    db = connect(state)
    try:
        with transaction(db):
            row = db.execute("SELECT request,attempted,delivery FROM jobs WHERE job=?", (job,)).fetchone()
            p.require(row["request"] is None or p.same(p.load_json(row["request"]), work), "work attempt binds different input")
            fresh = row["attempted"] == 0
            if fresh:
                db.execute("UPDATE jobs SET request=?,attempted=1 WHERE job=?", (p.canonical(work), job))
        if row["delivery"] is not None:
            delivery = p.load_json(row["delivery"])
            rejected, _ = review.terminal(work, delivery, peers)
        else:
            if fresh:
                if fault == "--crash-before-work":
                    crash()
                output = request(state, url, "review", work, signed=True)
                receipt = output["task"]["metadata"]["chio"]["receipt"]
                if receipt["decision"] != {"verdict": "deny", "guard": "checked_output", "reason": p.REJECTION_REASON}:
                    review.verify_report(work, review.decode_reveal(payload(output)))
            # No retry of paid work after an attempted send. Recover only from
            # retained delivery evidence, including after the agreement expires.
            delivery = payload(request(state, url, "delivery", accepted))
            review.terminal(work, delivery, peers)
            if fault == "--crash-after-check":
                crash()
            rejected = commit_terminal(db, job, work, delivery, peers)
        return {**account(db), "request": work, "delivery": delivery, "creditProfile": p.CREDIT,
                "reviewRejected": rejected, "workExecuted": True, "buyerVerified": True,
                "localCreditSettled": True, "externalFundsTransferred": False}
    finally:
        db.close()


def main(args):
    match args:
        case ["init", state]:
            return init(state)
        case ["probe", path]:
            try:
                with open(path, "rb"):
                    return {"readable": True}
            except OSError:
                return {"readable": False}
        case ["snapshot", state]:
            return snapshot(state)
        case ["buyer", state, url, *flags] if not flags or flags == ["--crash-before-send"]:
            negotiate(state, url, bool(flags))
            return snapshot(state)
        case ["work", state, url, *flags] if not flags or flags in (["--crash-after-check"], ["--crash-before-work"]):
            return work(state, url, flags[0] if flags else "")
        case ["request", state, url, tool, file]:
            return request(state, url, tool, read(file))
        case ["review-request", state, url, file, proof] if proof in ("signed", "missing"):
            return request(state, url, "review", read(file), proof == "signed")
        case ["verify-work", peers, public]:
            value = read(public)
            rejected, receipt_id = review.terminal(value["request"], value["delivery"], read(peers))
            return {"buyerVerified": True, "reviewRejected": rejected, "receiptId": receipt_id, "externalFundsTransferred": False}
        case _:
            raise p.ProtocolError("unsupported buyer command")


if __name__ == "__main__":
    os.umask(0o077)
    try:
        sys.stdout.buffer.write(p.canonical(main(sys.argv[1:])) + b"\n")
    except Exception as error:
        # Do not print raw transport bodies, credentials, or disclosed inputs.
        message = str(error) if isinstance(error, p.ProtocolError) else type(error).__name__
        print("buyer: " + message, file=sys.stderr)
        sys.exit(1)
