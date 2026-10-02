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
import ssl
import sqlite3
import sys
import time
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import protocol as p
import review
import socket
import incident
import resolution


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
        CREATE TABLE IF NOT EXISTS unknown_resolutions(job TEXT PRIMARY KEY REFERENCES incidents(job),
            intent BLOB NOT NULL, receipt BLOB);
        CREATE TABLE IF NOT EXISTS resolved_reservations(job TEXT PRIMARY KEY REFERENCES unknown_resolutions(job),
            resolution_id TEXT NOT NULL UNIQUE);
        CREATE TABLE IF NOT EXISTS incidents(job TEXT PRIMARY KEY REFERENCES reservations(job),
            operation_id TEXT NOT NULL UNIQUE, artifact BLOB NOT NULL);
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
                "reserved": db.execute("SELECT COALESCE(SUM(r.amount),0) FROM reservations r LEFT JOIN terminals t ON r.job=t.job LEFT JOIN resolved_reservations u ON r.job=u.job WHERE t.job IS NULL AND u.job IS NULL").fetchone()[0]}


def snapshot(state):
    db = connect(state)
    try:
        result = account(db)
        result["jobs"] = [{"job": row["job"], "state": row["state"],
                           "acceptance": p.load_json(row["acceptance"]) if row["acceptance"] else None}
                          for row in db.execute("SELECT * FROM jobs ORDER BY job")]
        result["reservationCount"] = db.execute("SELECT COUNT(*) FROM reservations").fetchone()[0]
        result["mutualReleaseCount"] = db.execute("SELECT COUNT(*) FROM resolved_reservations").fetchone()[0]
        result["incidentCount"] = db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        completed = db.execute("SELECT COUNT(*) FROM terminals").fetchone()[0]
        attempted = db.execute("SELECT COUNT(*) FROM jobs WHERE attempted=1").fetchone()[0]
        result.update(workExecuted=True if completed else (None if attempted else False), settled=bool(completed))
        return result
    finally:
        db.close()


# A parent review includes the specialist round trip and durable native writes.
# Keep its response wait bounded by the receiver connection lifetime. A timeout
# still leaves execution uncertain and does not authorize retrying the effect.
HTTP_TIMEOUT_SECONDS = 30


class UnixHttpsConnection(http.client.HTTPConnection):
    """TLS across an operator-mounted tunnel, inside a disconnected network namespace."""
    def __init__(self, host, port, context, socket_path):
        super().__init__(host, port, timeout=HTTP_TIMEOUT_SECONDS)
        self.tls_context, self.socket_path = context, socket_path

    def connect(self):
        stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            stream.settimeout(self.timeout)
            stream.connect(self.socket_path)
            self.sock = self.tls_context.wrap_socket(stream, server_hostname=self.host)
        except BaseException:
            stream.close()
            raise


class Transport:
    """Locally activated HTTPS or explicit legacy loopback HTTP, without redirects."""
    def __init__(self, url, enrollment=None, socket_path=None):
        self.tls = None
        self.socket_path = socket_path
        p.require(socket_path is None or (enrollment is not None and type(socket_path) is str and socket_path.startswith("/") and len(socket_path.encode()) < 104), "local tunnel requires selected HTTPS enrollment")
        if enrollment is not None:
            p.require(url == enrollment["origin"], "endpoint differs from the locally activated origin")
            self.host, self.port = https_origin(url)
            self.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            self.tls.minimum_version = ssl.TLSVersion.TLSv1_3
            self.tls.hostname_checks_common_name = False
            self.tls.set_alpn_protocols(["http/1.1"])
            self.tls.load_verify_locations(cadata=enrollment["caPem"])
        else:
            match = re.fullmatch(r"http://127\.0\.0\.1:([1-9][0-9]{0,4})", url)
            p.require(match is not None, "HTTPS requires local enrollment; legacy HTTP requires literal loopback")
            self.host, self.port = "127.0.0.1", int(match[1])
            p.integer(self.port, 1, 65535)
        card = self.http("GET", "/.well-known/agent-card.json")
        interfaces = card.get("supportedInterfaces", [])
        p.require(type(interfaces) is list and any(type(i) is dict and i.get("url") == url + "/rpc"
                  and i.get("protocolBinding") == "JSONRPC" and i.get("protocolVersion") == "1.0"
                  for i in interfaces), "provider does not advertise the pinned A2A interface")
        self.skills = {}
        for skill in card.get("skills", []):
            if skill.get("id") in ("quote", "accept", "status", "review", "delivery", "resolve"):
                p.require(skill["id"] not in self.skills, "ambiguous advertised skill")
                self.skills[skill["id"]] = skill["id"]

    def http(self, method, path, body=None, headers=None):
        connection = (http.client.HTTPSConnection(self.host, self.port, timeout=HTTP_TIMEOUT_SECONDS, context=self.tls)
                      if self.tls else http.client.HTTPConnection(self.host, self.port, timeout=HTTP_TIMEOUT_SECONDS))
        if self.socket_path is not None:
            connection = UnixHttpsConnection(self.host, self.port, self.tls, self.socket_path)
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
        if self.tls:
            p.require(all(grant.get("dpop_required") is True for grant in cap["scope"]["grants"]),
                      "HTTPS credentials must require proof of possession")
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
    identity, peers = key(state), configured_peers(state)
    p.fields(peers, ("buyer", "provider"))
    p.require(identity.public_key().public_bytes_raw().hex() == peers["buyer"], "buyer identity differs from configured peer")
    return identity, peers


def request(state, url, tool, args, signed=None):
    identity, peers = context(state)
    connection = configured_connection(state)
    session = connection["session"] if connection else read(Path(state) / "session.json")
    cap = args["acceptance"]["ask"]["body"]["tokenOffer"] if tool == "review" else session
    if signed is None:
        signed = any(grant.get("dpop_required") is True for grant in cap["scope"]["grants"])
    egress = Path(state) / "egress.json"
    local_socket = None
    if egress.exists():
        local_socket = p.fields(read(egress), ("socket",))["socket"]
    return Transport(url, connection, local_socket).invoke(tool, args, cap, peers, identity if signed else None)


def https_origin(value):
    p.require(type(value) is str and all(33 <= ord(c) <= 126 for c in value), "HTTPS origin must be visible ASCII")
    parsed = urlsplit(value)
    p.require(parsed.scheme == "https" and parsed.hostname and parsed.username is None and parsed.password is None
              and not parsed.path and not parsed.query and not parsed.fragment
              and value == "https://" + parsed.netloc and parsed.netloc == parsed.netloc.lower()
              and not any(c in parsed.netloc for c in ("%", "\\", " ", "\t", "\r", "\n")),
              "HTTPS origin must be canonical and contain no credentials or route")
    port = parsed.port if parsed.port is not None else 443
    p.integer(port, 1, 65535)
    authority = "[" + parsed.hostname + "]" if ":" in parsed.hostname else parsed.hostname
    authority += ":" + str(port) if port != 443 else ""
    p.require(parsed.netloc == authority, "HTTPS authority is not canonical")
    return parsed.hostname, port


def verify_enrollment(value, provider, buyer, origin):
    body = p.envelope(value, provider)
    modern = body.get("schema") == "chio.example.https-enrollment.v3"
    fields = ("schema", "profiles" if modern else "profile", "buyer", "provider", "origin", "caPem", "session")
    p.fields(body, fields + (("subcontractPromisor",) if modern else ()))
    if modern and body["subcontractPromisor"] is not None:
        p.hex_bytes(body["subcontractPromisor"])
        p.require(body["subcontractPromisor"] not in (provider, buyer), "enrollment confuses promisor and agent roles")
    import subcontract
    profiles = body["profiles"] if modern else [body["profile"]]
    p.require(body["schema"] in ("chio.example.https-enrollment.v1", "chio.example.https-enrollment.v2", "chio.example.https-enrollment.v3")
              and profiles in ([p.PROFILE], [p.PROFILE, subcontract.PROFILE]) and (modern or profiles == [p.PROFILE])
              and body["buyer"] == buyer and body["provider"] == provider and body["origin"] == origin,
              "enrollment changes configured identity, origin or work profiles")
    https_origin(origin)
    p.require(type(body["caPem"]) is str and len(body["caPem"].encode()) <= 64 * 1024, "TLS trust material exceeds profile")
    session = body["session"]
    p.fields(session, ("schema", "id", "issuer", "subject", "scope", "issued_at", "expires_at", "signature"))
    p.require(session["schema"] == "chio.capability.v1" and session["issuer"] == provider
              and session["subject"] == buyer, "enrollment credential changes authority")
    p.integer(session["issued_at"], 1)
    p.require(type(session["id"]) is str and 1 <= len(session["id"]) <= 256, "invalid enrollment credential id")
    p.integer(session["expires_at"], session["issued_at"] + 1)
    p.verify_signature({k: v for k, v in session.items() if k != "signature"}, session["signature"], provider)
    expected = {"grants": [{"server_id": p.SERVER, "tool_name": tool, "operations": ["invoke"],
                            "constraints": [{"type": "max_args_size", "value": 256 * 1024}], "dpop_required": True}
                           for tool in (("quote", "accept", "status", "delivery") if body["schema"].endswith(".v1")
                                        else ("quote", "accept", "status", "delivery", "resolve"))]}
    p.require(p.same(session["scope"], expected), "enrollment widens the negotiation authority")
    return body


def configured_connection(state):
    file = Path(state) / "connection.json"
    if not file.exists():
        return None
    value = read(file)
    p.fields(value, ("provider", "origin", "enrollment"))
    return verify_enrollment(value["enrollment"], value["provider"],
                             key(state).public_key().public_bytes_raw().hex(), value["origin"])


def configured_peers(state):
    connection = configured_connection(state)
    return {name: connection[name] for name in ("buyer", "provider")} if connection else read(Path(state) / "peers.json")


def enroll(state, provider, origin, value):
    identity = key(state).public_key().public_bytes_raw().hex()
    body = verify_enrollment(value, provider, identity, origin)
    p.integer(int(time.time()), body["session"]["issued_at"], body["session"]["expires_at"] - 1)
    # Parse the explicitly selected trust roots before making them active.
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    tls.load_verify_locations(cadata=body["caPem"])
    file = Path(state) / "connection.json"
    if file.exists() or (Path(state) / "peers.json").exists():
        p.require(configured_peers(state) == {"buyer": identity, "provider": provider},
                  "existing state belongs to different peers")
    temporary = Path(state) / ("connection-" + secrets.token_hex(16) + ".tmp")
    try:
        fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(p.canonical({"provider": provider, "origin": origin, "enrollment": value}))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, file)
        fd = os.open(state, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        temporary.unlink(missing_ok=True)
    return {"buyer": identity, "provider": provider, "origin": origin, "senderConstrained": True}


def crash():
    os.kill(os.getpid(), signal.SIGKILL)
    raise p.ProtocolError("crash injection did not terminate the buyer")


def negotiate(state, url, before_send=False):
    identity, peers = context(state)
    a = p.agreement(read(Path(state) / "agreement.json"), peers)
    connection = configured_connection(state)
    if connection:
        profiles = connection.get("profiles", [connection.get("profile")])
        p.require(a["profile"] in profiles, "selected provider does not support required work profile")
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
                permit_file = Path(state) / "subcontract-permit.json"
                promisor = connection.get("subcontractPromisor") if connection else None
                if permit_file.exists():
                    import subcontract
                    p.require(promisor is not None, "provider did not activate delegated procurement")
                    quote["subcontractPermit"] = read(permit_file)
                    subcontract.verify_permit(quote["subcontractPermit"], a, promisor)
                p.require(("subcontractPermit" in quote) == (promisor is not None), "procurement requires a receiver-accepted permit")
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
        p.require(db.execute("SELECT 1 FROM incidents WHERE job=?", (job,)).fetchone() is None,
                  "recorded incident requires separate resolution authority")
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


def commit_incident(db, job, work, artifact, peers):
    operation_id = incident.verify(work, artifact, peers)
    p.require(work["acceptance"]["quote"]["agreement"]["jobId"] == job, "incident changes local job id")
    with transaction(db):
        row = db.execute("SELECT request,delivery,attempted FROM jobs WHERE job=?", (job,)).fetchone()
        p.require(row is not None and row["attempted"] == 1 and row["delivery"] is None
                  and p.same(p.load_json(row["request"]), work), "incident has no unresolved local work attempt")
        prior = db.execute("SELECT operation_id,artifact FROM incidents WHERE job=?", (job,)).fetchone()
        if prior:
            p.require(prior["operation_id"] == operation_id and p.same(p.load_json(prior["artifact"]), artifact),
                      "incident conflicts with retained evidence")
        else:
            db.execute("INSERT INTO incidents VALUES(?,?,?)", (job, operation_id, p.canonical(artifact)))


def incident_summary(db, work, artifact, peers):
    operation_id = incident.verify(work, artifact, peers)
    summary = {**account(db), "request": work, "incident": artifact, "operationId": operation_id,
            "creditProfile": p.CREDIT, "outcome": incident.UNKNOWN, "paymentResolution": "required",
            "workExecuted": None, "buyerVerified": False, "incidentVerified": True,
            "localCreditSettled": False, "externalFundsTransferred": False}
    job = work["acceptance"]["quote"]["agreement"]["jobId"]
    row = db.execute("SELECT intent,receipt FROM unknown_resolutions WHERE job=?", (job,)).fetchone()
    if row and row["receipt"] is not None:
        public = {"request": work, "incident": artifact, "consent": p.load_json(row["intent"]), "receipt": p.load_json(row["receipt"])}
        resolution.verify(public, peers)
        summary.update(paymentResolution="released_by_agreement", localCreditSettled=True, release=public)
    return summary


def retain_release_intent(db, job, work, artifact, intent, peers, at):
    resolution.consent(work, artifact, intent, peers, at)
    with transaction(db):
        row = db.execute("SELECT j.request,j.delivery,i.artifact FROM jobs j JOIN incidents i ON i.job=j.job WHERE j.job=? AND j.attempted=1", (job,)).fetchone()
        p.require(row and row["delivery"] is None and p.same(p.load_json(row["request"]), work)
                  and p.same(p.load_json(row["artifact"]), artifact), "release has no matching local incident")
        # A competing process may already have selected another live offer. It
        # wins this local CAS; only that retained consent can ever be sent.
        db.execute("INSERT OR IGNORE INTO unknown_resolutions(job,intent) VALUES(?,?)", (job, p.canonical(intent)))
        return p.load_json(db.execute("SELECT intent FROM unknown_resolutions WHERE job=?", (job,)).fetchone()[0])


def commit_release(db, job, public, peers):
    operation_id = resolution.verify(public, peers)
    p.require(public["request"]["acceptance"]["quote"]["agreement"]["jobId"] == job, "release changes local job")
    with transaction(db):
        row = db.execute("SELECT u.intent,u.receipt,j.request,j.delivery,i.artifact,i.operation_id FROM unknown_resolutions u JOIN jobs j ON j.job=u.job JOIN incidents i ON i.job=u.job WHERE u.job=?", (job,)).fetchone()
        p.require(row and row["delivery"] is None and row["operation_id"] == operation_id
                  and p.same(p.load_json(row["intent"]), public["consent"])
                  and p.same(p.load_json(row["request"]), public["request"])
                  and p.same(p.load_json(row["artifact"]), public["incident"]), "release does not bind locally retained intent")
        if row["receipt"] is not None:
            p.require(p.same(p.load_json(row["receipt"]), public["receipt"]), "release receipt changed after accounting")
            return
        db.execute("INSERT INTO resolved_reservations VALUES(?,?)", (job, operation_id))
        db.execute("UPDATE unknown_resolutions SET receipt=? WHERE job=?", (p.canonical(public["receipt"]), job))
        db.execute("UPDATE account SET available=available+(SELECT amount FROM reservations WHERE job=?)", (job,))


def resolve(state, url, fault=""):
    peers = configured_peers(state)
    db = connect(state)
    try:
        rows = db.execute("SELECT j.job,j.request,i.artifact FROM jobs j JOIN incidents i ON i.job=j.job").fetchall()
        p.require(len(rows) == 1, "resolution requires one retained incident in this profile")
        row = rows[0]
        job, work, artifact = row["job"], p.load_json(row["request"]), p.load_json(row["artifact"])
        retained = db.execute("SELECT intent,receipt FROM unknown_resolutions WHERE job=?", (job,)).fetchone()
        if retained and retained["receipt"] is not None:
            return incident_summary(db, work, artifact, peers)
        if retained:
            intent = p.load_json(retained["intent"])
        else:
            offer = payload(request(state, url, "resolve", {"action": "offer", "work": work}))
            at = time.time_ns() // 1_000_000
            intent = resolution.countersign(work, artifact, offer, peers, key(state), at)
            intent = retain_release_intent(db, job, work, artifact, intent, peers, at)
        if fault == "--crash-after-intent":
            crash()
        receipt = payload(request(state, url, "resolve", {"action": "accept", "work": work, "consent": intent}))
        public = {"request": work, "incident": artifact, "consent": intent, "receipt": receipt}
        resolution.verify(public, peers)
        if fault == "--crash-after-check":
            crash()
        commit_release(db, job, public, peers)
        return incident_summary(db, work, artifact, peers)
    finally:
        db.close()


def work(state, url, fault=""):
    accepted = negotiate(state, url)
    peers = configured_peers(state)
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
        retained_incident = db.execute("SELECT artifact FROM incidents WHERE job=?", (job,)).fetchone()
        if retained_incident:
            return incident_summary(db, work, p.load_json(retained_incident[0]), peers)
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
            if delivery.get("schema") == incident.SCHEMA:
                incident.verify(work, delivery, peers)
                if fault == "--crash-after-check":
                    crash()
                commit_incident(db, job, work, delivery, peers)
                return incident_summary(db, work, delivery, peers)
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
        case ["probe-sandbox", state, origin]:
            host, port = https_origin(origin)
            connected = False
            try:
                with socket.create_connection((host, port), timeout=0.5):
                    connected = True
            except OSError:
                pass
            return {"directTcpConnected": connected, "agentKey": key(state).public_key().public_bytes_raw().hex(),
                    "parentFilesystemReadable": Path("/home/connor/backbay/arc").exists()}
        case ["snapshot", state]:
            return snapshot(state)
        case ["enroll", state, provider, origin, enrollment]:
            return enroll(state, provider, origin, read(enrollment))
        case ["buyer", state, url, *flags] if not flags or flags == ["--crash-before-send"]:
            negotiate(state, url, bool(flags))
            return snapshot(state)
        case ["work", state, url, *flags] if not flags or flags in (["--crash-after-check"], ["--crash-before-work"]):
            return work(state, url, flags[0] if flags else "")
        case ["request", state, url, tool, file]:
            return request(state, url, tool, read(file))
        case ["review-request", state, url, file, proof] if proof in ("signed", "missing"):
            return request(state, url, "review", read(file), proof == "signed")
        case ["resolve", state, url, *flags] if not flags or flags in (["--crash-after-check"], ["--crash-after-intent"]):
            return resolve(state, url, flags[0] if flags else "")
        case ["verify-release", peers, public]:
            operation_id = resolution.verify(read(public), read(peers))
            return {"releaseVerified": True, "operationId": operation_id, "workExecuted": None,
                    "localCreditSettled": True, "externalFundsTransferred": False}
        case ["verify-work", peers, public]:
            value = read(public)
            rejected, receipt_id = review.terminal(value["request"], value["delivery"], read(peers))
            return {"buyerVerified": True, "reviewRejected": rejected, "receiptId": receipt_id, "externalFundsTransferred": False}
        case ["verify-incident", peers, public]:
            value = read(public)
            operation_id = incident.verify(value["request"], value["incident"], read(peers))
            return {"incidentVerified": True, "operationId": operation_id, "workExecuted": None,
                    "localCreditSettled": False, "externalFundsTransferred": False}
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
