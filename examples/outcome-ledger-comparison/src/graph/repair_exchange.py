"""Trusted local exchange fixture. Credits are test units, not external money.

This worker has private settlement access. It is not an authenticated network
API, a zero-knowledge verifier, or a replacement for the native repair checker.
"""

import hashlib
import json
import os
from pathlib import Path
import signal
import sqlite3
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encoded(value):
    # Only fixed ASCII names and safe integers occur in offer metadata.
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def offer_at(directory):
    return json.loads((directory / "offer.json").read_bytes())


def decrypt(offer, key):
    if digest(key) != offer["keySha256"]:
        raise ValueError("wrong decryption key")
    plaintext = AESGCM(key).decrypt(
        bytes.fromhex(offer["nonce"]),
        bytes.fromhex(offer["ciphertext"]),
        encoded(offer["terms"]),
    )
    if digest(plaintext) != offer["artifactSha256"]:
        raise ValueError("wrong artifact digest")
    return plaintext


def connect(directory):
    connection = sqlite3.connect(directory / "settlement.sqlite", isolation_level=None)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=FULL")
    connection.execute("PRAGMA busy_timeout=10000")
    return connection


def snapshot(connection):
    offer_hash, state, price, key = connection.execute(
        "SELECT offer_hash,state,price,released_key FROM trade"
    ).fetchone()
    balances = dict(connection.execute("SELECT name,balance FROM accounts"))
    transitions = connection.execute(
        "SELECT count(*) FROM settlement_events"
    ).fetchone()[0]
    locked = price if state == "funded" else 0
    if sum(balances.values()) + locked != 100:
        raise ValueError("test credit conservation failed")
    if (key is not None) != (state == "settled"):
        raise ValueError("key released without settlement")
    return {
        "offerSha256": offer_hash,
        "state": state,
        "balances": balances,
        "locked": locked,
        "releasedKey": key,
        "settlementEvents": transitions,
    }


def crash(selected, point):
    if selected == point:
        print(f"EXCHANGE_KILL {point}", file=sys.stderr, flush=True)
        os.kill(os.getpid(), signal.SIGKILL)


def main():
    action, raw_directory, *options = sys.argv[1:]
    directory = Path(raw_directory)
    if action == "seal":
        key = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)
        terms = json.loads((directory / "terms.json").read_bytes())
        plaintext = (directory / "private-artifact.json").read_bytes()
        offer = {
            "terms": terms,
            "nonce": nonce.hex(),
            "ciphertext": AESGCM(key).encrypt(nonce, plaintext, encoded(terms)).hex(),
            "keySha256": digest(key),
            "artifactSha256": digest(plaintext),
        }
        with os.fdopen(
            os.open(
                directory / "private-key.bin",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            ),
            "wb",
        ) as stream:
            stream.write(key)
        write(directory / "offer.json", offer)
        print(json.dumps({"sealed": True, "offerSha256": digest(encoded(offer))}))
        return
    if action == "check-open":
        key = (directory / "private-key.bin").read_bytes()
        plaintext = decrypt(offer_at(directory), key)
        (directory / "checker-artifact.json").write_bytes(plaintext)
        print(json.dumps({"decryptedSha256": digest(plaintext)}))
        return
    if action == "receive":
        view = json.loads((directory / "settlement-view.json").read_bytes())
        offer = offer_at(directory)
        if view["state"] != "settled" or view["offerSha256"] != digest(encoded(offer)):
            raise ValueError("no settled delivery")
        plaintext = decrypt(offer, bytes.fromhex(view["releasedKey"]))
        (directory / "buyer-artifact.json").write_bytes(plaintext)
        print(json.dumps({"receivedSha256": digest(plaintext)}))
        return
    with connect(directory) as connection:
        if action == "fund":
            offer = offer_at(directory)
            terms = offer["terms"]
            price = terms["price"]
            if type(price) is not int or not 0 < price <= 100:
                raise ValueError("invalid test price")
            # The controller selects these roles, terms and offer before funding.
            if terms["buyer"] != "buyer" or terms["seller"] != "seller":
                raise ValueError("unselected test accounts")
            connection.executescript(
                "CREATE TABLE accounts(name TEXT PRIMARY KEY, balance INTEGER NOT NULL CHECK(balance>=0));"
                "CREATE TABLE trade(offer_hash TEXT PRIMARY KEY, offer TEXT NOT NULL, price INTEGER NOT NULL,"
                "state TEXT NOT NULL CHECK(state IN ('funded','settled','refunded')), released_key TEXT);"
                "CREATE TABLE settlement_events(kind TEXT NOT NULL);"
            )
            connection.execute("BEGIN IMMEDIATE")
            connection.executemany(
                "INSERT INTO accounts VALUES (?,?)",
                [("buyer", 100 - price), ("seller", 0)],
            )
            connection.execute(
                "INSERT INTO trade VALUES (?,?,?,'funded',NULL)",
                (digest(encoded(offer)), encoded(offer).decode(), price),
            )
            connection.commit()
        elif action in {"settle", "refund"}:
            connection.execute("BEGIN IMMEDIATE")
            offer_hash, stored, price, state = connection.execute(
                "SELECT offer_hash,offer,price,state FROM trade"
            ).fetchone()
            offer = offer_at(directory)
            if (
                offer_hash != digest(encoded(offer))
                or stored != encoded(offer).decode()
            ):
                raise ValueError("offer differs from funded trade")
            now = int(options[0])
            if action == "refund":
                if now < offer["terms"]["deadline"] or state != "funded":
                    raise ValueError("refund is not eligible")
                connection.execute(
                    "UPDATE accounts SET balance=balance+? WHERE name='buyer'", (price,)
                )
                connection.execute("UPDATE trade SET state='refunded'")
                connection.execute("INSERT INTO settlement_events VALUES ('refund')")
                connection.commit()
            else:
                if now >= offer["terms"]["deadline"] or state == "refunded":
                    raise ValueError("settlement is not eligible")
                key = (directory / options[1]).read_bytes()
                decrypt(offer, key)
                fault = options[2] if len(options) > 2 else "none"
                if state == "funded":
                    connection.execute(
                        "UPDATE accounts SET balance=balance+? WHERE name='seller'",
                        (price,),
                    )
                    crash(fault, "after_credit_before_commit")
                    connection.execute(
                        "UPDATE trade SET state='settled',released_key=?", (key.hex(),)
                    )
                    connection.execute(
                        "INSERT INTO settlement_events VALUES ('settle')"
                    )
                    connection.commit()
                    crash(fault, "after_commit_before_reply")
                else:
                    connection.rollback()
        elif action != "view":
            raise ValueError("unknown exchange action")
        print(json.dumps(snapshot(connection), sort_keys=True))


if __name__ == "__main__":
    main()
