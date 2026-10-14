"""Ordinary trusted SQLite escrow, compared with retained reference-model traces.

Research comparator, not a network service: symbolic actors are authenticated by
assumption, money is logical units, one administrator owns the SQL connection.
No Chio authorization/kernel code is imported. Replay is sequential; this makes
no claim about hostile database owners, disk crashes, or production payments.
"""
import argparse
import json
import sqlite3
from pathlib import Path

MAX_UNITS = 2**53 - 1


class SqlEscrow:
    def __init__(self, deposits):
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            CREATE TABLE source(id TEXT PRIMARY KEY, deposit INTEGER, available INTEGER);
            CREATE TABLE work(id TEXT PRIMARY KEY, source TEXT, recipient TEXT, verifier TEXT,
                amount INTEGER, submit_by INTEGER, challenge_until INTEGER,
                resolve_by INTEGER, refund_after INTEGER, state TEXT DEFAULT 'Funded',
                commitment TEXT DEFAULT '', decision TEXT DEFAULT '', accepted INTEGER DEFAULT 0,
                unknown INTEGER DEFAULT 0, paid INTEGER DEFAULT 0, refunded INTEGER DEFAULT 0,
                locked INTEGER);
        """)
        for name, value in deposits.items():
            if not name or type(value) is not int or not 0 <= value <= MAX_UNITS:
                raise ValueError("invalid funding source")
            self.db.execute("INSERT INTO source VALUES (?,?,?)", (name, value, value))
        self.db.commit()

    def close(self):
        self.db.close()

    def fund(self, job, terms, *, now):
        deadlines = (terms.submit_by, terms.challenge_until, terms.resolve_by, terms.refund_after)
        if (not job or not terms.recipient or not terms.verifier
                or terms.source == terms.recipient or terms.verifier in (terms.source, terms.recipient)
                or type(terms.amount) is not int or not 0 < terms.amount <= MAX_UNITS
                or any(type(t) is not int or not 0 <= t <= MAX_UNITS for t in deadlines)
                or not now < deadlines[0] < deadlines[1] < deadlines[2] < deadlines[3]):
            return False
        with self.db:
            if self.db.execute("SELECT 1 FROM work WHERE id=?", (job,)).fetchone():
                return False
            changed = self.db.execute("UPDATE source SET available=available-? WHERE id=? AND available>=?",
                                      (terms.amount, terms.source, terms.amount)).rowcount
            if not changed:
                return False
            self.db.execute("""INSERT INTO work
                (id,source,recipient,verifier,amount,submit_by,challenge_until,resolve_by,refund_after,locked)
                VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (job, terms.source, terms.recipient, terms.verifier, terms.amount, *deadlines, terms.amount))
        return True

    def submit(self, job, actor, commitment, *, now):
        if not commitment:
            return False
        with self.db:
            old = self.db.execute("SELECT * FROM work WHERE id=? AND recipient=?", (job, actor)).fetchone()
            if old is None:
                return False
            if old["commitment"]:
                return old["commitment"] == commitment
            return bool(self.db.execute("""UPDATE work SET state='Submitted', commitment=?
                WHERE id=? AND state='Funded' AND submit_by>=?""", (commitment, job, now)).rowcount)

    def decide(self, job, actor, decision, accepted, *, now):
        if not decision or type(accepted) is not bool:
            return False
        with self.db:
            old = self.db.execute("SELECT * FROM work WHERE id=? AND verifier=?", (job, actor)).fetchone()
            if old is None:
                return False
            if old["decision"]:
                return old["decision"] == decision and bool(old["accepted"]) == accepted
            return bool(self.db.execute("""UPDATE work SET state=?, decision=?, accepted=?
                WHERE id=? AND state='Submitted' AND challenge_until<? AND resolve_by>=?""",
                ('Payable' if accepted else 'Rejected', decision, accepted, job, now, now)).rowcount)

    def expire(self, job, *, now):
        with self.db:
            old = self.db.execute("SELECT state FROM work WHERE id=?", (job,)).fetchone()
            if old and old[0] == 'TimedOut':
                return True
            return bool(self.db.execute("""UPDATE work SET state='TimedOut'
                WHERE id=? AND state IN ('Funded','Submitted') AND refund_after<?""", (job, now)).rowcount)

    def pay(self, job, actor, *, now, transfer_ok=True):
        if not transfer_ok:
            return False
        with self.db:
            return bool(self.db.execute("""UPDATE work SET state='Paid', paid=amount, locked=0
                WHERE id=? AND recipient=? AND state='Payable'""", (job, actor)).rowcount)

    def refund(self, job, *, now, transfer_ok=True):
        if not transfer_ok:
            return False
        with self.db:
            return bool(self.db.execute("""UPDATE work SET state='Refunded', refunded=amount, locked=0
                WHERE id=? AND (state IN ('Rejected','TimedOut') OR
                (state IN ('Funded','Submitted') AND refund_after<?))""", (job, now)).rowcount)

    def mark_unknown(self, job):
        with self.db:
            self.db.execute("UPDATE work SET unknown=1 WHERE id=?", (job,))

    def snapshot(self):
        result = {}
        for row in self.db.execute("SELECT * FROM work ORDER BY id"):
            result[row['id']] = {key: bool(row[key]) if key in ('accepted','unknown') else row[key]
                                for key in ('state','commitment','decision','accepted','unknown','paid','refunded','locked')}
        return result

    def accounts(self, source):
        available = self.db.execute("SELECT available FROM source WHERE id=?", (source,)).fetchone()[0]
        sums = self.db.execute("SELECT COALESCE(SUM(paid),0),COALESCE(SUM(refunded),0),COALESCE(SUM(locked),0) FROM work WHERE source=?", (source,)).fetchone()
        return (available, *tuple(sums))


def compare_corpus(path):
    # Terms are plain immutable test inputs. No reference model transition is used.
    from types import SimpleNamespace
    corpus = json.loads(Path(path).read_text())
    mismatches = []
    steps = 0
    outcomes = set()
    for index, trace in enumerate(corpus['traces']):
        rail = SqlEscrow({'A': 3, 'B': 2})
        for name, source, recipient, amount in [('parent','A','B',3), ('child','B','C',2)]:
            assert rail.fund(name, SimpleNamespace(source=source, recipient=recipient, verifier='V', amount=amount,
                             submit_by=2, challenge_until=4, resolve_by=6, refund_after=8), now=0)
        try:
            for step in trace['steps']:
                if step['op'] == 'advance':
                    continue
                op, job, now = step['op'], step['job'], step['time']
                if op == 'submit':
                    ok = rail.submit(job, step['actor'], step['commitment'], now=now)
                elif op == 'decide':
                    ok = rail.decide(job, step['actor'], step['decision'], step['accepted'], now=now)
                elif op == 'pay':
                    ok = rail.pay(job, step['actor'], now=now)
                elif op in ('refund','expire'):
                    ok = getattr(rail, op)(job, now=now)
                elif op == 'unknown':
                    rail.mark_unknown(job)
                    ok = True
                else:
                    raise ValueError(op)
                steps += 1
                actual = rail.snapshot()
                if ok != step['ok'] or actual != step['expected']:
                    mismatches.append(dict(trace=index, step=step, ok=ok, actual=actual))
                for source, deposited in [('A',3),('B',2)]:
                    account = rail.accounts(source)
                    if min(account) < 0 or sum(account) != deposited:
                        mismatches.append(dict(trace=index, error='conservation', account=account))
                outcomes.update(v['state'] for v in actual.values())
        finally:
            rail.close()
    return dict(schema='chio.paper.matched-escrow.v1', traces=len(corpus['traces']), checked_steps=steps,
                states_seen=sorted(outcomes), mismatches=mismatches,
                scope='sequential trusted SQL rail; symbolic authenticated actors; same-author implementation',
                conclusion='same observable monetary behavior on the finite trace corpus' if not mismatches else 'mismatch')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--corpus', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = compare_corpus(args.corpus)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
    raise SystemExit(bool(result['mismatches']))
