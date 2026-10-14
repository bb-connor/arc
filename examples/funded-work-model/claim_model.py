"""Trusted serial reference model; no signatures, custody or chain finality.

Source deposits are fixed for one exploration. Refunded cash is reported as
withdrawn, not silently redeposited. Execution uncertainty is independent of
the monetary state. Failed transfers model an atomic reverted transaction.
"""

from dataclasses import dataclass, field

MAX_UNITS = 2**53 - 1


@dataclass(frozen=True)
class Terms:
    source: str
    recipient: str
    verifier: str
    amount: int
    submit_by: int
    challenge_until: int
    resolve_by: int
    refund_after: int


@dataclass
class Job:
    terms: Terms
    state: str = "Funded"
    commitment: str = ""
    decision: str = ""
    accepted: bool = False
    execution_unknown: bool = False
    paid: int = 0
    refunded: int = 0
    locked: int = field(init=False)

    def __post_init__(self):
        self.locked = self.terms.amount


@dataclass
class ClaimLedger:
    deposits: dict[str, int]
    jobs: dict[str, Job] = field(default_factory=dict, init=False)
    available: dict[str, int] = field(default_factory=dict, init=False)

    def __post_init__(self):
        if any(not key or type(value) is not int or not 0 <= value <= MAX_UNITS
               for key, value in self.deposits.items()):
            raise ValueError("invalid model funding source")
        self.deposits = dict(self.deposits)
        self.available = dict(self.deposits)

    def accounts(self, source):
        """Return available, paid, refunded, locked for one source."""
        paid = refunded = locked = 0
        for job in self.jobs.values():
            if job.terms.source != source:
                continue
            paid += job.paid
            refunded += job.refunded
            locked += job.locked
        return self.available[source], paid, refunded, locked

    def fund(self, job_id, terms, *, now):
        deadlines = (terms.submit_by, terms.challenge_until, terms.resolve_by, terms.refund_after)
        if (not job_id or job_id in self.jobs or terms.source not in self.deposits
                or not terms.recipient or not terms.verifier
                or terms.source == terms.recipient
                or terms.verifier in (terms.source, terms.recipient)
                or type(terms.amount) is not int or not 0 < terms.amount <= MAX_UNITS
                or any(type(t) is not int or not 0 <= t <= MAX_UNITS for t in deadlines)
                or not now < deadlines[0] < deadlines[1] < deadlines[2] < deadlines[3]
                or terms.amount > self.accounts(terms.source)[0]):
            return False
        self.jobs[job_id] = Job(terms)
        self.available[terms.source] -= terms.amount
        return True

    def submit(self, job_id, actor, commitment, *, now):
        job = self.jobs.get(job_id)
        if job is None or actor != job.terms.recipient or not commitment:
            return False
        if job.commitment:
            return job.commitment == commitment
        if job.state != "Funded" or now > job.terms.submit_by:
            return False
        job.commitment = commitment
        job.state = "Submitted"
        return True

    def decide(self, job_id, actor, decision, accepted, *, now):
        job = self.jobs.get(job_id)
        if job is None or actor != job.terms.verifier or not decision or type(accepted) is not bool:
            return False
        if job.decision:
            return (job.decision, job.accepted) == (decision, accepted)
        if job.state != "Submitted" or not job.terms.challenge_until < now <= job.terms.resolve_by:
            return False
        job.decision = decision
        job.accepted = accepted
        job.state = "Payable" if accepted else "Rejected"
        return True

    def expire(self, job_id, *, now):
        job = self.jobs.get(job_id)
        if job is None:
            return False
        if job.state == "TimedOut":
            return True
        if job.state not in ("Funded", "Submitted") or now <= job.terms.refund_after:
            return False
        job.state = "TimedOut"
        return True

    def pay(self, job_id, actor, *, now, transfer_ok=True):
        job = self.jobs.get(job_id)
        if job is None or actor != job.terms.recipient or job.state != "Payable" or not transfer_ok:
            return False
        job.state = "Paid"
        job.paid += job.terms.amount
        job.locked = 0
        return True

    def refund(self, job_id, *, now, transfer_ok=True):
        job = self.jobs.get(job_id)
        if job is None or not transfer_ok:
            return False
        if job.state not in ("Rejected", "TimedOut"):
            if job.state not in ("Funded", "Submitted") or now <= job.terms.refund_after:
                return False
        job.state = "Refunded"
        job.refunded += job.terms.amount
        job.locked = 0
        return True

    def mark_unknown(self, job_id):
        self.jobs[job_id].execution_unknown = True
