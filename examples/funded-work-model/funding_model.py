"""Serial allocation model. No signatures, monetary terminals or real funds."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Claim:
    source: str
    job: str
    recipient: str
    units: int


class AllocationAuthority:
    def __init__(self, source: str, deposited: int):
        if not source or type(deposited) is not int or deposited < 0:
            raise ValueError("invalid model funding source")
        self.source = source
        self.available = deposited
        self.claims: dict[str, Claim] = {}

    def reserve(self, claim: Claim) -> bool:
        if (
            claim.source != self.source
            or not claim.job
            or not claim.recipient
            or type(claim.units) is not int
            or claim.units <= 0
        ):
            return False
        existing = self.claims.get(claim.job)
        if existing is not None:
            return existing == claim
        if claim.units > self.available:
            return False
        self.available -= claim.units
        self.claims[claim.job] = claim
        return True
