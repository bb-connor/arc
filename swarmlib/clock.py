"""Clock helpers. SWARM_FAKE_NOW (ISO-8601 UTC) pins the clock for tests."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def now() -> datetime:
    fake = os.environ.get("SWARM_FAKE_NOW")
    if fake:
        return parse(fake)
    return datetime.now(timezone.utc).replace(microsecond=0)


def fmt(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime(FORMAT)


def parse(text: str) -> datetime:
    return datetime.strptime(text, FORMAT).replace(tzinfo=timezone.utc)


def stamp(moment: datetime | None = None) -> str:
    """Compact, sortable timestamp for file names."""
    return (moment or now()).strftime("%Y%m%dT%H%M%SZ")


def minutes(count: float) -> timedelta:
    return timedelta(minutes=count)
