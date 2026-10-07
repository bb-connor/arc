"""Section 10 metrics from item logs, local slot-wait records and CI history."""

from __future__ import annotations

import json
import re
import statistics
from datetime import datetime, timedelta
from pathlib import Path

from . import clock, items
from .store import Store

LOG_LINE = re.compile(r"^- (\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ) (\S+): (.*)$", re.M)


def events(item: items.Item) -> list[tuple[datetime, str, str]]:
    return [(clock.parse(ts), who, text) for ts, who, text in LOG_LINE.findall(item.body)]


def integrated_since(store: Store, since: datetime) -> list[str]:
    everything, _ = items.all_items(store)
    return sorted(
        i.id for i in everything
        if any(at >= since and text.startswith("status ready -> integrated") for at, _, text in events(i))
    )


def bounce_rate(store: Store, since: datetime) -> float | None:
    everything, _ = items.all_items(store)
    verdicts = [text for i in everything for at, _, text in events(i) if at >= since and text.startswith("verdict ")]
    if not verdicts:
        return None
    return sum(v.startswith("verdict changes") for v in verdicts) / len(verdicts)


def slot_wait_median(log_path: Path, since: datetime) -> float | None:
    if not log_path.exists():
        return None
    waits = []
    for line in log_path.read_text().splitlines():
        record = json.loads(line)
        if clock.parse(record["at"]) >= since:
            waits.append(float(record["waited_s"]))
    return statistics.median(waits) if waits else None


def report(store: Store, *, hours: int, slot_log: Path, ci_green: float | None) -> str:
    since = clock.now() - timedelta(hours=hours)
    done = integrated_since(store, since)
    bounce = bounce_rate(store, since)
    wait = slot_wait_median(slot_log, since)
    lines = [
        f"Window: last {hours}h",
        f"- Items integrated: {len(done)} ({', '.join(done) or 'none'})",
        f"- Review bounce rate: {'n/a' if bounce is None else f'{bounce:.0%}'} (target under 30%)",
        f"- Median build-slot wait: {'n/a' if wait is None else f'{wait / 60:.1f} min'} (target under 20 min)",
        f"- Hosted CI green rate on beta-next: {'n/a' if ci_green is None else f'{ci_green:.0%}'} (target 80%+)",
    ]
    return "\n".join(lines)
