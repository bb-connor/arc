"""`swarm` command line. Exit 0 ok, 1 nothing/negative result, 2 refused or failed."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from . import agents, board, build, ci, claims, clock, gitio, items, lifecycle, merge, metrics, msgs, reviews, secrets, train, watch, worktree
from .store import Store, SwarmError, halt, record, resume, set_config


def _split(values: list[str] | None) -> list[str]:
    return [part for value in values or [] for part in value.replace(",", " ").split()]


def _env_path(name: str, default: str) -> Path:
    return Path(os.environ.get(name, default)).expanduser()


def cmd_register(store: Store, a: argparse.Namespace) -> int:
    agents.register(store, agent_id=a.id or store.agent, machine=a.machine, vendor=a.vendor, role=a.role,
                    model=a.model, effort=a.effort, tiers=_split(a.tiers))
    return 0


def cmd_item_new(store: Store, a: argparse.Namespace) -> int:
    items.new(store, item_id=a.id, title=a.title, severity=a.severity, wave=a.wave, tier=a.tier,
              paths=_split(a.paths), depends_on=_split(a.depends), estimate_hours=a.estimate,
              assignee=a.assignee, brief=Path(a.brief_file).read_text())
    return 0


def cmd_list(store: Store, a: argparse.Namespace) -> int:
    store.sync()
    everything, broken = items.all_items(store)
    for item in everything:
        if (a.status and item.status != a.status) or (a.owner and item.meta["owner"] != a.owner):
            continue
        print(f"{item.id}\t{item.meta['severity']}\t{item.status}\t{item.meta['owner'] or '-'}\t{item.meta['title']}")
    for name in broken:
        print(f"UNPARSEABLE\titems/{name}", file=sys.stderr)
    return 0


def cmd_brief(store: Store, a: argparse.Namespace) -> int:
    print(lifecycle.brief(store, a.item))
    return 0


def cmd_claim(store: Store, a: argparse.Namespace) -> int:
    claims.claim(store, a.item, _split(a.paths), share=a.share, steal=a.steal, ttl=a.ttl)
    return 0


def cmd_release(store: Store, a: argparse.Namespace) -> int:
    claims.release(store, a.item)
    return 0


def cmd_reassign(store: Store, a: argparse.Namespace) -> int:
    claims.reassign(store, a.item, a.owner, ttl=a.ttl)
    return 0


def cmd_heartbeat(store: Store, a: argparse.Namespace) -> int:
    claims.heartbeat(store)
    return 0


def cmd_status(store: Store, a: argparse.Namespace) -> int:
    lifecycle.status(store, a.item, a.status, a.note or "")
    return 0


def cmd_submit(store: Store, a: argparse.Namespace) -> int:
    commits = lifecycle.submit(store, a.item, Path(a.worktree or Path.cwd()), repo_url=worktree.repo_url(),
                               base_branch=store.config()["base_branch"])
    print(f"submitted {a.item} with {len(commits)} commits")
    return 0


def cmd_verdict(store: Store, a: argparse.Namespace) -> int:
    findings = Path(a.findings_file).read_text() if a.findings_file else ""
    lifecycle.verdict(store, a.item, a.decision, findings)
    return 0


def cmd_send(store: Store, a: argparse.Namespace) -> int:
    body = Path(a.body_file).read_text() if a.body_file else (a.body or "")
    msgs.send(store, a.to, a.kind, a.item or "", a.subject, body)
    return 0


def cmd_inbox(store: Store, a: argparse.Namespace) -> int:
    found = msgs.inbox(store, include_seen=a.all, mark=not a.peek)
    for message in found:
        print(f"== {message['sent']} {message['from']} -> {message['to']} [{message['kind']}] {message['item']}: {message['subject']}")
        print(message["body"].rstrip())
    return 0 if found else 1


def cmd_wait(store: Store, a: argparse.Namespace) -> int:
    found = lifecycle.wait(store, timeout=a.timeout, interval=a.interval, digest_every=a.digest)
    for line in found:
        print(line)
    return 0 if found else 1


def cmd_next(store: Store, a: argparse.Namespace) -> int:
    if store.role == "reviewer":
        picked = lifecycle.next_review(store)
    else:
        me = agents.load(store, store.agent) or {}
        picked = lifecycle.next_item(store, _split(a.tiers) or me.get("tiers") or ["mid"])
    if picked:
        print(picked)
    return 0 if picked else 1


def cmd_board(store: Store, a: argparse.Namespace) -> int:
    if a.write:
        board.write(store)
    else:
        store.sync()
        print(board.render(store))
    return 0


def cmd_metrics(store: Store, a: argparse.Namespace) -> int:
    store.sync()
    green = None
    if not a.no_ci:
        green = ci.green_rate(ci.default_runner, store.config()["base_branch"])
    print(metrics.report(store, hours=a.hours, slot_log=build.slot_dir() / "waits.log", ci_green=green))
    return 0


def cmd_build(store: Store, a: argparse.Namespace) -> int:
    command = a.command[1:] if a.command[:1] == ["--"] else a.command
    return build.run(command, item=a.item or "", build_class=a.build_class or build.class_for_role(store.role))


def cmd_prune_target(store: Store, a: argparse.Namespace) -> int:
    removed, freed, busy = build.prune_target(Path(a.target).expanduser(), older_than_hours=a.hours, dry_run=a.dry_run)
    verb = "would remove" if a.dry_run else "removed"
    print(f"{verb} {removed} files, {freed / 2**30:.1f} GB not accessed in {a.hours:g}h")
    for profile in busy:
        print(f"skipped {profile}: a cargo build holds its lock")
    return 0


def cmd_ci(store: Store, a: argparse.Namespace) -> int:
    store.sync()
    item = items.load(store, a.item)
    ref = a.ref or item.meta["branch"]
    if not ref:
        raise SwarmError(f"{a.item} has no branch yet; pass --ref")
    sha = ci.resolve_sha(ref, worktree.repo_url())
    runner = ci.default_runner
    ci.wait_for_capacity(runner, store.config()["ci_max_in_flight"])
    nonce = ci.dispatch(runner, item=a.item, target_ref=sha, packages=_split(a.packages),
                        test_filter=a.filter or "", features=a.features or "")
    run_id, url = ci.find_run(runner, nonce)
    print(url, flush=True)
    passed = ci.watch(runner, run_id)
    lifecycle.record_evidence(
        store, a.item,
        {"kind": "lane-test", "url": url, "conclusion": "success" if passed else "failure", "ref": ref, "sha": sha,
         "packages": _split(a.packages), "at": clock.fmt(clock.now())},
        ci_failed=not passed,
    )
    return 0 if passed else 1


def cmd_ci_busy(store: Store, a: argparse.Namespace) -> int:
    return 0 if ci.busy(ci.default_runner, a.branch or store.config()["base_branch"]) else 1


def cmd_import_reviews(store: Store, a: argparse.Namespace) -> int:
    created = reviews.import_reviews(store, ci.default_runner, a.pr)
    for item_id in created:
        print(item_id)
    return 0


def cmd_worktree(store: Store, a: argparse.Namespace) -> int:
    path = worktree.create(
        store, a.item, repo=_env_path("SWARM_REPO", "~/backbay/arc"), lanes=_env_path("SWARM_LANES", "~/lanes/swarm"),
        base_branch=store.config()["base_branch"], review=a.review,
    )
    print(path)
    return 0


def cmd_sweep(store: Store, a: argparse.Namespace) -> int:
    for item_id in lifecycle.sweep(store):
        print(item_id)
    return 0


def cmd_halt(store: Store, a: argparse.Namespace) -> int:
    halt(store, a.scope, a.reason)
    return 0


def cmd_resume(store: Store, a: argparse.Namespace) -> int:
    resume(store, a.scope)
    return 0


def cmd_config(store: Store, a: argparse.Namespace) -> int:
    set_config(store, a.key, a.value)
    return 0


def cmd_record(store: Store, a: argparse.Namespace) -> int:
    print(record(store, a.kind, a.name, Path(a.file).read_text()))
    return 0


def cmd_review_pr(store: Store, a: argparse.Namespace) -> int:
    if store.role not in ("conductor", "integrator"):
        raise SwarmError("only the integrator or the conductor requests a whole-PR review")
    info = merge.pull(ci.default_runner, a.pr)
    created = lifecycle.request_pr_review(store, a.pr, head=info["head"]["sha"], branch=info["head"]["ref"],
                                          author_vendor=a.author_vendor or store.vendor, base=info["base"]["ref"])
    print(f"PR{a.pr}: review {'requested' if created else 'already requested'} for {info['head']['sha'][:12]}")
    return 0


def cmd_merge_gate(store: Store, a: argparse.Namespace) -> int:
    sha, reasons = merge.gate(store, ci.default_runner, a.pr)
    for reason in reasons:
        print(reason)
    print(f"PR #{a.pr} at {sha[:12]}: {'blocked' if reasons else 'mergeable'}")
    return 1 if reasons else 0


def cmd_merge(store: Store, a: argparse.Namespace) -> int:
    sha = merge.merge(store, ci.default_runner, a.pr)
    print(f"merged PR #{a.pr} at {sha}")
    return 0


def cmd_check_train(store: Store, a: argparse.Namespace) -> int:
    store.sync()
    host = store.config()["train_host"]
    args = ((["--land"] if a.land else []) + (["--max-lanes", str(a.max_lanes)] if a.max_lanes else [])
            + (["--allow-red"] if a.allow_red else []))
    if host and host != os.environ.get("SWARM_MACHINE", "") and not a.local:
        return subprocess.call(train.remote_command(host, agent=store.agent, role=store.role, vendor=store.vendor, args=args))
    result = train.run_train(
        store, repo=_env_path("SWARM_REPO", "~/backbay/arc"), lanes_dir=_env_path("SWARM_LANES", "~/lanes/swarm"),
        repo_url=worktree.repo_url(), land=a.land, ci_runner=ci.default_runner if a.land else None,
        max_lanes=a.max_lanes, allow_red=a.allow_red,
    )
    print(f"train {result.train_id} on {result.base[:12] or '-'}: green {result.green or '-'}, red {result.red or '-'}, "
          f"conflicted {result.conflicted or '-'}")
    if result.landed:
        print(f"landed {result.landed[:12]}")
    for line in result.loose:
        print(f"unattributed: {line}")
    if result.note:
        print(result.note)
    return 1 if result.loose else 0


def cmd_watch(store: Store, a: argparse.Namespace) -> int:
    home = Path.home()
    if a.snapshot:
        print(json.dumps(watch.snapshot(home=home, minutes=a.minutes, keep=a.keep)))
        return 0
    hosts = [h for h in (a.hosts or os.environ.get("SWARM_WATCH_HOSTS") or "local").split(",") if h]

    def frame() -> str:
        snaps = watch.gather(hosts, local=lambda: watch.snapshot(home=home, minutes=a.minutes, keep=a.keep),
                             minutes=a.minutes, keep=a.keep)
        try:
            summary = watch.store_summary(store)
        except (SwarmError, gitio.GitError, OSError) as err:
            summary = {"items": {f"(store unavailable: {err})": 0}, "claims": [], "messages": []}
        width = shutil.get_terminal_size((160, 40)).columns
        return watch.render(snaps, summary, now=clock.now(), width=width, agent=a.agent or "", actions=a.keep,
                            minutes=a.minutes)

    if a.once:
        print(frame())
        return 0
    try:
        while True:
            text = frame()
            print("\033[H\033[2J" + text, flush=True)
            time.sleep(a.interval)
    except KeyboardInterrupt:
        return 0


def cmd_scan(store: Store, a: argparse.Namespace) -> int:
    dirty = False
    for name in a.files:
        for kind, line in secrets.scan(Path(name).read_text(errors="replace")):
            print(f"{name}:{line}: {kind}")
            dirty = True
    return 1 if dirty else 0


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="swarm", description="Chio swarm coordination")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("register", help="add or refresh an agent in agents/")
    s.add_argument("--id")
    s.add_argument("--machine", required=True)
    s.add_argument("--vendor", required=True, choices=agents.VENDORS)
    s.add_argument("--role", required=True, choices=agents.ROLES)
    s.add_argument("--model", required=True)
    s.add_argument("--effort", default="")
    s.add_argument("--tiers", nargs="*", default=["mid"])
    s.set_defaults(fn=cmd_register)

    s = sub.add_parser("item", help="conductor: create items")
    item_sub = s.add_subparsers(dest="item_command", required=True)
    n = item_sub.add_parser("new")
    n.add_argument("id")
    n.add_argument("--title", required=True)
    n.add_argument("--severity", default="P2", choices=items.SEVERITIES)
    n.add_argument("--wave", type=int, default=1)
    n.add_argument("--tier", default="mid", choices=agents.TIERS)
    n.add_argument("--paths", nargs="*", default=[])
    n.add_argument("--depends", nargs="*", default=[])
    n.add_argument("--estimate", type=float, default=4)
    n.add_argument("--assignee", default="")
    n.add_argument("--brief-file", required=True)
    n.set_defaults(fn=cmd_item_new)

    s = sub.add_parser("list", help="list items")
    s.add_argument("--status", choices=items.STATUSES)
    s.add_argument("--owner")
    s.set_defaults(fn=cmd_list)

    s = sub.add_parser("brief", help="print an item as a self-contained prompt")
    s.add_argument("item")
    s.set_defaults(fn=cmd_brief)

    s = sub.add_parser("claim", help="claim an item and its paths")
    s.add_argument("item")
    s.add_argument("--paths", nargs="*", default=[])
    s.add_argument("--share", action="store_true")
    s.add_argument("--steal", action="store_true")
    s.add_argument("--ttl", type=int, default=claims.DEFAULT_TTL_MINUTES)
    s.set_defaults(fn=cmd_claim)

    s = sub.add_parser("release", help="drop your claim")
    s.add_argument("item")
    s.set_defaults(fn=cmd_release)

    s = sub.add_parser("reassign", help="conductor: move an item to another owner")
    s.add_argument("item")
    s.add_argument("owner")
    s.add_argument("--ttl", type=int, default=claims.DEFAULT_TTL_MINUTES)
    s.set_defaults(fn=cmd_reassign)

    sub.add_parser("heartbeat", help="renew your claims and heartbeat").set_defaults(fn=cmd_heartbeat)

    s = sub.add_parser("status", help="move an item to a new status")
    s.add_argument("item")
    s.add_argument("status", choices=items.STATUSES)
    s.add_argument("--note")
    s.set_defaults(fn=cmd_status)

    s = sub.add_parser("submit", help="push your lane branch and request review")
    s.add_argument("item")
    s.add_argument("--worktree")
    s.set_defaults(fn=cmd_submit)

    s = sub.add_parser("verdict", help="reviewer: accept or request changes")
    s.add_argument("item")
    s.add_argument("decision", choices=("accept", "changes"))
    s.add_argument("--findings-file")
    s.set_defaults(fn=cmd_verdict)

    s = sub.add_parser("send", help="post a message")
    s.add_argument("to")
    s.add_argument("--kind", required=True, choices=msgs.KINDS)
    s.add_argument("--item", default="")
    s.add_argument("--subject", required=True)
    s.add_argument("--body")
    s.add_argument("--body-file")
    s.set_defaults(fn=cmd_send)

    s = sub.add_parser("inbox", help="show unread messages")
    s.add_argument("--all", action="store_true")
    s.add_argument("--peek", action="store_true", help="do not mark as read")
    s.set_defaults(fn=cmd_inbox)

    s = sub.add_parser("wait", help="block until a message or item change arrives")
    s.add_argument("--timeout", type=float, default=540)
    s.add_argument("--interval", type=float, default=30)
    s.add_argument("--digest", type=float, help="hold routine events this many seconds; blockers still wake at once")
    s.set_defaults(fn=cmd_wait)

    s = sub.add_parser("next", help="resume or claim the next item for this agent")
    s.add_argument("--tiers", nargs="*")
    s.set_defaults(fn=cmd_next)

    s = sub.add_parser("board", help="render BOARD.md")
    s.add_argument("--write", action="store_true")
    s.set_defaults(fn=cmd_board)

    s = sub.add_parser("metrics", help="section 10 metrics")
    s.add_argument("--hours", type=int, default=24)
    s.add_argument("--no-ci", action="store_true")
    s.set_defaults(fn=cmd_metrics)

    s = sub.add_parser("build", help="run a build command in a build slot")
    s.add_argument("--item")
    s.add_argument("--class", dest="build_class", choices=build.CLASSES,
                   help="integrator builds may use the reserved slot; defaults from SWARM_ROLE")
    s.add_argument("command", nargs=argparse.REMAINDER)
    s.set_defaults(fn=cmd_build)

    s = sub.add_parser("prune-target", help="delete cargo artifacts not accessed recently (skips profiles in use)")
    s.add_argument("target")
    s.add_argument("--hours", type=float, default=48)
    s.add_argument("--dry-run", action="store_true")
    s.set_defaults(fn=cmd_prune_target)

    s = sub.add_parser("ci", help="dispatch lane-test.yml for an item and wait")
    s.add_argument("item")
    s.add_argument("--packages", nargs="+", required=True)
    s.add_argument("--filter")
    s.add_argument("--features")
    s.add_argument("--ref")
    s.set_defaults(fn=cmd_ci)

    s = sub.add_parser("ci-busy", help="exit 0 while CI runs on the integration branch")
    s.add_argument("--branch")
    s.set_defaults(fn=cmd_ci_busy)

    s = sub.add_parser("import-reviews", help="turn review-bot comments into items")
    s.add_argument("pr", type=int)
    s.set_defaults(fn=cmd_import_reviews)

    s = sub.add_parser("worktree", help="create the lane (or review) worktree for an item")
    s.add_argument("item")
    s.add_argument("--review", action="store_true")
    s.set_defaults(fn=cmd_worktree)

    sub.add_parser("sweep", help="janitor: block items over their time budget").set_defaults(fn=cmd_sweep)

    s = sub.add_parser("halt", help="conductor: stop the swarm, a role or an agent")
    s.add_argument("--scope", default="all")
    s.add_argument("--reason", required=True)
    s.set_defaults(fn=cmd_halt)

    s = sub.add_parser("resume", help="conductor: lift a halt")
    s.add_argument("--scope")
    s.set_defaults(fn=cmd_resume)

    s = sub.add_parser("config", help="conductor: set a config.json key (JSON value)")
    s.add_argument("key")
    s.add_argument("value")
    s.set_defaults(fn=cmd_config)

    s = sub.add_parser("record", help="conductor: write a decision (auto-numbered) or a digest")
    s.add_argument("kind", choices=("decision", "digest"))
    s.add_argument("name", help="decision slug, or digest name such as 2026-10-07-am")
    s.add_argument("--file", required=True)
    s.set_defaults(fn=cmd_record)

    s = sub.add_parser("review-pr", help="integrator/conductor: request a whole-PR cross-vendor review of the head")
    s.add_argument("pr", type=int)
    s.add_argument("--author-vendor", choices=agents.VENDORS)
    s.set_defaults(fn=cmd_review_pr)

    s = sub.add_parser("merge-gate", help="report why a PR may not merge (exit 0 when mergeable)")
    s.add_argument("pr", type=int)
    s.set_defaults(fn=cmd_merge_gate)

    s = sub.add_parser("merge", help="integrator/conductor: merge a PR that passes the merge gate")
    s.add_argument("pr", type=int)
    s.set_defaults(fn=cmd_merge)

    s = sub.add_parser("check-train", help="integrator/conductor: verify submitted lanes in one build; --land pushes")
    s.add_argument("--land", action="store_true", help="push the train when every lane is green (integrator only)")
    s.add_argument("--max-lanes", type=int)
    s.add_argument("--allow-red", action="store_true", help="land even though CI on the base is red (the train fixes it)")
    s.add_argument("--local", action="store_true", help="run here even if config train_host names another host")
    s.set_defaults(fn=cmd_check_train)

    s = sub.add_parser("watch", help="read-only live view of hosts, build slots, agent sessions and the store")
    s.add_argument("--hosts", help="comma-separated ssh hosts; 'local' is this machine (default $SWARM_WATCH_HOSTS)")
    s.add_argument("--agent", help="zoom into sessions whose label, id, cwd or model contains this text")
    s.add_argument("--minutes", type=float, default=30, help="show sessions active within this many minutes")
    s.add_argument("--keep", type=int, default=3, help="recent actions per session")
    s.add_argument("--interval", type=float, default=15, help="seconds between refreshes")
    s.add_argument("--once", action="store_true", help="print one frame and exit")
    s.add_argument("--snapshot", action="store_true", help="print this host's JSON snapshot (used over ssh)")
    s.set_defaults(fn=cmd_watch)

    s = sub.add_parser("scan", help="check files for credential-shaped strings")
    s.add_argument("files", nargs="+")
    s.set_defaults(fn=cmd_scan)
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    store = Store.from_env()
    store.hooks.append(lambda: claims.renew_mine(store))
    try:
        return int(args.fn(store, args))
    except (SwarmError, gitio.GitError, ci.CIError, build.BuildRefused, FileNotFoundError) as err:
        print(f"swarm: {err}", file=sys.stderr)
        return 2
