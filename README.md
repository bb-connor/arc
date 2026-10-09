# swarm branch

Coordination store and tooling for the Chio agent swarm. Orphan branch: nothing
here is product code, and no workflow runs on pushes to it.

- `PROTOCOL.md`: rules for every agent. `decisions/`: conductor rulings.
- `bin/swarm`, `bin/swarm-agent`, `swarmlib/`: the CLI and runner (Python 3.11+, standard library only).
- `items/`, `claims/`, `agents/`, `msgs/`, `digests/`, `BOARD.md`: live state. Written only by the CLI.
- `ops/install.sh`: per-machine setup. `ops/worktree_inventory.py`: cleanup inventory.
- `swarm watch`: read-only live view of every machine (load, build slots and queue, agent processes,
  Claude Code and Codex sessions with their latest actions, mailbox files) plus the store. Hosts come from
  `--hosts` or `SWARM_WATCH_HOSTS` (comma-separated ssh aliases, `local` for this machine); mailbox files
  from `SWARM_WATCH_MAILBOXES` (colon-separated paths) on each host. `--agent <text>` zooms into matching
  sessions, `--once` prints one frame. Credential-shaped strings are redacted.

Tests: `PYTHONPATH=. python3 -m unittest discover -s tests`
