# swarm branch

Coordination store and tooling for the Chio agent swarm. Orphan branch: nothing
here is product code, and no workflow runs on pushes to it.

- `PROTOCOL.md`: rules for every agent. `decisions/`: conductor rulings.
- `bin/swarm`, `bin/swarm-agent`, `swarmlib/`: the CLI and runner (Python 3.11+, standard library only).
- `items/`, `claims/`, `agents/`, `msgs/`, `digests/`, `BOARD.md`: live state. Written only by the CLI.
- `ops/install.sh`: per-machine setup. `ops/worktree_inventory.py`: cleanup inventory.

Tests: `PYTHONPATH=. python3 -m unittest discover -s tests`
