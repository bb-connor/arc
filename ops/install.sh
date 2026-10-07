#!/usr/bin/env bash
# Per-machine setup for the Chio swarm. Safe to re-run.
set -euo pipefail

SWARM_HOME="${SWARM_HOME:-$HOME/swarm}"
SWARM_GIT_URL="${SWARM_GIT_URL:-https://github.com/bb-connor/arc.git}"

need() { command -v "$1" >/dev/null 2>&1 || { echo "install.sh: missing $1" >&2; exit 1; }; }
need git
need python3
need tmux
need gh
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' \
  || { echo "install.sh: python3 >= 3.11 required" >&2; exit 1; }

if [ ! -d "$SWARM_HOME/.git" ]; then
  git clone --quiet --single-branch --branch swarm "$SWARM_GIT_URL" "$SWARM_HOME"
fi
mkdir -p "$HOME/.local/bin" "$HOME/.swarm" "$HOME/.swarm-state" "$HOME/.swarm-build" "$HOME/.swarm-logs"
ln -sf "$SWARM_HOME/bin/swarm" "$HOME/.local/bin/swarm"
ln -sf "$SWARM_HOME/bin/swarm-agent" "$HOME/.local/bin/swarm-agent"

if [ ! -f "$HOME/.swarm/env" ]; then
  (
    umask 077
    cat > "$HOME/.swarm/env" <<ENV
# Chio swarm environment, sourced by swarm-agent. Keep this file mode 600 and out of git.
GH_TOKEN=
SWARM_EMAIL=
SWARM_MACHINE=${SWARM_MACHINE:-$(hostname -s)}
SWARM_HOME=$SWARM_HOME
SWARM_REPO=$HOME/backbay/arc
SWARM_LANES=$HOME/lanes/swarm
SWARM_GIT_URL=$SWARM_GIT_URL
PATH=$HOME/.local/bin:$PATH
ENV
  )
  echo "install.sh: wrote $HOME/.swarm/env; set GH_TOKEN (machine user token) and SWARM_EMAIL"
fi
echo "install.sh: ok, swarm at $(git -C "$SWARM_HOME" log -1 --format=%h)"
