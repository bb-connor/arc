#!/usr/bin/env bash
# mirror-to-chio.sh -- push this repo's main to the backbay-labs/chio mirror.
#
# arc is upstream; chio is a SHA-identical downstream mirror. Nothing is ever
# committed directly to chio, so chio/main must always be an ancestor of
# origin/main. The script refuses to push when that does not hold, because a
# non-ancestor means the histories have forked and a push would clobber commits
# that exist only on chio.
#
# Git LFS needs a separate transfer. `git lfs push <remote> <ref>` only computes
# objects for commits the remote lacks, so it exits 0 having transferred nothing
# whenever the git objects are already pushed. This script pushes by explicit
# object id instead, and verifies against the LFS batch API rather than trusting
# an exit code.
#
# Usage:
#   scripts/mirror-to-chio.sh
#   scripts/mirror-to-chio.sh --dry-run
#   scripts/mirror-to-chio.sh -h | --help

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
UPSTREAM_REMOTE="${MIRROR_UPSTREAM_REMOTE:-origin}"
UPSTREAM_REF="${MIRROR_UPSTREAM_REF:-main}"
MIRROR_REMOTE="${MIRROR_REMOTE:-chio}"
MIRROR_URL="${MIRROR_URL:-https://github.com/backbay-labs/chio.git}"
MIRROR_SLUG="${MIRROR_SLUG:-backbay-labs/chio}"
DRY_RUN=0

usage() {
  cat <<'USAGE'
Usage: scripts/mirror-to-chio.sh [--dry-run]

Pushes origin/main to the backbay-labs/chio mirror, reconciles Git LFS
objects, and verifies the mirror matches byte for byte.

Options:
  --dry-run   Report what would be pushed without pushing.
  -h, --help  Show this message.
USAGE
}

die() {
  printf '%s: %s\n' "$SCRIPT_NAME" "$1" >&2
  exit 1
}

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown argument: $1" ;;
  esac
  shift
done

command -v git >/dev/null 2>&1 || die "git not found"
command -v gh >/dev/null 2>&1 || die "gh not found (needed for the LFS verification)"

if ! git remote get-url "$MIRROR_REMOTE" >/dev/null 2>&1; then
  printf 'adding remote %s -> %s\n' "$MIRROR_REMOTE" "$MIRROR_URL"
  git remote add "$MIRROR_REMOTE" "$MIRROR_URL"
fi

printf '==> fetching %s and %s\n' "$UPSTREAM_REMOTE" "$MIRROR_REMOTE"
git fetch "$UPSTREAM_REMOTE" "$UPSTREAM_REF" --quiet
git fetch "$MIRROR_REMOTE" --quiet --force

SRC="$(git rev-parse "$UPSTREAM_REMOTE/$UPSTREAM_REF")"
DST="$(git rev-parse "$MIRROR_REMOTE/main" 2>/dev/null || echo "")"

printf '    upstream %s/%s = %s\n' "$UPSTREAM_REMOTE" "$UPSTREAM_REF" "$SRC"
printf '    mirror   %s/main = %s\n' "$MIRROR_REMOTE" "${DST:-<absent>}"

if [ "$SRC" = "$DST" ]; then
  printf '==> mirror already current\n'
elif [ -n "$DST" ] && ! git merge-base --is-ancestor "$DST" "$SRC"; then
  die "$MIRROR_REMOTE/main ($DST) is not an ancestor of $UPSTREAM_REMOTE/$UPSTREAM_REF.
The histories have forked, which means something was committed directly to the
mirror. Resolve by hand; this script will not clobber it."
else
  AHEAD="$(git rev-list --count "$SRC" ${DST:+^$DST})"
  printf '==> %s commit(s) to mirror\n' "$AHEAD"
  if [ "$DRY_RUN" -eq 1 ]; then
    git log --oneline "$SRC" ${DST:+^$DST} | head -20
  else
    git push "$MIRROR_REMOTE" "$SRC:refs/heads/main"
  fi
fi

printf '==> reconciling Git LFS objects\n'
LFS_PATHS="$(git lfs ls-files --name-only "$SRC" 2>/dev/null || true)"

if [ -z "$LFS_PATHS" ]; then
  printf '    no LFS objects tracked on %s\n' "$UPSTREAM_REF"
else
  OIDS=""
  MANIFEST=""
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    pointer="$(git show "$SRC:$path" 2>/dev/null || true)"
    oid="$(printf '%s\n' "$pointer" | awk '/^oid sha256:/ {sub(/^oid sha256:/, "", $0); print $0}')"
    size="$(printf '%s\n' "$pointer" | awk '/^size / {print $2}')"
    [ -n "$oid" ] && [ -n "$size" ] || continue
    OIDS="$OIDS $oid"
    MANIFEST="$MANIFEST$oid $size $path"$'\n'
  done <<< "$LFS_PATHS"

  COUNT="$(printf '%s' "$OIDS" | wc -w | tr -d ' ')"
  printf '    %s LFS object(s) referenced\n' "$COUNT"

  if [ "$DRY_RUN" -eq 0 ] && [ "$COUNT" -gt 0 ]; then
    # Already-present objects get no upload action from the server, so this is
    # idempotent and only transfers what the mirror is missing.
    # shellcheck disable=SC2086
    git lfs push --object-id "$MIRROR_REMOTE" $OIDS
  fi

  if [ "$COUNT" -gt 0 ]; then
    printf '==> verifying LFS objects on %s\n' "$MIRROR_SLUG"
    printf '%s' "$MANIFEST" | python3 -c '
import json, subprocess, sys, urllib.request

entries = [l.split(" ", 2) for l in sys.stdin.read().splitlines() if l.strip()]
if not entries:
    sys.exit(0)

token = subprocess.check_output(["gh", "auth", "token"], text=True).strip()
body = json.dumps({
    "operation": "download",
    "transfers": ["basic"],
    "objects": [{"oid": o, "size": int(s)} for o, s, _ in entries],
}).encode()

req = urllib.request.Request(
    "https://github.com/'"$MIRROR_SLUG"'.git/info/lfs/objects/batch",
    data=body,
    headers={
        "Accept": "application/vnd.git-lfs+json",
        "Content-Type": "application/vnd.git-lfs+json",
        "Authorization": "Basic " + __import__("base64").b64encode(f"x:{token}".encode()).decode(),
    },
)
with urllib.request.urlopen(req) as resp:
    data = json.load(resp)

paths = {o: p for o, _, p in entries}
missing = 0
for obj in data.get("objects", []):
    err = obj.get("error")
    name = paths.get(obj["oid"], obj["oid"][:12])
    if err:
        missing += 1
        reason = err.get("message", "unknown")
        print(f"    MISSING  {name}  ({reason})")
    else:
        print(f"    ok       {name}")
if missing:
    print(f"{missing} LFS object(s) missing from the mirror", file=sys.stderr)
    sys.exit(1)
'
  fi
fi

if [ "$DRY_RUN" -eq 1 ]; then
  printf '==> dry run, nothing pushed\n'
  exit 0
fi

printf '==> verifying mirror\n'
git fetch "$MIRROR_REMOTE" --quiet --force
FINAL="$(git rev-parse "$MIRROR_REMOTE/main")"
SRC_TREE="$(git rev-parse "$SRC^{tree}")"
DST_TREE="$(git rev-parse "$MIRROR_REMOTE/main^{tree}")"

[ "$FINAL" = "$SRC" ] || die "commit mismatch after push: mirror=$FINAL upstream=$SRC"
[ "$SRC_TREE" = "$DST_TREE" ] || die "tree mismatch after push: mirror=$DST_TREE upstream=$SRC_TREE"

printf '    commit %s\n' "$FINAL"
printf '    tree   %s\n' "$DST_TREE"
printf '==> mirror verified\n'
