#!/usr/bin/env bash
# mirror-to-chio.sh -- publish a filtered copy of this repo's main to the
# backbay-labs/chio mirror.
#
# arc is upstream; chio is a derived, public downstream. Each sync writes one
# commit on chio whose tree is arc main's tree minus every path matched by
# scripts/mirror-exclude.txt (read from the arc commit being mirrored), whose
# parent is the previous chio main, and whose message reads as ordinary
# project history: the mirrored commit's own subject, a count of the changes
# it brings in, and a trailer recording the upstream commit:
#
#   docs: settle the README program on outcomes under cross-examination
#
#   Includes 2 changes.
#
#   Upstream-Commit: <sha>
#
# Nothing is ever committed directly to chio. The script refuses to push unless
# chio/main carries an Upstream-Commit trailer naming an arc commit that is an
# ancestor of origin/main. Anything else means chio has diverged and a push
# would bury commits that exist only there.
#
# Git LFS needs a separate transfer. `git lfs push <remote> <ref>` only computes
# objects for commits the remote lacks, so it exits 0 having transferred nothing
# whenever the git objects are already pushed. This script pushes by explicit
# object id instead, and verifies against the LFS batch API rather than trusting
# an exit code.
#
# With --tag, the mirror commit is built from the release tag's commit instead
# of main's tip, and the tag is pushed to the mirror pointing at that mirror
# commit. Run it at the cut, before main is mirrored past the tag.
#
# Usage:
#   scripts/mirror-to-chio.sh
#   scripts/mirror-to-chio.sh --dry-run
#   scripts/mirror-to-chio.sh --tag v0.2.0-alpha.1
#   scripts/mirror-to-chio.sh --exclude-file PATH --dry-run
#   scripts/mirror-to-chio.sh -h | --help

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
UPSTREAM_REMOTE="${MIRROR_UPSTREAM_REMOTE:-origin}"
UPSTREAM_REF="${MIRROR_UPSTREAM_REF:-main}"
UPSTREAM_SLUG="${MIRROR_UPSTREAM_SLUG:-bb-connor/arc}"
MIRROR_REMOTE="${MIRROR_REMOTE:-chio}"
MIRROR_URL="${MIRROR_URL:-https://github.com/backbay-labs/chio.git}"
MIRROR_SLUG="${MIRROR_SLUG:-backbay-labs/chio}"
EXCLUDE_PATH="scripts/mirror-exclude.txt"
EXCLUDE_FILE=""
DRY_RUN=0
TAG=""

usage() {
  cat <<'USAGE'
Usage: scripts/mirror-to-chio.sh [--dry-run] [--exclude-file PATH] [--tag TAG]

Commits origin/main's tree, minus the paths in scripts/mirror-exclude.txt, onto
the backbay-labs/chio mirror, reconciles Git LFS objects, and verifies the
mirror's tree matches the filtered tree.

Options:
  --dry-run            Build the filtered commit locally and report it without
                       pushing.
  --exclude-file PATH  Read exclusions from PATH instead of
                       scripts/mirror-exclude.txt at origin/main.
  --tag TAG            Mirror the commit of release tag TAG (v<semver>, an
                       ancestor of origin/main) and push TAG to the mirror at
                       the resulting mirror commit.
  -h, --help           Show this message.
USAGE
}

die() {
  printf '%s: %s\n' "$SCRIPT_NAME" "$1" >&2
  exit 1
}

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --exclude-file)
      [ $# -ge 2 ] || die "--exclude-file needs a path"
      EXCLUDE_FILE="$2"
      shift
      ;;
    --tag)
      [ $# -ge 2 ] || die "--tag needs a release tag"
      TAG="$2"
      shift
      ;;
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
if [ -n "$TAG" ]; then
  printf '%s\n' "$TAG" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$' \
    || die "release tag must be v<semver>: $TAG"
  git fetch "$UPSTREAM_REMOTE" "refs/tags/$TAG:refs/tags/$TAG" --quiet --force \
    || die "$UPSTREAM_REMOTE has no tag $TAG"
  TAGGED="$(git rev-parse --verify "refs/tags/$TAG^{commit}")"
  git merge-base --is-ancestor "$TAGGED" "$SRC" \
    || die "$TAG ($TAGGED) is not on $UPSTREAM_REMOTE/$UPSTREAM_REF"
  SRC="$TAGGED"
  SRC_LABEL="$TAG"
else
  SRC_LABEL="$UPSTREAM_REMOTE/$UPSTREAM_REF"
fi
DST="$(git rev-parse --verify --quiet "$MIRROR_REMOTE/main" || true)"
# arc PR numbers would link to unrelated issues on the mirror, so drop them
SUBJECT="$(git log -1 --format=%s "$SRC" | sed -E 's/ \(#[0-9]+\)$//')"
TRAILER_KEY="Upstream-Commit"

printf '    upstream %s = %s\n' "$SRC_LABEL" "$SRC"
printf '    mirror   %s/main = %s\n' "$MIRROR_REMOTE" "${DST:-<absent>}"

# chio/main must record, in its Upstream-Commit trailer, an arc commit that
# origin/main still contains, so arc has every commit chio's tip depends on.
MIRRORED=""
if [ -n "$DST" ]; then
  MIRRORED="$(git log -1 --format="%(trailers:key=$TRAILER_KEY,valueonly,separator=)" "$DST")"
  [ -n "$MIRRORED" ] \
    || die "$MIRROR_REMOTE/main ($DST) has no $TRAILER_KEY trailer. Something was
committed directly to the mirror. Resolve by hand; this script will not bury it."
  git merge-base --is-ancestor "$MIRRORED" "$SRC" 2>/dev/null \
    || die "$MIRROR_REMOTE/main mirrors $MIRRORED, which is not an ancestor of
$SRC_LABEL ($SRC). Resolve by hand; this script will not
move the mirror backwards or across a rewritten upstream."
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if [ -n "$EXCLUDE_FILE" ]; then
  cp "$EXCLUDE_FILE" "$WORK/exclude" || die "cannot read $EXCLUDE_FILE"
else
  git show "$SRC:$EXCLUDE_PATH" > "$WORK/exclude" 2>/dev/null \
    || die "$EXCLUDE_PATH is missing at $SRC; refusing to mirror an unfiltered tree"
fi

PATTERNS=()
while IFS= read -r line || [ -n "$line" ]; do
  line="${line%%#*}"
  line="$(printf '%s' "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
  [ -n "$line" ] && PATTERNS+=(":(glob)$line")
done < "$WORK/exclude"
[ "${#PATTERNS[@]}" -gt 0 ] || die "exclude list is empty; refusing to mirror an unfiltered tree"

# Lists the paths in a tree that match the given pathspecs, NUL-separated,
# using a scratch index so the caller's index and work tree are untouched.
matching_paths() {
  local tree="$1"
  shift
  GIT_INDEX_FILE="$WORK/scan" git read-tree "$tree"
  GIT_INDEX_FILE="$WORK/scan" git ls-files -z -- "$@"
}

printf '==> filtering %s (%s pattern(s))\n' "$SRC" "${#PATTERNS[@]}"
matching_paths "$SRC" "${PATTERNS[@]}" > "$WORK/excluded"
EXCLUDED="$(tr -cd '\0' < "$WORK/excluded" | wc -c | tr -d ' ')"

for pattern in "${PATTERNS[@]}"; do
  if [ -z "$(GIT_INDEX_FILE="$WORK/scan" git ls-files -- "$pattern" | head -1)" ]; then
    printf '    note: %s matches nothing\n' "${pattern#:(glob)}"
  fi
done

GIT_INDEX_FILE="$WORK/index" git read-tree "$SRC"
GIT_INDEX_FILE="$WORK/index" git update-index -z --force-remove --stdin < "$WORK/excluded"
TREE="$(GIT_INDEX_FILE="$WORK/index" git write-tree)"

[ -z "$(matching_paths "$TREE" "${PATTERNS[@]}" | head -c1)" ] \
  || die "filtered tree $TREE still contains excluded paths"

printf '    %s path(s) excluded\n' "$EXCLUDED"
printf '    filtered tree %s\n' "$TREE"

if [ "$DRY_RUN" -eq 1 ]; then
  tr '\0' '\n' < "$WORK/excluded" | awk -F/ '{ d = $1; for (i = 2; i < NF && i <= 3; i++) d = d "/" $i; print d }' \
    | sort | uniq -c | sort -rn | sed 's/^/    /'
fi

if [ -n "$DST" ] && [ "$(git rev-parse "$DST^{tree}")" = "$TREE" ]; then
  printf '==> mirror already current\n'
  NEW="$DST"
else
  if [ -n "$MIRRORED" ]; then
    CHANGES="$(git rev-list --count "$MIRRORED..$SRC")"
  else
    CHANGES="$(git rev-list --count "$SRC")"
  fi
  [ "$CHANGES" -eq 1 ] && NOUN="change" || NOUN="changes"
  NEW="$(git commit-tree "$TREE" ${DST:+-p "$DST"} -m "$SUBJECT" \
    -m "Includes $CHANGES $NOUN." -m "$TRAILER_KEY: $SRC")"
  printf '==> mirror commit %s\n' "$NEW"
  printf '    %s\n' "$SUBJECT"
  if [ "$DRY_RUN" -eq 0 ]; then
    git push "$MIRROR_REMOTE" "$NEW:refs/heads/main"
  fi
fi

printf '==> reconciling Git LFS objects\n'
LFS_PATHS="$(git lfs ls-files --name-only "$NEW" 2>/dev/null || true)"

if [ -z "$LFS_PATHS" ]; then
  printf '    no LFS objects tracked in the filtered tree\n'
else
  OIDS=""
  MANIFEST=""
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    pointer="$(git show "$NEW:$path" 2>/dev/null || true)"
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

# The batch API rejects oversized requests, so ask in fixed-size chunks.
objects = []
for start in range(0, len(entries), 100):
    body = json.dumps({
        "operation": "download",
        "transfers": ["basic"],
        "objects": [{"oid": o, "size": int(s)} for o, s, _ in entries[start:start + 100]],
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
        objects.extend(json.load(resp).get("objects", []))

paths = {o: p for o, _, p in entries}
missing = 0
if {obj["oid"] for obj in objects} != set(paths):
    print("LFS batch response does not cover every referenced object", file=sys.stderr)
    sys.exit(1)
for obj in objects:
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
' || [ "$DRY_RUN" -eq 1 ] || exit 1
  fi
fi

if [ -n "$TAG" ]; then
  REMOTE_TAG="$(git ls-remote "$MIRROR_REMOTE" "refs/tags/$TAG" | awk '{print $1}')"
  [ -z "$REMOTE_TAG" ] || [ "$REMOTE_TAG" = "$NEW" ] \
    || die "$MIRROR_REMOTE already has $TAG at $REMOTE_TAG, not $NEW; refusing to move a release tag"
  printf '==> tag %s -> %s (mirror of %s@%s)\n' "$TAG" "$NEW" "$UPSTREAM_SLUG" "$SRC"
  if [ "$DRY_RUN" -eq 0 ] && [ -z "$REMOTE_TAG" ]; then
    git push "$MIRROR_REMOTE" "$NEW:refs/tags/$TAG"
  fi
fi

if [ "$DRY_RUN" -eq 1 ]; then
  printf '==> dry run, nothing pushed\n'
  exit 0
fi

printf '==> verifying mirror\n'
git fetch "$MIRROR_REMOTE" --quiet --force
FINAL="$(git rev-parse "$MIRROR_REMOTE/main")"
DST_TREE="$(git rev-parse "$MIRROR_REMOTE/main^{tree}")"

[ "$FINAL" = "$NEW" ] || die "commit mismatch after push: mirror=$FINAL expected=$NEW"
[ "$DST_TREE" = "$TREE" ] || die "tree mismatch after push: mirror=$DST_TREE filtered upstream=$TREE"
[ -z "$(matching_paths "$FINAL" "${PATTERNS[@]}" | head -c1)" ] \
  || die "mirror tree $DST_TREE contains excluded paths"

printf '    commit %s\n' "$FINAL"
printf '    tree   %s\n' "$DST_TREE"
if [ -n "$TAG" ]; then
  [ "$(git ls-remote "$MIRROR_REMOTE" "refs/tags/$TAG" | awk '{print $1}')" = "$NEW" ] \
    || die "$MIRROR_REMOTE tag $TAG does not point at $NEW"
  printf '    tag    %s\n' "$TAG"
fi
printf '==> mirror verified\n'
