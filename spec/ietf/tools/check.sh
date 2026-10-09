#!/bin/sh
# Regenerate the draft into a temporary directory and compare the result with
# the committed renderings. Fails on any difference, on a stale generated
# appendix, and on any idnits error or warning.
#
# xml2rfc and idnits compare the document date with today's date, so their
# date-proximity warnings depend on when the check runs, not on the source.
# The freshness check reports only that warning without failing. The
# submission check (CHIO_IETF_SUBMISSION=1, `make submission-check`) keeps it
# fatal, so the date is current when the draft is posted.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cd "$here"
out=draft-whelan-chio-protocol-00

python3 tools/render_vectors.py --vectors ../../tests/bindings/vectors --out generated --check
python3 tools/test_render_vectors.py
python3 tools/test_build_gates.py
python3 tools/check_fonts.py
make --no-print-directory OUTDIR="$tmp" all >"$tmp/build.log" 2>&1 || {
  cat "$tmp/build.log" >&2
  exit 1
}
submission=${CHIO_IETF_SUBMISSION:-0}
diagnostics="$tmp/build.log"
if [ "$submission" != 1 ]; then
  diagnostics="$tmp/diagnostics.log"
  if rg -v "Warning: The document date \([0-9-]+\) is more than 3 days away from today's date$" \
    "$tmp/build.log" >"$diagnostics"; then
    :
  else
    date_filter_status=$?
    if [ "$date_filter_status" -ne 1 ]; then
      echo 'check: unable to scan writer diagnostics' >&2
      exit 1
    fi
  fi
  if rg -q "Warning: The document date \([0-9-]+\) is more than 3 days away" "$tmp/build.log"; then
    echo 'check: note: the document date is not current; run make submission-check before posting' >&2
  fi
fi
if rg -i '^.*(Warning:|Error:)' "$diagnostics"; then
  echo 'check: xml2rfc emitted a warning or error' >&2
  exit 1
else
  draft_scan_status=$?
  if [ "$draft_scan_status" -ne 1 ]; then
    echo 'check: unable to scan writer diagnostics' >&2
    exit 1
  fi
fi
python3 tools/check_xml.py "$out.xml" "$tmp/$out.xml"

status=0
for ext in xml txt; do
  if ! cmp -s "$out.$ext" "$tmp/$out.$ext"; then
    echo "check: $out.$ext differs from a fresh build; run make" >&2
    status=1
  fi
done
normalize() { sed -E 's/prepTime="[^"]*"/prepTime=""/' "$1"; }
normalize "$tmp/$out.prepped.xml" > "$tmp/$out.prepped.norm"
if ! normalize "$out.prepped.xml" | cmp -s - "$tmp/$out.prepped.norm"; then
  echo "check: $out.prepped.xml differs from a fresh build; run make" >&2
  status=1
fi
# The PDF embeds a creation time and host-dependent font subsets, so compare
# its extracted text and, because text does not cover figure artwork, its
# pages rasterized at a low resolution. Reproducible layout uses the pinned
# fonts selected by Makefile's FONTCONFIG_FILE.
if command -v pdftotext >/dev/null 2>&1 && command -v pdftoppm >/dev/null 2>&1; then
  pdftotext -layout "$out.pdf" "$tmp/committed.pdf.txt"
  pdftotext -layout "$tmp/$out.pdf" "$tmp/fresh.pdf.txt"
  if ! cmp -s "$tmp/committed.pdf.txt" "$tmp/fresh.pdf.txt"; then
    echo "check: $out.pdf text differs from a fresh build; run make" >&2
    status=1
  fi
  mkdir "$tmp/committed-pages" "$tmp/fresh-pages"
  pdftoppm -r 50 -gray "$out.pdf" "$tmp/committed-pages/page"
  pdftoppm -r 50 -gray "$tmp/$out.pdf" "$tmp/fresh-pages/page"
  if ! python3 tools/compare_pages.py "$tmp/committed-pages" "$tmp/fresh-pages"; then
    echo "check: $out.pdf pages differ from a fresh build; run make" >&2
    status=1
  fi
else
  echo 'check: pdftotext and pdftoppm are required to verify the PDF' >&2
  status=1
fi

if awk 'length > 72 { found = 1 } END { exit !found }' "$out.txt"; then
  echo "check: $out.txt has lines longer than 72 characters" >&2
  status=1
fi

if command -v idnits >/dev/null 2>&1; then
  if idnits --mode submission --no-progress --output json "$out.xml" > "$tmp/idnits.json" 2> "$tmp/idnits.stderr"; then
    if [ "$submission" = 1 ]; then
      python3 tools/idnits_gate.py "$tmp/idnits.json" || status=1
    else
      python3 tools/idnits_gate.py --allow-stale-date "$tmp/idnits.json" || status=1
    fi
  else
    cat "$tmp/idnits.stderr" >&2
    echo "check: idnits did not complete successfully" >&2
    status=1
  fi
else
  echo "check: idnits is not installed (npm install -g @ietf-tools/idnits)" >&2
  status=1
fi
exit $status
