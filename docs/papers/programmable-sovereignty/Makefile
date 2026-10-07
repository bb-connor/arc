# Submission-check harness for the programmable-sovereignty paper.
#
# This Makefile template is reused for papers/sensor-grounded-admission/Makefile
# (copy-edit the TARGET defaults and the submit-check recipe to point at the
# right .tex stem). The check primitives (check-log, check-bibtex, check-pages)
# are paper-agnostic and reusable as-is.
#
# Pass criteria for a submission-ready build:
#   1. pdflatex 4-pass clean (exit 0 every pass).
#   2. Zero lines beginning with "!" in the .log.
#   3. Zero "LaTeX Warning: There were undefined references" lines.
#   4. Zero "LaTeX Warning: Citation" lines.
#   5. Zero "Warning--" or error lines in the .blg.
#   6. Body-page count (pages preceding References) within the venue body-limit
#      (default 13 for USENIX Security; references are excluded).
#
# Targets:
#   build-acmart            4-pass build of paper.tex (acmart fallback).
#   build-usenix            4-pass build of paper-usenix.tex (submission target).
#   check-log TARGET=stem   Scan stem.log for fatal errors / undefined refs / citations.
#   check-bibtex TARGET=stem Scan stem.blg for warnings or errors.
#   check-pages TARGET=stem MAX=N  Fail if body-page count (pages preceding the
#                                  References heading) exceeds N. The heading's
#                                  page is read from the References entry that
#                                  hyperref records in stem.aux, so the .tex
#                                  must add References to the table of contents
#                                  (\phantomsection\addcontentsline before
#                                  \bibliography). The body count is what USENIX
#                                  Security measures against the per-cycle limit.
#   submit-check            build-usenix + all three checks against paper-usenix.
#   submit-check-acmart     same gate against paper.tex (sanity-check fallback).
#   refresh-results         Re-run both benchmark scripts in place (results land
#                           in bench/results and the claim ledger's generated
#                           Measurements region is rewritten), rebuild both PDFs,
#                           then regenerate the supplementary artifact pinned at
#                           the current HEAD. Commit the refreshed results, PDFs,
#                           ledger, and supplementary files together; the
#                           generator's --check then verifies that commit.
#                           Benchmark knobs: CHIO_BENCH_SAMPLES,
#                           CHIO_CRITERION_SAMPLES, CHIO_SUSTAINED_SECONDS,
#                           CHIO_BENCH_MAX_LOAD (see bench/run-bilateral-admission.sh).
#   clean                   remove aux files but keep PDFs.

LATEX     ?= pdflatex
BIBTEX    ?= bibtex
PDFINFO   ?= pdfinfo
PDFTOTEXT ?= pdftotext
PYTHON    ?= python3
LATEXOPTS ?= -interaction=nonstopmode -halt-on-error -file-line-error

# Repository root, two directories above docs/papers.
REPO ?= $(abspath $(CURDIR)/../../..)

# Default body-page limit for USENIX Security.
MAX ?= 13

# Default target stem for parameterized check-* targets when not overridden.
TARGET ?= paper-usenix

.PHONY: all build-acmart build-usenix check-log check-bibtex check-pages \
        submit-check submit-check-acmart refresh-results clean

all: submit-check

# ---- Build recipes ---------------------------------------------------------
#
# Four passes: latex / bibtex / latex / latex. The final pass settles cross-
# references and the bibliography. Each pdflatex pass's exit code is echoed.
# We use `set -e` style chaining so a hard failure aborts the recipe.

build-acmart:
	@echo "[build-acmart] pass 1 (pdflatex)"
	$(LATEX) $(LATEXOPTS) paper.tex && echo "  exit=0"
	@echo "[build-acmart] pass 2 (bibtex)"
	$(BIBTEX) paper && echo "  exit=0"
	@echo "[build-acmart] pass 3 (pdflatex)"
	$(LATEX) $(LATEXOPTS) paper.tex && echo "  exit=0"
	@echo "[build-acmart] pass 4 (pdflatex)"
	$(LATEX) $(LATEXOPTS) paper.tex && echo "  exit=0"

build-usenix:
	@echo "[build-usenix] pass 1 (pdflatex)"
	$(LATEX) $(LATEXOPTS) paper-usenix.tex && echo "  exit=0"
	@echo "[build-usenix] pass 2 (bibtex)"
	$(BIBTEX) paper-usenix && echo "  exit=0"
	@echo "[build-usenix] pass 3 (pdflatex)"
	$(LATEX) $(LATEXOPTS) paper-usenix.tex && echo "  exit=0"
	@echo "[build-usenix] pass 4 (pdflatex)"
	$(LATEX) $(LATEXOPTS) paper-usenix.tex && echo "  exit=0"

# ---- Gate primitives -------------------------------------------------------
#
# Each check reads a single artefact and exits non-zero on any match. The
# echoed lines name the offending content so failures are debuggable from CI
# output alone.

check-log:
	@if [ ! -f $(TARGET).log ]; then \
	  echo "[check-log] FAIL: $(TARGET).log not found"; exit 1; \
	fi
	@echo "[check-log] scanning $(TARGET).log"
	@fail=0; \
	if grep -n '^!' $(TARGET).log >/dev/null 2>&1; then \
	  echo "[check-log] FAIL: fatal '!' lines:"; \
	  grep -n '^!' $(TARGET).log; fail=1; \
	fi; \
	if grep -nE '(LaTeX|Package natbib) Warning: There were undefined (references|citations)' $(TARGET).log >/dev/null 2>&1; then \
	  echo "[check-log] FAIL: undefined references / citations:"; \
	  grep -nE '(LaTeX|Package natbib) Warning: There were undefined (references|citations)' $(TARGET).log; fail=1; \
	fi; \
	if grep -nE '(LaTeX|Package natbib) Warning: Citation' $(TARGET).log >/dev/null 2>&1; then \
	  echo "[check-log] FAIL: citation warnings:"; \
	  grep -nE '(LaTeX|Package natbib) Warning: Citation' $(TARGET).log; fail=1; \
	fi; \
	if grep -nE 'LaTeX Warning: Reference .* undefined' $(TARGET).log >/dev/null 2>&1; then \
	  echo "[check-log] FAIL: undefined cross-references:"; \
	  grep -nE 'LaTeX Warning: Reference .* undefined' $(TARGET).log; fail=1; \
	fi; \
	if [ $$fail -eq 0 ]; then echo "[check-log] OK"; fi; \
	exit $$fail

check-bibtex:
	@if [ ! -f $(TARGET).blg ]; then \
	  echo "[check-bibtex] FAIL: $(TARGET).blg not found"; exit 1; \
	fi
	@echo "[check-bibtex] scanning $(TARGET).blg"
	@fail=0; \
	if grep -n 'Warning--' $(TARGET).blg >/dev/null 2>&1; then \
	  echo "[check-bibtex] FAIL: BibTeX warnings:"; \
	  grep -n 'Warning--' $(TARGET).blg; fail=1; \
	fi; \
	if grep -nE '^(I was|---|Error|error message)' $(TARGET).blg >/dev/null 2>&1; then \
	  echo "[check-bibtex] FAIL: BibTeX error markers:"; \
	  grep -nE '^(I was|---|Error|error message)' $(TARGET).blg; fail=1; \
	fi; \
	if [ $$fail -eq 0 ]; then echo "[check-bibtex] OK"; fi; \
	exit $$fail

# The References page comes from the table-of-contents entry hyperref writes
# to the .aux file when the bibliography is registered with \addcontentsline:
#   \@writefile{toc}{\contentsline {section}{References}{9}{section*.30}...}
# The .out bookmark names the same anchor but carries no page number, so the
# .aux entry is the anchor. A missing entry fails closed rather than falling
# back to a text search of the PDF, which misfires on body lines that begin
# with the word "References".
check-pages:
	@if [ ! -f $(TARGET).pdf ]; then \
	  echo "[check-pages] FAIL: $(TARGET).pdf not found"; exit 1; \
	fi
	@if [ ! -f $(TARGET).aux ]; then \
	  echo "[check-pages] FAIL: $(TARGET).aux not found; build $(TARGET) first"; exit 1; \
	fi
	@total=$$($(PDFINFO) $(TARGET).pdf | awk '/^Pages:/ {print $$2}'); \
	if [ -z "$$total" ]; then \
	  echo "[check-pages] FAIL: could not parse page count"; exit 1; \
	fi; \
	refs_page=$$(sed -n 's/^\\@writefile{toc}{\\contentsline {section}{\(\\numberline {[^}]*}\)\{0,1\}References}{\([0-9][0-9]*\)}.*/\2/p' $(TARGET).aux | head -n 1); \
	if [ -z "$$refs_page" ]; then \
	  printf '%s\n' '[check-pages] FAIL: $(TARGET).aux has no References contents entry; add \phantomsection\addcontentsline{toc}{section}{References} before \bibliography in $(TARGET).tex'; \
	  exit 1; \
	fi; \
	if [ "$$refs_page" -lt 1 ] || [ "$$refs_page" -gt "$$total" ]; then \
	  echo "[check-pages] FAIL: References page $$refs_page is outside 1..$$total"; \
	  exit 1; \
	fi; \
	body=$$((refs_page - 1)); \
	echo "[check-pages] $(TARGET).pdf: total=$$total, refs start page=$$refs_page, body=$$body (max=$(MAX))"; \
	if [ $$body -gt $(MAX) ]; then \
	  echo "[check-pages] FAIL: body pages $$body exceeds limit $(MAX)"; \
	  exit 1; \
	fi; \
	echo "[check-pages] OK"

# ---- Composite gates -------------------------------------------------------
#
# submit-check is the primary submission gate. It exits 0 iff every primitive
# above succeeds. submit-check-acmart is the acmart-fallback variant.

submit-check: build-usenix
	@echo "[submit-check] running gates against paper-usenix"
	@$(MAKE) --no-print-directory check-log    TARGET=paper-usenix
	@$(MAKE) --no-print-directory check-bibtex TARGET=paper-usenix
	@$(MAKE) --no-print-directory check-pages  TARGET=paper-usenix MAX=$(MAX)
	@echo "[submit-check] VERDICT: PASS (paper-usenix is submission-ready)"

submit-check-acmart: build-acmart
	@echo "[submit-check-acmart] running gates against paper"
	@$(MAKE) --no-print-directory check-log    TARGET=paper
	@$(MAKE) --no-print-directory check-bibtex TARGET=paper
	@$(MAKE) --no-print-directory check-pages  TARGET=paper MAX=$(MAX)
	@echo "[submit-check-acmart] VERDICT: PASS (acmart fallback is submission-ready)"

# ---- Evidence refresh ------------------------------------------------------
#
# Runs in place: the benchmark scripts write bench/results and rewrite the
# claim ledger's generated region, both PDFs are rebuilt from the refreshed
# macros, and the artifact generator pins the supplementary package at HEAD.
# The generator compares benchmark inputs (crates, scripts, corpora) with HEAD
# and content-addresses the paper's own outputs, so the refreshed files are
# committed together afterwards.

refresh-results:
	@echo "[refresh-results] bilateral admission benchmark"
	bash bench/run-bilateral-admission.sh
	@echo "[refresh-results] replay corpus benchmark"
	bash bench/run-replay-corpus.sh
	@$(MAKE) --no-print-directory build-usenix
	@$(MAKE) --no-print-directory build-acmart
	@echo "[refresh-results] regenerating the supplementary artifact"
	$(PYTHON) $(REPO)/scripts/generate-programmable-sovereignty-artifact.py \
	  --source-commit "$$(git -C $(REPO) rev-parse HEAD)"

# ---- Housekeeping ----------------------------------------------------------

clean:
	rm -f paper.aux paper.bbl paper.blg paper.log paper.out
	rm -f paper-usenix.aux paper-usenix.bbl paper-usenix.blg paper-usenix.log paper-usenix.out
