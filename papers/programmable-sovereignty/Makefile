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
#   6. Body-page count (pages preceding the first appendix or References
#      heading) within the venue body-limit (default 13 for USENIX Security;
#      appendices and references are excluded).
#
# Targets:
#   build-acmart            4-pass build of paper.tex (acmart fallback).
#   build-usenix            4-pass build of paper-usenix.tex (submission target).
#   check-log TARGET=stem   Scan stem.log for fatal errors / undefined refs / citations.
#   check-bibtex TARGET=stem Scan stem.blg for warnings or errors.
#   preflight              Check required TeX and PDF inspection tools.
#   check-pages TARGET=stem MAX=N  Fail if body-page count (pages preceding the
#                                  first appendix or References heading) exceeds
#                                  N. Appendices, references, and pages they
#                                  share are excluded; the body count is what
#                                  USENIX Security measures against the
#                                  per-cycle page limit.
#   submit-check            build-usenix + all three checks against paper-usenix.
#   submit-check-acmart     same gate against paper.tex (sanity-check fallback).
#   clean                   remove aux files but keep PDFs.

LATEX     ?= pdflatex
BIBTEX    ?= bibtex
PDFINFO   ?= pdfinfo
PDFTOTEXT ?= pdftotext
LATEXOPTS ?= -interaction=nonstopmode -halt-on-error -file-line-error

# Default body-page limit for USENIX Security.
MAX ?= 13

# Default target stem for parameterized check-* targets when not overridden.
TARGET ?= paper-usenix

.PHONY: all preflight build-acmart build-usenix check-log check-bibtex check-pages \
        submit-check submit-check-acmart clean

all: submit-check

# ---- Build recipes ---------------------------------------------------------
#
# Four passes: latex / bibtex / latex / latex. The final pass settles cross-
# references and the bibliography. Each pass echoes and then preserves the
# underlying tool exit code so a hard failure aborts the recipe.

build-acmart: preflight
	@echo "[build-acmart] pass 1 (pdflatex)"
	@$(LATEX) $(LATEXOPTS) paper.tex; status=$$?; echo "  exit=$$status"; exit $$status
	@echo "[build-acmart] pass 2 (bibtex)"
	@$(BIBTEX) paper; status=$$?; echo "  exit=$$status"; exit $$status
	@echo "[build-acmart] pass 3 (pdflatex)"
	@$(LATEX) $(LATEXOPTS) paper.tex; status=$$?; echo "  exit=$$status"; exit $$status
	@echo "[build-acmart] pass 4 (pdflatex)"
	@$(LATEX) $(LATEXOPTS) paper.tex; status=$$?; echo "  exit=$$status"; exit $$status

build-usenix: preflight
	@echo "[build-usenix] pass 1 (pdflatex)"
	@$(LATEX) $(LATEXOPTS) paper-usenix.tex; status=$$?; echo "  exit=$$status"; exit $$status
	@echo "[build-usenix] pass 2 (bibtex)"
	@$(BIBTEX) paper-usenix; status=$$?; echo "  exit=$$status"; exit $$status
	@echo "[build-usenix] pass 3 (pdflatex)"
	@$(LATEX) $(LATEXOPTS) paper-usenix.tex; status=$$?; echo "  exit=$$status"; exit $$status
	@echo "[build-usenix] pass 4 (pdflatex)"
	@$(LATEX) $(LATEXOPTS) paper-usenix.tex; status=$$?; echo "  exit=$$status"; exit $$status

preflight:
	@fail=0; \
	if command -v $(LATEX) >/dev/null 2>&1; then \
	  echo "[preflight] LATEX=$(LATEX) -> $$(command -v $(LATEX))"; \
	else \
	  echo "[preflight] FAIL: LATEX=$(LATEX) not found"; fail=1; \
	fi; \
	if command -v $(BIBTEX) >/dev/null 2>&1; then \
	  echo "[preflight] BIBTEX=$(BIBTEX) -> $$(command -v $(BIBTEX))"; \
	else \
	  echo "[preflight] FAIL: BIBTEX=$(BIBTEX) not found"; fail=1; \
	fi; \
	if command -v $(PDFINFO) >/dev/null 2>&1; then \
	  echo "[preflight] PDFINFO=$(PDFINFO) -> $$(command -v $(PDFINFO))"; \
	else \
	  echo "[preflight] FAIL: PDFINFO=$(PDFINFO) not found"; fail=1; \
	fi; \
	if command -v $(PDFTOTEXT) >/dev/null 2>&1; then \
	  echo "[preflight] PDFTOTEXT=$(PDFTOTEXT) -> $$(command -v $(PDFTOTEXT))"; \
	else \
	  echo "[preflight] FAIL: PDFTOTEXT=$(PDFTOTEXT) not found"; fail=1; \
	fi; \
	if [ $$fail -eq 0 ]; then echo "[preflight] OK"; fi; \
	exit $$fail

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

check-pages:
	@if [ ! -f $(TARGET).pdf ]; then \
	  echo "[check-pages] FAIL: $(TARGET).pdf not found"; exit 1; \
	fi
	@total=$$($(PDFINFO) $(TARGET).pdf | awk '/^Pages:/ {print $$2}'); \
	if [ -z "$$total" ]; then \
	  echo "[check-pages] FAIL: could not parse page count"; exit 1; \
	fi; \
	boundary_page=0; \
	appendix_page=0; \
	refs_page=0; \
	heading_re='^[[:space:]]*([A-Z0-9]+[.]?[[:space:]]+)?(Ethical Considerations|Ethics Considerations|Open Science|References)([[:space:]]|$$)'; \
	appendix_re='^[[:space:]]*([A-Z0-9]+[.]?[[:space:]]+)?(Ethical Considerations|Ethics Considerations|Open Science)([[:space:]]|$$)'; \
	refs_re='^[[:space:]]*([A-Z0-9]+[.]?[[:space:]]+)?References([[:space:]]|$$)'; \
	for p in $$(seq 1 $$total); do \
	  page_text=$$($(PDFTOTEXT) -layout -f $$p -l $$p $(TARGET).pdf - 2>/dev/null); \
	  if [ $$appendix_page -eq 0 ] && printf '%s\n' "$$page_text" | grep -qE "$$appendix_re"; then \
	    appendix_page=$$p; \
	  fi; \
	  if [ $$refs_page -eq 0 ] && printf '%s\n' "$$page_text" | grep -qE "$$refs_re"; then \
	    refs_page=$$p; \
	  fi; \
	  if [ $$boundary_page -eq 0 ] && printf '%s\n' "$$page_text" | grep -qE "$$heading_re"; then \
	    boundary_page=$$p; \
	  fi; \
	done; \
	if [ $$boundary_page -eq 0 ]; then \
	  echo "[check-pages] FAIL: could not locate Open Science, Ethical Considerations, or References heading in PDF"; \
	  exit 1; \
	fi; \
	if [ $$refs_page -eq 0 ]; then refs_msg="not found"; else refs_msg=$$refs_page; fi; \
	if [ $$appendix_page -eq 0 ]; then appendix_msg="not found"; else appendix_msg=$$appendix_page; fi; \
	body=$$((boundary_page - 1)); \
	echo "[check-pages] $(TARGET).pdf: total=$$total, appendix start page=$$appendix_msg, refs start page=$$refs_msg, body=$$body (max=$(MAX))"; \
	if [ $$body -gt $(MAX) ]; then \
	  echo "[check-pages] FAIL: body pages $$body exceeds limit $(MAX)"; \
	  exit 1; \
	fi; \
	echo "[check-pages] OK"

# ---- Composite gates -------------------------------------------------------
#
# submit-check is the primary submission gate. It exits 0 iff every primitive
# above succeeds. submit-check-acmart is the acmart-fallback variant.

submit-check: preflight build-usenix
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

# ---- Housekeeping ----------------------------------------------------------

clean:
	rm -f paper.aux paper.bbl paper.blg paper.log paper.out
	rm -f paper-usenix.aux paper-usenix.bbl paper-usenix.blg paper-usenix.log paper-usenix.out
