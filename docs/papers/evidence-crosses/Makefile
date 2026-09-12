PAPER     := paper
LATEX     := pdflatex -interaction=nonstopmode -halt-on-error
BIBTEX    := bibtex
MAXPAGES  := 10
MAXWORDS  := 5000
RESULTS   := ../programmable-sovereignty/bench/results

.PHONY: all build check check-log check-bibtex check-pages check-words check-macros macros words clean

all: build check

check: check-log check-bibtex check-pages check-words check-macros

macros:
	python3 tools/derive-macros.py

build: macros
	$(LATEX) $(PAPER).tex
	-$(BIBTEX) $(PAPER)
	$(LATEX) $(PAPER).tex
	$(LATEX) $(PAPER).tex

# Fail on an undefined control sequence, an undefined reference or citation, a
# TeX error, or an em dash anywhere in the source.
check-log:
	@fail=0; \
	if grep -qE "Undefined control sequence" $(PAPER).log; then \
	  echo "FAIL: undefined control sequence"; \
	  grep -n -A2 "Undefined control sequence" $(PAPER).log | head -40; fail=1; fi; \
	if grep -qE "There were undefined references" $(PAPER).log; then \
	  echo "FAIL: undefined references"; \
	  grep -n "LaTeX Warning: \(Reference\|Citation\)" $(PAPER).log | head -40; fail=1; fi; \
	if grep -qE "Citation .* undefined" $(PAPER).log; then \
	  echo "FAIL: undefined citation"; \
	  grep -n "Citation .* undefined" $(PAPER).log | head -40; fail=1; fi; \
	if grep -qE "^! " $(PAPER).log; then \
	  echo "FAIL: TeX error"; grep -n -A3 "^! " $(PAPER).log | head -60; fail=1; fi; \
	if grep -rnP "\xe2\x80\x94" *.tex sections/*.tex figures/*.tex bib.bib README.md >/dev/null 2>&1; then \
	  echo "FAIL: em dash (U+2014) present"; \
	  grep -rnP "\xe2\x80\x94" *.tex sections/*.tex figures/*.tex bib.bib README.md; fail=1; fi; \
	if grep -qE "Overfull \\\\hbox \([0-9]{2,}\." $(PAPER).log; then \
	  echo "note: overfull boxes over 10pt:"; grep -c "Overfull" $(PAPER).log; fi; \
	if [ $$fail -eq 0 ]; then echo "check-log: clean"; else exit 1; fi

# Fail on any BibTeX error or warning, and on a cited key with no entry.
check-bibtex:
	@fail=0; \
	if [ ! -f $(PAPER).blg ]; then echo "FAIL: no $(PAPER).blg; run make build"; exit 1; fi; \
	if grep -qiE "^(I couldn't open|I was expecting|Warning--|Repeated entry|Sorry)" $(PAPER).blg; then \
	  echo "FAIL: bibtex diagnostics"; \
	  grep -niE "^(I couldn't open|I was expecting|Warning--|Repeated entry|Sorry)" $(PAPER).blg | head -40; fail=1; fi; \
	if grep -qE "There (was|were) [0-9]+ error message" $(PAPER).blg; then \
	  echo "FAIL: bibtex errors"; cat $(PAPER).blg; fail=1; fi; \
	if grep -qE "Citation .* undefined" $(PAPER).log; then \
	  echo "FAIL: cited key with no bib entry"; fail=1; fi; \
	if [ $$fail -eq 0 ]; then echo "check-bibtex: clean"; else exit 1; fi

# Fail if the built PDF exceeds MAXPAGES pages, references included.
check-pages:
	@pages=$$(pdfinfo $(PAPER).pdf | awk '/^Pages:/ {print $$2}'); \
	echo "pages: $$pages (maximum $(MAXPAGES))"; \
	if [ "$$pages" -gt "$(MAXPAGES)" ]; then \
	  echo "FAIL: $$pages pages exceeds $(MAXPAGES)"; exit 1; fi; \
	echo "check-pages: clean"

# Body prose word count: the nine sections with listings, tables, figures and
# their captions removed, so the number is the prose a reader reads.
words:
	@cat sections/0*.tex figures/*.tex \
	| awk '/\\begin\{(lstlisting|tikzpicture|tabular|longtable|table|figure)\}/{d++} \
	       d==0{print} \
	       /\\end\{(lstlisting|tikzpicture|tabular|longtable|table|figure)\}/{if(d>0)d--}' \
	| detex -n | tr -s ' \n' ' \n' | wc -w

# Fail if the body prose exceeds MAXWORDS. The goal for this paper is under
# 5,000 body words; the gate sits at that goal, so the text cannot grow and
# every addition has to buy its space from an existing paragraph.
check-words:
	@words=$$($(MAKE) -s --no-print-directory words); \
	echo "body words: $$words (maximum $(MAXWORDS))"; \
	if [ "$$words" -gt "$(MAXWORDS)" ]; then \
	  echo "FAIL: $$words body words exceeds $(MAXWORDS)"; exit 1; fi; \
	echo "check-words: clean"

# Fail if a derived count has drifted from the artifact it was read from.
check-macros:
	@python3 tools/derive-macros.py --check

clean:
	rm -f $(PAPER).aux $(PAPER).log $(PAPER).out $(PAPER).bbl $(PAPER).blg \
	      $(PAPER).toc $(PAPER).pdf
