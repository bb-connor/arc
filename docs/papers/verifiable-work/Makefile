export SOURCE_DATE_EPOCH = 1790899200
export FORCE_SOURCE_DATE = 1
.PHONY: build render check test clean
build: render
	python3 tools/check.py
render: results.tex
	pdflatex -interaction=nonstopmode -halt-on-error paper.tex > build-first.log
	bibtex paper > build-bib.log
	pdflatex -interaction=nonstopmode -halt-on-error paper.tex > build-second.log
	pdflatex -interaction=nonstopmode -halt-on-error paper.tex > build-final.log
results.tex: tools/check.py evidence/claim-traces.json evidence/comparison.json evidence/contracts.log evidence/erc8183/REPORT.json $(wildcard evidence/integration-summary.json)
	python3 tools/check.py --refresh
check:
	python3 tools/check.py
test:
	python3 -B -m unittest discover -s tools -p 'test_*.py' -v
clean:
	python3 -c 'from pathlib import Path; [p.unlink() for p in Path(".").iterdir() if p.suffix in (".aux", ".bbl", ".blg", ".log", ".out") and p.is_file()]'
