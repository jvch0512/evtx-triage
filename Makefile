.PHONY: build test sample

build:
	mkdir -p bin && ldc2 -O -of=bin/evtx-triage src/evtx.d src/app.d

test: build
	mkdir -p build && ldc2 -of=build/test tests/test.d src/evtx.d && ./build/test && sh tests/cli.sh

sample: build
	mkdir -p docs site
	bin/evtx-triage examples > docs/sample-output.txt; true
	bin/evtx-triage examples --tsv > docs/sample-output.tsv; true
	python3 scripts/site.py docs/sample-output.tsv site/index.html "evtx-triage" "Triages Windows event logs exported as JSON: log clearing, RDP from the internet, brute force and success after failures, new services, admin group changes, encoded PowerShell and LSASS access. D." "Synthetic data."
