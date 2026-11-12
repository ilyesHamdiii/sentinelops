.PHONY: install lint test phase0-check

install:
	python -m pip install -U pip
	python -m pip install -e ".[dev]"

lint:
	ruff check .

format:
	ruff format .

test:
	pytest -q

phase0-check:
	@echo "Phase 0: repo baseline, ADRs, documentation, and no live AWS deployment allowed."
