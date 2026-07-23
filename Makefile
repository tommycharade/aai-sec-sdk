PYTHON ?= python3

.PHONY: check format lint type test coverage guardrails docs docs-check package-check security-check

check: format-check lint type test coverage guardrails docs-check

package-check:
	rm -rf dist
	$(PYTHON) -m build --sdist --wheel --outdir dist
	$(PYTHON) -m twine check dist/*
	$(PYTHON) scripts/check_artifacts.py

security-check:
	$(PYTHON) -m pip_audit --strict -r requirements-docs.txt

docs:
	$(PYTHON) scripts/generate_readme.py
	$(PYTHON) -m mkdocs build --strict

docs-check:
	$(PYTHON) scripts/generate_readme.py --check
	$(PYTHON) -m mkdocs build --strict --site-dir /tmp/agentic-security-sdk-site

format:
	$(PYTHON) -m ruff format src tests scripts

format-check:
	$(PYTHON) -m ruff format --check src tests scripts

lint:
	$(PYTHON) -m ruff check src tests scripts

type:
	@if find src -name '*.py' -print -quit | grep -q .; then \
		$(PYTHON) -m mypy src tests scripts; \
	else \
		$(PYTHON) -m mypy tests scripts; \
	fi

test:
	$(PYTHON) -m pytest

coverage:
	@if find src -name '*.py' -print -quit | grep -q .; then \
		$(PYTHON) -m pytest --cov --cov-report=term-missing --cov-fail-under=90; \
	else \
		$(PYTHON) -m pytest; \
	fi

guardrails:
	$(PYTHON) scripts/check_guardrails.py
