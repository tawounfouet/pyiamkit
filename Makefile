.PHONY: install lint format format-check typecheck test coverage build smoke security check

install:
	python -m pip install -e .
	python -m pip install build mypy pytest pytest-cov ruff

lint:
	ruff check .

format:
	ruff format .

format-check:
	ruff format --check .

typecheck:
	mypy src

test:
	pytest

coverage:
	pytest --cov=pyiamkit --cov-report=term-missing --cov-fail-under=90

build:
	python -m build

smoke:
	python scripts/smoke_install.py

security:
	bandit -q -r src

check: lint format-check typecheck coverage build smoke
