.PHONY: build check clean coverage format install lint test typecheck

install:
	python -m pip install -e '.[dev]'

format:
	python -m ruff format .
	python -m ruff check --fix .

lint:
	python -m ruff format --check .
	python -m ruff check .

typecheck:
	python -m mypy src tests

test:
	python -m pytest

coverage:
	python -m pytest --cov=sensitive_word_analyzer --cov-report=term-missing --cov-report=xml

build:
	python -m build

check: lint typecheck coverage build

clean:
	rm -rf build dist .coverage coverage.xml .mypy_cache .pytest_cache .ruff_cache
