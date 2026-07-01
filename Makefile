.PHONY: dev ci lint test eval demo schema serve clean

PY ?= /opt/homebrew/bin/python3.12
VENV = .venv
BIN = $(VENV)/bin

dev:
	$(PY) -m venv $(VENV)
	$(BIN)/pip install -q -e ".[dev]"

lint:
	$(BIN)/ruff check src tests

test:
	$(BIN)/pytest

eval:
	$(BIN)/sqlguard eval

demo:
	$(BIN)/sqlguard demo

schema:
	$(BIN)/sqlguard schema

serve:
	$(BIN)/sqlguard serve --role analyst

ci: lint test eval

clean:
	rm -rf $(VENV) .pytest_cache .ruff_cache **/__pycache__
