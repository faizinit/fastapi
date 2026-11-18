PYTHON ?= python
VENV ?= .venv
ifeq ($(OS),Windows_NT)
BIN := $(VENV)/Scripts
else
BIN := $(VENV)/bin
endif

.PHONY: install run test lint format typecheck migrate seed docker-up

install:
	$(PYTHON) -m venv $(VENV)
	$(BIN)/python -m pip install -r requirements-dev.txt

run:
	$(BIN)/python -m uvicorn app.main:create_app --factory --reload

test:
	$(BIN)/python -m pytest

lint:
	$(BIN)/python -m ruff check .
	$(BIN)/python -m ruff format --check .

format:
	$(BIN)/python -m ruff check --fix .
	$(BIN)/python -m ruff format .

typecheck:
	$(BIN)/python -m mypy

migrate:
	$(BIN)/python -m alembic upgrade head

seed:
	$(BIN)/python -m scripts.seed

docker-up:
	docker compose up --build
