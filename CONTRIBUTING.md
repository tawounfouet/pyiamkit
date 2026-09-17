# Contributing to PyIAMKit

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
make install
make check
```

## Pull requests

Keep changes small and cohesive. Every change should identify its impact on:

- public API;
- tenant isolation;
- authorization semantics;
- persistence or migrations;
- security assumptions.

Add or update tests for every behavior change. Security-sensitive changes should include negative tests.

## Coding conventions

- Python 3.12+.
- Ruff for linting and formatting.
- mypy for static typing.
- pytest for tests.
- No ORM, Web framework or Pydantic dependency inside the domain layer.
- No global mutable `current_user` or `current_tenant` state.

## Before opening a PR

```bash
make check
```

Update `CHANGELOG.md` and documentation when the public behavior changes.
