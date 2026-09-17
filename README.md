# PyIAMKit

PyIAMKit is a modular, framework-agnostic Python foundation for Identity and Access Management (IAM), RBAC, multi-tenancy, policy-based authorization, delegation, and auditability.

> **Status:** Pre-Alpha (`0.1.0a1`) — not yet recommended for production use.

## Goals

PyIAMKit is being designed around a small set of security principles:

- default deny;
- least privilege;
- explicit tenant and scope boundaries;
- explainable authorization decisions;
- strong revocation semantics;
- separation between authentication and authorization;
- framework-independent domain logic.

## Current milestone

`0.1.0a1` implements the first real bounded context: **Identity**. It provides User and ServiceAccount identities, an explicit security-sensitive lifecycle, external identity links, domain events and an in-memory repository.

## Quickstart

Python 3.12+ is required.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
python -m pip install build mypy pytest pytest-cov ruff
make check
```

```python
from pyiamkit.identity import IdentityApplicationService
from pyiamkit.identity.adapters.memory import (
    InMemoryDomainEventSink,
    InMemoryIdentityRepository,
)
from pyiamkit.shared import SystemClock

service = IdentityApplicationService(
    repository=InMemoryIdentityRepository(),
    clock=SystemClock(),
    event_sink=InMemoryDomainEventSink(),
)

alice = service.create_user(
    display_name="Alice",
    primary_email="alice@example.com",
)
alice = service.activate_identity(alice.id)

print(alice.status.value)
```

## Architecture

```text
Applications
    ↓
Application Services
    ↓
Domain Aggregates
    ↓
Ports
    ↓
Adapters
```

The core remains independent from Django, FastAPI, SQLAlchemy, Redis and external identity providers.

## Roadmap

```text
0.0.1      Repository bootstrap
0.1.0a1    Identity domain
0.1.0a2    Tenancy / Membership
0.1.0b1    Roles & Permissions
0.1.0b2    RoleBindings + Scoped RBAC
0.2.x      Authorization, hierarchy, policies, SoD, delegation
0.3.x      Persistence, sessions, credentials, JWT, FastAPI
0.4.x      Federation, MFA, Django, SCIM
0.5.x      Distributed operations and production qualification
1.0.0      Stable public API
```

## Security

Please do not report security vulnerabilities through a public GitHub issue. See [`SECURITY.md`](SECURITY.md).

## Public API

The intentionally supported public surface is tracked in [`PUBLIC_API.md`](PUBLIC_API.md).

## License

A project license has not yet been selected. Do not assume an open-source license until a `LICENSE` file is added.
