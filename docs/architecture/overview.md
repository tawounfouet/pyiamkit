# Architecture overview

PyIAMKit follows a domain-first ports-and-adapters architecture.

```text
Applications
    ↓
Public Python API
    ↓
Application Services
    ↓
Domain
    ↓
Ports
    ↓
Adapters
```

The planned bounded contexts are Identity, Tenancy, Authentication, Authorization, Policy, Delegation, Governance, Audit and Security.

The core domain must remain independent from Django, FastAPI, SQLAlchemy, Redis and external identity providers.
