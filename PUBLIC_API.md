# PyIAMKit Public API

This file records the API surface that PyIAMKit intentionally exposes to consumers.

## 0.1.0a1

Root-level stable-for-this-alpha symbol:

```python
pyiamkit.__version__
```

Alpha Identity API from `pyiamkit.identity`:

```text
Identity
IdentityId
IdentityType
IdentityStatus
User
ServiceAccount
EmailAddress
IdentityApplicationService
IdentityRepository
IdentityError
IdentityNotFound
InvalidIdentityTransition
InvalidDisplayName
InvalidEmailAddress
InvalidServiceAccount
InvalidExternalIdentity
ExternalIdentityAlreadyLinked
ExternalIdentityLinkNotFound
```

These Identity contracts are intentionally public but remain pre-1.0 alpha APIs.

## 0.0.1

The initial root public API contained only `pyiamkit.__version__`.
