# PyIAMKit Public API

This file records the API surface that PyIAMKit intentionally exposes to consumers.

## 0.1.0b1

The Identity and Tenancy alpha APIs remain available.

Beta Roles and Permissions API from `pyiamkit.authorization`:

```text
Permission
PermissionCode
Role
RoleId
RoleStatus
RoleType
RoleCatalogApplicationService
PermissionCatalogRepository
RoleRepository
AuthorizationModelError
InvalidPermissionCode
InvalidRoleName
PermissionAlreadyAssigned
PermissionAlreadyExists
PermissionNotAssigned
PermissionNotFound
RoleAlreadyExists
RoleInactive
RoleNotFound
```

RoleBinding and Subject assignment are intentionally absent until `0.1.0b2`.

## 0.1.0a2

Alpha Tenancy API is available from `pyiamkit.tenancy`.

## 0.1.0a1

Alpha Identity API is available from `pyiamkit.identity`.

## 0.0.1

The initial root public API contained only `pyiamkit.__version__`.
