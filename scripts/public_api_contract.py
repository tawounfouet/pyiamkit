"""Build and verify the PyIAMKit public API freeze manifest."""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import importlib
import inspect
import json
import re
import sys
from enum import Enum
from pathlib import Path
from types import ModuleType
from typing import Any

SCHEMA_VERSION = 1
_ERROR_CODE_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]*$")

PUBLIC_MODULES: dict[str, tuple[str, ...] | None] = {
    "pyiamkit": None,
    "pyiamkit.shared": None,
    "pyiamkit.identity": None,
    "pyiamkit.identity.adapters.memory": None,
    "pyiamkit.tenancy": None,
    "pyiamkit.tenancy.adapters": None,
    "pyiamkit.authorization": None,
    "pyiamkit.authorization.adapters": None,
    "pyiamkit.authentication": None,
    "pyiamkit.authentication.adapters": None,
    "pyiamkit.audit": None,
    "pyiamkit.audit.adapters": None,
    "pyiamkit.operations": None,
    "pyiamkit.operations.adapters": None,
    "pyiamkit.provisioning": None,
    "pyiamkit.provisioning.adapters": None,
    "pyiamkit.conformance": None,
    "pyiamkit.persistence": None,
    "pyiamkit.persistence.sqlalchemy": None,
    "pyiamkit.authentication.adapters.jwt": ("JwtTokenProvider",),
    "pyiamkit.authentication.adapters.oidc": (
        "OidcConfigurationError",
        "StaticOidcAssuranceResolver",
        "StaticOidcIdTokenVerifier",
    ),
    "pyiamkit.authentication.adapters.oidc_discovery": (
        "DiscoveredOidcIdTokenVerifier",
        "HttpxOidcTransport",
        "JwksKeyResolver",
        "OidcDiscoveryClient",
        "OidcDiscoveryError",
        "OidcJsonTransport",
        "OidcJwksError",
        "OidcProviderMetadata",
        "OidcRemoteError",
    ),
    "pyiamkit.authentication.adapters.totp": (
        "InMemoryMfaSecretStore",
        "PyOtpTotpProvider",
    ),
    "pyiamkit.operations.adapters.redis": (
        "RedisAuthorizationCache",
        "RedisInvalidationPublisher",
        "RedisInvalidationSubscriber",
        "RedisRevocationRegistry",
        "RedisSecurityStateProjection",
    ),
    "pyiamkit.integrations.fastapi": (
        "AuthenticationDependency",
        "CorrelationIdResolver",
        "ResourceResolver",
        "ScopeResolver",
        "TenantResolver",
        "bearer_authentication",
        "require_permission",
    ),
    "pyiamkit.integrations.fastapi_scim": (
        "ScimAccessDependency",
        "create_scim_router",
    ),
    "pyiamkit.integrations.django": (
        "DjangoAuthenticationRequired",
        "DjangoCorrelationIdResolver",
        "DjangoResourceResolver",
        "DjangoScopeResolver",
        "DjangoTenantResolver",
        "PyIAMKitAuthenticationMiddleware",
        "authenticate_request",
        "bearer_required",
        "get_authenticated_claims",
        "get_authorization_decision",
        "permission_required",
    ),
}


def _signature(value: object) -> str | None:
    try:
        return str(inspect.signature(value))
    except (TypeError, ValueError):
        return None


def _json_value(value: object) -> object:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Enum):
        return value.value
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: _json_value(getattr(value, field.name))
            for field in dataclasses.fields(value)
        }
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    if isinstance(value, frozenset):
        return sorted((_json_value(item) for item in value), key=repr)
    if isinstance(value, dict):
        return {
            str(key): _json_value(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    return {"type": f"{type(value).__module__}.{type(value).__qualname__}"}


def _class_members(cls: type[Any]) -> dict[str, object]:
    members: dict[str, object] = {}
    for name, raw in sorted(cls.__dict__.items()):
        if name.startswith("_"):
            continue
        if isinstance(raw, (staticmethod, classmethod)):
            members[name] = {
                "kind": type(raw).__name__,
                "signature": _signature(raw.__func__),
            }
        elif isinstance(raw, property):
            members[name] = {
                "kind": "property",
                "getter_signature": None if raw.fget is None else _signature(raw.fget),
            }
        elif inspect.isfunction(raw):
            members[name] = {
                "kind": "method",
                "signature": _signature(raw),
            }
    return members


def _describe_symbol(name: str, value: object) -> dict[str, object]:
    if inspect.isclass(value):
        cls = value
        descriptor: dict[str, object] = {
            "kind": "class",
            "qualified_name": f"{cls.__module__}.{cls.__qualname__}",
            "signature": _signature(cls),
            "members": _class_members(cls),
        }
        if issubclass(cls, BaseException):
            code = getattr(cls, "code", None)
            if code is not None:
                descriptor["exception_code"] = _json_value(code)
        if issubclass(cls, Enum):
            descriptor["enum_values"] = [
                {"name": member.name, "value": _json_value(member.value)} for member in cls
            ]
        if dataclasses.is_dataclass(cls):
            descriptor["dataclass_fields"] = [
                {
                    "name": field.name,
                    "type": str(field.type),
                    "has_default": (
                        field.default is not dataclasses.MISSING
                        or field.default_factory is not dataclasses.MISSING
                    ),
                }
                for field in dataclasses.fields(cls)
            ]
        return descriptor

    if inspect.isfunction(value):
        return {
            "kind": "function",
            "qualified_name": f"{value.__module__}.{value.__qualname__}",
            "signature": _signature(value),
        }

    if name == "__version__":
        return {"kind": "version-token"}

    return {
        "kind": "value",
        "value": _json_value(value),
    }


def _exports(module: ModuleType, explicit: tuple[str, ...] | None) -> tuple[str, ...]:
    if explicit is not None:
        return tuple(sorted(explicit))

    declared = getattr(module, "__all__", None)
    if declared is None:
        raise RuntimeError(f"{module.__name__} is frozen without explicit exports or __all__")
    if not isinstance(declared, (list, tuple)):
        raise RuntimeError(f"{module.__name__}.__all__ must be a list or tuple")
    return tuple(sorted(str(name) for name in declared))


def _module_contract(module_name: str, explicit: tuple[str, ...] | None) -> dict[str, object]:
    module = importlib.import_module(module_name)
    export_names = _exports(module, explicit)

    missing = tuple(name for name in export_names if not hasattr(module, name))
    if missing:
        raise RuntimeError(f"{module_name} declares missing public export(s): {', '.join(missing)}")

    symbols = {name: _describe_symbol(name, getattr(module, name)) for name in export_names}
    canonical = json.dumps(
        {"exports": list(export_names), "symbols": symbols},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return {
        "exports": list(export_names),
        "fingerprint": hashlib.sha256(canonical).hexdigest(),
    }


def build_manifest() -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "python": f"{sys.version_info.major}.{sys.version_info.minor}",
        "modules": {
            module_name: _module_contract(module_name, explicit)
            for module_name, explicit in sorted(PUBLIC_MODULES.items())
        },
    }


def check_manifest(baseline_path: Path) -> tuple[str, ...]:
    expected = json.loads(baseline_path.read_text(encoding="utf-8"))
    actual = build_manifest()

    failures: list[str] = []
    if expected.get("schema_version") != actual["schema_version"]:
        failures.append("public API manifest schema version changed")

    expected_modules = expected.get("modules")
    actual_modules = actual["modules"]
    if not isinstance(expected_modules, dict):
        failures.append("public API baseline has no module mapping")
        return tuple(failures)

    if set(expected_modules) != set(actual_modules):
        removed = sorted(set(expected_modules) - set(actual_modules))
        added = sorted(set(actual_modules) - set(expected_modules))
        if removed:
            failures.append(f"frozen public module(s) removed: {', '.join(removed)}")
        if added:
            failures.append(f"new public module(s) require freeze review: {', '.join(added)}")

    for module_name in sorted(set(expected_modules) & set(actual_modules)):
        expected_entry = expected_modules[module_name]
        actual_entry = actual_modules[module_name]
        if not isinstance(expected_entry, dict) or not isinstance(actual_entry, dict):
            failures.append(f"invalid public API manifest entry: {module_name}")
            continue
        if expected_entry.get("exports") != actual_entry.get("exports"):
            failures.append(f"public exports changed: {module_name}")
        if expected_entry.get("fingerprint") != actual_entry.get("fingerprint"):
            failures.append(f"public signature/contract fingerprint changed: {module_name}")

    return tuple(failures)


def audit_public_contract() -> tuple[str, ...]:
    failures: list[str] = []
    public_exceptions: dict[str, type[BaseException]] = {}

    for module_name, explicit in sorted(PUBLIC_MODULES.items()):
        module = importlib.import_module(module_name)
        for name in _exports(module, explicit):
            value = getattr(module, name)
            if inspect.isclass(value) and issubclass(value, BaseException):
                qualified = f"{value.__module__}.{value.__qualname__}"
                public_exceptions[qualified] = value

    codes: dict[str, str] = {}
    for qualified, exc_type in sorted(public_exceptions.items()):
        code = getattr(exc_type, "code", None)
        if not isinstance(code, str) or not _ERROR_CODE_PATTERN.fullmatch(code):
            failures.append(f"public exception has no canonical code: {qualified}")
            continue
        previous = codes.get(code)
        if previous is not None and previous != qualified:
            failures.append(
                f"public exception code {code} is duplicated by {previous} and {qualified}"
            )
        codes[code] = qualified

    from pyiamkit.authorization import AuthorizationReason, InvalidPermissionCode, PermissionCode

    for reason in AuthorizationReason:
        if reason.name != reason.value:
            failures.append(
                f"AuthorizationReason name/value mismatch: {reason.name}={reason.value!r}"
            )
        if not reason.value.startswith(("ALLOW_", "DENY_")):
            failures.append(f"AuthorizationReason lacks ALLOW_/DENY_ prefix: {reason.value}")

    valid_permissions = (
        ("invoice.approve", "invoice.approve"),
        ("billing.invoice.approve", "billing.invoice.approve"),
        ("User_Profile.Read", "user_profile.read"),
    )
    for raw, expected in valid_permissions:
        actual = str(PermissionCode(raw))
        if actual != expected:
            failures.append(f"PermissionCode canonicalization changed: {raw!r} -> {actual!r}")

    for raw in ("read", ".read", "invoice.", "invoice-read", "invoice..read"):
        try:
            PermissionCode(raw)
        except InvalidPermissionCode:
            continue
        failures.append(f"PermissionCode accepted invalid public form: {raw!r}")

    return tuple(failures)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--emit",
        action="store_true",
        help="Print a compact manifest for the current public API.",
    )
    parser.add_argument(
        "--check",
        type=Path,
        help="Compare the current public API to a committed freeze manifest.",
    )
    parser.add_argument(
        "--audit",
        action="store_true",
        help="Audit exception codes, reason codes and PermissionCode naming.",
    )
    args = parser.parse_args()

    selected = int(args.emit) + int(args.check is not None) + int(args.audit)
    if selected != 1:
        parser.error("choose exactly one of --emit, --check or --audit")

    if args.emit:
        print(json.dumps(build_manifest(), sort_keys=True, separators=(",", ":")))
        return 0

    if args.audit:
        failures = audit_public_contract()
        if failures:
            for failure in failures:
                print(f"ERROR: {failure}")
            return 1
        print("Public API semantic audit passed.")
        return 0

    failures = check_manifest(args.check)
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}")
        print(
            "CURRENT_MANIFEST="
            + json.dumps(build_manifest(), sort_keys=True, separators=(",", ":"))
        )
        return 1

    print(f"Public API freeze verified against {args.check}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
