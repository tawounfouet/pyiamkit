# Changelog

All notable changes to PyIAMKit will be documented in this file.

The project follows Semantic Versioning and PEP 440 for Python pre-releases.

## [Unreleased]

## [0.1.0a1] - 2026-09-17

### Added

- Initial Identity bounded context.
- `IdentityId`, `IdentityType`, `IdentityStatus` and `EmailAddress` value objects.
- User and ServiceAccount profiles.
- Explicit Identity lifecycle state machine and domain events.
- External identity linking keyed by provider plus external subject.
- `IdentityRepository` port and database-like InMemory adapter.
- `IdentityApplicationService` and InMemory event sink.
- Unit and repository-conformance tests.
- Executable basic Identity example and guide.

## [0.0.1] - 2026-09-17

### Added

- Initial repository structure using a `src/` layout.
- Package metadata and build configuration.
- Ruff, mypy, pytest and coverage configuration.
- Minimal shared kernel primitives.
- CI, security and release-validation workflows.
- Public API manifest, security policy and contribution guide.
