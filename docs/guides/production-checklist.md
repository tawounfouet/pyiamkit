# Production checklist — PyIAMKit 0.5.0

Use this checklist before recommending a concrete deployment for production.

## Release evidence

- [ ] exact PyIAMKit version is pinned;
- [ ] candidate commit/release passed CI;
- [ ] candidate passed Security workflow;
- [ ] candidate passed Production Qualification;
- [ ] wheel/sdist origin is trusted;
- [ ] checksums/provenance were reviewed when available;
- [ ] changelog and migration impact were reviewed.

## Persistence

- [ ] authoritative database backup exists;
- [ ] migration plan is documented;
- [ ] `migrate_schema()` succeeds in staging;
- [ ] rollback/restore procedure was tested;
- [ ] transaction ownership is explicit;
- [ ] PostgreSQL/SQLite choice fits workload and availability needs.

## Authentication and secrets

- [ ] production secret store is configured;
- [ ] signing keys are protected outside source control;
- [ ] key rotation procedure is documented;
- [ ] Session persistence is durable;
- [ ] Session revocation path is tested;
- [ ] privileged operations require MFA;
- [ ] break-glass procedure is controlled and monitored.

## Authorization

- [ ] Tenant boundary is explicit in host application code;
- [ ] known ALLOW path is tested;
- [ ] known DENY path is tested;
- [ ] cross-Tenant negative path is tested;
- [ ] revocation removes access;
- [ ] SoD/constraint rules required by the application are tested;
- [ ] no framework/native superuser path silently bypasses PyIAMKit policy.

## Distributed operations

- [ ] Redis is treated as derived state only;
- [ ] Redis outage/fallback behavior is tested when enabled;
- [ ] stale-cache and revocation failure modes are understood;
- [ ] cache/invalidation telemetry is monitored.

## Audit and monitoring

- [ ] durable audit store is configured;
- [ ] outbox delivery worker is operated;
- [ ] failed/retrying outbox entries are monitored;
- [ ] SIEM/security sink is configured when required;
- [ ] duplicate deliveries are handled idempotently;
- [ ] privileged and break-glass events are alerted appropriately.

## Integrations

- [ ] FastAPI/Django version is within the qualified range;
- [ ] OIDC issuer/audience configuration is explicit;
- [ ] OIDC/JWKS failure path is monitored;
- [ ] SCIM provider behavior is tested against the chosen provider/profile;
- [ ] external Group → Role mapping, if added by the host, is explicit and policy controlled.

## Operational readiness

- [ ] health/smoke checks exist;
- [ ] backup restore has been exercised;
- [ ] incident owner/on-call path is known;
- [ ] dependency/security alerts are monitored;
- [ ] known residual risks for 0.5.0 are accepted/documented.

A completed checklist is deployment evidence, not a guarantee. Host-specific risk,
scale, regulatory obligations and infrastructure controls still require independent
review.
