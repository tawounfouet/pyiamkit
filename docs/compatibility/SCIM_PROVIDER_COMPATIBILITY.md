# SCIM Provider Compatibility Matrix

Qualified release: **0.4.0b8**

This matrix describes deterministic offline compatibility tests. It is not a vendor certification statement.

| Capability | Generic SCIM | Microsoft Entra profile | Okta profile |
| --- | --- | --- | --- |
| Protected SCIM endpoints | Supported | Qualified | Qualified |
| ServiceProviderConfig | Supported | Qualified | Supported |
| ResourceTypes / Schemas | Supported | Qualified | Supported |
| User create | Supported | Qualified | Qualified |
| User lookup by userName | Supported | Supported | Qualified |
| User lookup by externalId | Supported | Qualified, including unquoted value | Supported |
| User active=false | Supported | Qualified | Qualified |
| Group create | Supported | Qualified | Qualified |
| Group displayName lookup | Supported | Qualified | Supported |
| Group externalId lookup | Supported | Supported, unquoted value supported | Supported |
| Group GET excludedAttributes=members | Supported | Qualified | Supported |
| Group list excludedAttributes=members | Supported | Qualified | Supported |
| Group member PATCH add | Supported | Qualified | Qualified |
| Group member PATCH remove | Supported | Qualified | Qualified |
| Pathless Group PATCH replace | Supported | Supported | Qualified |
| ETag / If-Match | Supported | Covered by core conformance | Covered by core conformance |
| Nested Groups | Not supported | Not qualified | Not qualified |
| Group → Role mapping | Never implicit | Never implicit | Never implicit |
| Password provisioning | Rejected | Rejected | Rejected |
| Bulk operations | Not supported | Not qualified | Not qualified |
| Sorting | Not supported | Not qualified | Not qualified |
| Live vendor certification | N/A | **Not certified** | **Not certified** |

## Interpretation

**Supported** means the generic PyIAMKit contract implements the capability.

**Qualified** means a dedicated provider-specific offline CI scenario exercises the capability.

**Not qualified** means the feature is either unsupported or deliberately outside the provider qualification scenario.

The provider harnesses use the same public FastAPI SCIM router and framework-neutral transport used by applications; they do not bypass the production code path.
