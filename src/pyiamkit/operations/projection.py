"""Safe projection wrappers for distributed security state."""

from pyiamkit.identity import IdentityId
from pyiamkit.tenancy import TenantId

from .ports import SecurityStateProjection, SecurityStateReader
from .state import SecurityStateStamp


class ProjectingSecurityStateReader(SecurityStateReader):
    """Read authoritative state first, then project it best-effort."""

    def __init__(
        self,
        authoritative: SecurityStateReader,
        projection: SecurityStateProjection,
    ) -> None:
        self._authoritative = authoritative
        self._projection = projection

    def stamp_for(
        self,
        *,
        identity_id: IdentityId,
        tenant_id: TenantId,
    ) -> SecurityStateStamp:
        stamp = self._authoritative.stamp_for(
            identity_id=identity_id,
            tenant_id=tenant_id,
        )
        self._projection.project(
            identity_id=identity_id,
            tenant_id=tenant_id,
            stamp=stamp,
        )
        return stamp
