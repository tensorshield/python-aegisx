from aegisx.ext.oauth.models import TokenResponse


class ClientRepository:

    async def grant(
        self,
        client_id: str
    ) -> TokenResponse:
        """Lookup a grant from the persistent data storage."""
        raise NotImplementedError