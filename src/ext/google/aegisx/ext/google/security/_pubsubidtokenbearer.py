from typing import Literal

from aegisx.ext.oauth.resource.security import OIDCTokenBearer


class PubSubIDTokenBearer(OIDCTokenBearer):

    def __init__(
        self,
        audience: set[str] | None = None,
        audience_mode: Literal['domain', 'path'] = 'domain',
        subjects: set[str] | None = None
    ):
        super().__init__(
            issuers={'https://accounts.google.com'},
            audience=audience,
            audience_mode=audience_mode,
            subjects=subjects
        )