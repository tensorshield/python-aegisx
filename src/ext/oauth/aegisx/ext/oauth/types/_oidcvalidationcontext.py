from typing import TypedDict
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aegisx.ext.oauth.models import AuthorizationRequestParameters
    from aegisx.ext.oauth.models import ServerMetadata
    from aegisx.ext.oauth.models import TokenResponse
    from aegisx.ext.jose import JSONWebSignature


class OIDCValidationContext(TypedDict):
    client_id: str
    grant: 'TokenResponse'
    jws: 'JSONWebSignature'
    metadata: 'ServerMetadata'
    now: int
    params: 'AuthorizationRequestParameters'