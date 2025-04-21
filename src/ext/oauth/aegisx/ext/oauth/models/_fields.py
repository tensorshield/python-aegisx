from typing import Annotated

import pydantic
from aegisx.types import SpaceSeparatedSet
from aegisx.ext.jose.types import JWECompactEncoded
from aegisx.ext.jose.types import JWSCompactEncoded

from aegisx.ext.oauth.types import AccessTokenType
from aegisx.ext.oauth.types import IssuerIdentifier


AccessTokenField = Annotated[
    str,
    pydantic.Field(
        default=...
    )
]

AccessTokenTypeField = Annotated[
    AccessTokenType,
    pydantic.Field(
        default=...,
        title="Token type",
        description=(
            "The type of the token issued as described in "
            "Section 7.1 of RFC 6749. Value is case insensitive."
        )
    )
]

AccessTokenExpiresInField = Annotated[
    int | None,
    pydantic.Field(
        default=None,
        title="Expires in",
        description=(
            "The lifetime in seconds of the access token.  For example, the "
            "value `3600` denotes that the access token will expire in one "
            "hour from the time the response was generated. If omitted, the "
            "authorization server SHOULD provide the expiration time via other "
            "means or document the default value."
        )
    )
]

AccessTokenScopeField = Annotated[
    SpaceSeparatedSet,
    pydantic.Field(
        default_factory=SpaceSeparatedSet,
        title="Scope",
        description=(
            "May be present, if identical to the scope requested by the client; "
            "otherwise, it MUST be present. The scope of the access token as "
            "described by Section 3.3 of RFC 6749."
        )
    )
]


AuthorizationRequestScopeField = Annotated[
    SpaceSeparatedSet,
    pydantic.Field(
        default_factory=SpaceSeparatedSet,
        title="Scope",
        description="The scope of the access request."
    )
]

IDTokenField = Annotated[
    JWECompactEncoded | JWSCompactEncoded,
    pydantic.Field(
        default=...,
        title="ID Token",
        description=(
            "The OpenID Connect ID Token received from the authorization server. ID Tokens "
            "MUST be signed using JWS and optionally both signed and then encrypted using "
            "JWS and JWE respectively, thereby providing authentication, integrity, non-"
            "repudiation, and optionally, confidentiality, per Section 16.14 of OpenID "
            "Connect Core 1.0 incorporating errata set 2. If the ID Token is encrypted, "
            "it MUST be signed then encrypted, with the result being a Nested JWT, as "
            "defined in RFC 7519. ID Tokens MUST NOT use none as the `alg` value unless the "
            "Response Type used returns no ID Token from the Authorization Endpoint "
            "(such as when using the Authorization Code Flow) and the Client explicitly "
            "requested the use of none at Registration time."
        )
    )
]

StateField = Annotated[
    str | None,
    pydantic.Field(
        default=None,
        title="State",
        description=(
            "Present if the `state` parameter was present in the client "
            "authorization request.  The exact value received from the "
            "client."
        )
    )
]

# RFC 9702 Section 2: The iss parameter value is the issuer identifier of the
# authorization server that created the authorization response, as defined in
# [RFC8414]. Its value MUST be a URL that uses the "https" scheme without any
# query or fragment components.
IssuerIdentifierField = Annotated[
    IssuerIdentifier | None,
    pydantic.Field(
        default=None,
        title="Issuer identifier",
        description=(
            "The `iss` parameter value is the issuer identifier of the "
            "authorization server that created the authorization response, "
            "as defined in RFC 8414. Its value MUST be a URL that uses the "
            "`https` scheme without any query or fragment components."
        )
    )
]