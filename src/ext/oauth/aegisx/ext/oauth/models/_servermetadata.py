import contextlib
import logging
import json
import os
from typing import Any
from typing import Union

import httpx
import pydantic
from aegisx.ext.jose import JSONWebKeySet

from aegisx.ext.oauth.types import ClientAuthenticationMethod
from aegisx.ext.oauth.types import HTTPSResourceLocator
from aegisx.ext.oauth.types import NotDiscoverable


logger: logging.Logger = logging.getLogger(__name__)

DISCOVERED: dict[str, 'ServerMetadata'] = {}


class ServerMetadata(pydantic.BaseModel):
    issuer: str = pydantic.Field(
        default=...,
        title="Issuer",
        description="Authorization server's issuer identifier URL.",
    )

    authorization_endpoint: HTTPSResourceLocator | None = pydantic.Field(
        default=None,
        title="Authorization endpoint",
        description="URL of the authorization server's authorization endpoint.",
    )

    token_endpoint: HTTPSResourceLocator | None = pydantic.Field(
        default=None,
        title="Token endpoint",
        description="URL of the authorization server's token endpoint.",
    )

    jwks_uri: HTTPSResourceLocator | None = pydantic.Field(
        default=None,
        title="JSON Web Key Set (JWKS) URI",
        description="URL of the authorization server's JWK Set document.",
    )

    registration_endpoint: HTTPSResourceLocator | None = pydantic.Field(
        default=None,
        title="Registration endpoint",
        description=(
            "URL of the authorization server's **OAuth 2.0 Dynamic Client "
            "Registration Endpoint**."
        ),
    )

    scopes_supported: list[str] | None = pydantic.Field(
        default=[],
        title="Supported scopes",
        description=(
            "JSON array containing a list of the OAuth 2.0 `scope` values that "
            "this authorization server supports."
        ),
    )

    response_types_supported: list[str] | None = pydantic.Field(
        default=[],
        title="Supported response types",
        description=(
            "JSON array containing a list of the OAuth 2.0 `response_type` "
            "values that this authorization server supports."
        ),
    )

    response_modes_supported: list[str] | None = pydantic.Field(
        default=[],
        title="Supported response modes",
        description=(
            "JSON array containing a list of the OAuth 2.0 `response_mode` "
            "values that this authorization server supports."
        ),
    )

    grant_types_supported: list[str] | None = pydantic.Field(
        default=[],
        title="Supported grant types",
        description=(
            "JSON array containing a list of the OAuth 2.0 `grant_types` "
            "values that this authorization server supports."
        ),
    )

    token_endpoint_auth_methods_supported: list[ClientAuthenticationMethod] = pydantic.Field(
        default=[],
        title="Supported client authentication methods",
        description=(
            "JSON array containing a list of client authentication methods "
            "supported by this token endpoint."
        ),
    )

    token_endpoint_auth_signing_alg_values_supported: list[str] | None = pydantic.Field(
        default=[],
        title="Supported signature algorithms",
        description=(
            "JSON array containing a list of the JWS signing algorithms "
            "supported by the token endpoint for the signature on the JWT "
            "used to authenticate the client at the token endpoint."
        ),
    )

    service_documentation: str | None = pydantic.Field(
        default=None,
        title="Documentation",
        description=(
            "URL of a page containing human-readable information that "
            "developers might want or need to know when using the "
            "authorization server."
        ),
    )

    ui_locales_supported: list[str] | None = pydantic.Field(
        default=[],
        title="Supported locals for UI",
        description=(
            "Languages and scripts supported for the user interface, "
            "represented as a JSON array of language tag values from BCP 47."
        ),
    )

    op_policy_uri: str | None= pydantic.Field(
        default=None,
        title="Data policy URL",
        description=(
            "URL that the authorization server provides to the person "
            "registering the client to read about the authorization server's "
            "requirements on how the client can use the data provided by the "
            "authorization server."
        ),
    )

    op_tos_uri: str | None= pydantic.Field(
        default=None,
        title="Terms of service URL",
        description=(
            "URL that the authorization server provides to the person "
            "registering the client to read about the authorization server's "
            "terms of service."
        ),
    )

    revocation_endpoint: HTTPSResourceLocator | None = pydantic.Field(
        default=None,
        title="Revocation endpoint",
        description="URL of the authorization server's revocation endpoint.",
    )

    revocation_endpoint_auth_methods_supported: list[str] | None = pydantic.Field(
        default=[],
        title="Supported authentication methods",
        description=(
            "JSON array containing a list of client authentication methods "
            "supported by this revocation endpoint."
        ),
    )

    revocation_endpoint_auth_signing_alg_values_supported: list[str] | None = pydantic.Field(
        default=[],
        title="Supported signature algorithms",
        description=(
            "JSON array containing a list of the JWS signing algorithms "
            "supported by the revocation endpoint for the signature on the JWT "
            "used to authenticate the client at the revocation endpoint."
        ),
    )

    introspection_endpoint: HTTPSResourceLocator | None = pydantic.Field(
        default=None,
        title="Introspection endpoint",
        description="URL of the authorization server's introspection endpoint.",
    )

    introspection_endpoint_auth_methods_supported: list[str] | None = pydantic.Field(
        default=[],
        title="Supported authentication methods",
        description=(
            "JSON array containing a list of client authentication methods "
            "supported by this introspection endpoint."
        ),
    )

    introspection_endpoint_auth_signing_alg_values_supported: list[str] | None = pydantic.Field(
        default=[],
        title="Supported signature algorithms",
        description=(
            "JSON array containing a list of the JWS signing algorithms "
            "supported by the introspection endpoint for the signature on the JWT "
            "used to authenticate the client at the introspection endpoint."
        ),
    )

    signed_metadata: str | None = pydantic.Field(
        default=None,
        title="Signed metadata",
        description=(
            "Signed JWT containing metadata values about the authorization "
            "server as claims."
        )
    )

    device_authorization_endpoint: HTTPSResourceLocator | None = pydantic.Field(
        default=None,
        title="Device authorization endpoint",
        description=(
            "URL of the authorization server's device authorization endpoint."
        ),
    )

    tls_client_certificate_bound_access_tokens: bool | None = pydantic.Field(
        default=True,
        title="Supports mTLS certificate-bound access tokens",
        description=(
            "Indicates authorization server support for mutual-TLS client "
            "certificate-bound access tokens."
        ),
    )

    mtls_endpoint_aliases: dict[str, str] | None = pydantic.Field(
        default={},
        title="Alternative mTLS endpoints",
        description=(
            "JSON object containing alternative authorization server "
            "endpoints, which a client intending to do mutual TLS will "
            "use in preference to the conventional endpoints."
        ),
    )

    nfv_token_signing_alg_values_supported: list[str] | None = pydantic.Field(
        default=[],
        title="Supported signature algorithms",
        description=(
            "JSON array containing a list of the JWS signing algorithms "
            "supported by the server for signing the JWT used as NFV Token."
        ),
    )

    nfv_token_encryption_alg_values_supported: list[str] | None = pydantic.Field(
        default=[],
        title="Supported encryption algorithms",
        description=(
            "JSON array containing a list of the JWE encryption algorithms "
            "(`alg` values) supported by the server to encode the JWT used as "
            "NFV Token."
        ),
    )

    nfv_token_encryption_enc_values_supported: list[str] | None = pydantic.Field(
        default=[],
        title="Supported content encryption algorithms",
        description=(
            "JSON array containing a list of the JWE encryption algorithms "
            "(`enc` values) supported by the server to encode the JWT used as "
            "NFV Token."
        ),
    )

    userinfo_endpoint: str | None = pydantic.Field(
        default=None,
        title="UserInfo endpoint",
        description="URL of the authorization servers' UserInfo Endpoint.",
    )

    acr_values_supported: list[str] | None = pydantic.Field(
        default=[],
        title="Supported ACR",
        description=(
            "JSON array containing a list of the Authentication Context Class "
            "References that this authorization server supports."
        ),
    )

    subject_types_supported: list[str] | None = pydantic.Field(
        default=[],
        title="Supported subject types",
        description=(
            "JSON array containing a list of the Subject Identifier types that "
            "this authorization server supports"
        ),
    )

    id_token_signing_alg_values_supported: list[str] | None = pydantic.Field(
        default=[],
        title="Supported signature algorithms",
        description=(
            "JSON array containing a list of the JWS signing algorithms "
            "supported by the server for signing the JWT used as ID Token."
        ),
    )

    id_token_encryption_alg_values_supported: list[str] | None = pydantic.Field(
        default=[],
        title="Supported encryption algorithms",
        description=(
            "JSON array containing a list of the JWE encryption algorithms "
            "(`alg` values) supported by the server to encode the JWT used as "
            "ID Token."
        ),
    )

    id_token_encryption_enc_values_supported: list[str] | None = pydantic.Field(
        default=[],
        title="Supported content encryption algorithms",
        description=(
            "JSON array containing a list of the JWE encryption algorithms "
            "(`enc` values) supported by the server to encode the JWT used as "
            "ID Token."
        ),
    )

    userinfo_signing_alg_values_supported: list[str] | None = pydantic.Field(
        default=[],
        title="Supported signature algorithms",
        description=(
            "JSON array containing a list of the JWS signing algorithms "
            "supported by the server for signing the JWT used as UserInfo Endpoint."
        ),
    )

    userinfo_encryption_alg_values_supported: list[str] | None = pydantic.Field(
        default=[],
        title="Supported encryption algorithms",
        description=(
            "JSON array containing a list of the JWE encryption algorithms "
            "(`alg` values) supported by the server to encode the JWT used as "
            "UserInfo Endpoint."
        ),
    )

    userinfo_encryption_enc_values_supported: list[str] | None = pydantic.Field(
        default=[],
        title="Supported content encryption algorithms",
        description=(
            "JSON array containing a list of the JWE encryption algorithms "
            "(`enc` values) supported by the server to encode the JWT used as "
            "UserInfo Endpoint."
        ),
    )

    request_object_signing_alg_values_supported: list[str] | None = pydantic.Field(
        default=[],
        title="Supported signature algorithms",
        description=(
            "JSON array containing a list of the JWS signing algorithms "
            "supported by the server for signing the JWT used as Request Object."
        ),
    )

    request_object_encryption_alg_values_supported: list[str] | None = pydantic.Field(
        default=[],
        title="Supported encryption algorithms",
        description=(
            "JSON array containing a list of the JWE encryption algorithms "
            "(`alg` values) supported by the server to encode the JWT used as "
            "Request Object."
        ),
    )

    request_object_encryption_enc_values_supported: list[str] | None = pydantic.Field(
        default=[],
        title="Supported content encryption algorithms",
        description=(
            "JSON array containing a list of the JWE encryption algorithms "
            "(`enc` values) supported by the server to encode the JWT used as "
            "Request Object."
        ),
    )

    display_values_supported: list[str] | None = pydantic.Field(
        default=[],
        title="Supported display modes",
        description=(
            "JSON array containing a list of the `display` parameter values "
            "that the OpenID Provider supports."
        ),
    )

    claim_types_supported: list[str] | None = pydantic.Field(
        default=[],
        title="Supported Claims Types",
        description=(
            "JSON array containing a list of the Claims Types "
            "that the OpenID Provider supports."
        )
    )

    claims_supported: list[str] | None = pydantic.Field(
        default=[],
        title="Supported Claims Types",
        description=(
            "JSON array containing a list of the Claim Names of the Claims "
            "that the OpenID Provider MAY be able to supply values for."
        )
    )

    claims_locales_supported: list[str] | None = pydantic.Field(
        default=[],
        title="Supported claim locales",
        description=(
            "Languages and scripts supported for values in Claims being "
            "returned, represented as a JSON array of BCP 47."
        ),
    )

    claims_parameter_supported: bool | None = pydantic.Field(
        default=False,
        title="Supports `claims` parameter?",
        description=(
            "Boolean value specifying whether the OP supports use of the "
            "`claims` parameter."
        ),
    )

    request_parameter_supported: bool | None = pydantic.Field(
        default=False,
        title="Supports `request` parameter?",
        description=(
            "Boolean value specifying whether the OP supports use of the "
            "`request` parameter."
        ),
    )

    request_uri_parameter_supported: bool | None = pydantic.Field(
        default=False,
        title="Supports `request_uri` parameter?",
        description=(
            "Boolean value specifying whether the OP supports use of the "
            "`request_uri` parameter."
        ),
    )

    require_request_uri_registration: bool | None = pydantic.Field(
        default=True,
        title="Requires pre-regiration?",
        description=(
            "Boolean value specifying whether the OP requires any `request_uri` "
            "values used to be pre-registered."
        ),
    )

    require_signed_request_object: bool | None = pydantic.Field(
        default=True,
        title="Requires pre-regiration?",
        description=(
            "Indicates where authorization request needs to be protected as "
            "**Request Object** and provided through either `request` or "
            "`request_uri` parameter."
        ),
    )

    pushed_authorization_request_endpoint: HTTPSResourceLocator | None = pydantic.Field(
        default=None,
        title="Pushed Authorization Request (PAR) endpoint",
        description=(
            "URL of the authorization server's pushed authorization request "
            "endpoint."
        ),
    )

    require_pushed_authorization_requests: bool | None = pydantic.Field(
        default=False,
        title="Requires PAR?",
        description=(
            "Indicates whether the authorization server accepts authorization "
            "requests only via PAR."
        ),
    )

    introspection_signing_alg_values_supported: list[str] | None = pydantic.Field(
        default=[],
        title="Supported signature algorithms",
        description=(
            "JSON array containing a list of algorithms supported by the "
            "authorization server for introspection response signing."
        ),
    )

    introspection_encryption_alg_values_supported: list[str] | None = pydantic.Field(
        default=[],
        title="Supported encryption algorithms",
        description=(
            "JSON array containing a list of algorithms supported by the "
            "authorization server for introspection response content key "
            "encryption (`alg` value)."
        ),
    )

    introspection_encryption_enc_values_supported: list[str] | None = pydantic.Field(
        default=[],
        title="Supported content encryption algorithms",
        description=(
            "JSON array containing a list of algorithms supported by the "
            "authorization server for introspection response content "
            "encryption (`enc` value)."
        ),
    )

    authorization_response_iss_parameter_supported: bool | None = pydantic.Field(
        default=False,
        title="Supports `iss` parameter in authorization response?",
        description=(
            "Boolean value indicating whether the authorization server "
            "provides the `iss` parameter in the authorization response."
        ),
    )

    authorization_signing_alg_values_supported: list[str] = pydantic.Field(
        default=[],
        title="JARM signature algorithms",
        description=(
            "A JSON array containing a list of the JWS signing algorithms "
            "(`alg` values) supported by the authorization endpoint to "
            "sign the response."
        )
    )

    authorization_encryption_alg_values_supported: list[str] = pydantic.Field(
        default=[],
        title="JARM key wrapping or key agreement algorithms",
        description=(
            "A JSON array containing a list of the JWS signing algorithms "
            "(`alg` values) supported by the authorization endpoint to "
            "encrypt the response."
        )
    )

    authorization_encryption_enc_values_supported: list[str] = pydantic.Field(
        default=[],
        title="JARM encryption algorithms",
        description=(
            "A JSON array containing a list of the JWE encryption algorithms "
            "(`enc` values) supported by the authorization endpoint to "
            "encrypt the response."
        )
    )

    signed_metadata: str | None = pydantic.Field(
        default=None,
        title="Signed metadata",
        description=(
            "A JWT containing metadata values about the authorization server as claims. "
            "This is a string value consisting of the entire signed JWT.  A `signed_metadata` "
            "metadata value SHOULD NOT appear as a claim in the JWT."
        )
    )

    jwks: JSONWebKeySet = pydantic.Field(
        default_factory=JSONWebKeySet,
        exclude=True
    )

    discovered: bool = pydantic.Field(
        default=False,
        exclude=True
    )

    metadata_url: str | None = pydantic.Field(
        default=None,
        exclude=True
    )

    @pydantic.model_validator(mode='before')
    def preprocess(cls, values: Union[dict[str, Any], 'ServerMetadata']):
        if isinstance(values, dict)\
        and values.get('issuer')\
        and DISCOVERED.get(values['issuer']):
            values = DISCOVERED[ values['issuer'] ].model_dump()
        return values

    @staticmethod
    def clear():
        """Clear the in-memory issuer cache."""
        DISCOVERED.clear()

    @staticmethod
    def is_cached(issuer: str):
        """Return a boolean indicating if the issuer is cached."""
        return bool(DISCOVERED.get(issuer))

    @classmethod
    async def get(cls, issuer: str):
        self = cls(issuer=issuer)
        await self.discover()
        return self

    def is_discovered(self):
        """Return a boolean indicating is the metadata is discovered."""
        return self.discovered

    async def discover(
        self,
        client: httpx.AsyncClient | None = None,
        metadata_url: str | None = None,
        force: bool = False
    ) -> bool:
        """Discover the authorization server metadata.

        By default, :meth:`ServerMetadata.discover()` uses the :attr:`issuer`
        to construct the URI of the metadata endpoint. If the server uses a
        non-standard or non-default metadata endpoint, it may be provided
        using the `metadata_url` parameter.

        The response from the authorization server will not override any
        properties already set on :class:`ServerMetadata`. This is to allow
        the implementer to provide their own values in cases where this is
        needed.

        Set the `force` parameter to ``True`` to force discovery for
        :class:`ServerMetadata` instances that have previously invoked
        the :meth:`discover()` method.
        """
        if self.is_discovered() and not force:
            return False
        metadata_url = self.metadata_url or metadata_url
        metadata = DISCOVERED.get(self.issuer)
        if metadata is None:
            async with self._client(client) as client:
                logger.debug("Retrieving server metadata (issuer: %s)", self.issuer)
                response = await self._discover_metadata_endpoint(client, metadata_url=metadata_url)
                if response is None:
                    raise NotDiscoverable(f"Unable to discover server metadata for {self.issuer}")
                try:
                    data = dict(response.json())
                    metadata = ServerMetadata.model_validate(data)
                except (TypeError, ValueError, json.JSONDecodeError, pydantic.ValidationError):
                    raise ValueError(
                        f"The metadata endpoint of {self.issuer} returned an unexpected "
                        f"response (url: {response.url})"
                    )

                # Fetch the JWKS. Do this before assigning the attributes so any failure
                # leaves the original fields untouched.
                jwks_uri = self.jwks_uri or metadata.jwks_uri
                if jwks_uri:
                    response = await client.get(url=jwks_uri)
                    if response.status_code != 200:
                        raise ValueError(
                            f"Unable to retrieve JWKS for {self.issuer}"
                            f": {response.status_code}"
                        )
                    try:
                        data = dict(response.json())
                        self.jwks = JSONWebKeySet.model_validate(data)
                    except (TypeError, ValueError, json.JSONDecodeError, pydantic.ValidationError):
                        raise ValueError(
                            f"The JWKS endpoint of {self.issuer} returned an unexpected "
                            f"response (url: {response.url})"
                        )

        # RFC 8414: The "issuer" value returned MUST be identical to the authorization
        # server's issuer identifier value into which the well-known URI string was
        # inserted to create the URL used to retrieve the metadata. If these values
        # are not identical, the data contained in the response MUST NOT be used.
        if self.issuer != metadata.issuer:
            raise ValueError(
                f"Metadata discovered from {self.issuer} specifies a different issuer"
                f": {metadata.issuer}"
            )

        for field in ServerMetadata.model_fields:
            if field in self.model_fields_set and not getattr(self, field) is None:
                continue
            setattr(self, field, getattr(metadata, field))

        self.discovered = True
        if metadata.signed_metadata:
            logger.warning(
                "Received unsupported signed_metadata from %s",
                self.issuer
            )

        DISCOVERED[self.issuer] = self
        return True

    @contextlib.asynccontextmanager
    async def _client(self, client: httpx.AsyncClient | None):
        if client is not None:
            yield client
            return
        async with httpx.AsyncClient(base_url=self.issuer, verify=not os.getenv('AEGISX_SSL_VERIFY') == '0') as client:
            yield client

    async def _discover_metadata_endpoint(
        self,
        client: httpx.AsyncClient,
        metadata_url: str | None = None,
        timeout: float = 10.0
    ) -> httpx.Response | None:
        metadata_url = metadata_url or self.metadata_url
        match bool(self.metadata_url):
            case False:
                paths: list[str] = [
                    '.well-known/oauth-authorization-server',
                    '.well-known/openid-configuration'
                ]
                for path in paths:
                    response = await client.get(
                        url=f'{str.strip(self.issuer, '/')}/{path}',
                        follow_redirects=True,
                        timeout=timeout
                    )
                    if response.status_code != 200:
                        continue
                    if str(response.url) != self.metadata_url:
                        self.metadata_url = str(response.url)
                    break
                else:
                    response = None
            case True:
                assert self.metadata_url is not None
                response = await client.get(
                    url=self.metadata_url,
                    follow_redirects=True
                )
                if response.status_code != 200:
                    response = None
        return response


    # TODO: These are non-standard properties.
    #token_endpoint_auth_encryption_alg_values_supported: list[str] | None = []
    #token_endpoint_auth_encryption_enc_values_supported: list[str] | None = []
    #assertion_signing_alg_values_supported: list[str] | None = []
    #assertion_encryption_alg_values_supported: list[str] | None = []
    #assertion_encryption_enc_values_supported: list[str] | None = []
    #required_encrypted_token_endpoint_auth: bool | None = False
    #require_encrypted_assertion: bool | None = False