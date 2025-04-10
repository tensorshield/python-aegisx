import hashlib
from typing import cast
from typing import ClassVar
from typing import Literal
from typing import TypeVar

import pydantic
from aegisx.types import SpaceSeparatedSet
from aegisx.ext.jose.models import JSONWebToken
from libcanonical.types import Base64
from libcanonical.types import EmailAddress
from libcanonical.types import HTTPResourceLocator

from aegisx.ext.oauth.types import AuthenticationMethodReferenceLiteral
from aegisx.ext.oauth.types import OIDCValidationContext


R = TypeVar('R')


class OIDCToken(JSONWebToken):
    supported_algorithms: ClassVar[set[str]] = {
        'HS256', 'HS384', 'HS512',
        'RS256', 'RS384', 'RS512',
        'PS256', 'PS384', 'PS512',
        'ES256', 'ES384', 'ES512',
    }

    acr: HTTPResourceLocator | Literal['0'] = pydantic.Field(
        default='0',
        title="Authentication Context Class Reference (ACR)",
        description=(
            "String specifying an Authentication Context Class Reference (ACR) value "
            "that identifies the Authentication Context Class (ACC) that the "
            "authentication performed satisfied. The value `0` indicates the end-"
            "user authentication did not meet the requirements of ISO/IEC 29115 level "
            "1. For historic reasons, the value `0` is used to indicate that there is "
            "no confidence that the same person is actually there. Authentications with "
            "level 0 SHOULD NOT be used to authorize access to any resource of any "
            "monetary value. An absolute URI or an RFC 6711 registered name SHOULD "
            "be used as the `acr` value; registered names MUST NOT be used with a "
            "different meaning than that which is registered. Parties using this "
            "claim will need to agree upon the meanings of the values used, which "
            "may be context specific. The `acr` value is a case-sensitive string."
        )
    )

    amr: list[AuthenticationMethodReferenceLiteral] = pydantic.Field(
        default_factory=list,
        title="Authentication methods",
        description=(
            "JSON array of strings that are identifiers for authentication "
            "methods used in the authentication."
        )
    )

    at_hash: Base64 | None = pydantic.Field(
        default=None,
        title="Access token hash",
        description=(
            "The base64url encoding of the left-most half of the hash of the octets of the "
            "ASCII representation of the `access_token` value, where the hash algorithm used "
            "is the hash algorithm used in the `alg` header parameter of the ID Token's JOSE "
            "header. For instance, if the alg is `RS256`, hash the `access_token` value with "
            "SHA-256, then take the left-most 128 bits and base64url-encode them. The "
            "`at_hash` value is a case-sensitive string."
        )
    )

    azp: HTTPResourceLocator | str | None = pydantic.Field(
        default=None,
        title="Authorized party",
        description=(
            "The party to which the ID Token was issued. If present, it "
            "MUST contain the OAuth 2.0 Client ID of this party. The `azp` "
            "value is a case-sensitive string containing a string or URI value."
        )
    )

    auth_time: int | None = pydantic.Field(
        default=None,
        title="Authenticated",
        description=(
            "Time when the end-user authentication occurred. Its value is a JSON "
            "number representing the number of seconds from 1970-01-01T00:00:00Z "
            "as measured in UTC until the date/time. When a `max_age` request is "
            "made or when `auth_tim`e` is requested as an essential claim, then t"
            "his claim is present; otherwise, its inclusion is optional."
        )
    )

    c_hash: Base64 | None = pydantic.Field(
        default=None,
        title="Code hash",
        description=(
            "The base64url encoding of the left-most half of the hash of the octets "
            "of the ASCII representation of the `code` value, where the hash algorithm "
            "used is the hash algorithm used in the `alg` Header Parameter of the ID "
            "Token's JOSE Header. For instance, if the alg is HS512, hash the `code` "
            "value with SHA-512, then take the left-most 256 bits and base64url-encode "
            "them. The `c_hash` value is a case-sensitive string. If the ID Token is "
            "issued from the authorization endpoint with a code, which is the case for "
            "the `response_type` values `code id_token` and `code id_token token`, "
            "this parameter is REQUIRED; otherwise, its inclusion is OPTIONAL."
        )
    )

    email: EmailAddress | None = pydantic.Field(
        default=None,
        title="Email",
        description=(
            "The end-user's preferred e-mail address. Its value MUST conform to "
            "the RFC 5322 addr-spec syntax."
        )
    )

    email_verified: bool = pydantic.Field(
        default=False,
        title="Email verified?",
        description=(
            "Is `true` if the end-user's e-mail address has been verified; otherwise `false`. "
            "When `email_verified` is `true`, this means that the authorization server took "
            "affirmative steps to ensure that this e-mail address was controlled by the end-"
            "user at the time the verification was performed."
        )
    )

    family_name: str | None = pydantic.Field(
        default=None,
        title="Family name",
        description=(
            "The surname(s) or last name(s) of the end-user. Note that in some "
            "cultures, people can have multiple family names or no family name; "
            "all can be present, with the names being separated by space characters."
        )
    )

    given_name: str | None = pydantic.Field(
        default=None,
        title="Given name",
        description=(
            "The given name(s) or first name(s) of the end-user. Note that in "
            "some cultures, people can have multiple given names; all can be "
            "present, with the names being separated by space characters."
        )
    )

    name: str | None = pydantic.Field(
        default=None,
        title="Name",
        description=(
            "The end-user's full name in displayable form including all name "
            "parts, possibly including titles and suffixes, ordered according "
            "to the end-user's locale and preferences."
        )
    )

    nonce: str | None = pydantic.Field(
        default=None,
        title="Nonce",
        description=(
            "String value used to associate a client session with an ID Token, and "
            "to mitigate replay attacks. The value is passed through unmodified "
            "from the authorization request to the ID Token. If present in the "
            "ID Token, Clients must verify that the `nonce` claim value is equal "
            "to the value of the `nonce` parameter sent in the authorization request."
        )
    )

    picture: HTTPResourceLocator | None = pydantic.Field(
        default=None,
        title="Picture",
        description=(
            "The URL of the end-user's profile picture. This URL MUST refer "
            "to an image file (for example, a PNG, JPEG, or GIF image file), "
            "rather than to a web page containing an image. Note that this "
            "URL SHOULD specifically reference a profile photo of the end-user "
            "suitable for displaying when describing the end-user, rather than "
            "an arbitrary photo taken by the End-User."
        )
    )

    preferred_username: str | None = pydantic.Field(
        default=None,
        title="Preferred username",
        description=(
            "Shorthand name by which the end-user wishes to be referred to at the "
            "client, such as `janedoe` or `j.doe`. This value MAY be any valid JSON "
            "string including special characters such as @, /, or whitespace. The "
            "client MUST NOT rely upon this value being unique"
        )
    )

    sid: str | None = pydantic.Field(
        default=None,
        title="Session ID",
        description=(
            "The end-users' session identifier. See OpenID Connect Front-Channel "
            "Logout 1.0, Section 3."
        )
    )

    # Non Standard
    typ: str | None = pydantic.Field(
        default=None,
        title="Type"
    )

    hd: str | None = pydantic.Field(
        default=None,
        title="HD",
        description=(
            "Streamline the login process for accounts owned by a Google Cloud "
            "organization. By including the Google Cloud organization domain "
            "(for example, `mycollege.edu`), you can indicate that the account "
            "selection UI should be optimized for accounts at that domain. To "
            "optimize for Google Cloud organization accounts generally instead "
            "of just one Google Cloud organization domain, set a value of an "
            "asterisk (`*`): `hd=*.`."
        )
    )

    @property
    def scope(self) -> SpaceSeparatedSet:
        return SpaceSeparatedSet()

    @pydantic.model_validator(mode='after')
    def validate_oidc(
        self,
        info: pydantic.ValidationInfo,
    ):
        # It is assumed here that all tokens are issued through the
        # authorization code or hybrid flow.
        ctx = cast(OIDCValidationContext | None, info.context)
        if ctx is not None and ctx.get('client_id'): # TODO
            assert set(ctx.keys()) >= {'client_id', 'grant', 'jws', 'metadata', 'now', 'params'}
            now = ctx['now']
            if not ctx['grant'].access_token:
                raise ValueError(
                    'an OpenID Connect ID Token must be validated '
                    'against an access token.'
                )
            if len(ctx['jws'].signatures) > 1:
                raise ValueError('OpenID ID Tokens can not have multiple signers.')
            if len(ctx['jws'].signatures) == 0:
                raise ValueError('OpenID ID Tokens must be signed.')

            # For now only algorithms that have a hash are supported.
            # Other algorithms, such as EdDSA are pending a decision,
            # see https://bitbucket.org/openid/connect/issues/1125/_hash-algorithm-for-eddsa-id-tokens
            alg = list(ctx['jws'].algorithms)[0]
            if alg not in self.supported_algorithms:
                raise ValueError(f'unsupported signature algorithm: {alg}')
            assert alg.dig is not None

            # Validate at_hash and c_hash
            l = (int(alg[-3:]) // 8) // 2
            h = hashlib.new(alg.dig)
            h.update(str.encode(ctx['grant'].access_token, 'ascii'))
            if not self.at_hash:
                raise ValueError('the "at_hash" claim MUST be present.')
            if l != len(self.at_hash):
                raise ValueError(f'invalid "at_hash" length: {len(self.at_hash)}.')
            if bytes(self.at_hash) != h.digest()[:l]:
                raise ValueError('digest mismatch between "at_hash" and "access_token".')

            if self.c_hash:
                h = hashlib.new(alg.dig)
                h.update(str.encode(ctx['grant'].access_token, 'ascii'))
                if l != len(self.c_hash):
                    raise ValueError(f'invalid "c_hash" length: {len(self.c_hash)}.')
                if bytes(self.c_hash) != h.digest()[:l]:
                    raise ValueError('digest mismatch between "c_hash" and "access_token".')

            if self.azp and self.azp != ctx['client_id']:
                raise ValueError('requesting client is not the authorized party.')

            if ctx['client_id'] not in self.aud:
                raise ValueError('requesting client is not the audience.')

            if ctx['params'].max_age:
                # Presence of this attribute is guaranteed by the "required"
                # specification in the validation context.
                assert self.iat
                if (now - self.iat) > ctx['params'].max_age:
                    raise ValueError('"iat" is too far in the past.')

            if ctx['params'].nonce != self.nonce:
                raise ValueError('the "nonce" claim does not match the request parameter.')

        return self