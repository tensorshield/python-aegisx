import pydantic
from libcanonical.types import Base64URLEncoded

from aegisx.ext.jose.types import JSONWebAlgorithm
from aegisx.ext.jose.types import JSONWebKeySetURL
from aegisx.ext.jose.types import X509CertificateURL
from aegisx.ext.jose.types import X509CertificateChain
from .jwk import JSONWebKey


class KeyIdentifier(pydantic.BaseModel):
    alg: JSONWebAlgorithm = pydantic.Field(
        default=...
    )

    jku: JSONWebKeySetURL | None = pydantic.Field(
        default=None
    )

    jwk: JSONWebKey | None = pydantic.Field(
        default=None
    )

    kid: str | None = pydantic.Field(
        default=None
    )

    x5u: X509CertificateURL | None = pydantic.Field(
        default=None
    )

    x5c: X509CertificateChain | None = pydantic.Field(
        default=None
    )

    x5t: Base64URLEncoded | None = pydantic.Field(
        default=None
    )

    x5t_s256: Base64URLEncoded | None = pydantic.Field(
        default=None,
        alias='x5t#S256'
    )