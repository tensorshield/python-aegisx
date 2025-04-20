import datetime
import ipaddress
from typing import ClassVar
from typing import Literal

import pydantic
from aegisx.ext.jose import JSONWebKey
from aegisx.ext.jose.models import JWSCompactSerialization
from libcanonical.types import EmailAddress

from ._authorizedkeytoken import AuthorizedKeyToken


class AuthorizedKey(pydantic.BaseModel):
    thumbprint_digest: ClassVar[Literal['sha256', 'sha384', 'sha512']] = 'sha256'

    email: EmailAddress = pydantic.Field(
        default=...
    )

    key: JSONWebKey = pydantic.Field(
        default=...
    )

    sig: JWSCompactSerialization[AuthorizedKeyToken] | None = pydantic.Field(
        default_factory=lambda: None
    )

    attestation: None = pydantic.Field(
        default_factory=lambda: None
    )

    authorized: datetime.datetime = pydantic.Field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc)
    )

    host: ipaddress.IPv4Address = pydantic.Field(
        default=...
    )

    @property
    def thumbprint(self):
        return self.key.thumbprint(self.thumbprint_digest)

    @pydantic.field_validator('key', mode='after')
    def validate_key(cls, key: JSONWebKey):
        if not key.is_public():
            raise ValueError(
                "only public keys are allowed as authorized keys."
            )
        if not key.is_asymmetric(): # pragma: no cover
            raise ValueError(
                "only asymmetric keys are allowed as authorized "
                "keys."
            )
        return key