import pydantic
from libcanonical.types import EmailAddress

from aegisx.types import SpaceSeparatedSet
from aegisx.ext.jose import JSONWebToken
from aegisx.ext.jose.types import InvalidToken


class GoogleServiceAccountToken(JSONWebToken):
    model_config = {'extra': 'forbid'}

    __ttl__ = 600

    iss: EmailAddress = pydantic.Field( # type: ignore
        default=...,
        pattern=r'^[a-z0-9\-]+@[a-z0-9\-]+\.iam\.gserviceaccount\.com'
    )

    sub: EmailAddress = pydantic.Field( # type: ignore
        default=...,
        pattern=r'^[a-z0-9\-]+@[a-z0-9\-]+\.iam\.gserviceaccount\.com'
    )

    exp: int = pydantic.Field( # type: ignore
        default=...
    )

    iat: int = pydantic.Field( # type: ignore
        default=...
    )

    scope: SpaceSeparatedSet = pydantic.Field(
        default_factory=SpaceSeparatedSet,
        min_length=1
    )

    @property
    def email(self):
        return self.iss

    @property
    def email_verified(self):
        # The email is considered verified because the token does
        # not validate if the service account does not exist (will
        # be apparent when the JWKS can not be retrieved and the
        # signature does not validate).
        return True

    @pydantic.model_validator(mode='after')
    def validate_sub_equals_iss(self):
        if self.iss != self.sub:
            raise InvalidToken('Only self-issued access tokens are accepted.')
        return self

    @pydantic.model_serializer(mode='wrap')
    def include_calculated_properties(
        self,
        nxt: pydantic.SerializerFunctionWrapHandler,
        info: pydantic.SerializationInfo,
    ):
        values = nxt(self)
        if info.mode == 'python':
            values.update({
                'email': self.email,
                'email_verified': self.email_verified,
                'service_account': self.is_service_account()
            })
        return values

    def is_service_account(self):
        return True

    def get_jwks_uri(self):
        return f'https://www.googleapis.com/service_accounts/v1/metadata/jwk/{self.iss}'