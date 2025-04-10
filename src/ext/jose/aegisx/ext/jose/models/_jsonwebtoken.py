import datetime
import time
from typing import Any
from typing import Iterable

import pydantic
from libcanonical.types import HTTPResourceLocator
from libcanonical.utils.encoding import b64encode

from aegisx.ext.jose.types import ForbiddenAudience
from aegisx.ext.jose.types import MissingAudience
from aegisx.ext.jose.types import UntrustedIssuer


class JSONWebToken(pydantic.BaseModel):
    model_config = {
        'extra': 'forbid',
        'populate_by_name': True
    }

    iss: HTTPResourceLocator | str | None = pydantic.Field(
        default=None
    )

    sub: str | None = pydantic.Field(
        default=None
    )

    aud: set[HTTPResourceLocator | str] = pydantic.Field(
        default_factory=set
    )

    exp: int | None = pydantic.Field(
        default=None
    )

    nbf: int | None = pydantic.Field(
        default=None
    )

    iat: int | None = pydantic.Field(
        default=None
    )

    jti: str | None = pydantic.Field(
        default=None
    )

    @property
    def claims(self):
        return self.model_dump(
            mode='json',
            exclude_defaults=True,
            exclude_none=True,
            exclude_unset=True
        )

    @pydantic.field_validator('aud', mode='before')
    def preprocess_aud(cls, value: Iterable[HTTPResourceLocator | str] | HTTPResourceLocator | str | None):
        if isinstance(value, (HTTPResourceLocator, str)):
            value = {value}
        return value

    @pydantic.field_serializer('aud', when_used='always')
    def postprocess_aud(self, value: Iterable[HTTPResourceLocator | str] | HTTPResourceLocator | str | None):
        if isinstance(value, set) and len(value) == 1:
            value = set(value).pop()
        return value

    @pydantic.field_validator('aud', mode='after')
    def validate_aud(cls, value: set[str] | None, info: pydantic.ValidationInfo):
        if info.context:
            claimed: set[str] = value or set()
            allowed: set[str] = info.context.get('audiences') or set()
            if allowed and not bool(allowed & claimed) or (allowed and not claimed):
                forbidden = claimed - allowed
                match bool(forbidden):
                    case True:
                        raise ForbiddenAudience(f"audience not allowed: {str.join(', ', sorted(forbidden))}")
                    case False:
                        raise MissingAudience(f"token audience must be one of: {str.join(', ', allowed)}")
        return value

    @pydantic.field_validator('exp', mode='before')
    def validate_exp(cls, value: int | None, info: pydantic.ValidationInfo) -> int | None:
        if info.context:
            mode = info.context.get('mode')
            now: int = info.context.get('now') or int(time.time())
            dt = datetime.datetime.fromtimestamp(now, datetime.timezone.utc)
            if mode == 'deserialize' and value is not None:
                if value < now:
                    raise ValueError(f'token expired at {dt}')
        return value

    @pydantic.model_validator(mode='after')
    def validate_iss(self, info: pydantic.ValidationInfo):
        if info.context and info.context.get('mode') == 'deserialize':
            issuers: set[str] = info.context.get('issuers')
            if issuers and self.iss not in issuers:
                raise UntrustedIssuer
        return self

    @pydantic.field_validator('nbf', mode='before')
    def validate_nbf(cls, value: int | None, info: pydantic.ValidationInfo) -> int | None:
        if info.context:
            mode = info.context.get('mode')
            now: int = info.context.get('now') or int(time.time())
            dt = datetime.datetime.fromtimestamp(now, datetime.timezone.utc)
            if mode == 'deserialize' and value is not None:
                if value > now:
                    raise ValueError(f'token must not be used before {dt}')
        return value

    @classmethod
    def deserialize(
        cls,
        claims: dict[str, Any] | bytes | str,
        audiences: set[str] | None = None,
        now: float | None = None
    ):
        ctx: dict[str, Any] = {
            'mode': 'deserialize',
            'now': now or int(time.time()),
            'audiences': audiences or set()
        }
        match isinstance(claims, dict):
            case True:
                return cls.model_validate(claims, context=ctx)
            case False:
                assert isinstance(claims, (str, bytes))
                return cls.model_validate_json(claims, context=ctx)

    def __str__(self): # pragma: no cover
        return self.model_dump_json(
            exclude_defaults=True,
            exclude_none=True,
            by_alias=True
        )

    def __bytes__(self): # pragma: no cover
        return b64encode(str(self))