import datetime
import time
from typing import cast
from typing import Any
from typing import ClassVar
from typing import Iterable

import pydantic
import pydantic_core
from libcanonical.types import HTTPResourceLocator
from libcanonical.utils.encoding import b64encode
from libcanonical.utils.encoding import b64decode_json


class JSONWebToken(pydantic.BaseModel):
    model_config = {
        'extra': 'forbid',
        'populate_by_name': True
    }

    #: Indicates the claims that are required on this specific JSON
    #: Web Token (JWT) model.
    required: ClassVar[set[str]] = set()

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

    @pydantic.model_validator(mode='wrap')
    @classmethod
    def preprocess(
        cls,
        value: Any,
        nxt: pydantic.ValidatorFunctionWrapHandler
    ):
        if isinstance(value, (bytes, str)):
            # Assume Base64 url encoding
            value = b64decode_json(value)
        return nxt(value)

    @pydantic.model_validator(mode='before')
    def validate_required(
        cls,
        values: dict[str, Any],
        info: pydantic.ValidationInfo
    ):
        # If the requirement member is present, it MUST be a set and
        # it defines the required fields in this JWT.
        ctx = cast(dict[str, Any], info.context or {})
        required: set[str] = set(ctx.get('required') or []) | cls.required

        # If the context specifies audiences, then the "aud" claim
        # must be present.
        if ctx.get('audiences'):
            required.add('aud')
        missing = required - set(values.keys())

        if bool(missing):
            raise pydantic_core.PydanticCustomError(
                'missing',
                "Missing required claims: {missing}",
                {'missing': ', '.join(sorted(missing))}
            )
        return values

    @pydantic.field_validator('aud', mode='before')
    def preprocess_aud(cls, value: Iterable[HTTPResourceLocator | str] | HTTPResourceLocator | str | None):
        if isinstance(value, (HTTPResourceLocator, str)):
            value = {value}
        return value

    @pydantic.field_serializer('aud', when_used='always')
    def postprocess_aud(self, value: Iterable[HTTPResourceLocator | str] | HTTPResourceLocator | str | None):
        if isinstance(value, set) and len(value) == 1:
            value = set(value).pop()
        elif not value:
            value = None
        return value

    @pydantic.field_validator('aud', mode='after')
    def validate_aud(cls, value: set[str] | None, info: pydantic.ValidationInfo):
        if info.context:
            claimed: set[str] = value or set()
            allowed: set[str] = info.context.get('audiences') or set()
            if not bool(allowed & claimed) or (allowed and not claimed):
                forbidden = claimed - allowed
                match bool(forbidden):
                    case True:
                        raise ValueError(f"audience not allowed: {str.join(', ', sorted(forbidden))}")
                    case False:
                        raise ValueError(f"token audience must be one of: {str.join(', ', allowed)}")
        return value

    @pydantic.field_validator('exp', mode='before')
    def validate_exp(cls, value: int | None, info: pydantic.ValidationInfo) -> int | None:
        if info.context:
            mode = info.context.get('mode')
            now: int = info.context.get('now', int(time.time()))
            dt = datetime.datetime.fromtimestamp(now, datetime.timezone.utc)
            if mode == 'deserialize':
                max_clock_skew: int = info.context.get('max_clock_skew', 0)
                if value is not None and value <= (now - max_clock_skew):
                    raise ValueError(f'token expired at {dt}')

                ttl: int = info.context.get('ttl')
                if ttl and value is None:
                    raise ValueError(
                        'token did not set the "exp" claim but a '
                        f'maximum age of {ttl} seconds is specified.'
                    )
                if ttl and value and (age := now - value) > ttl:
                    raise ValueError(
                        f'token can not be older than {ttl} seconds: {age}.'
                    )
        return value

    @pydantic.model_validator(mode='after')
    def validate_iss(self, info: pydantic.ValidationInfo):
        if info.context:
            if info.context.get('mode') == 'deserialize':
                issuers: set[str] = info.context.get('issuers')
                if issuers and not self.iss:
                    raise ValueError(
                        'The token does not specify the "iss" claim.'
                    )
                if issuers and self.iss not in issuers:
                    raise ValueError(
                        f"Tokens issued by {self.iss} are not accepted."
                    )
        return self

    @pydantic.field_validator('nbf', mode='before')
    def validate_nbf(cls, value: int | None, info: pydantic.ValidationInfo) -> int | None:
        if info.context:
            mode = info.context.get('mode')
            now: int = info.context.get('now', int(time.time()))
            dt = datetime.datetime.fromtimestamp(now, datetime.timezone.utc)
            if mode == 'deserialize' and value is not None:
                max_clock_skew: int = info.context.get('max_clock_skew', 0)
                if value > (now - max_clock_skew):
                    raise ValueError(f'token must not be used before {dt}')
        return value

    @pydantic.field_validator('sub', mode='before')
    def validate_sub(cls, value: str | None, info: pydantic.ValidationInfo) -> str | None:
        if info.context:
            subjects: set[str] = info.context.get('subjects') or set()
            if subjects and value not in subjects:
                raise ValueError(
                    'The subject specified by the "sub" claim is '
                    'not accepted.'
                )
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
            exclude_unset=True,
            by_alias=True
        )

    def __bytes__(self): # pragma: no cover
        return b64encode(str(self))