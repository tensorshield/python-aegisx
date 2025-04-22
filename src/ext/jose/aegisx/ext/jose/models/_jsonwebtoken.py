import datetime
import time
from typing import cast
from typing import Any
from typing import Callable
from typing import ClassVar
from typing import Iterable
from typing import Self

import pydantic
import pydantic_core
from aegisx.types import SpaceSeparatedSet
from libcanonical.types import HTTPResourceLocator
from libcanonical.utils.encoding import b64encode
from libcanonical.utils.encoding import b64decode_json
from pydantic_core import PydanticCustomError

from aegisx.ext.jose.types import UntrustedIssuer


class JSONWebToken(pydantic.BaseModel):
    __ttl__: ClassVar[int] = 0
    __typ__: ClassVar[str] = 'JWT'
    __cty__: ClassVar[str] = 'JWT'

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

    scope: SpaceSeparatedSet = pydantic.Field(
        default_factory=SpaceSeparatedSet,
        title="Scopes",
        description=(
            "A space-separated list of scopes associated with the token, "
            "in the format described in Section 3.3 of RFC 6749."
        )
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
            try:
                value = b64decode_json(value)
            except Exception:
                raise pydantic_core.PydanticCustomError(
                    'jose.malformed.token',
                    'The payload could not be decoded as a JSON Web '
                    'Token (JWT). Ensure that the payload is a JSON '
                    'object, encoded as urlsafe base64.'
                )
            if not isinstance(value, dict):
                raise pydantic_core.PydanticCustomError(
                    'jose.malformed.token',
                    'The payload could not be decoded as a JSON Web '
                    'Token (JWT) because the decoded value is not '
                    'a JSON object.'
                )

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
                        raise PydanticCustomError(
                            'jwt.aud.forbidden',
                            f"audience not allowed: {str.join(', ', sorted(forbidden))}", # type: ignore
                            info.context
                        )
                    case False:
                        raise PydanticCustomError(
                            'jwt.aud.missing',
                            'The "aud" claim must be one of {allowed}',
                            {'allowed': str.join(', ', allowed)}
                        )
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

    @pydantic.field_validator('iat', mode='before')
    def validate_iat(
        cls,
        value: int | None,
        info: pydantic.ValidationInfo
    ):
        ctx = cast(dict[str, Any], info.context or {})
        now = ctx.get('now', int(time.time()))
        if cls.__ttl__:
            if value is None:
                raise ValueError(
                    f'A time-to-live of {cls.__ttl__} is specified but '
                    'the token does not specify the "iat" claim.'
                )
            if (now - value) > cls.__ttl__:
                raise ValueError('The token is too old.')
        return value

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

    @pydantic.model_validator(mode='after')
    def validate_iss(self, info: pydantic.ValidationInfo):
        if info.context:
            if info.context.get('mode') == 'deserialize':
                issuers: set[str] | Callable[[Self], bool] = info.context.get('issuers', cast(set[str], set()))
                if isinstance(issuers, set) and issuers and not self.iss:
                    raise UntrustedIssuer(
                        'The token does not specify the "iss" claim.'
                    )
                if not self.is_acceped_issuer(issuers): # type: ignore
                    raise UntrustedIssuer(
                        f"Tokens issued by {self.iss} are not accepted."
                    )
        return self

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

    def is_acceped_issuer(self, issuers: set[str] | Callable[[Self], bool]):
        match bool(callable(issuers)):
            case True:
                assert callable(issuers)
                return issuers(self)
            case False:
                assert isinstance(issuers, set)
                return any([
                    self.iss in issuers,
                    not self.iss and not issuers
                ])

    def is_service_account(self) -> bool:
        """Return ``True`` if the JSON Web Token (JWT) represents an identity
        and the identity is a service account.
        """
        return False

    def get_jwks_uri(self) -> str | None:
        return None

    def __str__(self): # pragma: no cover
        return self.model_dump_json(
            exclude_defaults=True,
            exclude_none=True,
            exclude_unset=True,
            by_alias=True
        )

    def __bytes__(self): # pragma: no cover
        return b64encode(str(self))