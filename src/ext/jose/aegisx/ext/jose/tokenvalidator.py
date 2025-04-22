import functools
import time
from typing import overload
from typing import Any
from typing import Generic
from typing import Iterable
from typing import Literal
from typing import TypeVar
from typing import Union

import pydantic
from libcanonical.types import HTTPResourceLocator
from libcanonical.utils.encoding import b64decode

from aegisx.ext.jose.types import ForbiddenAudience
from aegisx.ext.jose.types import InvalidSignature
from aegisx.ext.jose.types import MalformedPayload
from aegisx.ext.jose.types import MalformedEncoding
from aegisx.ext.jose.types import MalformedObject
from aegisx.ext.jose.types import JSONObject
from aegisx.ext.jose.types import JWECompactEncoded
from aegisx.ext.jose.types import JWSCompactEncoded
from .cache import JOSECache
from .models import JSONWebToken
from .models import JSONWebKey
from .models import JSONWebKeySet
from .models import JWSHeader
from .models import JWEGeneralSerialization
from .models import JWSCompactSerialization
from .models import JWSFlattenedSerialization
from .models import JWSGeneralSerialization
from .models import Signature
from .tokenbuilder import SerializationFormat


T = TypeVar('T', default=bytes, bound=bytes | JSONWebToken)

JOSEGeneralType = Union[JWSGeneralSerialization | JWEGeneralSerialization]


class TokenValidator(Generic[T]):
    ForbiddenAudience = ForbiddenAudience
    InvalidSignature = InvalidSignature
    MalformedEncoding = MalformedEncoding
    MalformedPayload = MalformedPayload
    MalformedObject = MalformedObject
    adapter: pydantic.TypeAdapter[T]
    audience: set[str]
    context_override: dict[str, Any]
    decoder: pydantic.TypeAdapter[JWECompactEncoded | JWSCompactEncoded | JSONObject]
    jwt_media_types: set[str] = {'application/jwt', 'application/at+jwt'}
    jose: pydantic.TypeAdapter[
        Union[
            JWSGeneralSerialization,
            JWSFlattenedSerialization,
            JWSCompactSerialization
        ]
    ]
    issuer: set[str]
    required: set[str]
    subjects: set[str]
    ttl: int | None

    @property
    def context(self) -> dict[str, Any]:
        return self.get_context()

    @overload
    def __init__(
        self,
        types: type[T] = ...,
        *,
        audience: set[str] | str | None = ...,
        issuer: set[str] | str | None = ...,
        jwks: JSONWebKeySet | None = ...,
        required: set[str] | None = ...,
        verify: bool = ...,
        key: JSONWebKey | None = ...,
        keys: list[JSONWebKey] | None = ...,
        context: dict[str, Any] | None = ...,
        cache: JOSECache = JOSECache()
    ) -> None: ...

    # This second overload is for unsupported special forms (such as Annotated, Union, etc.)
    # Currently there is no way to type this correctly
    # See https://github.com/python/typing/pull/1618
    @overload
    def __init__(
        self,
        types: Any = ...,
        *,
        audience: set[str] | str | None = ...,
        issuer: set[str] | str | None = ...,
        jwks: JSONWebKeySet | None = ...,
        required: set[str] | None = ...,
        verify: bool = ...,
        key: JSONWebKey | None = ...,
        keys: list[JSONWebKey] | None = ...,
        context: dict[str, Any] | None = ...,
        max_clock_skew: int = 0,
        cache: JOSECache = JOSECache()
    ) -> None: ...

    def __init__(
        self,
        types: Any = bytes,
        *,
        audience: set[str] | str | None = None,
        issuer: set[str] | str | None = None,
        jwks: JSONWebKeySet | None = None,
        required: set[str] | None = None,
        verify: bool = True,
        key: JSONWebKey | None = None,
        keys: list[JSONWebKey] | None = None,
        context: dict[str, Any] | None = None,
        max_clock_skew: int = 0,
        cache: JOSECache = JOSECache()
    ):
        if isinstance(audience, str):
            audience = {audience}
        if isinstance(issuer, str):
            issuer = {issuer}
        self.adapter = pydantic.TypeAdapter(types)
        self.audience = audience or set()
        self.cache = cache
        self.context_override = context or {}
        self.decoder = pydantic.TypeAdapter(JWECompactEncoded | JWSCompactEncoded | JSONObject)
        self.issuer = issuer or set()
        self.jose = pydantic.TypeAdapter(
            Union[
                JWSGeneralSerialization,
                JWSFlattenedSerialization,
                JWSCompactEncoded
            ]
        )
        self.jwks = jwks or JSONWebKeySet()
        if key is not None:
            self.jwks.add(key)
        if keys is not None:
            self.jwks.update(keys)
        self.max_clock_skew = max_clock_skew
        self.ttl = None
        self.required = required or set()
        self.subjects = set()
        self._verify = verify

    def deserialize(
        self,
        typ: Literal['jws'],
        syntax: SerializationFormat,
        token: Any
    ):
        mode = f'{typ}:{syntax}'
        token = self.decoder.validate_python(token)
        match mode:
            case 'jws:compact':
                return JWSCompactSerialization.model_validate(token)
            case 'jws:flattened':
                return JWSFlattenedSerialization.model_validate(token)
            case 'jws:general':
                return JWSGeneralSerialization.model_validate(token)
            case _:
                pass

    def get_context(self) -> dict[str, Any]:
        ctx: dict[str, Any] = {
            'audiences': self.audience,
            'issuers': self.is_accepted_issuer,
            'max_clock_skew': self.max_clock_skew,
            'mode': 'deserialize',
            'now': int(time.time()),
            'ttl': self.ttl,
            'required': self.required,
            'subjects': self.subjects,
            **self.context_override
        }
        return ctx

    def inspect(self, encoded: Any):
        adapter: pydantic.TypeAdapter[JOSEGeneralType]
        adapter = pydantic.TypeAdapter(JOSEGeneralType)
        obj = adapter.validate_python(self.decoder.validate_python(encoded))
        return obj.headers

    def is_accepted_issuer(self, payload: JSONWebToken) -> bool:
        """Return a boolean indicating if the issuer of a JSON Web Token (JWT)
        is accepted."""
        return any([
            not self.issuer and payload.iss is None,
            payload.iss is not None and payload.iss in self.issuer
        ])

    def is_trusted_issuer(self, iss: HTTPResourceLocator | str | None):
        """Return ``True`` if the issuer is trusted for JSON Web Key Set (JWKS)
        retrieval over HTTP or any other discovery methods such as OAuth 2.x/Open
        ID Connect.
        """
        return str(iss) in self.issuer

    def max_age(self, seconds: int):
        """Configure the validator to only accept tokens with a maxmimum
        age of `seconds`.
        """
        self.ttl = seconds
        return self

    def validate_payload(self, payload: Any) -> T:
        return self.adapter.validate_python(payload, context=self.get_context())

    def validate_signature_header(self, header: JWSHeader):
        pass

    def with_audience(self, aud: str):
        """Configure the validator to only accept the given audience."""
        self.audience.add(aud)
        return self

    def with_audiences(self, audience: Iterable[str]):
        """Configure the validator to only accept the given audiences."""
        self.audience.update(audience)
        return self

    def with_issuer(self, iss: str):
        """Configure the validator to only accept the given issuer."""
        self.issuer.add(iss)
        return self

    def with_issuers(self, issuers: Iterable[str]):
        """Configure the validator to only accept the given issuers."""
        self.issuer.update(issuers)
        return self

    def with_subject(self, sub: str):
        """Configure the validator with a specific subject."""
        self.subjects.add(sub)
        return self

    def with_subjects(self, subjects: Iterable[str]):
        """Configure the validator with the given subjects."""
        self.subjects.update(subjects)
        return self

    async def get_verification_jwks(self, header: JWSHeader, payload: T):
        return self.jwks

    @functools.singledispatchmethod
    async def validate(self, token: Any) -> T:
        try:
            token = self.decoder.validate_python(token)
            return await self.validate(token)
        except pydantic.ValidationError as exception:
            for error in exception.errors():
                match error['type']:
                    case 'jose.malformed':
                        raise self.MalformedEncoding
                    case 'jose.malformed.token':
                        raise self.MalformedPayload(error['msg'])
                    case _:
                        continue
            raise # Should never happen

    async def validate_token(self, jwt: JSONWebToken):
        await self.cache.consume(jwt)

    async def verify(
        self,
        raw_payload: bytes,
        signature: Signature,
        *signatures: Signature,
        payload: T,
        jwks: JSONWebKeySet | None = None
    ) -> list[Signature]:
        valid: list[Signature] = []
        jwks = jwks or await self.get_verification_jwks(signature.protected, payload)
        match bool(signatures):
            case False:
                if await self.verify_signature(
                    signature,
                    signature.get_signing_input(raw_payload),
                    jwks=jwks
                ):
                    valid.append(signature)
            case True:
                # TODO: Run async
                for signature in [signature, *signatures]:
                    if await self.verify_signature(
                        signature,
                        signature.get_signing_input(raw_payload),
                        jwks=jwks
                    ):
                        valid.append(signature)
        return valid

    async def verify_signature(
        self,
        signature: Signature,
        payload: bytes,
        jwks: JSONWebKeySet
    ) -> bool:
        return await jwks.verify(signature, payload)

    @validate.register
    async def _(self, token: JSONObject) -> T:
        return await self.validate(self.jose.validate_python(token))

    @validate.register
    async def _(self, token: JWECompactEncoded) -> T:
        return await self.validate(JWEGeneralSerialization.model_validate(token))

    @validate.register
    async def _(self, token: JWSCompactEncoded) -> T:
        return await self.validate(JWSCompactSerialization.model_validate(token))

    @validate.register
    async def _(
        self,
        token: Union[
            JWSCompactSerialization,
            JWSFlattenedSerialization,
            JWSGeneralSerialization
        ]
    ) -> T: # type: ignore
        try:
            payload = self.adapter.validate_python(
                token.get_payload(),
                context=self.get_context()
            )
            assert isinstance(payload, (bytes, JSONWebToken))
            if self._verify and not (
                await self.verify(
                    token.get_raw_payload(),
                    *token.get_signatures(),
                    payload=payload
                )
            ):
                raise InvalidSignature

            # If the payload is bytes at this point,
            # assumed the raw payload is return and
            # decode from urlsafe b64.
            if isinstance(payload, bytes):
                payload = b64decode(payload)
            assert isinstance(payload, (bytes, JSONWebToken))
            return payload # type: ignore
        except pydantic.ValidationError as exception:
            for error in exception.errors():
                match error['type']:
                    case 'jwt.aud.forbidden':
                        raise ForbiddenAudience(f'Audience "{error["input"]}" is not acceptable.')
                    case 'jwt.aud.missing':
                        raise ForbiddenAudience(error['msg'])
                    case 'extra_forbidden':
                        raise self.MalformedPayload(error['msg'])
                    case _:
                        continue
            raise # Should not happen

    @validate.register
    async def _(self, token: JWEGeneralSerialization) -> T:
        _, pt = await self.jwks.decrypt(token)
        return self.adapter.validate_python(pt)

    @validate.register
    async def _(self, token: JSONWebToken) -> T:
        return self.validate_payload(token) # type: ignore