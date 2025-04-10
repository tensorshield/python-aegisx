import functools
import time
from typing import overload
from typing import Any
from typing import Generic
from typing import Iterable
from typing import TypeVar
from typing import Union

import pydantic
from libcanonical.types import Base64
from libcanonical.types import HTTPResourceLocator

from aegisx.ext.jose.types import InvalidSignature
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


T = TypeVar('T', default=Base64, bound=Base64 | JSONWebToken)

JOSEGeneralType = Union[JWSGeneralSerialization | JWEGeneralSerialization]


class TokenValidator(Generic[T]):
    InvalidSignature = InvalidSignature
    MalformedEncoding = MalformedEncoding
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
        types: Any = Base64,
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

    def get_context(self) -> dict[str, Any]:
        return {
            'audiences': self.audience,
            'issuers': self.issuer,
            'max_clock_skew': self.max_clock_skew,
            'mode': 'deserialize',
            'now': int(time.time()),
            'ttl': self.ttl,
            'required': self.required,
            'subjects': self.subjects,
            **self.context_override
        }

    def inspect(self, encoded: Any):
        adapter: pydantic.TypeAdapter[JOSEGeneralType]
        adapter = pydantic.TypeAdapter(JOSEGeneralType)
        obj = adapter.validate_python(encoded)
        return obj.headers

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

    @functools.singledispatchmethod
    async def validate(self, token: Any) -> T:
        try:
            token = self.decoder.validate_python(token)
        except pydantic.ValidationError:
            raise self.MalformedEncoding
        return await self.validate(token)

    async def validate_token(self, jwt: JSONWebToken):
        await self.cache.consume(jwt)

    async def verify(
        self,
        payload: bytes,
        signature: Signature,
        *signatures: Signature
    ) -> list[Signature]:
        valid: list[Signature] = []
        match bool(signatures):
            case False:
                if await self.verify_signature(
                    signature,
                    signature.get_signing_input(payload)
                ):
                    valid.append(signature)
            case True:
                # TODO: Run async
                for signature in [signature, *signatures]:
                    if await self.verify_signature(
                        signature,
                        signature.get_signing_input(payload)
                    ):
                        valid.append(signature)
        return valid

    async def verify_signature(self, signature: Signature, payload: bytes) -> bool:
        return await self.jwks.verify(signature, payload)

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
    async def _(self, token: JWSCompactSerialization | JWSFlattenedSerialization | JWSGeneralSerialization) -> T: # type: ignore
        if self._verify:
            await self.verify(token.get_raw_payload(), *token.get_signatures())
        return self.adapter.validate_python(
            token.get_payload(),
            context=self.get_context()
        )

    @validate.register
    async def _(self, token: JWEGeneralSerialization) -> T:
        _, pt = await self.jwks.decrypt(token)
        return self.adapter.validate_python(pt)

    @validate.register
    async def _(self, token: JSONWebToken) -> T:
        return self.validate_payload(token) # type: ignore