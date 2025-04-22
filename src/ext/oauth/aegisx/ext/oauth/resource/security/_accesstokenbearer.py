import inspect
import logging
import re
from typing import Any
from typing import Awaitable
from typing import Callable
from typing import Generic
from typing import Literal
from typing import TypeVar

import fastapi
import fastapi.security
import pydantic
from aegisx.ext.iam import AnonymousSubject
from aegisx.ext.iam import AuthenticatedSubject
from aegisx.ext.jose import JSONWebKeySet
from aegisx.ext.jose import JSONWebToken
from aegisx.ext.jose import JWKSResolver
from aegisx.ext.jose import TokenValidator
from aegisx.ext.jose.models import JWSHeader
from aegisx.ext.jose.types import JWECompactEncoded
from aegisx.ext.jose.types import JWSCompactEncoded
from aegisx.ext.jose.types import Malformed
from aegisx.ext.jose.types import NotVerifiable
from aegisx.ext.jose.types import ForbiddenAudience
from aegisx.ext.jose.types import InvalidSignature
from aegisx.ext.jose.types import InvalidToken
from aegisx.ext.jose.types import Undecryptable
from aegisx.ext.jose.types import UntrustedIssuer

from aegisx.ext.oauth.resource.types import ResourceServerException
from aegisx.ext.oauth.resource.types import InvalidRequestToken
from ._accesstokenvalidator import AccessTokenValidator


Subject = AnonymousSubject | AuthenticatedSubject

T = TypeVar('T', default=JSONWebToken, bound=JSONWebToken)


class AccessTokenBearer(fastapi.security.HTTPBearer, Generic[T]):
    adapter: pydantic.TypeAdapter[JWECompactEncoded | JWSCompactEncoded]
    audience: set[str]
    audience_mode: Literal['domain', 'path']
    issuers: set[str] | re.Pattern[str] | None
    logger: logging.Logger = logging.getLogger(__name__)
    max_age: int
    subject_factory: Callable[[T], Subject | None | Awaitable[Subject | None]]
    subjects: set[str]
    types: T
    validator_class: type[AccessTokenValidator[T]] = AccessTokenValidator

    def __init__(
        self,
        types: Any,
        issuers: set[str] | re.Pattern[str] | None = None,
        audience: set[str] | None = None,
        audience_mode: Literal['domain', 'path'] = 'domain',
        max_age: int = 0,
        subjects: set[str] | None = None,
        subject_factory: Callable[[T], Subject | None | Awaitable[Subject | None]] | None = None,
        jwks_resolver: JWKSResolver | None = None,
        logger: logging.Logger | None = None
    ):
        super().__init__(
            auto_error=False,
            description=("OIDC ID Token")
        )
        self.adapter = pydantic.TypeAdapter(JWECompactEncoded | JWSCompactEncoded)
        self.audience = audience or set()
        self.audience_mode = audience_mode
        self.issuers = issuers
        self.jwks_resolver = jwks_resolver or JWKSResolver(domains=[])
        self.logger = logger or self.logger
        self.max_age = max_age
        self.subjects = subjects or set()
        self.subject_factory = subject_factory or (lambda _: AnonymousSubject()) # type: ignore
        self.types = types

    def get_audience(self, request: fastapi.Request) -> set[str]:
        return {*self.audience, *self.request_audience(request)}

    def get_token_validator(self, request: fastapi.Request) -> TokenValidator[T]:
        return self.validator_class(types=self.types, security=self)\
            .max_age(self.max_age)\
            .with_audiences(self.get_audience(request))\
            .with_subjects(self.subjects)

    def is_accepted_issuer(self, token: T) -> bool:
        if not isinstance(self.issuers, re.Pattern) or token.iss is None:
            return NotImplemented
        return bool(self.issuers.match(token.iss))

    def is_service_account(self, token: T) -> bool:
        return False

    def request_audience(self, request: fastapi.Request) -> set[str]:
        audience: set[str] = set()
        match self.audience_mode:
            case 'domain':
                audience.add(f'{request.url.scheme}://{request.url.netloc}')
            case 'path':
                audience.add(f'{request.url.scheme}://{request.url.netloc}{request.url.path}')
        return audience

    async def authenticate(
        self,
        request: fastapi.Request,
        bearer: fastapi.security.HTTPAuthorizationCredentials | None
    ):
        request.state.subject = AnonymousSubject()
        request.state.scope = set()
        if bearer is not None:
            try:
                token = await self.validate(request, bearer.credentials)
                request.state.scope = set(token.scope)
                request.state.subject = await self.get_subject(token)
                await self.validate_request(request, token, request.state.subject)
            except NotVerifiable:
                # We don't have any keys that can verify the signature and
                # there were no instruments to obtain them.
                raise InvalidRequestToken(
                    message=(
                        "The JSON Web Token (JWS) provided in the Authorization "
                        "header was signed using a key that is not trusted "
                        "by the server, and it had no means to obtain trusted "
                        "public keys."
                    )
                )
            except ForbiddenAudience:
                raise InvalidRequestToken(
                    message=(
                        'The intended audience specified by the "aud" claim '
                        'is not accepted by the server.'
                    )
                )
            except InvalidSignature:
                raise InvalidRequestToken(
                    message=(
                        'The credential was signed by an untrusted '
                        'key.'
                    )
                )
            except Undecryptable:
                raise InvalidRequestToken(
                    message=(
                        'The encrypted credential in the Authorization header '
                        'could not be decrypted with any known key. Consult the '
                        'service documentation on how to properly encrypt an '
                        'access token.'
                    )
                )
            except UntrustedIssuer as e:
                raise InvalidRequestToken(message=e.message)
            except (pydantic.ValidationError, InvalidToken, Malformed):
                raise InvalidRequestToken(
                    message=(
                        'The credential provided in the Authorization header '
                        'is malformed.'
                    )
                )
            except Exception as e:
                self.logger.exception(
                    'Caught fatal %s while validating credential: %s',
                    type(e).__name__,
                    repr(e)
                )
                raise InvalidRequestToken(
                    message=(
                        'The credential provided in the Authorization header '
                        'is not accepted.'
                    )
                )
        return request.state.subject

    async def get_subject(
        self,
        token: T
    ) -> AuthenticatedSubject | AnonymousSubject:
        subject = self.subject_factory(token)
        if inspect.isawaitable(subject):
            subject = await subject
        return subject or AnonymousSubject()

    async def get_verification_jwks(
        self,
        header: JWSHeader,
        payload: T,
        default: JSONWebKeySet
    ) -> JSONWebKeySet:
        jwks = default
        jku = payload.get_jwks_uri()
        if jku is not None:
            keys: set[str] = set()
            if header.kid:
                keys.add(header.kid)
            jwks = await self.jwks_resolver.resolve(jku, keys=keys)
        return jwks

    async def validate(
        self,
        request: fastapi.Request,
        token: JWECompactEncoded | JWSCompactEncoded | str
    ) -> T:
        if not isinstance(token, (JWECompactEncoded, JWSCompactEncoded)):
            token = self.adapter.validate_python(token)
        validator = self.get_token_validator(request)
        return await validator.validate(token)

    async def validate_request(
        self,
        request: fastapi.Request,
        token: T,
        subject: Subject
    ) -> None:
        pass

    async def __call__(self, request: fastapi.Request): # type: ignore
        request.state.subject = AnonymousSubject()
        bearer = await super().__call__(request)
        try:
            return await self.authenticate(request, bearer)
        except ResourceServerException as e:
            raise e.http()