import inspect
from typing import cast
from typing import Any
from typing import Awaitable
from typing import Callable
from typing import Literal

import fastapi
import fastapi.security
import pydantic
from aegisx.ext.iam import AnonymousSubject
from aegisx.ext.iam import AuthenticatedSubject
from aegisx.ext.jose.types import JWECompactEncoded
from aegisx.ext.jose.types import JWSCompactEncoded

from aegisx.ext.oauth.models import OIDCToken
from ._oidctokenvalidator import OIDCTokenValidator


Subject = AnonymousSubject | AuthenticatedSubject

SubjectFactory = Callable[[OIDCToken], Subject | None | Awaitable[Subject | None]]


class OIDCTokenBearer(fastapi.security.HTTPBearer):
    adapter: pydantic.TypeAdapter[JWECompactEncoded | JWSCompactEncoded]
    audience_mode: Literal['domain', 'path']
    max_age: int
    subjects: set[str]

    def __init__(
        self,
        issuers: set[str],
        audience: set[str] | None = None,
        audience_mode: Literal['domain', 'path'] = 'domain',
        max_age: int = 0,
        subjects: set[str] | None = None,
        subject_factory: SubjectFactory | None = None
    ):
        super().__init__(
            auto_error=False,
            description=("OIDC ID Token")
        )
        self.adapter = pydantic.TypeAdapter(JWECompactEncoded | JWSCompactEncoded)
        self.audience = audience or set()
        self.audience_mode = audience_mode
        self.issuers = issuers
        self.max_age = max_age
        self.subjects = subjects or set()
        self.subject_factory = subject_factory or cast(SubjectFactory, lambda _: AnonymousSubject()) # type: ignore

    def get_audience(self, request: fastapi.Request) -> set[str]:
        return {*self.audience, *self.request_audience(request)}

    def is_service_account(self, token: OIDCToken) -> bool:
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
        if bearer is not None:
            request.state.subject = await self.get_subject(
                await OIDCTokenValidator()
                    .max_age(self.max_age)
                    .with_audiences(self.get_audience(request))
                    .with_issuers(self.issuers)
                    .with_subjects(self.subjects)
                    .validate(
                        self.adapter.validate_python(bearer.credentials)
                    )
            )

    async def get_subject(
        self,
        token: OIDCToken
    ) -> AuthenticatedSubject[Any] | AnonymousSubject:
        subject = self.subject_factory(token)
        if inspect.isawaitable(subject):
            subject = await subject
        return subject or AnonymousSubject()

    async def __call__(self, request: fastapi.Request):
        request.state.subject = AnonymousSubject()
        bearer = await super().__call__(request)
        await self.authenticate(request, bearer)
        return bearer