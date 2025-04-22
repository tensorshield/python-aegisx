import collections
import functools
import inspect
import re
from inspect import Parameter
from typing import Any
from typing import ClassVar
from typing import Generic
from typing import Iterable
from typing import TypeVar
from typing import Union

import fastapi
import pydantic
from aegisx.ext.iam import AnonymousSubject
from aegisx.ext.iam import AuthenticatedSubject
from aegisx.ext.iam import AuthorizationContext
from aegisx.ext.iam import IAMPolicy
from aegisx.ext.jose import JSONWebToken
from aegisx.ext.jose import JWKSResolver

from ._accesstokenbearer import AccessTokenBearer


T = TypeVar('T', default=JSONWebToken, bound=JSONWebToken)


class RequestContext(Generic[T]):
    __bearer_class__: ClassVar[type[AccessTokenBearer[T]]] = AccessTokenBearer[T] # type: ignore
    subject_claims: ClassVar[set[str]] = {'sub', 'email', 'email_verified'}
    subjects: pydantic.TypeAdapter[AnonymousSubject | AuthenticatedSubject]

    @functools.cached_property
    def __signature__(self) -> inspect.Signature:
        sig = inspect.signature(self.authorize)
        params = collections.OrderedDict(sig.parameters.items())
        params['subject'] = Parameter(
            kind=params['subject'].kind,
            name=params['subject'].name,
            annotation=params['subject'].annotation,
            default=fastapi.Depends(
                self.__bearer_class__(
                    types=Union[tuple(self.token_types)],
                    issuers=self.issuers,
                    jwks_resolver=self.jwks_resolver,
                    subject_factory=self.authenticate,
                    max_age=self.max_token_age
                )
            )
        )
        return sig.replace(parameters=list(params.values()))

    def __init__(
        self,
        token_types: Iterable[type[JSONWebToken]],
        *,
        issuers: set[str] | re.Pattern[str],
        domains: set[str],
        policy: IAMPolicy | None = None,
        max_token_age: int = 0
    ):
        self.domains = domains
        self.issuers = issuers
        self.jwks_resolver = JWKSResolver(domains=self.domains)
        self.max_token_age = max_token_age
        self.token_types = token_types
        self.policy = policy or IAMPolicy(bindings=tuple())
        self.subjects = (
            pydantic.TypeAdapter(AuthenticatedSubject | AnonymousSubject)
        )
        inspect.markcoroutinefunction(self)
        assert inspect.iscoroutinefunction(self)

    async def authenticate(self, token: T) -> AuthenticatedSubject | AnonymousSubject:
        claims = token.model_dump(
            include=self.subject_claims
        )
        return self.subjects.validate_python(claims)

    async def authorize(
        self,
        request: fastapi.Request,
        subject: AuthenticatedSubject | AnonymousSubject
    ) -> AuthorizationContext:
        assert request.client
        ctx = AuthorizationContext.model_validate({
            'subject': subject,
            'remote_host': request.client.host
        })
        subject.roles.update(self.policy.granted(ctx))
        return ctx

    async def __call__(self, *args: Any, **kwargs: Any):
        return await self.authorize(*args, **kwargs)