import inspect

import fastapi
from aegisx.ext.iam import AuthorizationContext
from aegisx.ext.iam import AnonymousSubject


class NullRequestContext:

    def __init__(self):
        inspect.markcoroutinefunction(self)
        assert inspect.iscoroutinefunction(self)

    async def __call__(self, request: fastapi.Request):
        assert request.client
        return AuthorizationContext.model_validate({
            'subject': AnonymousSubject(),
            'remote_host': request.client.host
        })