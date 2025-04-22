from typing import Iterable

import fastapi
from aegisx.ext.iam import AuthorizationContext

from aegisx.ext.oauth.resource.types import InvalidRequestScope
from aegisx.ext.oauth.resource.security import RequestContext
from ._currentscope import CurrentScope
from ._currentsubject import CurrentSubject


def Scope(scope: Iterable[str], *, context: RequestContext):
    required = set(scope)

    def require_scope(
        scope: CurrentScope,
        subject: CurrentSubject,
        context: AuthorizationContext = fastapi.Depends(context)
    ):
        missing = required - scope
        if missing:
            match subject.is_authenticated():
                case True:
                    raise InvalidRequestScope(missing).http()
                case False:
                    raise fastapi.HTTPException(
                        status_code=401,
                        headers={
                            'WWW-Authenticate': 'Bearer'
                        }
                    )

    return fastapi.Depends(require_scope)