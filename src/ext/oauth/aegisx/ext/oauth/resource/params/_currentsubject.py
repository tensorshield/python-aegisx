from typing import Annotated

import fastapi
from aegisx.ext.iam import AuthenticatedSubject
from aegisx.ext.iam import AnonymousSubject


async def get(request: fastapi.Request):
    subject = getattr(request.state, 'subject', None)
    if subject is None:
        subject = AnonymousSubject()
    return subject


CurrentSubject = Annotated[
    AuthenticatedSubject | AnonymousSubject,
    fastapi.Depends(get)
]