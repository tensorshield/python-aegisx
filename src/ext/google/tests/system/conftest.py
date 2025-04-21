import re

import fastapi
import httpx
import pydantic
import pytest
import pytest_asyncio
from aegisx.ext.iam import AnonymousSubject
from aegisx.ext.iam import AuthenticatedSubject
from aegisx.ext.jose import JWKSResolver
from aegisx.ext.oauth.resource.params import CurrentSubject
from aegisx.ext.oauth.resource.security import AccessTokenBearer

from aegisx.ext.google.auth import GoogleServiceAccountAuth
from aegisx.ext.google.models import GoogleServiceAccountToken


HTTP_METHODS: list[str] = [
    'GET',
    'POST',
    'PUT',
    'PATCH',
    'DELETE'
]


def subject_factory(token: GoogleServiceAccountToken):
    return AuthenticatedSubject(
        email=token.email,
        email_verified=token.email_verified,
        service_account=True
    )


async def userinfo(subject: CurrentSubject):
    response = UserInfoResponse(
        subject=subject
    )
    return fastapi.responses.JSONResponse(
        status_code=200,
        content=response.model_dump(mode='json')
    )


class UserInfoResponse(pydantic.BaseModel):
    subject: AnonymousSubject | AuthenticatedSubject


@pytest_asyncio.fixture(scope='module')
async def auth() -> None:
    return None


@pytest.fixture(scope='session')
def app() -> fastapi.FastAPI:
    app = fastapi.FastAPI(
        dependencies=[
            fastapi.Depends(
                AccessTokenBearer[GoogleServiceAccountToken](
                    GoogleServiceAccountToken,
                    issuers=re.compile(r'^[a-z0-9\-]+@[a-z0-9\-]+\.iam\.gserviceaccount\.com'),
                    jwks_resolver=JWKSResolver(domains={'www.googleapis.com'}),
                    subject_factory=subject_factory
                )
            )
        ]
    )
    app.add_api_route(
        path='/',
        endpoint=userinfo,
        methods=HTTP_METHODS,
        response_model=UserInfoResponse
    )
    return app


@pytest.fixture(scope='session')
def base_url() -> str:
    return 'http://127.0.0.1:8000'


@pytest_asyncio.fixture
async def default_auth(base_url: str):
    return GoogleServiceAccountAuth(
        audience=base_url
    )


@pytest_asyncio.fixture
async def transport(app: fastapi.FastAPI) -> httpx.ASGITransport:
    return httpx.ASGITransport(app=app)


@pytest_asyncio.fixture
async def client(
    auth: httpx.Auth | None,
    base_url: str,
    transport: httpx.AsyncBaseTransport
):
    client = httpx.AsyncClient(
        auth=auth,
        base_url=base_url,
        transport=transport
    )
    async with client:
        yield client