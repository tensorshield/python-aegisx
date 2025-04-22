import asyncio
import json
import logging
import os
import time
from typing import cast
from typing import Any
from typing import AsyncGenerator
from typing import Iterable

import httpx
import google.auth
from google.auth.impersonated_credentials import Credentials as ImpersonatedCredentials
from google.oauth2.credentials import Credentials as DefaultCredentials
from google.oauth2.service_account import Credentials as ServiceAccountCredentials
from google.cloud.iam_credentials_v1 import IAMCredentialsAsyncClient


Credentials = (ImpersonatedCredentials, ServiceAccountCredentials)


class GoogleServiceAccountAuth(httpx.Auth):
    """HTTPX authentication class using Google Service Account
    or impersonation.
    """
    audience: str
    client: IAMCredentialsAsyncClient | None
    credentials: ServiceAccountCredentials | ImpersonatedCredentials
    exp: int | None = None
    leeway: int = 60
    logger: logging.Logger = logging.getLogger(__name__)
    service_account: str
    target_scopes: set[str]
    timeout: float
    token_ttl: int
    token: str | None = None

    @staticmethod
    def default_credentials(
        credentials: ServiceAccountCredentials | ImpersonatedCredentials | DefaultCredentials | None = None,
        service_account: str | None = os.getenv('GOOGLE_SERVICE_ACCOUNT_EMAIL'),
        target_scopes: set[str] = {'https://www.googleapis.com/auth/cloud-platform'},
    ) -> tuple[str, ImpersonatedCredentials | ServiceAccountCredentials]:
        if credentials is None:
            credentials, _ = cast(
                tuple[DefaultCredentials, str],
                google.auth.default() # type: ignore
            )
        if isinstance(credentials, ServiceAccountCredentials): # pragma: no cover
            credentials = credentials
            service_account = credentials.service_account_email

        if not isinstance(credentials, Credentials):
            if service_account is None: # pragma: no cover
                raise TypeError(
                    'When impersonating a service account, it\'s email address '
                    'must be specified using the "service_account" parameter or '
                    'by setting the GOOGLE_SERVICE_ACCOUNT_EMAIL environment '
                    'variable.'
                )
            service_account = service_account
            credentials = ImpersonatedCredentials(
                source_credentials=credentials,
                target_principal=service_account,
                target_scopes=list(target_scopes)
            )
        assert isinstance(service_account, str)
        assert isinstance(credentials, Credentials)
        return service_account, credentials

    def __init__(
        self,
        audience: str,
        scope: Iterable[str] | None = None,
        credentials: ServiceAccountCredentials | ImpersonatedCredentials | DefaultCredentials | None = None,
        service_account: str | None = os.getenv('GOOGLE_SERVICE_ACCOUNT_EMAIL'),
        token_ttl: int = 600,
        logger: logging.Logger | None = None,
        timeout: float = 60.0,
        _client: IAMCredentialsAsyncClient | None = None
    ):
        """Initialize the :class:`GoogleServiceAccountAuth` instance.

        Args:
            audience (str): The audience claim for the JWT.
            credentials (Union[ServiceAccountCredentials, ImpersonatedCredentials, DefaultCredentials, None], optional):
                Credentials to use. If not provided, defaults will be used.
            target_scopes (set[str], optional): OAuth scopes to request. Defaults to cloud-platform scope.
            service_account (str | None, optional): Service account email address.
            token_ttl (int, optional): Lifetime of the token in seconds. Defaults to 600.
            logger (logging.Logger | None, optional): Logger instance. Defaults to module logger.
            timeout (float, optional): Request timeout in seconds. Defaults to 60.0.
            _client (IAMCredentialsAsyncClient | None, optional): Optional IAMCredentialsAsyncClient instance.
        """
        self.audience = audience
        self.lock = asyncio.Lock()
        self.logger = logger or self.logger
        self.scope = set(scope or [])
        self.timeout = timeout
        self.token_ttl = token_ttl
        self.service_account, self.credentials = self.default_credentials(
            credentials=credentials,
            service_account=service_account
        )
        self.client = _client or IAMCredentialsAsyncClient(credentials=self.credentials)

    def must_refresh(self):
        """Determine if the access token needs to be refreshed.

        Returns:
            bool: ``True`` if refresh is required, ``False`` otherwise.
        """
        now = int(time.time()) - self.leeway
        return any([
            self.token is None,
            self.exp is not None and now >= self.exp
        ])

    def set_access_token(self, request: httpx.Request, token: str):
        """Attach the access token to the Authorization header.

        Args:
            request (httpx.Request): The outgoing request object.
            token (str): The OAuth2 access token.
        """
        request.headers['Authorization'] = f'Bearer {token}'

    def with_audience(self, audience: str):
        """Create a copy of this auth instance with a different audience.

        Args:
            audience (str): The new audience value.

        Returns:
            GoogleServiceAccountAuth: A new auth instance configured
                for the new audience.
        """
        assert self.service_account
        return GoogleServiceAccountAuth(
            audience=audience,
            credentials=self.credentials,
            service_account=self.service_account,
            token_ttl=self.token_ttl,
            logger=self.logger,
            _client=self.client
        )

    async def async_auth_flow(
        self,
        request: httpx.Request
    ) -> AsyncGenerator[httpx.Request, httpx.Response]:
        """HTTPX async authentication flow.

        Args:
            request (httpx.Request): The outgoing HTTP request.

        Yields:
            httpx.Request: The authenticated HTTP request.
        """
        async with self.lock:
            if self.must_refresh():
                self.logger.debug(
                    "Refresing access token for %s",
                    self.service_account
                )
                self.token, self.exp = await self.refresh()
        assert self.token is not None
        self.set_access_token(request, self.token)
        yield request

    async def refresh(self) -> tuple[str, int]:
        """Refresh the access token by signing a JWT.

        Returns:
            tuple[str, int]: A tuple containing the signed
                JWT and its expiration timestamp.
        """
        if self.client is None:
            self.client = IAMCredentialsAsyncClient(credentials=self.credentials)
        now = int(time.time())
        exp = now + self.token_ttl
        claims: dict[str, Any] = {
            'aud': self.audience,
            'iss': self.service_account,
            'sub': self.service_account,
            'iat': now,
            'exp': exp,
        }
        if self.scope:
            claims['scope'] = ' '.join(sorted(self.scope))
        response = await self.client.sign_jwt( # type: ignore
            name=f"projects/-/serviceAccounts/{self.service_account}",
            timeout=self.timeout,
            payload=json.dumps(claims)
        )
        return response.signed_jwt, exp