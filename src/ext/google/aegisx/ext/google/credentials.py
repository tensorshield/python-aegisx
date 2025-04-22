import os
from typing import cast

import google.auth
from google.auth.impersonated_credentials import Credentials as ImpersonatedCredentials
from google.oauth2.credentials import Credentials as DefaultCredentials
from google.oauth2.service_account import Credentials as ServiceAccountCredentials


__all__: list[str] = ['default_credentials']


Credentials = (ImpersonatedCredentials, ServiceAccountCredentials)

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