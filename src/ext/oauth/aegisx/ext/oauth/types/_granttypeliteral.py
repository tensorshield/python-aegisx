from typing import Literal
from typing import TypeAlias


GrantTypeLiteral: TypeAlias = Literal[
    'authorization_code',
    'client_credentials',
    'refresh_token',
    'urn:ietf:params:oauth:grant-type:jwt-bearer',
    'urn:ietf:params:oauth:grant-type:saml2-bearer',
    'urn:ietf:params:oauth:grant-type:token-exchange',
    'urn:ietf:params:oauth:grant-type:device_code',
    'urn:ietf:params:oauth:grant-type:token-exchange'
]
