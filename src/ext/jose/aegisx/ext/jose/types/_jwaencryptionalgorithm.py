from typing import Literal


JWAEncryptionAlgorithm = Literal[
    'RSA1_5',
    'RSA-OAEP',
    'RSA-OAEP-256',
    'A128KW',
    'A192KW',
    'A256KW',
    'dir',
    'ECDH-ES',
    'ECDH-ES+A128KW',
    'ECDH-ES+A192KW',
    'ECDH-ES+A256KW',
    'A128GCMKW',
    'A192GCMKW',
    'A256GCMKW',
    'PBES2-HS256+A128KW',
    'PBES2-HS384+A192KW',
    'PBES2-HS512+A256KW'
]