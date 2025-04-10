from typing import Any
from typing import Literal

from ._jwacontentencryptionalgorithm import JWAContentEncryptionAlgorithm
from ._keymanagementmode import KeyManagementMode
from ._keyusetype import KeyUseType
from ._keyoperationtype import KeyOperationType
from ._curvename import CurveName


__all__: list[str] = [
    'JSONWebAlgorithmConfig',
]


class JSONWebAlgorithmConfig:
    registry: dict[str, 'JSONWebAlgorithmConfig'] = {}
    crv: CurveName | None = None
    dig: Literal['sha1', 'sha256', 'sha384', 'sha512'] | None
    enc: JWAContentEncryptionAlgorithm | None
    kty: Literal['RSA', 'EC', 'OKP', 'oct']
    key_ops: set[KeyOperationType] | None
    mode: KeyManagementMode | None
    pad: Literal['RSSASSA-PSS', 'PKCS1', 'OAEP'] | None
    use: Literal['sig', 'enc']
    cipher: Literal['AES+GCM', 'AES+CBC', 'AESWRAP'] | None
    wrap: str | None

    @classmethod
    def get(cls, name: str) -> 'JSONWebAlgorithmConfig': # pragma: no cover
        try:
            return JSONWebAlgorithmConfig.registry[name]
        except KeyError:
            raise ValueError(f"unsupported algorithm {name}")

    def __init__(
        self,
        name: str,
        kty: Literal['RSA', 'EC', 'OKP', 'oct'],
        use: KeyUseType,
        dig: Literal['sha1', 'sha256', 'sha384', 'sha512'] | None = None,
        pad: Literal['RSSASSA-PSS', 'PKCS1', 'OAEP'] | None = None,
        crv: CurveName | None = None,
        enc: JWAContentEncryptionAlgorithm | None = None,
        key_ops: set[KeyOperationType] | None = None,
        mode: KeyManagementMode | None = None,
        length: int | None = None,
        cipher: Literal['AES+GCM', 'AES+CBC', 'AESWRAP'] | None = None,
        wrap: str | None = None
    ):
        self.name = name
        self.crv = crv
        self.dig = dig
        self.enc = enc
        self.key_ops = key_ops
        self.kty = kty
        self.pad = pad
        self.use = use
        self.cipher = cipher
        self.length = length
        self.mode = mode
        self.wrap = wrap
        self._register()

    def _register(self):
        JSONWebAlgorithmConfig.registry[self.name] = self

    def params(self) -> dict[str, str | set[KeyOperationType] | None]:
        params: dict[str, Any] = {
            'alg': self.name,
            'crv': self.crv,
            'use': self.use,
            'kty': self.kty,
            'key_ops': self.key_ops
        }
        return {k: v for k, v in params.items() if v is not None}

    def __str__(self):
        return self.name


JSONWebAlgorithmConfig('HS256', 'oct', 'sig', dig='sha256', length=256, key_ops={'sign', 'verify'})
JSONWebAlgorithmConfig('HS384', 'oct', 'sig', dig='sha384', length=384, key_ops={'sign', 'verify'})
JSONWebAlgorithmConfig('HS512', 'oct', 'sig', dig='sha512', length=512, key_ops={'sign', 'verify'})
JSONWebAlgorithmConfig('RS256', 'RSA', 'sig', dig='sha256', pad='PKCS1', key_ops={'sign', 'verify'})
JSONWebAlgorithmConfig('RS384', 'RSA', 'sig', dig='sha384', pad='PKCS1', key_ops={'sign', 'verify'})
JSONWebAlgorithmConfig('RS512', 'RSA', 'sig', dig='sha512', pad='PKCS1', key_ops={'sign', 'verify'})
JSONWebAlgorithmConfig('PS256', 'RSA', 'sig', dig='sha256', pad='RSSASSA-PSS', key_ops={'sign', 'verify'})
JSONWebAlgorithmConfig('PS384', 'RSA', 'sig', dig='sha384', pad='RSSASSA-PSS', key_ops={'sign', 'verify'})
JSONWebAlgorithmConfig('PS512', 'RSA', 'sig', dig='sha512', pad='RSSASSA-PSS', key_ops={'sign', 'verify'})
JSONWebAlgorithmConfig('ES256', 'EC', 'sig', dig='sha256', crv='P-256', key_ops={'sign', 'verify'})
JSONWebAlgorithmConfig('ES256K', 'EC', 'sig', dig='sha256', crv='P-256K', key_ops={'sign', 'verify'})
JSONWebAlgorithmConfig('ES384', 'EC', 'sig', dig='sha384', crv='P-384', key_ops={'sign', 'verify'})
JSONWebAlgorithmConfig('ES512', 'EC', 'sig', dig='sha512', crv='P-521', key_ops={'sign', 'verify'})
JSONWebAlgorithmConfig('EdDSA', 'OKP', 'sig', key_ops={'sign', 'verify'})
JSONWebAlgorithmConfig('RSA-OAEP', 'RSA', 'enc', key_ops={'unwrapKey', 'wrapKey'}, dig='sha1', pad='OAEP', mode='KEY_ENCRYPTION')
JSONWebAlgorithmConfig('RSA-OAEP-256', 'RSA', 'enc', key_ops={'unwrapKey', 'wrapKey'}, dig='sha256', pad='OAEP', mode='KEY_ENCRYPTION')
JSONWebAlgorithmConfig('RSA-OAEP-384', 'RSA', 'enc', key_ops={'unwrapKey', 'wrapKey'}, dig='sha384', pad='OAEP', mode='KEY_ENCRYPTION')
JSONWebAlgorithmConfig('RSA-OAEP-512', 'RSA', 'enc', key_ops={'unwrapKey', 'wrapKey'}, dig='sha512', pad='OAEP', mode='KEY_ENCRYPTION')
JSONWebAlgorithmConfig('A128KW', 'oct', 'enc', key_ops={'encrypt', 'decrypt'}, length=128, mode='KEY_WRAPPING', cipher='AESWRAP')
JSONWebAlgorithmConfig('A192KW', 'oct', 'enc', key_ops={'encrypt', 'decrypt'}, length=192, mode='KEY_WRAPPING', cipher='AESWRAP')
JSONWebAlgorithmConfig('A256KW', 'oct', 'enc', key_ops={'encrypt', 'decrypt'}, length=256, mode='KEY_WRAPPING', cipher='AESWRAP')
JSONWebAlgorithmConfig('A128GCMKW', 'oct', 'enc', key_ops={'encrypt', 'decrypt'}, length=128, mode='KEY_WRAPPING', cipher='AES+GCM')
JSONWebAlgorithmConfig('A192GCMKW', 'oct', 'enc', key_ops={'encrypt', 'decrypt'}, length=192, mode='KEY_WRAPPING', cipher='AES+GCM')
JSONWebAlgorithmConfig('A256GCMKW', 'oct', 'enc', key_ops={'encrypt', 'decrypt'}, length=256, mode='KEY_WRAPPING', cipher='AES+GCM')
JSONWebAlgorithmConfig('ECDH-ES', 'EC', 'enc', key_ops={'unwrapKey', 'wrapKey'}, mode='DIRECT_KEY_AGREEMENT')
JSONWebAlgorithmConfig('ECDH-ES+A128KW', 'EC', 'enc', key_ops={'unwrapKey', 'wrapKey'}, length=128, wrap='A128KW', mode='KEY_AGREEMENT_WITH_KEY_WRAPPING')
JSONWebAlgorithmConfig('ECDH-ES+A192KW', 'EC', 'enc', key_ops={'unwrapKey', 'wrapKey'}, length=192, wrap='A192KW', mode='KEY_AGREEMENT_WITH_KEY_WRAPPING')
JSONWebAlgorithmConfig('ECDH-ES+A256KW', 'EC', 'enc', key_ops={'unwrapKey', 'wrapKey'}, length=256, wrap='A256KW', mode='KEY_AGREEMENT_WITH_KEY_WRAPPING')
JSONWebAlgorithmConfig('dir', 'oct', 'enc', key_ops={'encrypt', 'decrypt'}, mode='DIRECT_ENCRYPTION')
JSONWebAlgorithmConfig('A128GCM', 'oct', 'enc', key_ops={'encrypt', 'decrypt'}, length=128, mode='KEY_WRAPPING', cipher='AES+GCM')
JSONWebAlgorithmConfig('A192GCM', 'oct', 'enc', key_ops={'encrypt', 'decrypt'}, length=192, mode='KEY_WRAPPING', cipher='AES+GCM')
JSONWebAlgorithmConfig('A256GCM', 'oct', 'enc', key_ops={'encrypt', 'decrypt'}, length=256, mode='KEY_WRAPPING', cipher='AES+GCM')
JSONWebAlgorithmConfig('A128CBC-HS256', 'oct', 'enc', key_ops={'encrypt', 'decrypt'}, dig='sha256', length=128, mode='KEY_WRAPPING', cipher='AES+CBC')
JSONWebAlgorithmConfig('A192CBC-HS384', 'oct', 'enc', key_ops={'encrypt', 'decrypt'}, dig='sha384', length=192, mode='KEY_WRAPPING', cipher='AES+CBC')
JSONWebAlgorithmConfig('A256CBC-HS512', 'oct', 'enc', key_ops={'encrypt', 'decrypt'}, dig='sha512', length=256, mode='KEY_WRAPPING', cipher='AES+CBC')