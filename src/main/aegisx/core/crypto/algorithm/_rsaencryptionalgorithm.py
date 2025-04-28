import pydantic
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from aegisx.types import DigestAlgorithm
from aegisx.types import EncryptionResult
from aegisx.types import PaddingAlgorithm
from ._encryptionalgorithm import EncryptionAlgorithm


class RSAEncryptionAlgorithm(EncryptionAlgorithm):
    __supported_key_types__ = {'RSA'}

    pad: PaddingAlgorithm = pydantic.Field(
        default=...
    )

    dig: DigestAlgorithm | None = pydantic.Field(
        default=None
    )

    @property
    def digest_algorithm(self):
        match self.dig is not None:
            case True:
                assert self.dig
                return self.dig.hash('cryptography')
            case False:
                return None

    @property
    def padding(self):
        return self.pad.padding(self.digest_algorithm)

    def decrypt(self, key: RSAPrivateKey, result: EncryptionResult) -> bytes:
        return key.decrypt(result.ct, padding=self.padding)

    def encrypt(self, key: RSAPublicKey, plaintext: bytes) -> EncryptionResult:
        if len(plaintext) > key.key_size:
            raise ValueError(
                'The plain text must not be longer than the key size of '
                f'{key.key_size} when using RSA encryption.'
            )
        return EncryptionResult(
            ct=key.encrypt(plaintext, padding=self.padding)
        )