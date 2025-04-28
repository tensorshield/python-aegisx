import pydantic
from cryptography.exceptions import InvalidSignature

from aegisx.types import SymmetricSigningKey
from ._signingalgorithm import SigningAlgorithm


class HMACSigningAlgorithm(SigningAlgorithm):
    __supported_key_types__ = {'oct'}

    alg: str | None = pydantic.Field(
        default=None
    )

    def generate(self) -> SymmetricSigningKey:
        return SymmetricSigningKey.generate()

    def sign(
        self,
        key: SymmetricSigningKey,
        message: bytes,
        prehashed: bool = False
    ) -> bytes:
        assert self.dig
        assert isinstance(key, SymmetricSigningKey)
        return key.sign(message, dig=str(self.dig))

    def verify(
        self,
        key: SymmetricSigningKey,
        signature: bytes,
        message: bytes,
        prehashed: bool = False
    ) -> bool:
        assert self.dig
        assert isinstance(key, SymmetricSigningKey)
        try:
            key.verify(
                signature=signature,
                message=message,
                dig=str(self.dig)
            )
            return True
        except InvalidSignature:
            return False