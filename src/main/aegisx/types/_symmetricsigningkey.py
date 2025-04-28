import hmac
import secrets

from cryptography.exceptions import InvalidSignature


class SymmetricSigningKey:

    @classmethod
    def generate(cls):
        return cls(secrets.token_bytes(64))

    def __init__(self, k: bytes):
        self.k = k

    def sign(
        self,
        message: bytes,
        dig: str
    ) -> bytes:
        m = hmac.new(self.k, message, dig)
        return m.digest()

    def verify(
        self,
        signature: bytes,
        message: bytes,
        dig: str
    ):
        m = self.sign(message, dig)
        if not secrets.compare_digest(m, signature):
            raise InvalidSignature