import sr25519
from cryptography.exceptions import InvalidSignature


class Sr25519PublicKey:

    def __init__(self, x: bytes):
        self.x = x

    def verify(self, signature: bytes, data: bytes):
        try:
            if not sr25519.verify(signature, data, self.x): # type: ignore
                raise InvalidSignature
        except ValueError:
            raise InvalidSignature