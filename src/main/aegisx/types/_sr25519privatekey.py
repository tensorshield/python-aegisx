import sr25519
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ._sr25519publickey import Sr25519PublicKey


class Sr25519PrivateKey(Sr25519PublicKey):

    @classmethod
    def generate(cls):
        k = Ed25519PrivateKey.generate()
        x, d = sr25519.pair_from_seed(k.private_bytes_raw()) # type: ignore
        return cls(d, x) # type: ignore

    def __init__(self, d: bytes, x: bytes):
        self.d = d
        super().__init__(x=x)

    def public_key(self) -> Sr25519PublicKey:
        return Sr25519PublicKey(x=self.x)

    def sign(self, message: bytes) -> bytes:
        return sr25519.sign((self.x, self.d), message) # type: ignore