import secrets


class SymmetricEncryptionKey:

    @classmethod
    def generate(cls, length: int):
        return cls(secrets.token_bytes(length))

    def __init__(self, k: bytes):
        self.k = k

    def __bytes__(self):
        return self.k