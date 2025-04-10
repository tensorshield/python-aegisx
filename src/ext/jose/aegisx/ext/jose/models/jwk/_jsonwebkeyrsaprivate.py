from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateNumbers
from libcanonical.types import AwaitableBytes
from libcanonical.types import Base64

from aegisx.ext.jose.types import EncryptionResult
from aegisx.ext.jose.types import JSONWebAlgorithm
from ._jsonwebkeyrsapublic import JSONKeyRSAPublic


class JSONKeyRSAPrivate(JSONKeyRSAPublic):
    model_config = {
        'title': 'RSA Private Key'
    }

    d: Base64
    p: Base64
    q: Base64
    dp: Base64
    dq: Base64
    qi: Base64

    @property
    def private_numbers(self) -> RSAPrivateNumbers:
        return RSAPrivateNumbers(
            public_numbers=self.public_numbers,
            d=int(self.d),
            p=int(self.p),
            q=int(self.q),
            dmp1=int(self.dp),
            dmq1=int(self.dq),
            iqmp=int(self.qi)
        )

    @property
    def private_key(self):
        return self.private_numbers.private_key()

    @classmethod
    def generate(
        cls,
        alg: JSONWebAlgorithm = JSONWebAlgorithm.validate('RS256'),
        length: int = 4096,
        exponent: int = 65537
    ):
        k = generate_private_key(public_exponent=exponent, key_size=length)
        p = k.private_numbers()
        return cls.model_validate({
            **alg.config.params(),
            'n': p.public_numbers.n,
            'e': p.public_numbers.e,
            'd': p.d,
            'p': p.p,
            'q': p.q,
            'dp': p.dmp1,
            'dq': p.dmq1,
            'qi': p.iqmp,
        })

    def get_public_key(self):
        return JSONKeyRSAPublic.model_validate({
            **self.model_dump(
                exclude={'d', 'p', 'q', 'dp', 'dq', 'qi'}
            ),
            'key_ops': (self.key_ops & {'verify', 'encrypt', 'wrapKey'}) if self.key_ops else None
        })

    def decrypt(self, result: EncryptionResult) -> AwaitableBytes:
        assert self.alg is not None
        return AwaitableBytes(self.private_key.decrypt(result.ct, *self.get_encryption_params(self.alg)))

    def sign(self, message: bytes, alg: str | None = None) -> AwaitableBytes:
        alg = alg or self.alg
        assert alg is not None
        return AwaitableBytes(self.private_key.sign(message, *self.get_signature_params(alg))) # type: ignore