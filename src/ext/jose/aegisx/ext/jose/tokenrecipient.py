from typing import Unpack

import pydantic
from libcanonical.types import Base64

from .models import JSONWebKey
from .models import JWEHeader
from .types import JWEHeaderDict
from .types import JSONWebAlgorithm


class TokenRecipient(pydantic.BaseModel):
    model_config = {
        'extra': 'forbid',
    }

    kek: JSONWebKey = pydantic.Field(
        default=...
    )

    header: JWEHeader = pydantic.Field(
        default=JWEHeader()
    )

    encrypted_key: Base64 = pydantic.Field(
        default_factory=Base64
    )

    alg: JSONWebAlgorithm

    @classmethod
    def fromkey(cls, k: JSONWebKey, **header: Unpack[JWEHeaderDict]):
        return cls.model_validate(
            obj={
                'alg': header.get('alg') or k.alg,
                'kek': k,
                'header': header,
            },
            context={'strict': False}
        )

    def as_recipient(self) -> dict[str, str]:
        jwe = {
            'header': self.header.urlencode(),
            'encrypted_key': self.encrypted_key.urlencode()
        }
        return {k: bytes.decode(v, 'ascii') for k, v in jwe.items() if v}

    async def encrypt(self, cek: JSONWebKey):
        if not self.alg.is_direct():
            result = await self.encrypt_cek(self.alg, self.kek, cek)
            self.encrypted_key = Base64(result.ct)
            if result.epk:
                self.header.epk = result.epk
                self.header.apv = Base64(result.apv)
                self.header.apu = Base64(result.apu)
            if result.iv:
                self.header.iv = Base64(result.iv)
                self.header.tag = Base64(result.tag)

    async def encrypt_cek(
        self,
        alg: JSONWebAlgorithm,
        kek: JSONWebKey,
        cek: JSONWebKey
    ):
        """Encrypt the Content Encryption Key (CEK) for the given
        recipient.
        """
        assert alg.mode not in {'DIRECT_ENCRYPTION', 'DIRECT_KEY_AGREEMENT'}
        return await kek.encrypt(bytes(cek), alg=alg)