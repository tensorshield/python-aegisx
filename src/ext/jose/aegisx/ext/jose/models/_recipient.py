from typing import TYPE_CHECKING

import pydantic
from libcanonical.types import Base64

from aegisx.ext.jose.types import EncryptionResult
from .jwk import JSONWebKey
from ._jweheader import JWEHeader
if TYPE_CHECKING:
    from ._jwegeneralserialization import JWEGeneralSerialization


class Recipient(pydantic.BaseModel):
    header: JWEHeader = pydantic.Field(
        default=JWEHeader(),
        title="Header",
        description=(
            "The `header` member MUST be present and contain the value JWE Per-"
            "Recipient Unprotected Header when the JWE Per-Recipient Unprotected "
            "Header value is non-empty; otherwise, it MUST be absent.  This "
            "value is represented as an unencoded JSON object, rather than as "
            "a string.  These Header Parameter values are not integrity protected."
        )
    )

    encrypted_key: Base64 = pydantic.Field(
        default_factory=Base64,
        title="Encrypted key",
        description=(
            "The `encrypted_key` member MUST be present and contain the value "
            "`BASE64URL(JWE Encrypted Key)` when the JWE Encrypted Key value "
            "is non-empty; otherwise, it MUST be absent."
        )
    )

    _common: JWEHeader = pydantic.PrivateAttr(default_factory=JWEHeader)
    _kek: JSONWebKey | None = pydantic.PrivateAttr(default=None)
    _epk: JSONWebKey | None = pydantic.PrivateAttr(default=None)
    _encrypted: bool = pydantic.PrivateAttr(default=False)

    @property
    def alg(self):
        alg = self.header.alg or self._common.alg
        assert alg is not None, (
            "Missing `alg` claim was not detected during serialization or "
            "object construction."
        )
        return alg

    @property
    def apu(self):
        return self.header.apu or self._common.apu

    @property
    def apv(self):
        return self.header.apv or self._common.apv

    @property
    def enc(self):
        enc = self.header.enc or self._common.enc
        assert enc is not None, (
            "Missing `enc` claim was not detected during serialization or "
            "object construction."
        )
        return enc

    @property
    def epk(self):
        epk = self.header.epk or self._common.epk
        assert epk is not None, (
            "Missing `epk` claim was not detected during serialization or "
            "object construction."
        )
        return epk

    @pydantic.field_serializer('header', when_used='json')
    def serialize_compact(self, header: JWEHeader, info: pydantic.SerializationInfo):
        if info.context and info.context.get('mode'):
            return bytes.decode(header.urlencode(), 'utf-8')
        return header.model_dump(
            mode='json',
            exclude_none=True,
            exclude_defaults=True
        )

    def add_to_jwe(self, jwe: 'JWEGeneralSerialization'):
        self._common = jwe.protected

    def derive(self, key: JSONWebKey) -> JSONWebKey:
        assert self.alg.mode == 'DIRECT_KEY_AGREEMENT', (
            "Recipient.derive() must not be called with algorithms that "
            "do not use direct key agreement."
        )
        assert self.epk
        return key.derive_cek(
            alg=self.alg,
            enc=self.enc,
            private=key,
            public=self.epk,
            apu=self.apu,
            apv=self.apv
        )

    def get_decryption_input(self, protected: bytes, header: JWEHeader):
        enc = self.header.enc or header.enc
        assert enc is not None, (
            "Missing `enc` claim was not detected during serialization or "
            "object construction."
        )
        return EncryptionResult(
            alg=enc,
            ct=self.encrypted_key,
            aad=protected,
            iv=self.header.iv or header.iv,
            tag=self.header.tag or header.tag,
            epk=self.header.epk or header.epk,
            apu=self.header.apu or header.apu,
            apv=self.header.apv or header.apv
        )

    def might_decrypt(self, key: JSONWebKey, header: JWEHeader):
        """Return a boolean indicating if the given :class:`JSONWebKey` `key`
        _might_ decrypt the encrypted key.
        """
        return bool(self.encrypted_key) and any([
            key.kid and key.kid == header.kid,
            header.jwk and header.jwk.thumbprint('sha256') == key.thumbprint('sha256'),
            key.alg and key.alg == (self.header.alg or header.alg)
        ])

    async def decrypt(self, jwe: 'JWEGeneralSerialization', key: JSONWebKey):
        if not self.encrypted_key:
            raise ValueError(
                "Recipient does not have an encryption key. This is the case where "
                "direct encryption or key agreement algorithms are used, such as "
                "'dir' or 'ECDH-ES'."
            )
        try:
            self._kek = key
            return JSONWebKey.model_validate({
                'kty': 'oct',
                'k': Base64(await key.decrypt(jwe.get_encrypted_cek(self.header, self.encrypted_key)))
            })
        except Exception:
            self._kek = None
            raise