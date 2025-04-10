from typing import Any
from typing import Literal
from typing import Union

import pydantic
from libcanonical.types import Base64

from aegisx.ext.jose.types import JSONWebAlgorithm
from aegisx.ext.jose.types import JWECompactEncoded
from ._jsonwebkey import JSONWebKey
from ._jweheader import JWEHeader
from ._jwegeneralserialization import JWEGeneralSerialization
from ._recipient import Recipient



JSONWebEncryptionType = Union[
    JWEGeneralSerialization,
    JWECompactEncoded,
    bytes
]


class JSONWebEncryption(pydantic.RootModel[JSONWebEncryptionType]):

    @property
    def header(self):
        assert isinstance(self.root, JWEGeneralSerialization)
        return self.root.header

    @property
    def plaintext(self):
        assert isinstance(self.root, (bytes, JWEGeneralSerialization))
        return self.root if isinstance(self.root, bytes) else self.root.plaintext

    def model_post_init(self, _: Any):
        if isinstance(self.root, JWECompactEncoded):
            self.root = self.root.jose(JWEGeneralSerialization)
        elif isinstance(self.root, bytes):
            self.root = JWEGeneralSerialization(
                plaintext=self.root,
                protected=Base64(JWEHeader(cty='octet-stream'))
            )

    def decrypt(self, key: JSONWebKey):
        assert isinstance(self.root, JWEGeneralSerialization), repr(self.root)
        return self.root.decrypt(key)

    def encrypt(
        self,
        key: JSONWebKey,
        alg: JSONWebAlgorithm | None = None,
        enc: JSONWebAlgorithm = JSONWebAlgorithm.validate('A256GCM'),
        header: dict[str, Any] | None = None
    ) -> Recipient:
        """Encrypt the Content Encryption Key (CEK) with the given
        `key`. Return a :class:`~Recipient` instance representing
        the received.
        """
        assert isinstance(self.root, JWEGeneralSerialization)
        if (alg := alg or key.alg) is None:
            raise TypeError("The `alg` parameter can not be None.")
        return self.root.add_recipient(key, alg, enc, header=header or {})

    def serialize(
        self,
        mode: Literal['compact', 'flattened', 'general', 'auto'] = 'auto' # type: ignore
    ) -> str:
        assert isinstance(self.root, JWEGeneralSerialization)
        if not self.root.is_encrypted():
            raise ValueError("Can not serialize an unencrypted JWE.")
        mode = 'compact'

        serialized: str
        match mode:
            case 'compact':
                assert len(self.root.recipients) == 1
                assert not self.root.recipients[0].header, self.root.recipients[0].header
                assert not self.root.unprotected
                safe = self.root.model_dump(
                    mode='json',
                    exclude_defaults=True,
                    exclude_none=True,
                    context={'mode': mode}
                )
                serialized = str.join('.', [
                    safe['protected'],
                    safe['recipients'][0].get('encrypted_key', ''),
                    safe['iv'],
                    safe['ciphertext'],
                    safe['tag']
                ])
            case _:
                raise NotImplementedError(mode)
        return serialized

    async def finalize(self):
        assert isinstance(self.root, JWEGeneralSerialization)
        await self.root.finalize()
        return self

    def __await__(self):
        return self.finalize().__await__()

    def __str__(self):
        return self.serialize()