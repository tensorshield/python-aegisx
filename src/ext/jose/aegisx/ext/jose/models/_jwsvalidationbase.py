from typing import cast
from typing import Any

import pydantic
from cryptography.x509 import Certificate

from aegisx.ext.jose.types import InvalidSignature
from .jwk import JSONWebKey
from ._jwsheader import JWSHeader
from ._signature import Signature


class JWSValidationBase(pydantic.BaseModel):

    @staticmethod
    def encode_message(protected: bytes, payload: bytes):
        return b'.'.join([
            protected,
            payload
        ])

    @pydantic.model_validator(mode='after')
    def postprocess_jwk(self):
        payload = self.get_raw_payload()
        for signature in self.get_signatures():
            if not signature.protected or not signature.protected.jwk:
                continue
            if not signature.protected.jwk.is_asymmetric():
                raise InvalidSignature('The "jwk" Header Parameter must be an asymmetric key.')
            if not signature.protected.jwk.is_public():
                raise InvalidSignature(f'The "jwk" Header Parameter must be a public key: {signature.protected.jwk}.')
            if not signature.protected.encoded:
                raise ValueError('Encoded signature not retained during deserialization.')
            message = self.encode_message(
                bytes(signature.protected.encoded),
                payload
            )

            result = signature.verify(signature.protected.jwk, message)
            assert isinstance(result, int)
            if not bool(result):
                # Do not raise a ValueError here because if any signature
                # does not validate, the complete token is rejected.
                raise InvalidSignature(
                    'The signature was not created by the key specified by '
                    'the "jwk" Header Parameter.'
                )
        return self

    @pydantic.model_validator(mode='after')
    def postprocess_x5c(
        self,
        info: pydantic.ValidationInfo
    ):
        payload = self.get_raw_payload()
        ctx = cast(dict[str, Any], info.context or {})
        if not ctx.get('strict', True):
            return self
        for signature in self.get_signatures():
            if not signature.protected or not signature.protected.x5c:
                continue
            leaf = signature.protected.x5c.leaf
            try:
                key = JSONWebKey(alg=signature.alg, crt=leaf)
            except pydantic.ValidationError:
                raise ValueError(
                    'The X.509 signing certificate uses an unsupported '
                    f'key type: {leaf.public_key_algorithm_oid.dotted_string}.'
                )
            message = self.encode_message(
                bytes(signature.protected.encoded),
                payload
            )
            result = signature.verify(key, message)
            assert isinstance(result, int)
            if not bool(result):
                # Do not raise a ValueError here because if any signature
                # does not validate, the complete token is rejected.
                raise InvalidSignature(
                    'The signature was not created by the leaf certificate specified by '
                    'the "x5c" Header Parameter.'
                )
            crt: Certificate | None
            if (crt := ctx.get('certificate')) is not None\
            and not signature.protected.x5c.is_trusted(crt):
                raise InvalidSignature(
                    'The X.509 certificate chain is not trusted.'
                )

            if signature.protected.x5t\
            and signature.protected.x5t != signature.protected.x5c.thumbprint:
                raise ValueError(
                    'The "x5t" claim does not match the fingerprint of '
                    'the leaf certificate.'
                )

            if signature.protected.x5t_s256\
            and signature.protected.x5t_s256 != signature.protected.x5c.thumbprint_sha256:
                raise ValueError(
                    'The "x5t#s256" claim does not match the fingerprint of '
                    'the leaf certificate.'
                )
        return self

    def get_headers(self) -> tuple[JWSHeader | None, JWSHeader | None]:
        raise NotImplementedError

    def get_raw_payload(self) -> bytes:
        raise NotImplementedError

    def get_signatures(self) -> list[Signature]:
        raise NotImplementedError