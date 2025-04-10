import functools
from typing import Any
from typing import SupportsBytes

import pydantic
from libcanonical.types import Base64
from libcanonical.utils.encoding import b64encode

from aegisx.ext.jose.types import JSONWebAlgorithm
from aegisx.ext.jose.types import MissingPublicKey
from ._jsonwebkey import JSONWebKey
from ._jwsheader import JWSHeader


class Signature(pydantic.BaseModel):
    protected: JWSHeader | Base64 | None = None
    header: dict[str, Any] = {}
    signature: Base64

    # Private fields
    signer: JSONWebKey | None = pydantic.Field(
        default=None,
        exclude=True
    )

    verifier: JSONWebKey | None = pydantic.Field(
        default=None,
        exclude=True
    )

    @pydantic.field_validator('header', mode='before')
    @classmethod
    def validate_header(cls, value: dict[str, Any] | None):
        if value is not None:
            if 'crit' in value:
                raise ValueError(
                    "The `crit` claim must not be in the unprotected "
                    "JWS header."
                )
        return value

    @property
    def alg(self):
        # The alg parameter is mandatory.
        return JSONWebAlgorithm.validate(self.claims['alg'])

    @functools.cached_property
    def claims(self):
        return {
            **self.header,
            **self._header.model_dump(exclude_defaults=True, exclude_none=True)
        }

    @functools.cached_property
    def _header(self):
        assert isinstance(self.protected, Base64)
        return JWSHeader.model_validate_json(self.protected)

    @classmethod
    def create(
        cls,
        signer: JSONWebKey,
        alg: JSONWebAlgorithm,
        typ: str | None = None,
        kid: str | None = None,
        header: dict[str, Any] | None = None
    ):
        return cls.model_validate({
            'protected': JWSHeader(alg=alg, typ=typ, kid=kid),
            'signature': Base64(),
            'header': header or {},
            'signer':  signer
        })

    def has_public_key(self):
        return bool(self._header.jwk)

    def is_signed(self):
        return bool(self.signature)

    def is_valid(self):
        """Return a boolean indicating if the JWS conforms to the
        specification.
        """
        return all([
            bool(self.claims.get('alg'))
        ])

    def is_verified(self):
        return bool(self.verifier)

    def thumbprint(self):
        if not self._header.jwk:
            raise MissingPublicKey
        return self._header.jwk.thumbprint('sha256')

    async def verify(self, verifier: JSONWebKey, payload: bytes):
        if self.is_verified():
            return True
        if self.alg != verifier.alg:
            return False
        assert self.protected is not None
        assert isinstance(self.protected, Base64)
        message = bytes.join(b'.', [b64encode(self.protected), payload])
        if not await verifier.verify(self.signature, message, self.alg):
            return False
        self.verifier = verifier
        return True

    async def sign(self, claims: dict[str, Any], payload: bytes | SupportsBytes):
        assert self.signer is not None
        assert isinstance(self.protected, JWSHeader)
        if self.protected.typ is None:
            # Do not override the typ that was set during creation.
            self.protected.typ = claims.get('typ')
        if self.protected.cty is None:
            self.protected.cty = claims.get('cty')
        if self.signer.kid is not None:
            self.protected.kid = self.signer.kid
        if self.signer.is_asymmetric():
            self.protected.jwk = self.signer.public
        self.signature = await self.protected.sign(self.signer, payload)
        self.protected = Base64(self.protected)