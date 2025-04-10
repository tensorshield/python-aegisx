import asyncio
from typing import Any
from typing import Callable
from typing import Literal
from typing import TypeVar
from typing import Generic
from typing import SupportsBytes

import pydantic
from libcanonical.types import Base64

from aegisx.ext.jose.types import JSONWebAlgorithm
from ._jsonwebkey import JSONWebKey
from ._signature import Signature


T = TypeVar('T', bound=SupportsBytes, default=bytes)
P = TypeVar('P')


class SignedJWS(pydantic.BaseModel, Generic[T]):
    signatures: list[Signature] = pydantic.Field(
        default_factory=list
    )

    payload: bytes | T = pydantic.Field(
        default=...
    )

    claims: dict[str, Any] = pydantic.Field(
        default_factory=dict,
        exclude=True
    )

    @classmethod
    def model_validate_compact(cls, value: str):
        header, payload, signature = str.split(value, '.')
        return cls(
            signatures=[Signature.model_validate({'protected': header, 'signature': signature})],
            payload=str.encode(payload, 'ascii')
        )

    def deserialize(self, cls: Callable[[bytes], P]) -> P:
        assert isinstance(self.payload, bytes)
        return cls(Base64.b64decode(self.payload))

    def sign(
        self,
        signer: JSONWebKey,
        alg: JSONWebAlgorithm,
        kid: str | None = None,
        typ: str | None =None,
        header: dict[str, Any] | None = None
    ) -> 'SignedJWS[T]':
        sig = Signature.create(
            signer,
            alg=alg,
            kid=kid,
            typ=typ,
            header=header
        )
        self.signatures.append(sig)
        return self

    async def finalize(self):
        tasks: list[asyncio.Task[None]] = [
            asyncio.create_task(signature.sign(self.claims, self.payload))
            for signature in self.signatures
        ]
        await asyncio.gather(*tasks)

    async def verify(self, verifier: JSONWebKey) -> bool:
        assert verifier.alg is not None
        if not any([verifier.can_verify(sig.alg) for sig in self.signatures]):
            return False
        assert isinstance(self.payload, bytes)
        return any(await asyncio.gather(*[
            sig.verify(verifier, self.payload)
            for sig in self.signatures
        ]))

    def serialize(self, mode: Literal['compact', 'auto'] = 'auto'):
        if not self.signatures:
            raise ValueError("Can not serialize an unsigned JSON Web Signature (JWS).")
        if mode == 'compact' and len(self.signatures) > 1:
            raise ValueError(
                "JWS Compact Serialization can not be used with multiple "
                "signatures."
            )
        if len(self.signatures) == 1 and mode == 'auto':
            mode = 'compact'
        compact = mode == 'compact'
        match compact:
            case True:
                signature = self.signatures[0]
                if not signature.protected:
                    raise ValueError("Protected header is missing from the signature.")
                if not signature.is_signed():
                    raise ValueError("Can not serialize without signing the JWS")
                assert isinstance(signature.protected, Base64)
                assert isinstance(signature.signature, Base64)
                serialized = str.join('.', [
                    str(signature.protected),
                    bytes.decode(bytes(self.payload)),
                    str(signature.signature)
                ])
            case False:
                serialized = self.model_dump_json(
                    by_alias=True,
                    exclude_defaults=True
                )
        return serialized