import datetime
from typing import Any
from typing import Generic
from typing import Literal
from typing import TypeVar

import pydantic
from aegisx.ext.rfc3161 import ITimestampClient
from aegisx.ext.rfc3161 import TimestampToken
from libcanonical.types import DigestSHA256
from libcanonical.types import DomainName

from aegisx.ext.iam.types import PrincipalTypeVar
from ._authorizationcontext import AuthorizationContext
from ._iampolicy import IAMPolicy


C = TypeVar('C', bound=AuthorizationContext, default=AuthorizationContext)

R = TypeVar('R', bound=str, default=str)


class IAMAttachedPolicy(pydantic.BaseModel, Generic[R, C, PrincipalTypeVar]):
    """Represents a policy that is attached to a service or parent resource."""
    service: DomainName = pydantic.Field(
        default=...,
        frozen=True
    )

    policy: IAMPolicy[C, PrincipalTypeVar] = pydantic.Field(
        default=...,
        frozen=True
    )

    target: R | Literal[''] = pydantic.Field(
        default_factory=lambda: '',
        frozen=True
    )

    attached: datetime.datetime = pydantic.Field(
        default_factory=lambda : datetime.datetime.now(datetime.timezone.utc),
        frozen=True
    )

    digest: DigestSHA256 = pydantic.Field(
        default_factory=DigestSHA256
    )

    timestamps: tuple[TimestampToken, ...] = pydantic.Field(
        default_factory=tuple
    )

    block: int = pydantic.Field(
        default_factory=int
    )

    @pydantic.model_validator(mode='after')
    def postprocess(self):
        self.compute_digest()
        return self

    @pydantic.model_serializer(mode='wrap')
    def serialize(
        self,
        nxt: pydantic.SerializerFunctionWrapHandler,
        info: pydantic.SerializationInfo
    ) -> dict[str, Any]:
        self.compute_digest()
        match info.mode:
            case 'persist':
                return {
                    **self.model_dump(mode='json'),
                    'attached': self.attached,
                }
            case _:
                return nxt(self)

    def compute_digest(self):
        h = DigestSHA256.hasher()
        h.update(str.encode(self.attached.isoformat(), 'ascii'))
        h.update(str.encode(self.target, 'utf-8'))
        h.update(self.policy.digest)
        h.update(str.encode(self.service, 'utf-8'))
        if self.policy.signature:
            h.update(bytes(self.policy.signature))
        self.digest = DigestSHA256(h.digest())

    def is_signed(self):
        return self.policy.signature is not None

    async def stamp(self, client: ITimestampClient):
        self.compute_digest()
        self.timestamps = tuple(await client.timestamps(self.digest))

    def __hash__(self): # pragma: no cover
        return hash(self.digest)