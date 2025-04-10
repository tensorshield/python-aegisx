import datetime
import ipaddress
from typing import Generic

import celpy
import pydantic

from aegisx.ext.iam.types import PrincipalTypeVar
from aegisx.ext.iam.types import AnonymousPrincipal
from ._anonymoussubject import AnonymousSubject
from ._authenticatedsubject import AuthenticatedSubject


class AuthorizationContext(pydantic.BaseModel, Generic[PrincipalTypeVar]):
    """Represents the context of an access request for IAM evaluation.

    This context contains information about the requester (principal), the
    current time, and optionally the remote host IP address. It is used to
    evaluate IAM conditions, especially those expressed using CEL (Common
    Expression Language).

    The model supports serialization into CEL-compatible format via the
    `cel` mode, enabling CEL-based condition evaluation with celpy.
    """
    subject: AnonymousSubject | AuthenticatedSubject = pydantic.Field(
        default_factory=AnonymousSubject
    )

    principal: PrincipalTypeVar = pydantic.Field( # type: ignore
        default=AnonymousPrincipal.validate('allUsers')
    )

    now: datetime.datetime = pydantic.Field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc)
    )

    remote_host: ipaddress.IPv4Address | None = pydantic.Field(
        default=None
    )

    @pydantic.model_serializer(mode='wrap')
    def serialize(
        self,
        nxt: pydantic.SerializerFunctionWrapHandler,
        info: pydantic.SerializationInfo
    ):
        if info.mode != 'cel':
            return nxt(self)
        return {
            k: celpy.json_to_cel(v) # type: ignore
            for k, v in self.model_dump(mode='json').items()
        }

    def is_authenticated(self) -> bool:
        """Return ``True`` if the :class:`AuthorizationContext` represents
        an authenticated request.
        """
        return all([
            self.principal.is_subject(),
            self.principal.is_authenticated()
        ])

    def principals(self) -> set[PrincipalTypeVar]:
        p: set[PrincipalTypeVar] = {*self.subject.principals()} # type: ignore
        p.add(self.principal)
        return p