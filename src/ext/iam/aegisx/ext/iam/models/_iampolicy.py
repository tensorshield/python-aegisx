import functools
from typing import Generic
from typing import Iterable
from typing import TypeVar

import celpy # type: ignore
import pydantic
from aegisx.ext.jose import JSONWebKey
from aegisx.ext.jose import JSONWebKeySet
from aegisx.ext.jose import TokenBuilder
from aegisx.ext.jose import TokenValidator
from aegisx.ext.jose.types import JWSCompactEncoded
from libcanonical.types import DigestSHA256

from aegisx.ext.iam.types import PrincipalTypeVar
from ._authorizationcontext import AuthorizationContext
from ._iambinding import IAMBinding
from ._iampolicytoken import IAMPolicyToken


C = TypeVar('C', bound=AuthorizationContext, default=AuthorizationContext)


class IAMPolicy(pydantic.BaseModel, Generic[C, PrincipalTypeVar]):
    """Represents an IAM policy consisting of role bindings.

    The IAM policy binds a set of principals (members) to roles, optionally
    under conditions. This class supports evaluation of whether a principal
    has a given role in a specified authorization context.

    Type Args:
        C: A subclass of AuthorizationContext.
        P: A type of PrincipalType.
    """
    model_config = {
        'populate_by_name': True,
        'extra': 'forbid'
    }

    bindings: tuple[IAMBinding[C, PrincipalTypeVar], ...] = pydantic.Field(
        title="Bindings",
        description=(
            "Associates a list of `members`, or principals, with a `role`."
        ),
        frozen=True
    )

    signature: JWSCompactEncoded | None = pydantic.Field(
        default_factory=lambda: None
    )

    digest: DigestSHA256 = pydantic.Field(
        default_factory=DigestSHA256
    )

    @functools.cached_property
    def principal(self):
        assert self.signature
        assert self.token.iss
        return self.token.iss

    @property
    def roles(self) -> set[str]:
        """Return the set of all roles referenced in the policy.

        Returns:
            set[str]: A set of role strings used in the policy bindings.
        """
        return {x.role for x in self.bindings}

    @functools.cached_property
    def token(self):
        assert self.signature
        return self.signature.payload(IAMPolicyToken.model_validate)

    @pydantic.model_validator(mode='after')
    def compute_digest(self):
        h = DigestSHA256.hasher()
        for binding in self.bindings:
            h.update(binding.digest)
        self.digest = DigestSHA256(h.digest())
        return self

    @classmethod
    def root(cls, principals: Iterable[str], role: str = 'roles/owner'):
        """Create a root IAM policy binding the given principals to a role.

        This is a convenience constructor for creating a policy where a set of
        principals is directly assigned a role, typically used for bootstrapping
        or admin/root access.

        Args:
            principals (Iterable[str]): The principal identifiers to bind.
            role (str): The role to assign. Defaults to `roles/owner`.

        Returns:
            IAMPolicy: An instance of the policy with the specified binding.
        """
        return cls.model_validate({
            'bindings': [
                {
                    'role': role,
                    'members': principals
                }
            ]
        })

    def granted(self, context: C) -> set[str]:
        """Return the set of roles granted to the given context.

        Evaluates all bindings in the policy and returns the roles that are
        applicable to the provided authorization context, including any
        conditions.

        Args:
            context (C): The authorization context to evaluate.

        Returns:
            set[str]: A set of roles granted to the context.
        """
        env = celpy.Environment()
        return {
            x.role for x in self.bindings
            if x.is_match(context, env=env)
        }

    def is_signed(self):
        return self.signature is not None

    async def sign(self, key: JSONWebKey, service: str, target: str, principal: str):
        builder = TokenBuilder(
            IAMPolicyToken,
            signers=[key],
            autoinclude={'iat', 'nbf'}
        )
        jws = await builder\
            .update(aud=f'//{service}')\
            .update(iss=principal)\
            .update(dig=str(self.digest))\
            .update(sub=target)\
            .build(syntax='compact')
        self.signature = JWSCompactEncoded.validate(jws)

    async def verify(
        self,
        keys: list[JSONWebKey] | JSONWebKeySet,
        service: str,
        target: str,
        email: str,
    ):
        if isinstance(keys, list):
            keys = JSONWebKeySet(keys=keys)
        if not self.signature:
            return False
        validator = TokenValidator(
            IAMPolicyToken,
            audience=f'//{service}',
            issuer=email,
            required={'iss', 'aud', 'dig'},
            jwks=keys
        )
        try:
            jwt = await validator.validate(self.signature)
            return all([
                jwt.dig == self.digest,
                jwt.sub == target
            ])
        except validator.InvalidSignature:
            return False