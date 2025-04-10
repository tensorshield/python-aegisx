import logging
from typing import Any
from typing import Generic
from typing import TypeVar

import pydantic
from celpy import Environment
from libcanonical.types import DigestSHA256

from aegisx.ext.iam.types import PrincipalTypeVar
from aegisx.ext.iam.types import ANONYMOUS
from aegisx.ext.iam.types import AUTHENTICATED
from ._authorizationcontext import AuthorizationContext
from ._iamcondition import IAMCondition


C = TypeVar('C', bound=AuthorizationContext)

logger: logging.Logger = logging.getLogger(__name__)


class IAMBinding(pydantic.BaseModel, Generic[C, PrincipalTypeVar]):
    """Represents a binding of roles to principals within an IAM policy.

    This class associates a role with a list of principals (members) who 
    are granted the role. It can also include a condition that defines 
    when this binding applies, based on attributes in the authorization context.

    Attributes:
        role (str): The role that is assigned to the list of `members`. 
            For example, `roles/viewer`, `roles/editor`, or `roles/owner`.
        members (list[P]): A list of principals (users, groups, etc.) 
            requesting access for a resource.
        condition (IAMCondition | None): The condition that is associated 
            with this binding. If the condition evaluates to `true`, then 
            the binding applies.
    
    Methods:
        allow_anonymous(): Returns `True` if the binding allows anonymous access.
        allow_authenticated(): Returns `True` if the binding allows authenticated access.
        is_match(context: C, env: Environment | None = None) -> bool:
            Determines whether the current context matches the conditions 
            for this binding.
        add_condition(title: str, expression: str, description: str | None = None):
            Adds a condition to this binding.
        evaluate(env: Environment, context: C) -> bool:
            Evaluates the condition for this binding in the given environment 
            and context.
    """
    role: str = pydantic.Field(
        default=...,
        title="Role",
        description=(
            "Role that is assigned to the list of `members`, or principals. "
            "For example, `roles/viewer`, `roles/editor`, or `roles/owner`."
        ),
        frozen=True
    )

    members: tuple[PrincipalTypeVar, ...] = pydantic.Field(
        title="Members",
        min_length=1,
        description=(
            "Specifies the principals requesting access for a resource. "
            "The `members` array can have the following values:\n\n"
            "- **user:{email}**: an email address that is associated to "
            "a specific account."
        ),
        frozen=True
    )

    condition: IAMCondition | None = pydantic.Field(
        default=None,
        title="Condition",
        description=(
            "The condition that is associated with this binding.\n\n"
            "If the condition evaluates to `true`, then this binding "
            "applies to the current request.\n\n"
            "If the condition evaluates to `false`, then this binding "
            "does not apply to the current request. However, a different "
            "role binding might grant the same role to one or more "
            "of the principals in this binding.\n\n"
        ),
        frozen=False
    )

    digest: DigestSHA256 = pydantic.Field(
        default_factory=DigestSHA256,
    )

    @pydantic.model_validator(mode='after')
    def compute_digest(self):
        h = DigestSHA256.hasher()
        h.update(str.encode(self.role, 'ascii'))
        if self.condition:
            h.update(self.condition.digest)
        for member in sorted(list(self.members)):
            h.update(member.encode('utf-8'))
        self.digest = DigestSHA256(h.digest())
        return self

    def allow_anonymous(self):
        """Returns `True` if the binding allows anonymous access.

        The method checks whether `ANONYMOUS` is present in the `members` 
        list, indicating that the role binding is open to anonymous access.

        Returns:
            bool: `True` if anonymous access is allowed, `False` otherwise.
        """
        return any([
            ANONYMOUS in self.members,
        ])

    def allow_authenticated(self):
        """Returns `True` if the binding allows authenticated access.

        The method checks whether `AUTHENTICATED` is present in the `members` 
        list, indicating that the role binding is open to authenticated access.

        Returns:
            bool: `True` if authenticated access is allowed, `False` otherwise.
        """
        return any([
            AUTHENTICATED in self.members
        ])

    def is_match(self, context: C, env: Environment | None = None) -> bool:
        """Determines whether the current context matches the conditions 
        for this binding.

        The method evaluates the condition associated with this binding (if any)
        and checks if the current principal in the `context` is in the :attr:`members` 
        list or if the binding allows anonymous or authenticated access.

        Args:
            context (C): The authorization context to check for this binding.
            env (Environment | None, optional): The environment to evaluate the condition. 
                Defaults to None.

        Returns:
            bool: `True` if the context matches this binding, `False` otherwise.
        """
        if self.condition and env is None: # pragma: no cover
            logger.critical(
                'The "env" parameter is None and the binding specifies a condition.'
            )
            return False
        flags: list[bool] = []
        if env is not None and self.condition:
            flags.append(self.evaluate(env, context))
        flags.append(
            any([
                bool(set(self.members) & context.principals()), # type: ignore
                context.is_authenticated() and self.allow_authenticated(),
                self.allow_anonymous(),
            ])
        )
        return all(flags)

    def add_condition(
        self,
        title: str,
        expression: str,
        description: str | None = None
    ):
        """Adds a condition to this binding.

        This method associates a condition with the IAM binding. The condition 
        is defined by a title, expression, and an optional description.

        Args:
            title (str): The title of the condition.
            expression (str): The CEL expression that defines the condition logic.
            description (str | None, optional): A description of the condition.
                Defaults to None.
        """
        self.condition = IAMCondition.model_validate({
            'title': title,
            'description': description,
            'expression': expression,
        })

    def evaluate(self, env: Environment, context: C) -> bool:
        """Evaluates the condition for this binding in the given environment 
        and context.

        This method compiles the CEL expression in the condition and evaluates 
        it using the given context and environment.

        Args:
            env (Environment): The environment in which the condition will be evaluated.
            context (C): The authorization context to use for evaluating the condition.

        Returns:
            bool: `True` if the condition evaluates to `True`, `False` otherwise.
        """
        assert self.condition
        params: dict[str, Any] = {
            f'ctx.{k}': v for k, v in
            context.model_dump(mode='cel').items()
        }
        ast = env.compile(self.condition.expression)
        stm = env.program(ast)
        try:
            return bool(stm.evaluate(params))
        except Exception: # pragma: no cover
            # Should not happen because the expressions are
            # validated at the frontend.
            return False