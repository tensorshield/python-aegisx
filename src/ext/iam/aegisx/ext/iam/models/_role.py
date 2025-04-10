from typing import cast
from typing import Any
from typing import Generic
from typing import TypeVar

import pydantic

from aegisx.ext.iam.types import RoleValidationContext
from aegisx.ext.iam.types import Permission
from ._roledefinition import RoleDefinition
from ._roledefinitionrequest import RoleDefinitionRequest


N = TypeVar('N', default=str)


class Role(RoleDefinition[N, Permission], Generic[N]):
    """An IAM role instance with a fully resolved name and permissions.

    This model represents a role resource as stored or processed, with the
    role name and all permissions expanded from the request.
    """
    name: N = pydantic.Field(
        default=...,
        title="Name",
        description="The name of the role."
    )

    @pydantic.model_validator(mode='before')
    def preprocess(
        cls,
        values: dict[str, Any] | RoleDefinitionRequest,
        info: pydantic.ValidationInfo
    ):
        """Preprocess and normalize role data before validation.

        If the input is a :class:`RoleDefinitionRequest~, this
        method expands all included permissions using the validation
        context and constructs a complete role dictionary with a
        fully-qualified name.
        """
        context = cast(RoleValidationContext | None, info.context)
        if isinstance(values, RoleDefinitionRequest):
            assert context is not None, (
                'To create a Role from a RoleDefinition, the validation '
                'context must be provided.'
            )
            assert isinstance(context.get('permissions'), set), (
                'The validation context must specify the "permissions" member.'
            )
            assert isinstance(context.get('prefix'), str), (
                'The validation context must specify the "prefix" member.'
            )
            permissions: set[Permission] = set()
            for permission in values.role.included_permissions:
                permissions.update(permission.expand(context['permissions']))
            values = {
                **values.role.model_dump(),
                'name': f"{context['prefix']}/{values.role_id}",
                'included_permissions': permissions
            }
        return values