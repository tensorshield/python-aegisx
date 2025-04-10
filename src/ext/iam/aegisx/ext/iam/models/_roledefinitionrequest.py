from typing import Generic
from typing import TypeVar

import pydantic

from ._roledefinition import RoleDefinition


N = TypeVar('N', default=str)


class RoleDefinitionRequest(pydantic.BaseModel, Generic[N]):
    """Request body for creating a custom IAM role.

    This model represents the payload required to create a new IAM role,
    including its identifier and full role definition.

    Attributes:
        role_id (str): The unique identifier for the role. Must start with a
            lowercase letter and contain only lowercase letters, underscores
            (`_`), and periods (`.`). Must be 3 to 64 characters long.
        role (RoleDefinition[N]): The complete definition of the role,
            including permissions, title, and inheritance.
    """
    model_config = {
        'populate_by_name': True,
        'extra': 'forbid'
    }

    role_id: str = pydantic.Field(
        default=...,
        title="Role ID",
        description=(
            "The role ID to use for this role.\n\n"
            "A role ID may contain alphanumeric characters, underscores "
            "(`_`), and periods (`.`). It must contain a minimum of 3 "
            "characters and a maximum of 64 characters."
        ),
        max_length=64,
        min_length=3,
        pattern=r'^[a-z]([a-z._]+)$',
        alias='roleId'
    )

    role: RoleDefinition[N] = pydantic.Field(
        default=...,
        title="Definition",
        description="The Role resource to create."
    )