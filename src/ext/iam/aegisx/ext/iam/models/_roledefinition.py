from typing import Generic
from typing import TypeVar

import pydantic

from aegisx.ext.iam.types import Permission
from aegisx.ext.iam.types import WildcardPermission


N = TypeVar('N', default=str)
P = TypeVar('P', bound=Permission | WildcardPermission, default=Permission | WildcardPermission)


class RoleDefinition(pydantic.BaseModel, Generic[N, P]):
    """Defines a custom IAM role with permissions and inherited roles.

    This model represents a role that can be used in an IAM policy. It includes
    metadata like a title and description, a set of granted permissions, and a
    set of roles from which it inherits additional permissions.

    The role can include both specific permissions and wildcard permissions,
    allowing flexible definitions suitable for varying levels of access control.

    Attributes:
        title (str): A human-readable title for the role. Typically limited
            to 100 UTF-8 bytes.
        description (str): A human-readable description for the role. Defaults
            to an empty string. Limited to 512 UTF-8 bytes.
        included_permissions (set[P]): A set of permissions granted by this
            role. These may include specific or wildcard permissions.
        inherited_roles (set[N]): A set of role names that this role inherits
            from. Permissions from those roles are effectively added to this
            one.
    """
    title: str = pydantic.Field(
        default=...,
        title="Title",
        description=(
            "Optional. A human-readable title for the role. "
            "Typically this is limited to 100 UTF-8 bytes."
        ),
        max_length=100
    )

    description: str = pydantic.Field(
        default_factory=str,
        title="Description",
        description=(
            "Optional. A human-readable description for the role."
        ),
        max_length=512
    )

    included_permissions: set[P] = pydantic.Field(
        default_factory=set,
        title="Permissions",
        description=(
            "The names of the permissions this role grants when bound in "
            "an IAM policy."
        )
    )

    inherited_roles: set[N] = pydantic.Field(
        default_factory=set,
        title="Inherits",
        description=(
            "The names of roles from which this role inherits permissions. "
            "**Not implemented**."
        )
    )