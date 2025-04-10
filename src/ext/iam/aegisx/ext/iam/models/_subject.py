import pydantic

from aegisx.ext.iam.types import Permission


class Subject(pydantic.BaseModel):
    """Represents a generic subject in the IAM system.

    A subject represents an entity (such as a user, group, or service account)
    that can have permissions assigned to it. This class provides basic functionality
    for managing permissions and determining authentication status. The `is_authenticated`
    method is a placeholder and should be overridden in subclasses to provide 
    specific logic for different types of subjects.
    """
    permissions: set[Permission] = pydantic.Field(
        default_factory=set
    )

    def is_authenticated(self) -> bool: # pragma: no cover
        """Return ``True`` if the subject is authenticated.

        This is a placeholder method. Subclasses should override this method to 
        provide logic for checking whether the subject is authenticated.

        Returns:
            bool: Always returns ``False`` in this base class, but should be
                overridden in subclasses.
        """
        return False