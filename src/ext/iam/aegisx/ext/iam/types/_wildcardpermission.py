import re
from typing import Any
from typing import Iterable
from typing import Self

from ._permission import Permission


class WildcardPermission(Permission):
    """A class representing a wildcard-based permission.

    A :class:`WildcardPermission` allows matching permissions with wildcard characters 
    such as ``*`` (single wildcard) and ``**`` (double wildcard). The ``*`` character 
    can match any part of the permission, while ``**`` can match multiple levels 
    of permissions.
    """
    pattern: str = r'^([a-z]+(?:\.([a-z]+|[*]{1,2}))*)$'
    _pattern: re.Pattern[str] | None = None

    @classmethod
    def validate(cls, value: str) -> Self:
        """Validates and creates a :class:`WildcardPermission` instance from a string.

        This method validates that the provided wildcard permission value matches 
        the required format defined by the regular expression:
        `^([a-z]+(?:\\.([a-z]+|[*]{1,2}))*)$`.

        The format requirements are as follows:
        - The permission must consist of lowercase words and periods separating them.
        - A single `*` is allowed in the permission (matches any part of the permission).
        - The `**` (double wildcard) can appear only once and cannot be followed by any labels.
        
        If the `value` does not match these requirements, a :exc:`ValueError` is raised.

        Args:
            value (str): The permission string to be validated.

        Returns:
            WildcardPermission

        Raises:
            ValueError: If `value` does not match the required format or if the 
            double wildcard is used incorrectly.
        """
        value = super().validate(value)
        if value.count('**') > 1:
            raise ValueError('double wildcard can only appear once.')
        if value.count('**') == 1 and value[-2:] != '**':
            raise ValueError('no labels can appear after double wildcard.')
        return cls(value)

    def expand(
        self,
        permissions: Iterable['Permission']
    ) -> set['Permission']:
        """Expands the wildcard permission to match a set of permissions.

        This method compares the :class:`WildcardPermission` against a set
        of :class:`Permission`  instances and returns a set of `Permission`
        instances that match the wildcard  pattern.

        Args:
            permissions (Iterable[Permission]): An iterable collection of
            :class:`Permission` objects to check against the wildcard permission.

        Returns:
            set[Permission]
        """
        return {x for x in permissions if x == self}

    def __new__(cls, object: str):
        self = super().__new__(cls, object)
        if self.find('*') != -1:
            p = self.replace('**', 'ANY')
            if p.count('*') > 0:
                p = p.replace('*', '[a-z]+')
            p = p.replace('ANY', r'([a-z]+(?:\.[a-z]+)*)$')
            self._pattern = re.compile(p)
        return self

    def __hash__(self):
        return hash(f'{type(self).__name__}:{self}')

    def __eq__(self, permission: Permission | Any):
        if not isinstance(permission, Permission):
            return NotImplemented
        if isinstance(permission, WildcardPermission):
            return str(self) == str(permission)
        match bool(self._pattern):
            case True:
                assert self._pattern is not None
                print(self._pattern.pattern)
                return bool(self._pattern.match(permission))
            case False:
                return str(self) == str(permission)