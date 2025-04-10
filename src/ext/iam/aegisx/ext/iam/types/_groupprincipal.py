from typing import Self

from libcanonical.types import EmailAddress

from ._domainprincipal import DomainPrincipal
from ._principal import Principal


class GroupPrincipal(Principal[EmailAddress]):
    kind = 'group'
    name = 'Group'
    description = (
        'group:GROUP_EMAIL_ADDRESS\n\n'
        'Example: group:admins@example.com'
    )

    @property
    def domain(self): # pragma: no cover
        return DomainPrincipal.validate(self.value.domain)

    @classmethod
    def fromemail(cls, value: str):
        return cls.validate(f'{cls.kind}:{value}')

    @classmethod
    def validate(cls, value: str) -> Self:
        try:
            kind, value = str.split(value, ':')
        except ValueError:
            raise ValueError(f'malformed principal: {value}')
        if kind != cls.kind:
            raise ValueError(f'not a {cls.__name__}.')
        return cls(value=EmailAddress.fromstring(value))

    def is_authenticated(self) -> bool: # pragma: no cover
        return True

    def is_subject(self) -> bool: # pragma: no cover
        return False

    def __hash__(self) -> int:
        return hash(str(self))