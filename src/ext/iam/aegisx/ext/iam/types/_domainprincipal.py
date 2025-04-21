from typing import Self

from libcanonical.types import DomainName

from ._principal import Principal


class DomainPrincipal(Principal[DomainName]):
    kind = 'domain'
    name = 'Domain'
    description = (
        'domain:DOMAIN\n\n'
        'Example: domain:example.com'
    )

    @classmethod
    def validate(cls, value: str) -> Self:
        try:
            kind, value = str.split(value, ':')
        except ValueError:
            raise ValueError(f'malformed principal: {value}.')
        if kind != cls.kind:
            raise ValueError(f'not a {cls.__name__}.')
        return cls(value=DomainName.validate(value))

    @classmethod
    def fromdomain(cls, value: str):
        return cls.validate(f'domain:{value}')

    def is_authenticated(self) -> bool: # pragma: no cover
        return True

    def is_subject(self) -> bool: # pragma: no cover
        return False

    def __hash__(self) -> int:
        return hash(str(self))