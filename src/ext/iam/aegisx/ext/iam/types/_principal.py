import operator
from typing import cast
from typing import Any
from typing import Generic
from typing import Self
from typing import TypeVar

from pydantic_core import CoreSchema
from pydantic_core import core_schema
from pydantic.json_schema import JsonSchemaValue
from pydantic import GetJsonSchemaHandler


T = TypeVar('T', bound=str, default=str)


class Principal(Generic[T]):
    """The base class for all principals.

    This class represents the concept of a principal (e.g., user, service,
    or any identity) within an IAM (Identity and Access Management) system.
    It provides methods for validating and managing principal information,
    including authentication and subject resolution.

    Attributes:
        description (str | None): A description of the principal. Optional.
        kind (str): The type or kind of the principal (e.g., 'user', 'service').
    """
    description: str | None = None
    kind: str
    max_length: int = 128
    name: str
    strip_whitespace: bool = True
    lowercase: bool = True
    _kind: str
    _value: T

    @property
    def value(self): # pragma: no cover
        return self._value

    @classmethod
    def __get_pydantic_core_schema__(cls, *_: Any) -> CoreSchema:
        return core_schema.json_or_python_schema(
            json_schema=cls.__default_schema__(),
            python_schema=core_schema.union_schema([
                core_schema.is_instance_schema(cls),
                cls.__default_schema__(),
            ]),
            serialization=core_schema.plain_serializer_function_ser_schema(str)
        )

    @classmethod
    def __get_pydantic_json_schema__(
        cls,
        _: CoreSchema,
        handler: GetJsonSchemaHandler
    ) -> JsonSchemaValue:
        schema = handler(cls.__default_schema__())
        schema['title'] = cls.name
        if cls.description is not None:
            schema['description'] = cls.description
        return schema

    @classmethod
    def __default_schema__(cls):
        return core_schema.chain_schema([
            core_schema.str_schema(
                max_length=cls.max_length,
                strip_whitespace=True
            ),
            core_schema.no_info_plain_validator_function(cls.validate)
        ])

    @classmethod
    def validate(cls, value: str) -> Self:
        """Validate the principal's value.

        This method should be implemented in subclasses to define how to
        validate the principal's value.

        Args:
            value (str): The value of the principal to be validated.

        Raises:
            NotImplementedError: If the method is not overridden in a subclass.
        """
        raise NotImplementedError

    def __init__(self, value: T):
        self._value = value

    def encode(self, encoding: str = 'utf-8'):
        return str.encode(str(self), encoding=encoding)

    def is_authenticated(self) -> bool:
        """Check if the principal is authenticated.

        This method should be implemented in subclasses to define the logic
        for checking authentication status.

        Returns:
            bool: `True` if the principal is authenticated, `False` otherwise.

        Raises:
            NotImplementedError: If the method is not overridden in a subclass.
        """
        raise NotImplementedError

    def is_subject(self) -> bool:
        """Check if the principal resolves to a single subject.

        This method should be implemented in subclasses to define the logic
        for determining whether the principal represents a single subject.

        Returns:
            bool: `True` if the principal is a single subject, `False`
                otherwise.

        Raises:
            NotImplementedError: If the method is not overridden in a subclass.
        """
        raise NotImplementedError

    def __str__(self):
        match bool(self.kind):
            case True:
                return f'{self.kind}:{self._value}'
            case False:
                return self._value

    def __repr__(self):
        return f'<{type(self).__name__}: {str(self)}>'

    def __lt__(self, other: Any, /) -> bool:
        if not isinstance(other, Principal):
            return NotImplemented
        return operator.lt(str(self), str(cast(Principal[Any], other)))

    def __gt__(self, other: Any, /) -> bool:
        if not isinstance(other, Principal):
            return NotImplemented
        return operator.gt(str(self), str(cast(Principal[Any], other)))

    def __eq__(self, other: Any):
        if not isinstance(other, Principal):
            return NotImplemented
        return str(self) == str(other) # type: ignore