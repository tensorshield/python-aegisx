from typing import Any
from typing import Iterable
from typing import Self

from pydantic_core import CoreSchema
from pydantic_core import core_schema
from pydantic.json_schema import JsonSchemaValue
from pydantic import GetJsonSchemaHandler


class Permission(str):
    """Represents a permission as a string with validation and expansion support.

    The :class:`Permission` class represents a permission in the system as a string. 
    It validates that the permission follows a specific pattern and supports 
    expanding the permission based on a set of other permissions.
    """
    max_length: int = 128
    name: str = 'Permission'
    pattern: str = r'^([a-z]+(?:\.[a-z]+)*)$'

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
        return schema

    @classmethod
    def __default_schema__(cls):
        return core_schema.chain_schema([
            core_schema.str_schema(
                max_length=cls.max_length,
                strip_whitespace=True,
                pattern=cls.pattern
            ),
            core_schema.no_info_plain_validator_function(cls.validate)
        ])

    @classmethod
    def validate(cls, value: str) -> Self:
        """Validates and creates a `Permission` instance from a string value.

        This method validates that the provided permission value matches the 
        required format, which is defined by the regular expression 
        ``^([a-z]+(?:\\.[a-z]+)*)$``. The format requirements are as follows:

        - The permission must consist of one or more lowercase words.
        - Each word can contain only lowercase letters (`a-z`).
        - Words are separated by periods (`.`), if multiple words are present.
        - The permission must start and end with a lowercase word (no leading or 
          trailing periods).

        Example of valid permissions:
            - "read"
            - "read.write"
            - "user.create.profile"

        If `value` does not match this format, a :exc:`ValueError` will be raised.

        Args:
            value (str): The permission string to be validated.

        Returns:
            Permission

        Raises:
            ValueError: If `value` does not match the required format.
        """
        return cls(value)

    def expand(
        self,
        permissions: Iterable['Permission']
    ) -> set['Permission']:
        """Expands the permission by returning the permission itself in a set."""
        return {self}

    def __hash__(self):
        return hash(f'{type(self).__name__}:{self}')

    def __repr__(self):
        return f'<{type(self).__name__}: {str(self)}'