import re
from typing import Any
from typing import Generic
from typing import TypeVar

from pydantic_core import CoreSchema
from pydantic_core import core_schema
from pydantic.json_schema import JsonSchemaValue
from pydantic import GetJsonSchemaHandler


__all__: list[str] = [
    'SpaceSeparatedSet'
]

T = TypeVar('T', default=str)


class SpaceSeparatedSet(set[T], Generic[T]):
    __module__: str = 'canonical.ext.oauth2.types'

    @classmethod
    def __get_pydantic_core_schema__(cls, *_: Any) -> CoreSchema:
        return core_schema.json_or_python_schema(
            json_schema=core_schema.no_info_plain_validator_function(cls.fromstring),
            python_schema=core_schema.union_schema([
                core_schema.chain_schema([
                    core_schema.is_instance_schema(cls),
                ]),
                core_schema.chain_schema([
                    core_schema.is_instance_schema(set),
                    core_schema.no_info_plain_validator_function(cls.fromset)
                ]),
                core_schema.chain_schema([
                    core_schema.is_instance_schema(str),
                    core_schema.no_info_plain_validator_function(cls.fromstring),
                ]),
            ]),
            serialization=core_schema.plain_serializer_function_ser_schema(str),
        )

    @classmethod
    def __get_pydantic_json_schema__(
        cls,
        _: CoreSchema,
        handler: GetJsonSchemaHandler
    ) -> JsonSchemaValue:
        return handler(core_schema.str_schema())

    @classmethod
    def fromset(cls, v: set[Any]):
        if not all([isinstance(x, str) for x in v]):
            raise ValueError('all members must be strings')
        return cls(v)

    @classmethod
    def fromstring(cls, v: str):
        return set(filter(bool, {str.strip(x) for x in re.split(r'\s+', v)}))

    def __str__(self):
        return ' '.join(sorted(self)) # type: ignore