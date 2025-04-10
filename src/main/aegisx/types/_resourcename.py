from typing import Any
from typing import Self
from typing import TypeVar

from pydantic_core import CoreSchema
from pydantic_core import core_schema
from pydantic.json_schema import JsonSchemaValue
from pydantic import GetJsonSchemaHandler


T = TypeVar('T', bound=str, default=str)


class ResourceName(str):
    description: str = (
        'A **Resource Name** as specified in AIP-122. Most APIs expose resources '
        '(their primary nouns) which users are able to create, retrieve, and '
        'manipulate. Additionally, resources are _named_: each resource has a '
        'unique identifier that users use to reference that resource, and these '
        'names are what users should _store_ as the canonical names for the resources.'
    )
    max_length: int = 255
    name: str = 'Resource Name'
    strip_whitespace: bool = True
    lowercase: bool = True

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
        schema['description'] = cls.description
        return schema

    @classmethod
    def __default_schema__(cls):
        return core_schema.chain_schema([
            core_schema.str_schema(
                max_length=cls.max_length,
                strip_whitespace=True,
                pattern=r'//'
            ),
            core_schema.no_info_plain_validator_function(cls.validate)
        ])

    @classmethod
    def validate(cls, value: str) -> Self:
        raise NotImplementedError