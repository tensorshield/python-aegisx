import base64
import json
from typing import Any
from typing import TypeVar

from pydantic_core import CoreSchema
from pydantic_core import core_schema
from pydantic.json_schema import JsonSchemaValue
from pydantic import GetJsonSchemaHandler


__all__: list[str] = [
    'PlainBase64'
]

T = TypeVar('T', bound='PlainBase64')


class PlainBase64(bytes):
    __module__: str = 'aegisx.types'

    @classmethod
    def __get_pydantic_core_schema__(cls, *_: Any) -> CoreSchema:
        return core_schema.json_or_python_schema(
            json_schema=core_schema.no_info_plain_validator_function(cls.fromb64),
            python_schema=core_schema.union_schema([
                core_schema.chain_schema([
                    core_schema.is_instance_schema(cls),
                ]),
                core_schema.chain_schema([
                    core_schema.is_instance_schema(str),
                    core_schema.no_info_plain_validator_function(cls.fromb64),
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
    def b64decode(cls, value: bytes | str):
        return base64.b64decode(value)

    @classmethod
    def b64encode(cls, value: bytes) -> str:
        return bytes.decode(base64.b64encode(value), 'ascii')

    @classmethod
    def fromb64(cls, value: bytes | str):
        return cls(base64.b64decode(value))

    @classmethod
    def fromdict(cls, value: dict[str, Any]):
        return cls(str.encode(json.dumps(value), 'utf-8'))

    @classmethod
    def fromstring(cls, value: str):
        return cls(str.encode(value))

    @classmethod
    def validate(cls, instance: T) -> T:
        return instance

    def __str__(self):
        return bytes.decode(base64.b64encode(self), 'ascii')

    def __repr__(self):
        return str(self)